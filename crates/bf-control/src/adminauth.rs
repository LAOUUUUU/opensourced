//! The admin side of sign-in: who is an admin, the admin password and the unlock that opens the
//! admin pages for half an hour (`specs/accounts-and-admin.md`, slice 5).
//!
//! An admin signs in by email like everyone else and then proves they know the admin password.
//! Admin rights are given and taken away only from the command line. The password is kept as an
//! Argon2id hash; five wrong tries in a row lock the unlock for 15 minutes, and the right
//! password does not work while it is locked. Everything is a method on [`Store`] and takes the
//! time as an argument.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use rusqlite::{OptionalExtension, TransactionBehavior};

use crate::secrets::sha256;
use crate::signin::parse_cookie;
use crate::store::{Store, StoreError, from_sql, to_sql};

/// An unlock lasts this long.
pub const UNLOCK_SECS: u64 = 30 * 60;
/// This many wrong passwords in a row lock the unlock.
pub const MAX_WRONG_PASSWORDS: u32 = 5;
/// A lock lasts this long.
pub const LOCK_SECS: u64 = 15 * 60;
/// An admin password has at least this many characters.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// And at most this many bytes, so a huge "password" cannot be used to make the server work.
pub const MAX_PASSWORD_BYTES: usize = 256;

/// Argon2id version 19 with 19 MiB of memory, 2 passes and 1 lane: OWASP's first recommended
/// combination, which takes well under a second here.
fn argon2() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("these are valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Why a password cannot be an admin password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    TooShort,
    TooLong,
    /// The hasher itself failed (no randomness for the salt).
    Hashing,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(
                f,
                "an admin password has at least {MIN_PASSWORD_CHARS} characters"
            ),
            Self::TooLong => write!(
                f,
                "an admin password has at most {MAX_PASSWORD_BYTES} bytes"
            ),
            Self::Hashing => f.write_str("the password could not be hashed"),
        }
    }
}

/// The Argon2id hash of `password` as a PHC string, with a fresh random salt.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(PasswordError::TooShort);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong);
    }
    argon2()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError::Hashing)
}

/// Whether `password` is the one `phc` was made from. Anything that is not an Argon2id hash,
/// or is damaged, is a no.
pub fn verify_password(password: &str, phc: &str) -> bool {
    // Only Argon2id: a hash in a weaker variant is never accepted.
    if !phc.starts_with("$argon2id$") || password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    match PasswordHash::new(phc) {
        Ok(parsed) => argon2()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// What an attempt to unlock the admin pages came to. A page treats every one of them but
/// `Unlocked` the same way, so none of them says what was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminUnlock {
    Unlocked {
        until: u64,
    },
    WrongPassword,
    /// Too many wrong tries: nothing is checked until `until`.
    Locked {
        until: u64,
    },
    NotAdmin,
    /// An admin who has not been given a password yet.
    NoPassword,
    /// The session is not a live one.
    NoSession,
}

/// Why an admin password could not be set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetPasswordError {
    Password(PasswordError),
    NotAdmin,
    Store(StoreError),
}

impl std::fmt::Display for SetPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(e) => write!(f, "{e}"),
            Self::NotAdmin => {
                f.write_str("that account is not an admin: run `bf-control admin grant` first")
            }
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl From<StoreError> for SetPasswordError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<rusqlite::Error> for SetPasswordError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Store(e.into())
    }
}

impl Store {
    /// Makes an account an admin, or takes that away. Taking it away also forgets the
    /// password, any lock, and every unlock the account's sessions held, so it is over at once.
    pub fn set_admin(&mut self, account_id: i64, admin: bool) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE id = ?1)",
            [account_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NoSuchAccount);
        }
        tx.execute(
            "UPDATE accounts SET is_admin = ?2 WHERE id = ?1",
            rusqlite::params![account_id, admin],
        )?;
        if !admin {
            tx.execute(
                "UPDATE accounts SET admin_pw_hash = NULL, admin_fail_count = 0,
                                     admin_locked_until = NULL WHERE id = ?1",
                [account_id],
            )?;
            tx.execute(
                "UPDATE sessions SET admin_until = NULL WHERE account_id = ?1",
                [account_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn is_admin(&self, account_id: i64) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT is_admin FROM accounts WHERE id = ?1",
                [account_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// Sets (or replaces) an admin's password; a new password also clears the throttle and ends
    /// every unlock of that account, in the same transaction: if the old password may have
    /// leaked, nothing opened with it outlives it. The sessions stay (and stay admin
    /// sessions); they just ask for the password again.
    pub fn set_admin_password(
        &mut self,
        account_id: i64,
        password: &str,
    ) -> Result<(), SetPasswordError> {
        let admin: Option<bool> = self
            .conn
            .query_row(
                "SELECT is_admin FROM accounts WHERE id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .optional()?;
        match admin {
            None => return Err(StoreError::NoSuchAccount.into()),
            Some(false) => return Err(SetPasswordError::NotAdmin),
            Some(true) => {}
        }
        // The slow hashing is done before the write lock is taken.
        let hash = hash_password(password).map_err(SetPasswordError::Password)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE accounts SET admin_pw_hash = ?2, admin_fail_count = 0,
                                 admin_locked_until = NULL
             WHERE id = ?1 AND is_admin = 1",
            rusqlite::params![account_id, hash],
        )?;
        if changed == 0 {
            return Err(SetPasswordError::NotAdmin);
        }
        tx.execute(
            "UPDATE sessions SET admin_until = NULL WHERE account_id = ?1",
            [account_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Checks `password` for the account that holds the session `cookie`, and, if it is right,
    /// opens the admin pages on that session for [`UNLOCK_SECS`].
    pub fn admin_unlock(
        &mut self,
        cookie: &str,
        password: &str,
        now: u64,
    ) -> Result<AdminUnlock, StoreError> {
        let Some(session) = self.session(cookie, now)? else {
            return Ok(AdminUnlock::NoSession);
        };
        let Some((session_id, _)) = parse_cookie(cookie) else {
            return Ok(AdminUnlock::NoSession);
        };
        // Immediate, and the whole check inside it: two guesses at the same moment must not
        // both see the same count.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        type AdminRow = (bool, Option<String>, u32, Option<i64>);
        let row: Option<AdminRow> = tx
            .query_row(
                "SELECT is_admin, admin_pw_hash, admin_fail_count, admin_locked_until
                 FROM accounts WHERE id = ?1",
                [session.account_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((admin, hash, fails, locked_until)) = row else {
            return Ok(AdminUnlock::NoSession);
        };
        if !admin {
            return Ok(AdminUnlock::NotAdmin);
        }
        if let Some(until) = locked_until.map(from_sql)
            && until > now
        {
            return Ok(AdminUnlock::Locked { until });
        }
        let Some(hash) = hash else {
            return Ok(AdminUnlock::NoPassword);
        };
        if !verify_password(password, &hash) {
            let fails = fails + 1;
            if fails >= MAX_WRONG_PASSWORDS {
                tx.execute(
                    "UPDATE accounts SET admin_fail_count = 0, admin_locked_until = ?2
                     WHERE id = ?1",
                    rusqlite::params![session.account_id, to_sql(now + LOCK_SECS)],
                )?;
            } else {
                tx.execute(
                    "UPDATE accounts SET admin_fail_count = ?2 WHERE id = ?1",
                    rusqlite::params![session.account_id, fails],
                )?;
            }
            tx.commit()?;
            return Ok(AdminUnlock::WrongPassword);
        }
        let until = now + UNLOCK_SECS;
        tx.execute(
            "UPDATE accounts SET admin_fail_count = 0, admin_locked_until = NULL WHERE id = ?1",
            [session.account_id],
        )?;
        tx.execute(
            "UPDATE sessions SET admin_until = ?2 WHERE id = ?1",
            rusqlite::params![session_id, to_sql(until)],
        )?;
        tx.commit()?;
        Ok(AdminUnlock::Unlocked { until })
    }

    /// Closes the admin pages on this session.
    pub fn admin_lock(&mut self, cookie: &str) -> Result<(), StoreError> {
        let Some((id, secret)) = parse_cookie(cookie) else {
            return Ok(());
        };
        self.conn.execute(
            "UPDATE sessions SET admin_until = NULL WHERE id = ?1 AND secret_hash = ?2",
            rusqlite::params![id, sha256(secret.as_bytes()).to_vec()],
        )?;
        Ok(())
    }

    /// Whether this session may use the admin pages right now: it is live, its account is
    /// still an admin, and it has been unlocked less than [`UNLOCK_SECS`] ago.
    pub fn admin_unlocked(&self, cookie: &str, now: u64) -> Result<bool, StoreError> {
        let Some(session) = self.session(cookie, now)? else {
            return Ok(false);
        };
        Ok(self.is_admin(session.account_id)?
            && session.admin_until.is_some_and(|until| until > now))
    }

    /// Whether this session belongs to an admin, locked or not (the page that asks for the
    /// password is for them and nobody else).
    pub fn session_is_admin(&self, cookie: &str, now: u64) -> Result<bool, StoreError> {
        let Some(session) = self.session(cookie, now)? else {
            return Ok(false);
        };
        self.is_admin(session.account_id)
    }
}

// ---- what the admin pages list ----

/// Counts for the overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overview {
    pub accounts: u32,
    /// Devices that have not been removed.
    pub devices: u32,
    /// Kicks that are in force now, on devices that have not been removed.
    pub active_kicks: u32,
}

/// One account as the admin accounts page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAccount {
    pub id: i64,
    pub label: String,
    pub device_limit: u32,
    pub devices: u32,
    pub is_admin: bool,
    /// Whether the account has a sign-in address (only a fingerprint is kept, never the address).
    pub has_email: bool,
    pub created_at: u64,
}

/// One live device, with whose it is and whether it is kicked now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminDevice {
    pub id: i64,
    pub account_id: i64,
    pub account_label: String,
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub created_at: u64,
    pub kicked: bool,
    /// Whether the servers' resolver blocks trackers for it (`specs/trackers.md`).
    pub trackers: bool,
}

impl Store {
    pub fn admin_overview(&self, now: u64) -> Result<Overview, StoreError> {
        let count = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Result<u32, StoreError> {
            Ok(self.conn.query_row(sql, params, |row| row.get(0))?)
        };
        Ok(Overview {
            accounts: count("SELECT COUNT(*) FROM accounts", &[])?,
            devices: count("SELECT COUNT(*) FROM devices WHERE removed_at IS NULL", &[])?,
            // A removed device's kick counts: it still holds its account (decision 012).
            active_kicks: count(
                "SELECT COUNT(*) FROM kicks
                 WHERE started_at <= ?1
                   AND lifted_at IS NULL AND (until IS NULL OR until > ?1)",
                &[&to_sql(now)],
            )?,
        })
    }

    /// Every account, oldest first.
    pub fn admin_accounts(&self) -> Result<Vec<AdminAccount>, StoreError> {
        let mut query = self.conn.prepare(
            "SELECT accounts.id, accounts.label, accounts.device_limit, accounts.created_at,
                    accounts.is_admin, accounts.email_fp IS NOT NULL, COUNT(devices.id)
             FROM accounts LEFT JOIN devices
                  ON devices.account_id = accounts.id AND devices.removed_at IS NULL
             GROUP BY accounts.id ORDER BY accounts.id",
        )?;
        let rows = query.query_map([], |row| {
            Ok(AdminAccount {
                id: row.get(0)?,
                label: row.get(1)?,
                device_limit: row.get(2)?,
                created_at: from_sql(row.get(3)?),
                is_admin: row.get(4)?,
                has_email: row.get(5)?,
                devices: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Every device that has not been removed, oldest first.
    pub fn admin_devices(&self, now: u64) -> Result<Vec<AdminDevice>, StoreError> {
        let mut query = self.conn.prepare(
            "SELECT devices.id, devices.account_id, accounts.label, devices.name,
                    devices.address, devices.created_at,
                    EXISTS (SELECT 1 FROM kicks WHERE kicks.device_id = devices.id
                            AND kicks.started_at <= ?1 AND kicks.lifted_at IS NULL
                            AND (kicks.until IS NULL OR kicks.until > ?1)),
                    devices.tracker_filter
             FROM devices JOIN accounts ON accounts.id = devices.account_id
             WHERE devices.removed_at IS NULL ORDER BY devices.id",
        )?;
        let rows = query.query_map([to_sql(now)], |row| {
            Ok(AdminDevice {
                id: row.get(0)?,
                account_id: row.get(1)?,
                account_label: row.get(2)?,
                name: row.get(3)?,
                address: std::net::Ipv4Addr::from(row.get::<_, u32>(4)?),
                created_at: from_sql(row.get(5)?),
                kicked: row.get(6)?,
                trackers: row.get::<_, i64>(7)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery";
    const T0: u64 = 1_800_000_000;

    // ---- the hash ----

    #[test]
    fn a_password_hash_is_argon2id_with_the_recorded_parameters_and_does_not_hold_the_password() {
        let phc = hash_password(PASSWORD).unwrap();

        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(!phc.contains(PASSWORD));
        assert!(!phc.contains("correct"));
    }

    #[test]
    fn the_same_password_hashes_differently_each_time_and_each_hash_verifies() {
        let first = hash_password(PASSWORD).unwrap();
        let second = hash_password(PASSWORD).unwrap();

        assert_ne!(first, second, "a fresh salt each time");
        assert!(verify_password(PASSWORD, &first));
        assert!(verify_password(PASSWORD, &second));
    }

    #[test]
    fn a_wrong_password_a_near_miss_and_a_damaged_hash_all_fail() {
        let phc = hash_password(PASSWORD).unwrap();

        assert!(!verify_password("correct horse batterz", &phc));
        assert!(!verify_password("Correct horse battery", &phc));
        assert!(!verify_password("correct horse battery ", &phc));
        assert!(!verify_password("", &phc));
        assert!(!verify_password(PASSWORD, ""));
        assert!(!verify_password(PASSWORD, "not a hash"));
        assert!(!verify_password(PASSWORD, &phc[..phc.len() - 4]));
        assert!(!verify_password(
            PASSWORD,
            &phc.replace("argon2id", "argon2i")
        ));
        assert!(!verify_password(
            PASSWORD,
            &phc.replace("argon2id", "argon2d")
        ));
    }

    #[test]
    fn a_password_has_twelve_characters_and_at_most_256_bytes() {
        assert_eq!(
            hash_password("elevenchars").unwrap_err(),
            PasswordError::TooShort
        );
        assert!(hash_password("twelve chars").is_ok());
        assert_eq!(hash_password("").unwrap_err(), PasswordError::TooShort);
        // Characters, not bytes: eleven two-byte characters are still eleven.
        assert_eq!(
            hash_password(&"é".repeat(11)).unwrap_err(),
            PasswordError::TooShort
        );
        assert!(hash_password(&"é".repeat(12)).is_ok());
        assert!(hash_password(&"a".repeat(MAX_PASSWORD_BYTES)).is_ok());
        assert_eq!(
            hash_password(&"a".repeat(MAX_PASSWORD_BYTES + 1)).unwrap_err(),
            PasswordError::TooLong
        );
        assert_eq!(
            hash_password(&"é".repeat(129)).unwrap_err(),
            PasswordError::TooLong,
            "bytes count for the upper limit"
        );
    }

    // ---- who is an admin ----

    fn store_with_admin() -> (Store, i64) {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1).unwrap();
        store.set_admin(account.id, true).unwrap();
        (store, account.id)
    }

    #[test]
    fn nobody_is_an_admin_until_the_command_line_says_so_and_it_can_be_taken_away() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1).unwrap();
        assert!(!store.is_admin(account.id).unwrap());

        store.set_admin(account.id, true).unwrap();
        assert!(store.is_admin(account.id).unwrap());
        store.set_admin(account.id, true).unwrap();
        assert!(
            store.is_admin(account.id).unwrap(),
            "granting twice is fine"
        );

        store.set_admin(account.id, false).unwrap();
        assert!(!store.is_admin(account.id).unwrap());
        assert_eq!(store.set_admin(999, true), Err(StoreError::NoSuchAccount));
        assert_eq!(store.set_admin(999, false), Err(StoreError::NoSuchAccount));
        assert!(
            !store.is_admin(999).unwrap(),
            "an account that is not there is no admin"
        );
    }

    #[test]
    fn a_password_can_be_set_only_for_an_admin_and_replaced() {
        let mut store = Store::open_in_memory().unwrap();
        let plain = store.add_account("sam", 1).unwrap();
        assert_eq!(
            store.set_admin_password(plain.id, PASSWORD),
            Err(SetPasswordError::NotAdmin)
        );
        let (mut store, id) = store_with_admin();

        assert_eq!(
            store.set_admin_password(id, "short"),
            Err(SetPasswordError::Password(PasswordError::TooShort))
        );
        store.set_admin_password(id, PASSWORD).unwrap();
        let stored: String = store
            .conn
            .query_row(
                "SELECT admin_pw_hash FROM accounts WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(stored.starts_with("$argon2id$"));
        assert!(!stored.contains(PASSWORD));
        assert!(verify_password(PASSWORD, &stored));
        assert_eq!(
            store.set_admin_password(999, PASSWORD),
            Err(SetPasswordError::Store(StoreError::NoSuchAccount))
        );
    }

    // ---- unlocking ----

    fn signed_in(store: &mut Store, account_id: i64, now: u64) -> String {
        store.create_session(account_id, now).unwrap().cookie
    }

    #[test]
    fn the_right_password_opens_the_admin_pages_for_exactly_half_an_hour() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);
        assert!(store.session_is_admin(&cookie, T0).unwrap());
        assert!(
            !store.admin_unlocked(&cookie, T0).unwrap(),
            "locked until the password is given"
        );

        let result = store.admin_unlock(&cookie, PASSWORD, T0 + 10).unwrap();

        assert_eq!(
            result,
            AdminUnlock::Unlocked {
                until: T0 + 10 + UNLOCK_SECS
            }
        );
        assert!(store.admin_unlocked(&cookie, T0 + 10).unwrap());
        assert!(
            store
                .admin_unlocked(&cookie, T0 + 10 + UNLOCK_SECS - 1)
                .unwrap()
        );
        assert!(
            !store
                .admin_unlocked(&cookie, T0 + 10 + UNLOCK_SECS)
                .unwrap(),
            "over at the half hour"
        );
    }

    #[test]
    fn an_unlock_belongs_to_one_session_and_needs_the_whole_cookie() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let first = signed_in(&mut store, id, T0);
        let second = signed_in(&mut store, id, T0 + 1);
        store.admin_unlock(&first, PASSWORD, T0 + 2).unwrap();

        assert!(store.admin_unlocked(&first, T0 + 3).unwrap());
        assert!(
            !store.admin_unlocked(&second, T0 + 3).unwrap(),
            "another session is not unlocked"
        );
        let (lookup, secret) = first.split_once('.').unwrap();
        assert!(
            !store
                .admin_unlocked(&format!("{lookup}.{}", "0".repeat(secret.len())), T0 + 3)
                .unwrap()
        );
        assert!(!store.admin_unlocked("", T0 + 3).unwrap());
        assert!(!store.admin_unlocked("nonsense", T0 + 3).unwrap());
    }

    #[test]
    fn a_hash_made_by_a_weaker_argon2_variant_is_never_accepted_even_for_the_right_password() {
        for algorithm in [Algorithm::Argon2i, Algorithm::Argon2d] {
            let weaker = Argon2::new(
                algorithm,
                Version::V0x13,
                Params::new(19 * 1024, 2, 1, None).unwrap(),
            )
            .hash_password(PASSWORD.as_bytes())
            .unwrap()
            .to_string();

            assert!(!verify_password(PASSWORD, &weaker), "{weaker}");
        }
    }

    #[test]
    fn an_unlock_means_nothing_once_the_account_is_no_longer_an_admin() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);
        store.admin_unlock(&cookie, PASSWORD, T0).unwrap();
        // Somebody takes admin away behind the session's back (a half-finished revoke).
        store
            .conn
            .execute("UPDATE accounts SET is_admin = 0 WHERE id = ?1", [id])
            .unwrap();

        assert!(!store.admin_unlocked(&cookie, T0 + 1).unwrap());
    }

    #[test]
    fn locking_needs_the_whole_cookie_so_nobody_can_close_another_persons_admin_session() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);
        store.admin_unlock(&cookie, PASSWORD, T0).unwrap();
        let (lookup, secret) = cookie.split_once('.').unwrap();

        store
            .admin_lock(&format!("{lookup}.{}", "0".repeat(secret.len())))
            .unwrap();
        store.admin_lock(lookup).unwrap();
        store.admin_lock("").unwrap();

        assert!(
            store.admin_unlocked(&cookie, T0 + 1).unwrap(),
            "still unlocked"
        );
    }

    #[test]
    fn locking_closes_the_admin_pages_at_once() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);
        store.admin_unlock(&cookie, PASSWORD, T0).unwrap();

        store.admin_lock(&cookie).unwrap();

        assert!(!store.admin_unlocked(&cookie, T0 + 1).unwrap());
        assert!(
            store.session_is_admin(&cookie, T0 + 1).unwrap(),
            "still signed in as an admin"
        );
    }

    #[test]
    fn five_wrong_passwords_lock_the_unlock_for_fifteen_minutes_and_the_right_one_fails_meanwhile()
    {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);

        for n in 0..4 {
            assert_eq!(
                store
                    .admin_unlock(&cookie, "wrong password!", T0 + n)
                    .unwrap(),
                AdminUnlock::WrongPassword,
                "try {n}"
            );
        }
        let fifth = store
            .admin_unlock(&cookie, "wrong password!", T0 + 4)
            .unwrap();
        assert_eq!(
            fifth,
            AdminUnlock::WrongPassword,
            "the fifth is told the same as the others"
        );

        let right_now = store.admin_unlock(&cookie, PASSWORD, T0 + 5).unwrap();
        assert_eq!(
            right_now,
            AdminUnlock::Locked {
                until: T0 + 4 + LOCK_SECS
            }
        );
        assert!(!store.admin_unlocked(&cookie, T0 + 5).unwrap());
        let just_before = store
            .admin_unlock(&cookie, PASSWORD, T0 + 4 + LOCK_SECS - 1)
            .unwrap();
        assert!(
            matches!(just_before, AdminUnlock::Locked { .. }),
            "{just_before:?}"
        );

        let after = store
            .admin_unlock(&cookie, PASSWORD, T0 + 4 + LOCK_SECS)
            .unwrap();
        assert_eq!(
            after,
            AdminUnlock::Unlocked {
                until: T0 + 4 + LOCK_SECS + UNLOCK_SECS
            }
        );
    }

    #[test]
    fn the_lock_follows_the_account_so_a_new_session_does_not_get_a_fresh_five() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let first = signed_in(&mut store, id, T0);
        for n in 0..5 {
            store
                .admin_unlock(&first, "wrong password!", T0 + n)
                .unwrap();
        }
        let second = signed_in(&mut store, id, T0 + 10);

        let result = store.admin_unlock(&second, PASSWORD, T0 + 11).unwrap();

        assert!(matches!(result, AdminUnlock::Locked { .. }), "{result:?}");
    }

    #[test]
    fn a_right_password_forgets_the_wrong_ones_before_it_and_a_lock_that_ended_starts_from_zero() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);

        for n in 0..4 {
            store
                .admin_unlock(&cookie, "wrong password!", T0 + n)
                .unwrap();
        }
        assert!(matches!(
            store.admin_unlock(&cookie, PASSWORD, T0 + 5).unwrap(),
            AdminUnlock::Unlocked { .. }
        ));
        for n in 0..4 {
            assert_eq!(
                store
                    .admin_unlock(&cookie, "wrong password!", T0 + 10 + n)
                    .unwrap(),
                AdminUnlock::WrongPassword
            );
        }
        assert!(
            matches!(
                store.admin_unlock(&cookie, PASSWORD, T0 + 20).unwrap(),
                AdminUnlock::Unlocked { .. }
            ),
            "four and four wrong are not five in a row"
        );

        // A lock that has run out leaves a clean count: four more wrong ones do not lock again.
        for n in 0..5 {
            store
                .admin_unlock(&cookie, "wrong password!", T0 + 100 + n)
                .unwrap();
        }
        let later = T0 + 100 + LOCK_SECS + 10;
        for n in 0..4 {
            assert_eq!(
                store
                    .admin_unlock(&cookie, "wrong password!", later + n)
                    .unwrap(),
                AdminUnlock::WrongPassword
            );
        }
        assert!(matches!(
            store.admin_unlock(&cookie, PASSWORD, later + 10).unwrap(),
            AdminUnlock::Unlocked { .. }
        ));
    }

    #[test]
    fn someone_who_is_not_an_admin_or_has_no_password_or_no_session_cannot_unlock_and_is_not_counted()
     {
        let mut store = Store::open_in_memory().unwrap();
        let plain = store.add_account("sam", 1).unwrap();
        let plain_cookie = signed_in(&mut store, plain.id, T0);
        assert_eq!(
            store.admin_unlock(&plain_cookie, PASSWORD, T0).unwrap(),
            AdminUnlock::NotAdmin
        );
        assert!(!store.session_is_admin(&plain_cookie, T0).unwrap());

        let (mut store, id) = store_with_admin();
        let cookie = signed_in(&mut store, id, T0);
        assert_eq!(
            store.admin_unlock(&cookie, PASSWORD, T0).unwrap(),
            AdminUnlock::NoPassword
        );
        assert_eq!(
            store.admin_unlock("nonsense", PASSWORD, T0).unwrap(),
            AdminUnlock::NoSession
        );
        let expired = store
            .admin_unlock(&cookie, PASSWORD, T0 + 61 * 86_400)
            .unwrap();
        assert_eq!(
            expired,
            AdminUnlock::NoSession,
            "a session that ran out is no session"
        );
        let fails: i64 = store
            .conn
            .query_row(
                "SELECT admin_fail_count FROM accounts WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fails, 0);
    }

    #[test]
    fn taking_admin_away_closes_every_unlock_and_forgets_the_password_at_once() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);
        store.admin_unlock(&cookie, PASSWORD, T0).unwrap();
        assert!(store.admin_unlocked(&cookie, T0 + 1).unwrap());

        store.set_admin(id, false).unwrap();

        assert!(!store.admin_unlocked(&cookie, T0 + 1).unwrap());
        assert!(!store.session_is_admin(&cookie, T0 + 1).unwrap());
        let (hash, fails, locked, until): (Option<String>, i64, Option<i64>, Option<i64>) = store
            .conn
            .query_row(
                "SELECT admin_pw_hash, admin_fail_count, admin_locked_until,
                        (SELECT admin_until FROM sessions WHERE account_id = ?1) FROM accounts WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!((hash, fails, locked, until), (None, 0, None, None));
        // Granting again does not bring the old password back.
        store.set_admin(id, true).unwrap();
        assert_eq!(
            store.admin_unlock(&cookie, PASSWORD, T0 + 2).unwrap(),
            AdminUnlock::NoPassword
        );
    }

    #[test]
    fn a_new_password_ends_every_open_unlock_of_that_account_and_no_other() {
        // If the old password may have leaked, an unlock made with it must not outlive it.
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let other = store.add_account("second", T0).unwrap();
        store.set_admin(other.id, true).unwrap();
        store.set_admin_password(other.id, PASSWORD).unwrap();
        let first = signed_in(&mut store, id, T0);
        let second = signed_in(&mut store, id, T0);
        let elsewhere = signed_in(&mut store, other.id, T0);
        for cookie in [&first, &second, &elsewhere] {
            assert!(matches!(
                store.admin_unlock(cookie, PASSWORD, T0 + 1).unwrap(),
                AdminUnlock::Unlocked { .. }
            ));
        }

        store
            .set_admin_password(id, "a brand new password")
            .unwrap();

        for cookie in [&first, &second] {
            assert!(
                !store.admin_unlocked(cookie, T0 + 2).unwrap(),
                "unlocked with the old password"
            );
            assert!(
                store.session_is_admin(cookie, T0 + 2).unwrap(),
                "still signed in, and still an admin: only the unlock is over"
            );
        }
        assert!(
            store.admin_unlocked(&elsewhere, T0 + 2).unwrap(),
            "another account's unlock is none of this"
        );
    }

    #[test]
    fn a_new_password_replaces_the_old_one_and_clears_a_lock() {
        let (mut store, id) = store_with_admin();
        store.set_admin_password(id, PASSWORD).unwrap();
        let cookie = signed_in(&mut store, id, T0);
        for n in 0..5 {
            store
                .admin_unlock(&cookie, "wrong password!", T0 + n)
                .unwrap();
        }
        assert!(matches!(
            store.admin_unlock(&cookie, PASSWORD, T0 + 6).unwrap(),
            AdminUnlock::Locked { .. }
        ));

        store
            .set_admin_password(id, "a brand new password")
            .unwrap();

        assert_eq!(
            store.admin_unlock(&cookie, PASSWORD, T0 + 7).unwrap(),
            AdminUnlock::WrongPassword,
            "the old one is gone"
        );
        assert!(matches!(
            store
                .admin_unlock(&cookie, "a brand new password", T0 + 8)
                .unwrap(),
            AdminUnlock::Unlocked { .. }
        ));
    }

    // ---- the lists ----

    fn key(n: u8) -> String {
        crate::keys::KeyPair::from_private([n; 32]).public_key
    }

    #[test]
    fn the_overview_counts_accounts_live_devices_and_kicks_in_force_and_nothing_else() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(
            store.admin_overview(T0).unwrap(),
            Overview {
                accounts: 0,
                devices: 0,
                active_kicks: 0
            }
        );
        let lao = store.add_account("lao", 1).unwrap();
        let sam = store.add_account("sam", 1).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 2).unwrap();
        let laptop = store.add_device(lao.id, "laptop", &key(2), 3).unwrap();
        let tablet = store.add_device(sam.id, "tablet", &key(3), 4).unwrap();
        store.remove_device(tablet.id, 5).unwrap();
        use crate::store::KickEnd;
        store
            .kick(phone.id, KickEnd::At(T0 + 100), "admin", "", T0 - 10)
            .unwrap();
        store
            .kick(laptop.id, KickEnd::UntilLifted, "admin", "", T0 - 10)
            .unwrap();
        store.lift(laptop.id, "admin", T0 - 5).unwrap();

        assert_eq!(
            store.admin_overview(T0).unwrap(),
            Overview {
                accounts: 2,
                devices: 2,
                active_kicks: 1
            }
        );
        assert_eq!(
            store.admin_overview(T0 + 100).unwrap().active_kicks,
            0,
            "it ran out"
        );
    }

    #[test]
    fn a_kick_on_a_removed_device_still_counts_as_in_force_until_lifted() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 2).unwrap();
        store
            .kick(phone.id, crate::store::KickEnd::UntilLifted, "admin", "", 3)
            .unwrap();
        store.remove_device(phone.id, 4).unwrap();

        // It still stops the account adding a device (decision 012).
        assert_eq!(store.admin_overview(T0).unwrap().active_kicks, 1);
        store.lift(phone.id, "admin", 5).unwrap();
        assert_eq!(store.admin_overview(T0).unwrap().active_kicks, 0);
    }

    #[test]
    fn the_accounts_list_says_who_is_an_admin_who_has_an_address_and_how_many_devices() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1).unwrap();
        let sam = store.add_account("sam", 2).unwrap();
        store.set_email_fp(lao.id, &[7u8; 32]).unwrap();
        store.set_admin(lao.id, true).unwrap();
        store.add_device(lao.id, "phone", &key(1), 3).unwrap();
        let gone = store.add_device(lao.id, "old", &key(2), 4).unwrap();
        store.remove_device(gone.id, 5).unwrap();

        let rows = store.admin_accounts().unwrap();

        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            AdminAccount {
                id: lao.id,
                label: "lao".into(),
                device_limit: 3,
                devices: 1,
                is_admin: true,
                has_email: true,
                created_at: 1
            }
        );
        assert_eq!(
            (
                rows[1].id,
                rows[1].is_admin,
                rows[1].has_email,
                rows[1].devices
            ),
            (sam.id, false, false, 0)
        );
    }

    #[test]
    fn the_devices_list_has_live_devices_with_their_owner_and_whether_they_are_kicked_now() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 2).unwrap();
        let laptop = store.add_device(lao.id, "laptop", &key(2), 3).unwrap();
        let gone = store.add_device(lao.id, "gone", &key(3), 4).unwrap();
        store.remove_device(gone.id, 5).unwrap();
        store
            .kick(
                laptop.id,
                crate::store::KickEnd::At(T0 + 50),
                "admin",
                "",
                T0 - 1,
            )
            .unwrap();

        let rows = store.admin_devices(T0).unwrap();

        assert_eq!(
            rows.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            ["phone", "laptop"]
        );
        assert_eq!(rows[0].account_label, "lao");
        assert_eq!(rows[0].address, phone.address);
        assert_eq!((rows[0].kicked, rows[1].kicked), (false, true));
        assert!(
            !store.admin_devices(T0 + 50).unwrap()[1].kicked,
            "the kick ran out"
        );
    }

    #[test]
    fn the_devices_list_says_whether_each_device_has_trackers_blocked() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1).unwrap();
        store.add_device(lao.id, "phone", &key(1), 2).unwrap();
        let laptop = store.add_device(lao.id, "laptop", &key(2), 3).unwrap();
        store.set_tracker_filter(lao.id, laptop.id, false).unwrap();

        let rows = store.admin_devices(T0).unwrap();

        assert_eq!((rows[0].trackers, rows[1].trackers), (true, false));
    }
}
