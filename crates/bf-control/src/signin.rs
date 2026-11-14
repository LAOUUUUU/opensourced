//! Sign-in: emailed codes, sessions, and the limits that keep the mail budget safe.
//!
//! Everything here is a method on [`Store`], and every one that depends on the time takes
//! it as an argument (Unix seconds), as in the rest of the store. The email address is
//! never stored: callers pass its keyed fingerprint (`ControlKeys::email_fingerprint`).

/// Schema version 2, applied on top of version 1. `docs/SCHEMA.md` describes every column.
///
/// `login_codes` holds a keyed check value for each code (never the code). `sessions`
/// holds a lookup id and the SHA-256 of a separate secret (never the secret).
/// `mail_log` is what the three limits and the daily budget count; its rows are purged
/// after a day. The `accounts` columns are for the admin password and its throttle
/// (used from the admin slice).
pub(crate) const SCHEMA_2: &str = "
ALTER TABLE accounts ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1));
ALTER TABLE accounts ADD COLUMN admin_pw_hash TEXT;
ALTER TABLE accounts ADD COLUMN admin_fail_count INTEGER NOT NULL DEFAULT 0 CHECK (admin_fail_count >= 0);
ALTER TABLE accounts ADD COLUMN admin_locked_until INTEGER;

CREATE TABLE login_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email_fp   BLOB    NOT NULL,
    code_mac   BLOB    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    tries      INTEGER NOT NULL DEFAULT 0,
    used_at    INTEGER
) STRICT;
CREATE INDEX login_codes_by_email ON login_codes (email_fp);

CREATE TABLE sessions (
    id          TEXT    PRIMARY KEY,
    secret_hash BLOB    NOT NULL,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    csrf        TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    admin_until INTEGER
) STRICT;
CREATE INDEX sessions_by_account ON sessions (account_id);

CREATE TABLE mail_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at INTEGER NOT NULL,
    email_fp BLOB,
    ip_fp   BLOB,
    kind    TEXT    NOT NULL CHECK (kind IN ('request', 'sent', 'failed', 'quota')),
    outcome TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX mail_log_by_time ON mail_log (sent_at);
";

/// Version 3 to 4: whether a session was made with "keep me signed in" ticked. Only a kept
/// session is renewed when it is used; every session that exists already stays as it was.
pub(crate) const SCHEMA_4: &str = "
ALTER TABLE sessions ADD COLUMN keep INTEGER NOT NULL DEFAULT 0 CHECK (keep IN (0, 1));
";

use std::fmt;

use rusqlite::{OptionalExtension, TransactionBehavior};

use bf_common::sign::hex;

use crate::secrets::{ControlKeys, constant_time_eq, random_bytes, sha256};
use crate::store::{Account, Store, StoreError, account_from_row, from_sql, to_sql};

/// A sign-in code works for 10 minutes.
pub const CODE_LIFETIME_SECS: u64 = 600;
/// A code allows 5 wrong tries; the fifth ends it.
pub const MAX_WRONG_TRIES: u32 = 5;
/// Code requests allowed per address per hour (known or not).
pub const REQUESTS_PER_ADDRESS_PER_HOUR: u32 = 3;
/// Code requests allowed per network address per hour.
pub const REQUESTS_PER_NETWORK_PER_HOUR: u32 = 10;
/// Emails sent per UTC day. Resend's free plan allows 100; the rest is kept in hand.
pub const DAILY_MAIL_BUDGET: u32 = 90;
/// A session lasts 60 days from sign-in.
pub const SESSION_LIFETIME_SECS: u64 = 60 * 86_400;
/// A kept session (the person ticked "keep me signed in") never runs past this long after it
/// began, however often it is used. Chrome cuts a cookie's lifetime at 400 days.
pub const KEPT_SESSION_MAX_SECS: u64 = 365 * 86_400;
/// A kept session is renewed at most this often, so reading a page is not a write each time.
pub const RENEW_EVERY_SECS: u64 = 86_400;
/// An account keeps its newest ten sessions; older ones are dropped.
pub const MAX_SESSIONS_PER_ACCOUNT: u32 = 10;
/// Rows of the mail log, used codes and the like are kept this long.
pub const KEEP_SECS: u64 = 86_400;
/// Open sign-up: code requests for addresses with no account allowed per UTC day. The rest of
/// the daily mail budget is kept for people who already have accounts.
pub const NEW_ADDRESS_MAIL_PER_DAY: u32 = 60;
/// Open sign-up: new accounts allowed per UTC day, however they are made.
pub const NEW_ACCOUNTS_PER_DAY: u32 = 20;

/// The daily caps that go with open sign-up (spec: `specs/open-signup.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenLimits {
    pub new_mail_per_day: u32,
    pub new_accounts_per_day: u32,
}

impl Default for OpenLimits {
    fn default() -> Self {
        OpenLimits {
            new_mail_per_day: NEW_ADDRESS_MAIL_PER_DAY,
            new_accounts_per_day: NEW_ACCOUNTS_PER_DAY,
        }
    }
}

/// What a request for a sign-in code came to. The page the person sees is the same for
/// [`CodeRequest::Send`] and [`CodeRequest::Nothing`], so it never says whether an
/// account has the address; [`CodeRequest::Limited`] and [`CodeRequest::Paused`] are
/// decided without looking at accounts at all, so they too are the same for everyone.
#[derive(PartialEq, Eq)]
pub enum CodeRequest {
    /// An account has this address: email `code` to it. `code_id` is for the
    /// idempotency key, so a retry cannot send twice.
    Send { code_id: i64, code: String },
    /// Taken, but there is nothing to send.
    Nothing,
    /// Too many requests for this address, or from this network, in the last hour.
    Limited,
    /// Today's mail budget is used up, or Resend says its quota is.
    Paused,
    /// Open sign-up only, for an address with no account: today's share of mail for new
    /// addresses, or today's new accounts, is used up. Nothing was stored or counted.
    Full,
}

impl fmt::Debug for CodeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeRequest::Send { code_id, .. } => {
                write!(f, "Send {{ code_id: {code_id}, code: [hidden] }}")
            }
            CodeRequest::Nothing => write!(f, "Nothing"),
            CodeRequest::Limited => write!(f, "Limited"),
            CodeRequest::Paused => write!(f, "Paused"),
            CodeRequest::Full => write!(f, "Full"),
        }
    }
}

/// What came of handing a code to the mailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailResult {
    /// Resend took it. Counts against today's budget.
    Sent,
    /// Resend did not take it. Does not count.
    Failed,
    /// Resend says its sending quota is used up: no more mail until the UTC day ends.
    QuotaExhausted,
}

/// What checking a typed code came to. Everything that is not a right code is `Bad`,
/// whatever the reason (no code, expired, used up, wrong, wrong address), so the answer
/// tells nobody which it was.
#[derive(Debug, PartialEq, Eq)]
pub enum CodeCheck {
    Verified {
        account_id: i64,
    },
    /// Open sign-up: nobody had this address, and typing the code made the account.
    Created {
        account_id: i64,
    },
    /// Open sign-up: the code is right but today's new accounts are used up in the meantime.
    /// The code is left unused; nothing was made.
    Full,
    Bad,
}

/// A session just made. The cookie holds the secret and is shown once.
#[derive(Clone, PartialEq, Eq)]
pub struct NewSession {
    /// `<lookup id>.<secret>`, both lowercase hex: what goes in the cookie.
    pub cookie: String,
    /// The token for the hidden field of every form (not a secret of the cookie).
    pub csrf: String,
    pub expires_at: u64,
}

impl fmt::Debug for NewSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSession")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// A session that checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub account_id: i64,
    pub csrf: String,
    pub expires_at: u64,
    /// Until when the admin password has been accepted on this session (admin slice).
    pub admin_until: Option<u64>,
}

/// The start of the UTC day that `now` is in.
pub fn utc_day_start(now: u64) -> u64 {
    now - now % 86_400
}

impl Store {
    /// Lets anyone make an account by typing a sign-in code, up to these daily caps. Without
    /// it, only accounts an admin made can sign in.
    pub fn with_open_signup(mut self, limits: OpenLimits) -> Store {
        self.open_signup = Some(limits);
        self
    }

    /// The caps if sign-up is open, `None` in the closed beta.
    pub fn open_limits(&self) -> Option<OpenLimits> {
        self.open_signup
    }

    /// Gives an account its email fingerprint (never the address itself).
    pub fn set_email_fp(&mut self, account_id: i64, email_fp: &[u8; 32]) -> Result<(), StoreError> {
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
        let taken: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE email_fp = ?1 AND id != ?2)",
            rusqlite::params![&email_fp[..], account_id],
            |row| row.get(0),
        )?;
        if taken {
            return Err(StoreError::EmailInUse);
        }
        tx.execute(
            "UPDATE accounts SET email_fp = ?1 WHERE id = ?2",
            rusqlite::params![&email_fp[..], account_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Makes an account, with the fingerprint of its sign-in address if there is one, in one
    /// transaction: afterwards both are there or neither is. A used address is
    /// [`StoreError::EmailInUse`] and a bad label [`StoreError::BadName`], and nothing is made.
    pub fn add_account_with_email(
        &mut self,
        label: &str,
        email_fp: Option<&[u8; 32]>,
        now: u64,
    ) -> Result<Account, StoreError> {
        crate::store::check_name(label)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(email_fp) = email_fp {
            let taken: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM accounts WHERE email_fp = ?1)",
                [&email_fp[..]],
                |row| row.get(0),
            )?;
            if taken {
                return Err(StoreError::EmailInUse);
            }
        }
        tx.execute(
            "INSERT INTO accounts (label, email_fp, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![label, email_fp.map(|fp| &fp[..]), to_sql(now)],
        )?;
        let id = tx.last_insert_rowid();
        let account = tx.query_row(
            "SELECT id, label, device_limit, created_at FROM accounts WHERE id = ?1",
            [id],
            account_from_row,
        )?;
        tx.commit()?;
        Ok(account)
    }

    /// The account that has this email fingerprint, if any.
    pub fn account_for_email_fp(&self, email_fp: &[u8; 32]) -> Result<Option<Account>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, label, device_limit, created_at FROM accounts WHERE email_fp = ?1",
                [&email_fp[..]],
                account_from_row,
            )
            .optional()?)
    }

    /// The account with this id, if there is one.
    pub fn account(&self, account_id: i64) -> Result<Option<Account>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, label, device_limit, created_at FROM accounts WHERE id = ?1",
                [account_id],
                account_from_row,
            )
            .optional()?)
    }

    /// Someone asked for a sign-in code. See [`CodeRequest`]. `ip_fp` is the keyed
    /// fingerprint of their network address, if there is one.
    ///
    /// The order matters, and none of it looks at accounts until the very end: the budget
    /// first, then the two limits (every request counts, known address or not), and only
    /// then whether an account has the address.
    pub fn request_code(
        &mut self,
        keys: &ControlKeys,
        email_fp: &[u8; 32],
        ip_fp: Option<&[u8; 32]>,
        now: u64,
    ) -> Result<CodeRequest, StoreError> {
        let open = self.open_signup;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        purge(&tx, now)?;

        let day = to_sql(utc_day_start(now));
        let sent_today: u32 = tx.query_row(
            "SELECT COUNT(*) FROM mail_log WHERE kind = 'sent' AND sent_at >= ?1",
            [day],
            |row| row.get(0),
        )?;
        let quota_hit: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM mail_log WHERE kind = 'quota' AND sent_at >= ?1)",
            [day],
            |row| row.get(0),
        )?;
        if quota_hit || sent_today >= DAILY_MAIL_BUDGET {
            tx.commit()?;
            return Ok(CodeRequest::Paused);
        }

        let hour_ago = to_sql(now.saturating_sub(3_600));
        let by_address: u32 = tx.query_row(
            "SELECT COUNT(*) FROM mail_log WHERE kind = 'request' AND email_fp = ?1 AND sent_at > ?2",
            rusqlite::params![&email_fp[..], hour_ago],
            |row| row.get(0),
        )?;
        let by_network: u32 = match ip_fp {
            Some(ip) => tx.query_row(
                "SELECT COUNT(*) FROM mail_log WHERE kind = 'request' AND ip_fp = ?1 AND sent_at > ?2",
                rusqlite::params![&ip[..], hour_ago],
                |row| row.get(0),
            )?,
            None => 0,
        };
        if by_address >= REQUESTS_PER_ADDRESS_PER_HOUR
            || by_network >= REQUESTS_PER_NETWORK_PER_HOUR
        {
            tx.commit()?;
            return Ok(CodeRequest::Limited);
        }

        let has_account: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM accounts WHERE email_fp = ?1)",
            [&email_fp[..]],
            |row| row.get(0),
        )?;
        // Open sign-up lets strangers in, so how many may come in a day is capped. A refused
        // request is not written down: it used no mail, and it is not a try of theirs.
        if let (false, Some(limits)) = (has_account, open) {
            let new_today: u32 = tx.query_row(
                "SELECT COUNT(*) FROM mail_log
                 WHERE kind = 'request' AND outcome = 'new' AND sent_at >= ?1",
                [day],
                |row| row.get(0),
            )?;
            if new_today >= limits.new_mail_per_day
                || accounts_made_today(&tx, now)? >= limits.new_accounts_per_day
            {
                tx.commit()?;
                return Ok(CodeRequest::Full);
            }
        }
        let is_new = !has_account && open.is_some();
        tx.execute(
            "INSERT INTO mail_log (sent_at, email_fp, ip_fp, kind, outcome)
             VALUES (?1, ?2, ?3, 'request', ?4)",
            rusqlite::params![
                to_sql(now),
                &email_fp[..],
                ip_fp.map(|ip| &ip[..]),
                if is_new { "new" } else { "" }
            ],
        )?;
        if !has_account && open.is_none() {
            tx.commit()?;
            return Ok(CodeRequest::Nothing);
        }

        // One live code per address: a new request ends the old one.
        tx.execute(
            "DELETE FROM login_codes WHERE email_fp = ?1",
            [&email_fp[..]],
        )?;
        let code = crate::secrets::random_code().map_err(random_failed)?;
        let mac = keys.code_mac(email_fp, &code);
        tx.execute(
            "INSERT INTO login_codes (email_fp, code_mac, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                &email_fp[..],
                &mac[..],
                to_sql(now),
                to_sql(now + CODE_LIFETIME_SECS)
            ],
        )?;
        let code_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(CodeRequest::Send { code_id, code })
    }

    /// Writes down what happened to a code email, for the daily budget.
    pub fn record_mail_result(
        &mut self,
        email_fp: &[u8; 32],
        result: MailResult,
        now: u64,
    ) -> Result<(), StoreError> {
        let kind = match result {
            MailResult::Sent => "sent",
            MailResult::Failed => "failed",
            MailResult::QuotaExhausted => "quota",
        };
        self.conn.execute(
            "INSERT INTO mail_log (sent_at, email_fp, kind) VALUES (?1, ?2, ?3)",
            rusqlite::params![to_sql(now), &email_fp[..], kind],
        )?;
        Ok(())
    }

    /// Checks a typed code. A right code is used up; a wrong one costs one of five tries.
    pub fn verify_code(
        &mut self,
        keys: &ControlKeys,
        email_fp: &[u8; 32],
        code: &str,
        now: u64,
    ) -> Result<CodeCheck, StoreError> {
        // Not six digits: nothing to look up, and nothing to count as a try.
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(CodeCheck::Bad);
        }
        let open = self.open_signup;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let live: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT id, code_mac FROM login_codes
                 WHERE email_fp = ?1 AND used_at IS NULL AND expires_at > ?2 AND tries < ?3
                 ORDER BY id DESC LIMIT 1",
                rusqlite::params![&email_fp[..], to_sql(now), MAX_WRONG_TRIES],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((id, stored)) = live else {
            return Ok(CodeCheck::Bad);
        };

        let mac = keys.code_mac(email_fp, code);
        if !constant_time_eq(&stored, &mac) {
            tx.execute(
                "UPDATE login_codes SET tries = tries + 1 WHERE id = ?1",
                [id],
            )?;
            tx.commit()?;
            return Ok(CodeCheck::Bad);
        }

        let account: Option<i64> = tx
            .query_row(
                "SELECT id FROM accounts WHERE email_fp = ?1",
                [&email_fp[..]],
                |row| row.get(0),
            )
            .optional()?;
        // Open sign-up: the mailbox is proved, so the account can exist now.
        let (account, created) = match (account, open) {
            (None, Some(limits)) => {
                // The day's last place may have gone since the code was asked for. The
                // transaction is dropped, so the code is not used up.
                if accounts_made_today(&tx, now)? >= limits.new_accounts_per_day {
                    return Ok(CodeCheck::Full);
                }
                (Some(make_member(&tx, email_fp, now)?), true)
            }
            (other, _) => (other, false),
        };
        // The code is used up either way, and no other code for this address survives.
        tx.execute(
            "UPDATE login_codes SET used_at = ?2 WHERE id = ?1",
            rusqlite::params![id, to_sql(now)],
        )?;
        tx.execute(
            "DELETE FROM login_codes WHERE email_fp = ?1 AND id != ?2",
            rusqlite::params![&email_fp[..], id],
        )?;
        tx.commit()?;
        Ok(match account {
            Some(account_id) if created => CodeCheck::Created { account_id },
            Some(account_id) => CodeCheck::Verified { account_id },
            None => CodeCheck::Bad,
        })
    }

    /// Starts a session for an account. Every sign-in makes a new id. This one is not
    /// renewed when it is used: it ends sixty days after it began.
    pub fn create_session(&mut self, account_id: i64, now: u64) -> Result<NewSession, StoreError> {
        self.create_session_keeping(account_id, false, now)
    }

    /// Starts a session; with `keep` (the person ticked "keep me signed in on this device")
    /// using it renews it, see [`Store::renew_session`].
    pub fn create_session_keeping(
        &mut self,
        account_id: i64,
        keep: bool,
        now: u64,
    ) -> Result<NewSession, StoreError> {
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
        purge(&tx, now)?;

        let id = hex(&random_bytes::<16>().map_err(random_failed)?);
        let secret = hex(&random_bytes::<32>().map_err(random_failed)?);
        let csrf = hex(&random_bytes::<16>().map_err(random_failed)?);
        let expires_at = now + SESSION_LIFETIME_SECS;
        tx.execute(
            "INSERT INTO sessions (id, secret_hash, account_id, csrf, created_at, expires_at, keep)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                id,
                &sha256(secret.as_bytes())[..],
                account_id,
                csrf,
                to_sql(now),
                to_sql(expires_at),
                keep
            ],
        )?;
        // Keep the newest few; a lost phone's old session does not pile up forever.
        tx.execute(
            "DELETE FROM sessions WHERE account_id = ?1 AND id NOT IN
                 (SELECT id FROM sessions WHERE account_id = ?1
                  ORDER BY created_at DESC, rowid DESC LIMIT ?2)",
            rusqlite::params![account_id, MAX_SESSIONS_PER_ACCOUNT],
        )?;
        tx.commit()?;
        Ok(NewSession {
            cookie: format!("{id}.{secret}"),
            csrf,
            expires_at,
        })
    }

    /// The session a cookie stands for, if it is real and has not expired.
    pub fn session(&self, cookie: &str, now: u64) -> Result<Option<SessionInfo>, StoreError> {
        let Some((id, secret)) = parse_cookie(cookie) else {
            return Ok(None);
        };
        let row: Option<SessionRow> = self
            .conn
            .query_row(
                "SELECT secret_hash, account_id, csrf, expires_at, admin_until
                 FROM sessions WHERE id = ?1",
                [id],
                |row| {
                    Ok(SessionRow {
                        secret_hash: row.get(0)?,
                        account_id: row.get(1)?,
                        csrf: row.get(2)?,
                        expires_at: row.get(3)?,
                        admin_until: row.get(4)?,
                    })
                },
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(None);
        };
        if !constant_time_eq(&row.secret_hash, &sha256(secret.as_bytes()))
            || from_sql(row.expires_at) <= now
        {
            return Ok(None);
        }
        Ok(Some(SessionInfo {
            account_id: row.account_id,
            csrf: row.csrf,
            expires_at: from_sql(row.expires_at),
            admin_until: row.admin_until.map(from_sql),
        }))
    }

    /// Called when a session is used. A kept session (see [`Store::create_session_keeping`])
    /// that is live is given sixty more days from `now`, but never past a year from when it
    /// began, and not more than once a day (a renewal is a write). Returns the new end of the
    /// session if it was renewed, so the cookie can be sent again with the time that is left.
    /// Anything else (a session that was not kept, one that ran out, a cookie that is wrong)
    /// is `None` and changes nothing.
    pub fn renew_session(&mut self, cookie: &str, now: u64) -> Result<Option<u64>, StoreError> {
        let Some((id, secret)) = parse_cookie(cookie) else {
            return Ok(None);
        };
        // A plain read: most requests renew nothing, and they should not wait for (or take)
        // the database's write lock to find that out.
        let row: Option<(Vec<u8>, i64, i64, bool)> = self
            .conn
            .query_row(
                "SELECT secret_hash, created_at, expires_at, keep FROM sessions WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((secret_hash, created_at, stored_expiry, keep)) = row else {
            return Ok(None);
        };
        let (created_at, expires_at) = (from_sql(created_at), from_sql(stored_expiry));
        if !keep || expires_at <= now || !constant_time_eq(&secret_hash, &sha256(secret.as_bytes()))
        {
            return Ok(None);
        }
        let renewed = (now + SESSION_LIFETIME_SECS).min(created_at + KEPT_SESSION_MAX_SECS);
        // A session renewed less than a day ago ends later than a renewal now would make it.
        let renewed_recently = expires_at > now + SESSION_LIFETIME_SECS - RENEW_EVERY_SECS;
        if renewed <= expires_at || renewed_recently {
            return Ok(None);
        }
        // Only if the row is still the one just read: a session ended (or renewed) by anything
        // else in between is left as that left it.
        let changed = self.conn.execute(
            "UPDATE sessions SET expires_at = ?2 WHERE id = ?1 AND expires_at = ?3",
            rusqlite::params![id, to_sql(renewed), stored_expiry],
        )?;
        Ok((changed == 1).then_some(renewed))
    }

    /// Ends the session a cookie stands for. The secret has to be right.
    pub fn end_session(&mut self, cookie: &str) -> Result<(), StoreError> {
        let Some((id, secret)) = parse_cookie(cookie) else {
            return Ok(());
        };
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT secret_hash FROM sessions WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        if stored.is_some_and(|stored| constant_time_eq(&stored, &sha256(secret.as_bytes()))) {
            self.conn
                .execute("DELETE FROM sessions WHERE id = ?1", [id])?;
        }
        Ok(())
    }

    /// Throws away what is past its time: old mail log rows and codes, expired sessions.
    pub fn purge_signin(&mut self, now: u64) -> Result<(), StoreError> {
        purge(&self.conn, now)
    }
}

/// A row of the `sessions` table as the database gives it.
struct SessionRow {
    secret_hash: Vec<u8>,
    account_id: i64,
    csrf: String,
    expires_at: i64,
    admin_until: Option<i64>,
}

/// How many accounts, however made, have been made since 00:00 UTC on the day of `now`.
fn accounts_made_today(conn: &rusqlite::Connection, now: u64) -> Result<u32, StoreError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM accounts WHERE created_at >= ?1",
        [to_sql(utc_day_start(now))],
        |row| row.get(0),
    )?)
}

/// Makes the account for an address whose owner just typed a right code (open sign-up). The
/// label is `member-<id>`; the device limit is the table's default. Only the fingerprint of
/// the address is kept. A second program making the same account at once is stopped by the
/// unique fingerprint.
fn make_member(
    tx: &rusqlite::Transaction<'_>,
    email_fp: &[u8; 32],
    now: u64,
) -> Result<i64, StoreError> {
    tx.execute(
        "INSERT INTO accounts (label, email_fp, created_at) VALUES ('member', ?1, ?2)",
        rusqlite::params![&email_fp[..], to_sql(now)],
    )?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "UPDATE accounts SET label = 'member-' || id WHERE id = ?1",
        [id],
    )?;
    Ok(id)
}

/// Deletes what is past its time. Mail log rows and codes are kept a day (the longest
/// any limit looks back); a session goes when it expires.
fn purge(conn: &rusqlite::Connection, now: u64) -> Result<(), StoreError> {
    let cutoff = to_sql(now.saturating_sub(KEEP_SECS));
    conn.execute("DELETE FROM mail_log WHERE sent_at < ?1", [cutoff])?;
    conn.execute("DELETE FROM login_codes WHERE created_at < ?1", [cutoff])?;
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [to_sql(now)])?;
    Ok(())
}

/// A cookie is `<32 lowercase hex>.<64 lowercase hex>` and nothing else.
pub(crate) fn parse_cookie(cookie: &str) -> Option<(&str, &str)> {
    let (id, secret) = cookie.split_once('.')?;
    let lower_hex = |text: &str| {
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    (id.len() == 32 && secret.len() == 64 && lower_hex(id) && lower_hex(secret))
        .then_some((id, secret))
}

fn random_failed(e: std::io::Error) -> StoreError {
    StoreError::Database(format!("cannot get random bytes: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::sha256;
    use bf_common::sign::hex;

    const T0: u64 = 20_000 * 86_400 + 1_000; // some time early on a UTC day

    fn keys() -> ControlKeys {
        ControlKeys::from_parts([1; 32], [2; 32])
    }

    /// A store with one account that has this address.
    fn with_account(email: &str) -> (Store, i64, [u8; 32]) {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let fp = keys().email_fingerprint(email);
        store.set_email_fp(account.id, &fp).unwrap();
        (store, account.id, fp)
    }

    fn sent(request: CodeRequest) -> (i64, String) {
        match request {
            CodeRequest::Send { code_id, code } => (code_id, code),
            other => panic!("expected a code to send, got {other:?}"),
        }
    }

    // ---- who has which address ----

    #[test]
    fn an_email_fingerprint_belongs_to_one_account_and_finds_it() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let sam = store.add_account("sam", 1_000).unwrap();
        let fp = keys().email_fingerprint("lao@example.com");

        store.set_email_fp(lao.id, &fp).unwrap();

        assert_eq!(store.account_for_email_fp(&fp).unwrap(), Some(lao.clone()));
        assert_eq!(
            store
                .account_for_email_fp(&keys().email_fingerprint("sam@example.com"))
                .unwrap(),
            None
        );
        assert_eq!(store.set_email_fp(sam.id, &fp), Err(StoreError::EmailInUse));
        assert_eq!(
            store.set_email_fp(999, &[9; 32]),
            Err(StoreError::NoSuchAccount)
        );
        // The same account can be given the same fingerprint again, or another one.
        assert_eq!(store.set_email_fp(lao.id, &fp), Ok(()));
        store.set_email_fp(lao.id, &[7; 32]).unwrap();
        assert_eq!(
            store.account_for_email_fp(&fp).unwrap(),
            None,
            "the old address is let go"
        );
    }

    // ---- codes ----

    #[test]
    fn a_known_address_gets_a_six_digit_code_and_the_database_holds_only_a_check_value() {
        let (mut store, _, fp) = with_account("lao@example.com");

        let (code_id, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        let (mac, created, expires, tries, used): (Vec<u8>, i64, i64, i64, Option<i64>) = store
            .conn
            .query_row(
                "SELECT code_mac, created_at, expires_at, tries, used_at FROM login_codes WHERE id = ?1",
                [code_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            mac,
            keys().code_mac(&fp, &code).to_vec(),
            "a keyed check, not the code"
        );
        assert_eq!(mac.len(), 32);
        assert_eq!((created as u64, expires as u64), (T0, T0 + 600));
        assert_eq!((tries, used), (0, None));
        // Nothing in any column of the row is the code itself.
        let row_text: String = store
            .conn
            .query_row(
                "SELECT quote(email_fp) || quote(code_mac) || created_at || expires_at FROM login_codes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !row_text.to_lowercase().contains(&hex(code.as_bytes())),
            "not as hex either"
        );
        assert!(
            !format!(
                "{:?}",
                CodeRequest::Send {
                    code_id,
                    code: code.clone()
                }
            )
            .contains(&code)
        );
    }

    #[test]
    fn a_right_code_signs_in_once_and_never_again() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        let first = store.verify_code(&keys(), &fp, &code, T0 + 30).unwrap();
        let second = store.verify_code(&keys(), &fp, &code, T0 + 31).unwrap();

        assert_eq!(first, CodeCheck::Verified { account_id });
        assert_eq!(second, CodeCheck::Bad, "a code is single use");
    }

    #[test]
    fn a_wrong_code_costs_a_try_and_four_wrong_tries_still_leave_the_right_code_working() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        let wrong = if code == "000000" { "000001" } else { "000000" };

        for _ in 0..4 {
            assert_eq!(
                store.verify_code(&keys(), &fp, wrong, T0 + 5).unwrap(),
                CodeCheck::Bad
            );
        }

        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 6).unwrap(),
            CodeCheck::Verified { account_id }
        );
    }

    #[test]
    fn the_fifth_wrong_try_ends_the_code_even_for_the_right_one() {
        let (mut store, _, fp) = with_account("lao@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        let wrong = if code == "000000" { "000001" } else { "000000" };

        for _ in 0..5 {
            assert_eq!(
                store.verify_code(&keys(), &fp, wrong, T0 + 5).unwrap(),
                CodeCheck::Bad
            );
        }

        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 6).unwrap(),
            CodeCheck::Bad
        );
    }

    #[test]
    fn a_code_works_until_exactly_ten_minutes_and_not_a_second_longer() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 600).unwrap(),
            CodeCheck::Bad
        );
        // Ask again, and it is the last second before the end that still works.
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0 + 700).unwrap());
        assert_eq!(
            store
                .verify_code(&keys(), &fp, &code, T0 + 700 + 599)
                .unwrap(),
            CodeCheck::Verified { account_id }
        );
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0 + 2_000).unwrap());
        assert_eq!(
            store
                .verify_code(&keys(), &fp, &code, T0 + 2_000 + 600)
                .unwrap(),
            CodeCheck::Bad,
            "at exactly ten minutes it has ended"
        );
    }

    #[test]
    fn a_new_request_ends_the_older_code() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        let (_, first) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        let (_, second) = sent(store.request_code(&keys(), &fp, None, T0 + 10).unwrap());
        let kept: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM login_codes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            kept, 1,
            "the old code is thrown away at once, not left lying around"
        );

        if first != second {
            assert_eq!(
                store.verify_code(&keys(), &fp, &first, T0 + 20).unwrap(),
                CodeCheck::Bad
            );
        }
        assert_eq!(
            store.verify_code(&keys(), &fp, &second, T0 + 20).unwrap(),
            CodeCheck::Verified { account_id }
        );
        let live: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM login_codes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(live, 1, "only one code per address is kept at a time");
    }

    #[test]
    fn a_code_is_only_good_for_the_address_it_was_made_for() {
        let (mut store, _, fp) = with_account("lao@example.com");
        let other_account = store.add_account("sam", 1_000).unwrap();
        let other_fp = keys().email_fingerprint("sam@example.com");
        store.set_email_fp(other_account.id, &other_fp).unwrap();
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        assert_eq!(
            store
                .verify_code(&keys(), &other_fp, &code, T0 + 1)
                .unwrap(),
            CodeCheck::Bad
        );
        assert_eq!(
            store
                .verify_code(
                    &keys(),
                    &keys().email_fingerprint("nobody@example.com"),
                    &code,
                    T0 + 1
                )
                .unwrap(),
            CodeCheck::Bad
        );
        // And a different key (as after a stolen database) checks nothing.
        let other_keys = ControlKeys::from_parts([1; 32], [3; 32]);
        assert_eq!(
            store.verify_code(&other_keys, &fp, &code, T0 + 1).unwrap(),
            CodeCheck::Bad
        );
    }

    #[test]
    fn something_that_is_not_six_digits_is_bad_and_does_not_use_up_a_try() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        for junk in [
            "",
            "12345",
            "1234567",
            "12345a",
            " 123456",
            "123456 ",
            "١٢٣٤٥٦",
            "'; DROP TABLE accounts;--",
        ] {
            assert_eq!(
                store.verify_code(&keys(), &fp, junk, T0 + 1).unwrap(),
                CodeCheck::Bad,
                "{junk:?}"
            );
        }
        let tries: i64 = store
            .conn
            .query_row("SELECT tries FROM login_codes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(tries, 0);
        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 2).unwrap(),
            CodeCheck::Verified { account_id }
        );
    }

    #[test]
    fn a_code_for_an_account_that_has_gone_is_bad() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        store
            .conn
            .execute("DELETE FROM accounts WHERE id = ?1", [account_id])
            .unwrap();

        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 1).unwrap(),
            CodeCheck::Bad
        );
    }

    // ---- known and unknown addresses look the same ----

    #[test]
    fn an_unknown_address_gets_nothing_and_no_code_is_made() {
        let (mut store, _, _) = with_account("lao@example.com");
        let unknown = keys().email_fingerprint("nobody@example.com");

        assert_eq!(
            store.request_code(&keys(), &unknown, None, T0).unwrap(),
            CodeRequest::Nothing
        );

        let codes: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM login_codes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(codes, 0);
        let requests: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM mail_log WHERE kind = 'request'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(requests, 1, "it is counted, like any request");
    }

    #[test]
    fn known_and_unknown_addresses_hit_the_same_limits_at_the_same_moment() {
        let (mut store, _, known) = with_account("lao@example.com");
        let unknown = keys().email_fingerprint("nobody@example.com");

        for fp in [known, unknown] {
            let mut answers = Vec::new();
            for i in 0..5 {
                let answer = store.request_code(&keys(), &fp, None, T0 + i).unwrap();
                answers.push(match answer {
                    CodeRequest::Send { .. } | CodeRequest::Nothing => "accepted",
                    CodeRequest::Limited => "limited",
                    CodeRequest::Paused => "paused",
                    CodeRequest::Full => "full",
                });
            }
            assert_eq!(
                answers,
                ["accepted", "accepted", "accepted", "limited", "limited"]
            );
        }
    }

    // ---- the limits ----

    #[test]
    fn at_most_three_requests_per_address_an_hour_and_the_first_ages_out_at_exactly_an_hour() {
        let (mut store, _, fp) = with_account("lao@example.com");
        for _ in 0..3 {
            sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        }

        assert_eq!(
            store.request_code(&keys(), &fp, None, T0 + 1).unwrap(),
            CodeRequest::Limited
        );
        assert_eq!(
            store.request_code(&keys(), &fp, None, T0 + 3_599).unwrap(),
            CodeRequest::Limited
        );
        assert!(matches!(
            store.request_code(&keys(), &fp, None, T0 + 3_600).unwrap(),
            CodeRequest::Send { .. }
        ));
    }

    #[test]
    fn a_limited_request_does_not_extend_the_wait() {
        let (mut store, _, fp) = with_account("lao@example.com");
        for _ in 0..3 {
            sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        }
        for i in 1..20 {
            assert_eq!(
                store.request_code(&keys(), &fp, None, T0 + i).unwrap(),
                CodeRequest::Limited
            );
        }

        assert!(
            matches!(
                store.request_code(&keys(), &fp, None, T0 + 3_600).unwrap(),
                CodeRequest::Send { .. }
            ),
            "hammering does not push the hour out"
        );
    }

    #[test]
    fn at_most_ten_requests_per_network_address_an_hour_whatever_the_emails() {
        let mut store = Store::open_in_memory().unwrap();
        let ip = keys().ip_fingerprint("203.0.113.7");
        let other_ip = keys().ip_fingerprint("203.0.113.8");

        for i in 0..10 {
            let email_fp = keys().email_fingerprint(&format!("user{i}@example.com"));
            assert_eq!(
                store
                    .request_code(&keys(), &email_fp, Some(&ip), T0 + i)
                    .unwrap(),
                CodeRequest::Nothing
            );
        }
        let eleventh = keys().email_fingerprint("user10@example.com");
        assert_eq!(
            store
                .request_code(&keys(), &eleventh, Some(&ip), T0 + 10)
                .unwrap(),
            CodeRequest::Limited
        );
        assert_eq!(
            store
                .request_code(&keys(), &eleventh, Some(&other_ip), T0 + 10)
                .unwrap(),
            CodeRequest::Nothing,
            "another network is not held back"
        );
        assert_eq!(
            store
                .request_code(&keys(), &eleventh, None, T0 + 11)
                .unwrap(),
            CodeRequest::Nothing,
            "no address, no network limit (the per-address limit still applies)"
        );
        assert_eq!(
            store
                .request_code(&keys(), &eleventh, Some(&ip), T0 + 3_600)
                .unwrap(),
            CodeRequest::Nothing,
            "the first ten have aged out after an hour"
        );
    }

    // ---- the daily mail budget ----

    #[test]
    fn the_daily_budget_is_ninety_sent_emails_a_utc_day_and_a_new_day_starts_it_again() {
        let (mut store, _, fp) = with_account("lao@example.com");
        let day = utc_day_start(T0);
        for i in 0..89 {
            store
                .record_mail_result(&[i as u8; 32], MailResult::Sent, day + 100 + i)
                .unwrap();
        }
        assert!(
            matches!(
                store.request_code(&keys(), &fp, None, day + 5_000).unwrap(),
                CodeRequest::Send { .. }
            ),
            "89 sent: one left"
        );

        store
            .record_mail_result(&[99; 32], MailResult::Sent, day + 6_000)
            .unwrap();

        assert_eq!(
            store.request_code(&keys(), &fp, None, day + 7_000).unwrap(),
            CodeRequest::Paused
        );
        assert_eq!(
            store
                .request_code(&keys(), &fp, None, day + 86_399)
                .unwrap(),
            CodeRequest::Paused
        );
        assert!(
            matches!(
                store
                    .request_code(&keys(), &fp, None, day + 86_400)
                    .unwrap(),
                CodeRequest::Send { .. }
            ),
            "midnight UTC: a new day"
        );
    }

    #[test]
    fn a_failed_send_does_not_use_the_budget_and_a_resend_quota_pauses_the_rest_of_the_day() {
        let (mut store, _, fp) = with_account("lao@example.com");
        let day = utc_day_start(T0);
        for i in 0..200 {
            store
                .record_mail_result(&fp, MailResult::Failed, day + i)
                .unwrap();
        }
        assert!(
            matches!(
                store.request_code(&keys(), &fp, None, day + 1_000).unwrap(),
                CodeRequest::Send { .. }
            ),
            "failures cost nothing"
        );

        store
            .record_mail_result(&fp, MailResult::QuotaExhausted, day + 50_000)
            .unwrap();

        assert_eq!(
            store
                .request_code(&keys(), &fp, None, day + 60_000)
                .unwrap(),
            CodeRequest::Paused
        );
        assert!(matches!(
            store
                .request_code(&keys(), &fp, None, day + 86_400)
                .unwrap(),
            CodeRequest::Send { .. }
        ));
    }

    #[test]
    fn when_mail_is_paused_every_address_is_told_the_same() {
        let (mut store, _, known) = with_account("lao@example.com");
        let unknown = keys().email_fingerprint("nobody@example.com");
        let day = utc_day_start(T0);
        store
            .record_mail_result(&known, MailResult::QuotaExhausted, day + 10)
            .unwrap();

        assert_eq!(
            store.request_code(&keys(), &known, None, day + 20).unwrap(),
            CodeRequest::Paused
        );
        assert_eq!(
            store
                .request_code(&keys(), &unknown, None, day + 20)
                .unwrap(),
            CodeRequest::Paused
        );
    }

    #[test]
    fn day_starts_are_utc_midnights() {
        assert_eq!(utc_day_start(0), 0);
        assert_eq!(utc_day_start(86_399), 0);
        assert_eq!(utc_day_start(86_400), 86_400);
        assert_eq!(utc_day_start(T0), 20_000 * 86_400);
    }

    // ---- tidying up ----

    #[test]
    fn rows_older_than_a_day_are_purged_and_newer_ones_kept() {
        let (mut store, account_id, fp) = with_account("lao@example.com");
        store
            .conn
            .execute_batch(&format!(
            "INSERT INTO mail_log (sent_at, kind) VALUES ({old}, 'request'), ({fresh}, 'request');
             INSERT INTO login_codes (email_fp, code_mac, created_at, expires_at)
                 VALUES (x'01', x'02', {old}, {old_end}), (x'03', x'04', {fresh}, {fresh_end});",
            old = T0 - KEEP_SECS - 1,
            old_end = T0 - KEEP_SECS + 599,
            fresh = T0 - 100,
            fresh_end = T0 + 500,
        ))
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO sessions (id, secret_hash, account_id, csrf, created_at, expires_at)
                 VALUES ('old', x'00', ?1, 'c', 1, ?2), ('fresh', x'00', ?1, 'c', 1, ?3)",
                rusqlite::params![account_id, to_sql(T0 - 1), to_sql(T0 + 1)],
            )
            .unwrap();

        store.request_code(&keys(), &fp, None, T0).unwrap();

        let count = |sql: &str| -> i64 { store.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(
            count(&format!(
                "SELECT COUNT(*) FROM mail_log WHERE sent_at = {}",
                T0 - KEEP_SECS - 1
            )),
            0,
            "the day-old row is gone"
        );
        assert_eq!(
            count(&format!(
                "SELECT COUNT(*) FROM mail_log WHERE sent_at = {}",
                T0 - 100
            )),
            1,
            "the recent row stays"
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM login_codes WHERE email_fp IN (x'01')"),
            0
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM login_codes WHERE email_fp IN (x'03')"),
            1
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM sessions WHERE id = 'old'"),
            0,
            "expired sessions go"
        );
        assert_eq!(count("SELECT COUNT(*) FROM sessions WHERE id = 'fresh'"), 1);
    }

    // ---- sessions ----

    fn cookie_parts(cookie: &str) -> (&str, &str) {
        cookie.split_once('.').expect("id.secret")
    }

    #[test]
    fn a_session_cookie_is_an_id_and_a_secret_and_the_database_holds_only_the_id_and_a_hash() {
        let (mut store, account_id, _) = with_account("lao@example.com");

        let made = store.create_session(account_id, T0).unwrap();

        let (id, secret) = cookie_parts(&made.cookie);
        assert_eq!(id.len(), 32);
        assert_eq!(secret.len(), 64);
        for part in [id, secret, &made.csrf] {
            assert!(
                part.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{part}"
            );
        }
        assert_eq!(made.csrf.len(), 32);
        assert_ne!(made.csrf, id);
        assert_eq!(made.expires_at, T0 + 60 * 86_400);

        let (stored_id, stored_hash, stored_csrf): (String, Vec<u8>, String) = store
            .conn
            .query_row("SELECT id, secret_hash, csrf FROM sessions", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(stored_id, id);
        assert_eq!(
            stored_hash,
            sha256(secret.as_bytes()).to_vec(),
            "only a hash of the secret"
        );
        assert_eq!(stored_csrf, made.csrf);
        let everything: String = store
            .conn
            .query_row(
                "SELECT id || quote(secret_hash) || csrf || created_at || expires_at FROM sessions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !everything.contains(secret),
            "the secret is nowhere in the row"
        );
        assert!(!format!("{made:?}").contains(secret));
    }

    #[test]
    fn a_session_works_until_sixty_days_after_sign_in_and_not_a_second_longer() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session(account_id, T0).unwrap();
        let sixty_days = 60 * 86_400;

        let info = store
            .session(&made.cookie, T0 + 5)
            .unwrap()
            .expect("a live session");

        assert_eq!(
            info,
            SessionInfo {
                account_id,
                csrf: made.csrf.clone(),
                expires_at: T0 + sixty_days,
                admin_until: None
            }
        );
        assert!(
            store
                .session(&made.cookie, T0 + sixty_days - 1)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .session(&made.cookie, T0 + sixty_days)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .session(&made.cookie, T0 + sixty_days + 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_wrong_secret_an_unknown_id_or_a_mangled_cookie_is_simply_no_session() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session(account_id, T0).unwrap();
        let (id, secret) = cookie_parts(&made.cookie);
        let flipped = format!(
            "{}{}",
            if secret.starts_with('0') { "1" } else { "0" },
            &secret[1..]
        );

        for bad in [
            format!("{id}.{flipped}"),
            format!("{id}."),
            format!(".{secret}"),
            format!("{}.{secret}", "0".repeat(32)),
            id.to_string(),
            secret.to_string(),
            String::new(),
            format!("{id}.{secret}.extra"),
            format!("{id}.{}", secret.to_uppercase()),
            format!("{id}.{}", &secret[..63]),
            format!("{} .{secret}", &id[..31]),
            "'; DROP TABLE sessions;--".to_string(),
        ] {
            assert_eq!(store.session(&bad, T0 + 1).unwrap(), None, "{bad:?}");
        }
        assert!(
            store.session(&made.cookie, T0 + 1).unwrap().is_some(),
            "the real one still works"
        );
    }

    #[test]
    fn signing_out_ends_that_session_only_and_needs_the_right_secret() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let phone = store.create_session(account_id, T0).unwrap();
        let laptop = store.create_session(account_id, T0 + 1).unwrap();
        let (id, secret) = cookie_parts(&phone.cookie);
        let flipped = format!(
            "{}{}",
            if secret.starts_with('0') { "1" } else { "0" },
            &secret[1..]
        );

        store.end_session(&format!("{id}.{flipped}")).unwrap();
        assert!(
            store.session(&phone.cookie, T0 + 2).unwrap().is_some(),
            "wrong secret: nothing ended"
        );

        store.end_session(&phone.cookie).unwrap();
        assert!(store.session(&phone.cookie, T0 + 2).unwrap().is_none());
        assert!(
            store.session(&laptop.cookie, T0 + 2).unwrap().is_some(),
            "the other one is untouched"
        );
        store.end_session(&phone.cookie).unwrap();
        store.end_session("junk").unwrap();
    }

    /// `keep` of the session this cookie stands for.
    fn kept(store: &Store, cookie: &str) -> i64 {
        let (id, _) = cookie_parts(cookie);
        store
            .conn
            .query_row("SELECT keep FROM sessions WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap()
    }

    #[test]
    fn a_session_made_with_keep_ticked_is_marked_and_is_otherwise_the_same() {
        let (mut store, account_id, _) = with_account("lao@example.com");

        let plain = store.create_session(account_id, T0).unwrap();
        let ticked = store
            .create_session_keeping(account_id, true, T0 + 1)
            .unwrap();
        let unticked = store
            .create_session_keeping(account_id, false, T0 + 2)
            .unwrap();

        assert_eq!(kept(&store, &plain.cookie), 0, "no tick is today's session");
        assert_eq!(kept(&store, &unticked.cookie), 0);
        assert_eq!(kept(&store, &ticked.cookie), 1);
        let sixty_days = 60 * 86_400;
        assert_eq!(plain.expires_at, T0 + sixty_days);
        assert_eq!(
            ticked.expires_at,
            T0 + 1 + sixty_days,
            "it starts with the same sixty days"
        );
        assert_eq!(unticked.expires_at, T0 + 2 + sixty_days);
    }

    const DAY: u64 = 86_400;

    #[test]
    fn a_kept_session_that_is_used_later_runs_for_sixty_more_days_from_then() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session_keeping(account_id, true, T0).unwrap();

        let renewed = store.renew_session(&made.cookie, T0 + 2 * DAY).unwrap();

        assert_eq!(
            renewed,
            Some(T0 + 62 * DAY),
            "sixty days from the day it was used"
        );
        let info = store.session(&made.cookie, T0 + 2 * DAY).unwrap().unwrap();
        assert_eq!(info.expires_at, T0 + 62 * DAY);
        assert!(
            store
                .session(&made.cookie, T0 + 62 * DAY - 1)
                .unwrap()
                .is_some(),
            "it works past the original sixty days"
        );
        assert!(
            store
                .session(&made.cookie, T0 + 62 * DAY)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_kept_session_is_renewed_at_most_once_a_day() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session_keeping(account_id, true, T0).unwrap();
        assert_eq!(
            store.renew_session(&made.cookie, T0 + 2 * DAY).unwrap(),
            Some(T0 + 62 * DAY)
        );

        for too_soon in [T0 + 2 * DAY, T0 + 2 * DAY + 3_600, T0 + 3 * DAY - 1] {
            assert_eq!(
                store.renew_session(&made.cookie, too_soon).unwrap(),
                None,
                "used again {} seconds after the last renewal",
                too_soon - (T0 + 2 * DAY)
            );
        }
        let info = store
            .session(&made.cookie, T0 + 3 * DAY - 1)
            .unwrap()
            .unwrap();
        assert_eq!(info.expires_at, T0 + 62 * DAY, "nothing was written");

        assert_eq!(
            store.renew_session(&made.cookie, T0 + 3 * DAY).unwrap(),
            Some(T0 + 63 * DAY),
            "a full day later it renews again"
        );
    }

    #[test]
    fn a_kept_session_never_runs_past_a_year_from_sign_in() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session_keeping(account_id, true, T0).unwrap();
        let cap = T0 + 365 * DAY;

        // Used every thirty days for more than a year.
        let mut latest = made.expires_at;
        for day in (30..=420).step_by(30) {
            if let Some(new_end) = store.renew_session(&made.cookie, T0 + day * DAY).unwrap() {
                assert!(new_end > latest, "a renewal moves the end out");
                assert!(new_end <= cap, "day {day}: {new_end} is past the cap");
                latest = new_end;
            }
        }

        assert_eq!(latest, cap, "it did reach the cap");
        assert!(store.session(&made.cookie, cap - 1).unwrap().is_some());
        assert!(store.session(&made.cookie, cap).unwrap().is_none());
        assert_eq!(store.renew_session(&made.cookie, cap).unwrap(), None);
    }

    #[test]
    fn a_session_made_without_the_tick_is_never_renewed() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session(account_id, T0).unwrap();

        for later in [T0 + 2 * DAY, T0 + 30 * DAY, T0 + 59 * DAY] {
            assert_eq!(store.renew_session(&made.cookie, later).unwrap(), None);
        }

        let info = store.session(&made.cookie, T0 + 59 * DAY).unwrap().unwrap();
        assert_eq!(info.expires_at, T0 + 60 * DAY, "exactly as it was");
    }

    #[test]
    fn an_expired_wrong_or_made_up_cookie_is_not_renewed_and_revives_nothing() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session_keeping(account_id, true, T0).unwrap();
        let (id, _) = cookie_parts(&made.cookie);

        assert_eq!(
            store.renew_session(&made.cookie, T0 + 60 * DAY).unwrap(),
            None,
            "it ran out"
        );
        assert!(
            store
                .session(&made.cookie, T0 + 60 * DAY)
                .unwrap()
                .is_none()
        );

        let wrong_secret = format!("{id}.{}", "0".repeat(64));
        let unknown_id = format!("{}.{}", "1".repeat(32), "2".repeat(64));
        for cookie in [wrong_secret.as_str(), unknown_id.as_str(), "x", "", "a.b.c"] {
            assert_eq!(
                store.renew_session(cookie, T0 + 2 * DAY).unwrap(),
                None,
                "{cookie}"
            );
        }
        let info = store.session(&made.cookie, T0 + 2 * DAY).unwrap().unwrap();
        assert_eq!(info.expires_at, T0 + 60 * DAY, "untouched");
    }

    #[test]
    fn an_account_and_its_address_are_made_together_or_not_at_all() {
        let mut store = Store::open_in_memory().unwrap();
        let fp = [7u8; 32];

        let kim = store.add_account_with_email("kim", Some(&fp), T0).unwrap();
        assert_eq!(kim.label, "kim");
        assert_eq!(store.account_for_email_fp(&fp).unwrap().unwrap().id, kim.id);
        let plain = store.add_account_with_email("pat", None, T0).unwrap();
        assert_eq!(store.account(plain.id).unwrap().unwrap().label, "pat");

        let before = store.accounts().unwrap().len();
        assert_eq!(
            store.add_account_with_email("lee", Some(&fp), T0),
            Err(StoreError::EmailInUse)
        );
        assert_eq!(
            store.add_account_with_email("", Some(&[8u8; 32]), T0),
            Err(StoreError::BadName)
        );
        assert_eq!(store.accounts().unwrap().len(), before, "nothing half made");
        assert!(store.account_for_email_fp(&[8u8; 32]).unwrap().is_none());
    }

    #[test]
    fn every_sign_in_is_a_new_id_and_an_account_keeps_its_newest_ten_sessions() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let mut made = Vec::new();
        for i in 0..12 {
            made.push(store.create_session(account_id, T0 + i).unwrap());
        }

        let ids: std::collections::HashSet<&str> =
            made.iter().map(|m| cookie_parts(&m.cookie).0).collect();
        assert_eq!(ids.len(), 12, "never the same id twice");
        let alive: Vec<bool> = made
            .iter()
            .map(|m| store.session(&m.cookie, T0 + 20).unwrap().is_some())
            .collect();
        assert_eq!(alive[..2], [false, false], "the two oldest were dropped");
        assert!(alive[2..].iter().all(|&a| a), "the newest ten remain");
    }

    #[test]
    fn expired_sessions_are_swept_when_a_new_one_is_made_and_sessions_need_a_real_account() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let old = store.create_session(account_id, T0).unwrap();
        store
            .create_session(account_id, T0 + 60 * 86_400 + 5)
            .unwrap();

        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the expired one is gone from the table");
        assert!(
            store
                .session(&old.cookie, T0 + 60 * 86_400 + 6)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.create_session(999, T0).unwrap_err(),
            StoreError::NoSuchAccount
        );
    }

    #[test]
    fn a_session_dies_with_its_account() {
        let (mut store, account_id, _) = with_account("lao@example.com");
        let made = store.create_session(account_id, T0).unwrap();
        store
            .conn
            .execute("DELETE FROM accounts WHERE id = ?1", [account_id])
            .unwrap();

        assert_eq!(store.session(&made.cookie, T0 + 1).unwrap(), None);
    }

    #[test]
    fn the_whole_sign_in_from_request_to_session_works() {
        let (mut store, account_id, fp) = with_account("Lao@Example.com");
        let typed = keys().email_fingerprint("  lao@example.COM ");
        assert_eq!(
            typed, fp,
            "the person's capital letters and spaces do not matter"
        );

        let (code_id, code) = sent(store.request_code(&keys(), &typed, None, T0).unwrap());
        store
            .record_mail_result(&typed, MailResult::Sent, T0 + 1)
            .unwrap();
        let verified = store.verify_code(&keys(), &typed, &code, T0 + 20).unwrap();
        let CodeCheck::Verified { account_id: who } = verified else {
            panic!("{verified:?}")
        };
        let made = store.create_session(who, T0 + 21).unwrap();

        assert!(code_id > 0);
        assert_eq!(who, account_id);
        assert_eq!(
            store
                .session(&made.cookie, T0 + 22)
                .unwrap()
                .unwrap()
                .account_id,
            account_id
        );
    }

    // ---- open sign-up (specs/open-signup.md) ----

    #[test]
    fn open_the_default_caps_are_sixty_new_address_mails_and_twenty_new_accounts_a_day() {
        assert_eq!(
            OpenLimits::default(),
            OpenLimits {
                new_mail_per_day: 60,
                new_accounts_per_day: 20
            }
        );
    }

    fn open_store_with(new_mail_per_day: u32, new_accounts_per_day: u32) -> Store {
        Store::open_in_memory()
            .unwrap()
            .with_open_signup(OpenLimits {
                new_mail_per_day,
                new_accounts_per_day,
            })
    }

    fn fp_of(n: u32) -> [u8; 32] {
        keys().email_fingerprint(&format!("user{n}@example.com"))
    }

    fn requests_logged(store: &Store) -> i64 {
        store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM mail_log WHERE kind = 'request'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn open_the_twenty_new_accounts_cap_counts_every_account_of_the_day_however_made() {
        let mut store = open_store_with(60, 2);
        store.add_account("by-admin-1", T0).unwrap();
        store.add_account("by-admin-2", T0 + 1).unwrap();
        let yesterday = store.add_account("old", T0 - 86_400).unwrap();
        let old_fp = keys().email_fingerprint("old@example.com");
        store.set_email_fp(yesterday.id, &old_fp).unwrap();

        assert_eq!(
            store
                .request_code(&keys(), &fp_of(1), None, T0 + 5)
                .unwrap(),
            CodeRequest::Full
        );
        assert_eq!(requests_logged(&store), 0, "not written down");
        sent(store.request_code(&keys(), &old_fp, None, T0 + 6).unwrap());
        let next_day = utc_day_start(T0) + 86_400 + 5;
        sent(
            store
                .request_code(&keys(), &fp_of(1), None, next_day)
                .unwrap(),
        );
    }

    #[test]
    fn open_a_code_typed_after_the_last_account_of_the_day_went_is_full_and_not_used_up() {
        let mut store = open_store_with(60, 1);
        let fp = fp_of(1);
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        store.add_account("someone-else", T0 + 10).unwrap();

        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 20).unwrap(),
            CodeCheck::Full
        );

        assert_eq!(accounts_in(&store), 1, "no account was made");
        let unused: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM login_codes WHERE used_at IS NULL AND tries = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unused, 1, "the code is still good, with no try used");
    }

    #[test]
    fn open_when_the_days_mail_is_all_sent_new_and_known_addresses_are_paused_alike() {
        let mut store = open_store();
        let lao = store.add_account("lao", 1_000).unwrap();
        let lao_fp = keys().email_fingerprint("lao@example.com");
        store.set_email_fp(lao.id, &lao_fp).unwrap();
        for n in 0..DAILY_MAIL_BUDGET {
            store
                .record_mail_result(&fp_of(1_000 + n), MailResult::Sent, T0)
                .unwrap();
        }

        assert_eq!(
            store
                .request_code(&keys(), &fp_of(1), None, T0 + 1)
                .unwrap(),
            CodeRequest::Paused
        );
        assert_eq!(
            store.request_code(&keys(), &lao_fp, None, T0 + 2).unwrap(),
            CodeRequest::Paused
        );
        assert_eq!(accounts_in(&store), 1, "only lao's, made by hand");
    }

    #[test]
    fn open_new_addresses_are_held_to_the_daily_share_and_known_ones_are_not() {
        let mut store = open_store_with(3, 20);
        let lao = store.add_account("lao", 1_000).unwrap();
        let lao_fp = keys().email_fingerprint("lao@example.com");
        store.set_email_fp(lao.id, &lao_fp).unwrap();
        for n in 0..3 {
            sent(
                store
                    .request_code(&keys(), &fp_of(n), None, T0 + u64::from(n))
                    .unwrap(),
            );
        }

        assert_eq!(
            store
                .request_code(&keys(), &fp_of(3), None, T0 + 10)
                .unwrap(),
            CodeRequest::Full,
            "the fourth new address of the day"
        );
        assert_eq!(
            requests_logged(&store),
            3,
            "a refused request is not counted"
        );
        sent(store.request_code(&keys(), &lao_fp, None, T0 + 11).unwrap());
        let next_day = utc_day_start(T0) + 86_400 + 5;
        sent(
            store
                .request_code(&keys(), &fp_of(3), None, next_day)
                .unwrap(),
        );
    }

    fn open_store() -> Store {
        Store::open_in_memory()
            .unwrap()
            .with_open_signup(OpenLimits::default())
    }

    fn accounts_in(store: &Store) -> i64 {
        store
            .conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn closed_an_unknown_address_gets_no_code_and_no_account_ever_appears() {
        let mut store = Store::open_in_memory().unwrap();
        let fp = keys().email_fingerprint("new@example.com");

        assert_eq!(store.open_limits(), None, "closed unless asked");
        assert_eq!(
            store.request_code(&keys(), &fp, None, T0).unwrap(),
            CodeRequest::Nothing
        );
        assert_eq!(
            store.verify_code(&keys(), &fp, "123456", T0 + 5).unwrap(),
            CodeCheck::Bad
        );
        assert_eq!(accounts_in(&store), 0);
        let codes: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM login_codes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(codes, 0);
    }

    #[test]
    fn open_a_right_code_for_an_unknown_address_makes_the_account_and_uses_the_code() {
        let mut store = open_store();
        let fp = keys().email_fingerprint("New@Example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        let checked = store.verify_code(&keys(), &fp, &code, T0 + 30).unwrap();

        let CodeCheck::Created { account_id } = checked else {
            panic!("expected a new account, got {checked:?}")
        };
        let (label, limit, admin, made, stored): (String, i64, i64, i64, Vec<u8>) = store
            .conn
            .query_row(
                "SELECT label, device_limit, is_admin, created_at, email_fp
                 FROM accounts WHERE id = ?1",
                [account_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(label, format!("member-{account_id}"));
        assert_eq!((limit, admin, made as u64), (3, 0, T0 + 30));
        assert_eq!(stored, fp.to_vec(), "only the fingerprint is kept");
        assert_eq!(
            store.verify_code(&keys(), &fp, &code, T0 + 31).unwrap(),
            CodeCheck::Bad,
            "the code is used up, so it cannot make a second account"
        );
        assert_eq!(accounts_in(&store), 1);
    }

    #[test]
    fn open_signing_in_again_reaches_the_same_account_in_any_letter_case() {
        let mut store = open_store();
        let fp = keys().email_fingerprint("New@Example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        let CodeCheck::Created { account_id } =
            store.verify_code(&keys(), &fp, &code, T0 + 30).unwrap()
        else {
            panic!("expected a new account")
        };

        let again = keys().email_fingerprint("  new@EXAMPLE.com ");
        let (_, code) = sent(store.request_code(&keys(), &again, None, T0 + 60).unwrap());

        assert_eq!(
            store.verify_code(&keys(), &again, &code, T0 + 90).unwrap(),
            CodeCheck::Verified { account_id }
        );
        assert_eq!(accounts_in(&store), 1);
    }

    #[test]
    fn open_a_wrong_expired_or_used_up_code_makes_no_account() {
        let mut store = open_store();
        let fp = keys().email_fingerprint("new@example.com");
        let (_, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());
        let wrong = if code == "000000" { "000001" } else { "000000" };

        assert_eq!(
            store.verify_code(&keys(), &fp, wrong, T0 + 5).unwrap(),
            CodeCheck::Bad
        );
        assert_eq!(
            store
                .verify_code(&keys(), &fp, &code, T0 + CODE_LIFETIME_SECS)
                .unwrap(),
            CodeCheck::Bad,
            "dead at exactly ten minutes"
        );
        for _ in 0..5 {
            store.verify_code(&keys(), &fp, wrong, T0 + 6).unwrap();
        }
        assert_eq!(accounts_in(&store), 0);
    }

    #[test]
    fn open_an_unknown_address_gets_a_code_and_the_request_is_marked_new() {
        let mut store = open_store();
        let fp = keys().email_fingerprint("new@example.com");

        let (code_id, code) = sent(store.request_code(&keys(), &fp, None, T0).unwrap());

        assert_eq!(code.len(), 6);
        let outcome: String = store
            .conn
            .query_row(
                "SELECT outcome FROM mail_log WHERE kind = 'request'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "new");
        let stored: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM login_codes WHERE id = ?1 AND email_fp = ?2",
                rusqlite::params![code_id, &fp[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, 1);
        assert_eq!(
            accounts_in(&store),
            0,
            "no account before the code is typed"
        );
    }
}
