//! The control program's database: accounts, devices, kicks, and the peer list they
//! add up to.
//!
//! Every function that depends on the time takes it as an argument (Unix seconds), so
//! nothing here reads a clock.

use std::net::Ipv4Addr;
use std::path::Path;

use bf_common::peers::{PeerList, PeerSpec, is_valid_key};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

/// The first address a device can get. `10.77.0.1` is the server's.
const POOL_FIRST: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
/// The last one. `10.77.255.255` is the broadcast address of `10.77.0.0/16`.
const POOL_LAST: Ipv4Addr = Ipv4Addr::new(10, 77, 255, 254);

/// The schema this program reads and writes. A database with a higher number was made
/// by a newer program and is refused.
const SCHEMA_VERSION: u32 = 7;

/// Why the store could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// SQLite failed. The text is SQLite's own message.
    Database(String),
    /// The database was written by a newer version of this program.
    NewerSchema(u32),
    /// The file is a database that this program did not make.
    NotOurs,
    /// The file was made by an earlier draft of schema 1, before `devices.removed_at`.
    StaleDraft,
    /// A new device was not kept because the step that hands out its private key failed.
    NotKept(String),
    /// A label or name is empty, longer than 64 characters, or has control characters or
    /// characters that reorder or hide text.
    BadName,
    /// Not a WireGuard public key written the canonical way.
    BadKey,
    /// Another device already has this public key.
    KeyInUse,
    /// The account already holds this many devices, which is its limit.
    DeviceLimit(u32),
    /// A device of the account has a kick in force: the account cannot add a device, and
    /// its owner cannot remove the kicked one, until the kick ends or is lifted.
    Kicked,
    /// Every address in the pool belongs to a device.
    PoolFull,
    /// A kick must end later than it starts.
    BadKickEnd,
    /// A reason is longer than 200 characters or has control characters or characters
    /// that reorder or hide text.
    BadReason,
    NoSuchAccount,
    NoSuchDevice,
    /// Another account already has this email fingerprint.
    EmailInUse,
    /// A node name is not 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a
    /// letter and not ending with `-`.
    BadNodeName,
    /// A node address is not an IP address and a non-zero port.
    BadNodeAddress,
    /// A node title or place is empty, longer than 40 characters, or has control
    /// characters or characters that reorder or hide text.
    BadNodeText,
    /// A node's maintenance note is empty, only spaces, longer than 100 characters, or has
    /// control characters or characters that reorder or hide text.
    BadNodeNote,
    /// A node with this name or this address is already registered.
    NodeTaken,
    NoSuchNode,
    /// A version floor is zero or absurdly high.
    BadVersionFloor,
    /// A location is not a finite latitude from -90 to 90 and longitude from -180 to 180.
    BadLocation,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Database(why) => write!(f, "database error: {why}"),
            StoreError::NewerSchema(found) => write!(
                f,
                "the database has schema version {found}, newer than this program's {SCHEMA_VERSION}"
            ),
            StoreError::BadName => write!(
                f,
                "a name must be 1 to 64 characters with no control characters or text-reordering marks"
            ),
            StoreError::NotOurs => write!(
                f,
                "that file is a database, but not one made by bf-control; check BC_DB"
            ),
            StoreError::StaleDraft => write!(
                f,
                "that database was made by an earlier draft of schema 1 (no removed_at column); \
                 nothing was deployed with it, so delete the file and start again"
            ),
            StoreError::NotKept(why) => write!(
                f,
                "the new device's key could not be shown ({why}), so the device was not kept"
            ),
            StoreError::PoolFull => write!(f, "every tunnel address is taken"),
            StoreError::BadKickEnd => write!(f, "a kick must end later than now"),
            StoreError::BadReason => write!(
                f,
                "a reason is at most 200 characters with no control characters or text-reordering marks"
            ),
            StoreError::BadKey => write!(f, "that is not a WireGuard public key"),
            StoreError::KeyInUse => write!(
                f,
                "that key belongs to another device, or to one that was removed"
            ),
            StoreError::DeviceLimit(limit) => {
                write!(f, "the account already has its limit of {limit} devices")
            }
            StoreError::Kicked => write!(
                f,
                "a device of that account is kicked; lift the kick or wait for it to end first"
            ),
            StoreError::NoSuchAccount => write!(f, "there is no account with that id"),
            StoreError::EmailInUse => write!(f, "another account already has that email address"),
            StoreError::NoSuchDevice => write!(f, "there is no device with that id"),
            StoreError::BadNodeName => write!(
                f,
                "a node name is 1 to 32 characters of a-z, 0-9 and -, starting with a letter and not ending with -"
            ),
            StoreError::BadNodeAddress => {
                write!(
                    f,
                    "a node address is an IP address and a port, like 192.0.2.7:8443"
                )
            }
            StoreError::BadNodeText => write!(
                f,
                "a node title or place is 1 to 40 characters with no control characters or text-reordering marks"
            ),
            StoreError::BadNodeNote => write!(
                f,
                "a maintenance note is 1 to 100 characters, not only spaces, with no control characters or text-reordering marks"
            ),
            StoreError::NodeTaken => {
                write!(
                    f,
                    "a node with that name or that address is already registered"
                )
            }
            StoreError::NoSuchNode => write!(f, "there is no node with that name"),
            StoreError::BadVersionFloor => {
                write!(
                    f,
                    "the version must be a whole number from 1 to 1000000000000"
                )
            }
            StoreError::BadLocation => write!(
                f,
                "a location is a latitude from -90 to 90 and a longitude from -180 to 180, like 43.65,-79.38"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Database(e.to_string())
    }
}

/// Somebody who holds devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: i64,
    pub label: String,
    /// How many devices the account may hold.
    pub device_limit: u32,
    pub created_at: u64,
}

/// One WireGuard peer: a phone, a laptop. Only its public key is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub public_key: String,
    /// The device's address inside the tunnel.
    pub address: Ipv4Addr,
    /// Whether the node's DNS filters trackers for this device.
    pub tracker_filter: bool,
    pub created_at: u64,
    /// When the device was removed. A removed device is kept as history: it is not on
    /// the list, not counted against the limit and cannot be kicked, but its kicks stay.
    pub removed_at: Option<u64>,
}

/// What deleting an account took with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletedAccount {
    /// Its devices, live and removed.
    pub devices: u32,
}

/// When a kick ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KickEnd {
    /// At this time (Unix seconds).
    At(u64),
    /// Only when somebody lifts it.
    UntilLifted,
}

/// One kick: who took a device off the list, why, and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kick {
    pub id: i64,
    pub device_id: i64,
    pub by: String,
    pub reason: String,
    pub started_at: u64,
    /// `None` means until lifted.
    pub until: Option<u64>,
    pub lifted_at: Option<u64>,
    pub lifted_by: Option<String>,
}

const KICK_COLUMNS: &str =
    "id, device_id, kicked_by, reason, started_at, until, lifted_at, lifted_by";

const DEVICE_COLUMNS: &str =
    "id, account_id, name, public_key, address, tracker_filter, created_at, removed_at";

/// SQLite keeps whole numbers as `i64`. Times and counts here are never negative.
pub(crate) fn to_sql(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

pub(crate) fn from_sql(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

pub struct Store {
    pub(crate) conn: Connection,
    /// Devices get addresses from `pool_first` to `pool_last`, both included.
    pool_first: Ipv4Addr,
    pool_last: Ipv4Addr,
    /// `Some` when anyone may make an account by typing a sign-in code (see `signin.rs`);
    /// `None` is the closed beta, where only accounts an admin made can sign in.
    pub(crate) open_signup: Option<crate::signin::OpenLimits>,
}

impl Store {
    pub fn add_account(&mut self, label: &str, now: u64) -> Result<Account, StoreError> {
        check_name(label)?;
        self.conn.execute(
            "INSERT INTO accounts (label, created_at) VALUES (?1, ?2)",
            rusqlite::params![label, to_sql(now)],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok(self.conn.query_row(
            "SELECT id, label, device_limit, created_at FROM accounts WHERE id = ?1",
            [id],
            account_from_row,
        )?)
    }

    /// Every account, oldest first.
    pub fn accounts(&self) -> Result<Vec<Account>, StoreError> {
        let mut query = self
            .conn
            .prepare("SELECT id, label, device_limit, created_at FROM accounts ORDER BY id")?;
        let rows = query.query_map([], account_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Every account with the number of devices it holds, oldest first.
    pub fn accounts_with_device_counts(&self) -> Result<Vec<(Account, u32)>, StoreError> {
        let mut query = self.conn.prepare(
            "SELECT accounts.id, accounts.label, accounts.device_limit, accounts.created_at,
                    COUNT(devices.id)
             FROM accounts LEFT JOIN devices
                  ON devices.account_id = accounts.id AND devices.removed_at IS NULL
             GROUP BY accounts.id ORDER BY accounts.id",
        )?;
        let rows = query.query_map([], |row| Ok((account_from_row(row)?, row.get(4)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Adds a device to an account and gives it a tunnel address.
    pub fn add_device(
        &mut self,
        account_id: i64,
        name: &str,
        public_key: &str,
        now: u64,
    ) -> Result<Device, StoreError> {
        self.add_device_with(account_id, name, public_key, now, |_| Ok(()))
    }

    /// Like [`Store::add_device`], but calls `before_commit` with the new device before
    /// it is saved. If that returns an error the device is not saved and its address
    /// stays free. This is how the private key is shown before anything is kept: a
    /// crash at any point leaves no device whose key nobody holds.
    pub fn add_device_with(
        &mut self,
        account_id: i64,
        name: &str,
        public_key: &str,
        now: u64,
        before_commit: impl FnOnce(&Device) -> Result<(), String>,
    ) -> Result<Device, StoreError> {
        check_name(name)?;
        if !is_valid_key(public_key) {
            return Err(StoreError::BadKey);
        }
        let (first, last) = (u32::from(self.pool_first), u32::from(self.pool_last));
        // Immediate: the address is chosen and taken in one step, so two devices made
        // at the same moment cannot be given the same one.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let limit: Option<u32> = tx
            .query_row(
                "SELECT device_limit FROM accounts WHERE id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(limit) = limit else {
            return Err(StoreError::NoSuchAccount);
        };
        // A kick is on one device, but a new device would be a new key the kick does
        // not cover, so the account cannot add one until the kick ends. A removed
        // device's kick counts too, so tidying up a kicked device does not end it.
        // Checked inside the transaction, so a kick made at the same moment is not missed.
        let kicked: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM kicks JOIN devices ON devices.id = kicks.device_id
                            WHERE devices.account_id = ?1
                              AND kicks.started_at <= ?2 AND kicks.lifted_at IS NULL
                              AND (kicks.until IS NULL OR kicks.until > ?2))",
            rusqlite::params![account_id, to_sql(now)],
            |row| row.get(0),
        )?;
        if kicked {
            return Err(StoreError::Kicked);
        }
        let held: u32 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE account_id = ?1 AND removed_at IS NULL",
            [account_id],
            |row| row.get(0),
        )?;
        if held >= limit {
            return Err(StoreError::DeviceLimit(limit));
        }
        let key_taken: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM devices WHERE public_key = ?1)",
            [public_key],
            |row| row.get(0),
        )?;
        if key_taken {
            return Err(StoreError::KeyInUse);
        }
        // The lowest free address: the first one if nobody has it, else the one just
        // after the lowest taken address whose neighbour is free.
        let address: u32 = tx.query_row(
            "SELECT CASE
                 WHEN NOT EXISTS (SELECT 1 FROM devices
                                  WHERE address = ?1 AND removed_at IS NULL) THEN ?1
                 ELSE (SELECT MIN(taken.address) + 1 FROM devices AS taken
                       WHERE taken.address >= ?1 AND taken.removed_at IS NULL
                         AND NOT EXISTS (SELECT 1 FROM devices AS next
                                         WHERE next.address = taken.address + 1
                                           AND next.removed_at IS NULL))
             END",
            [first],
            |row| row.get(0),
        )?;
        if address > last {
            return Err(StoreError::PoolFull);
        }
        tx.execute(
            "INSERT INTO devices (account_id, name, public_key, address, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![account_id, name, public_key, address, to_sql(now)],
        )?;
        let id = tx.last_insert_rowid();
        let device = tx.query_row(
            &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id = ?1"),
            [id],
            device_from_row,
        )?;
        before_commit(&device).map_err(StoreError::NotKept)?;
        tx.commit()?;
        Ok(device)
    }

    /// Removes a device: it leaves the list and its address and slot are free again, but
    /// the row stays, with the time, so its kicks stay as history. Its key is never
    /// given to another device. Returns the device as it now is.
    /// Deletes an account and everything it owns, in one transaction: its devices (live and
    /// removed) and their kicks, and its sessions, by the database's own cascades; the sign-in
    /// codes waiting for its address; and the address's fingerprint in the mail log, whose
    /// lines stay so the day's mail caps still count. Its addresses are free again, and the
    /// next published list has none of its devices.
    pub fn delete_account(&mut self, account_id: i64) -> Result<DeletedAccount, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let email_fp: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT email_fp FROM accounts WHERE id = ?1",
                [account_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(email_fp) = email_fp else {
            return Err(StoreError::NoSuchAccount);
        };
        let devices: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE account_id = ?1",
            [account_id],
            |row| row.get(0),
        )?;
        if let Some(fp) = &email_fp {
            tx.execute("DELETE FROM login_codes WHERE email_fp = ?1", [fp])?;
            tx.execute(
                "UPDATE mail_log SET email_fp = NULL WHERE email_fp = ?1",
                [fp],
            )?;
        }
        tx.execute("DELETE FROM accounts WHERE id = ?1", [account_id])?;
        tx.commit()?;
        Ok(DeletedAccount {
            devices: u32::try_from(devices).unwrap_or(u32::MAX),
        })
    }

    pub fn remove_device(&mut self, device_id: i64, now: u64) -> Result<Device, StoreError> {
        self.conn
            .query_row(
                &format!(
                    "UPDATE devices SET removed_at = ?2
                     WHERE id = ?1 AND removed_at IS NULL RETURNING {DEVICE_COLUMNS}"
                ),
                rusqlite::params![device_id, to_sql(now)],
                device_from_row,
            )
            .optional()?
            .ok_or(StoreError::NoSuchDevice)
    }

    /// Removes a device for its owner: like [`Store::remove_device`], but only one of
    /// `account_id`'s own devices, and never one with a kick in force. Removing that one
    /// would end the kick's hold on the account and let its owner add a new device.
    pub fn remove_own_device(
        &mut self,
        account_id: i64,
        device_id: i64,
        now: u64,
    ) -> Result<Device, StoreError> {
        // Immediate: a kick made at the same moment either is seen here or waits for the
        // removal and then finds no device.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let own: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM devices
                            WHERE id = ?1 AND account_id = ?2 AND removed_at IS NULL)",
            [device_id, account_id],
            |row| row.get(0),
        )?;
        if !own {
            return Err(StoreError::NoSuchDevice);
        }
        if device_kicked(&tx, device_id, now)? {
            return Err(StoreError::Kicked);
        }
        let device = tx.query_row(
            &format!("UPDATE devices SET removed_at = ?2 WHERE id = ?1 RETURNING {DEVICE_COLUMNS}"),
            rusqlite::params![device_id, to_sql(now)],
            device_from_row,
        )?;
        tx.commit()?;
        Ok(device)
    }

    /// Turns tracker blocking on or off for one of the account's own live devices
    /// (`specs/trackers.md`). Another account's device, a removed one or an unknown id is
    /// `NoSuchDevice`. A kicked device can be switched: it changes nothing while it is off
    /// the list. The next publish carries the change.
    pub fn set_tracker_filter(
        &mut self,
        account_id: i64,
        device_id: i64,
        on: bool,
    ) -> Result<Device, StoreError> {
        self.conn
            .query_row(
                &format!(
                    "UPDATE devices SET tracker_filter = ?3
                     WHERE id = ?1 AND account_id = ?2 AND removed_at IS NULL
                     RETURNING {DEVICE_COLUMNS}"
                ),
                rusqlite::params![device_id, account_id, i64::from(on)],
                device_from_row,
            )
            .optional()?
            .ok_or(StoreError::NoSuchDevice)
    }

    /// Takes a device off the peer list from `now` until `end`.
    pub fn kick(
        &mut self,
        device_id: i64,
        end: KickEnd,
        by: &str,
        reason: &str,
        now: u64,
    ) -> Result<Kick, StoreError> {
        check_name(by)?;
        if reason.chars().count() > 200 || reason.chars().any(is_unsafe_in_text) {
            return Err(StoreError::BadReason);
        }
        let until = match end {
            KickEnd::At(time) if time <= now => return Err(StoreError::BadKickEnd),
            KickEnd::At(time) => Some(to_sql(time)),
            KickEnd::UntilLifted => None,
        };
        // Immediate, and look for the device inside it: a removal that is in progress
        // in another program is waited for, so a kick is never added to a removed device.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_live_device(&tx, device_id)?;
        tx.execute(
            "INSERT INTO kicks (device_id, kicked_by, reason, started_at, until)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![device_id, by, reason, to_sql(now), until],
        )?;
        let id = tx.last_insert_rowid();
        let kick = tx.query_row(
            &format!("SELECT {KICK_COLUMNS} FROM kicks WHERE id = ?1"),
            [id],
            kick_from_row,
        )?;
        tx.commit()?;
        Ok(kick)
    }

    /// Ends every kick still running on the device. Returns how many it ended. A removed
    /// device's kicks can be lifted too: they still stop its account adding a device.
    pub fn lift(&mut self, device_id: i64, by: &str, now: u64) -> Result<usize, StoreError> {
        check_name(by)?;
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM devices WHERE id = ?1)",
            [device_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NoSuchDevice);
        }
        Ok(self.conn.execute(
            "UPDATE kicks SET lifted_at = ?2, lifted_by = ?3
             WHERE device_id = ?1 AND lifted_at IS NULL AND (until IS NULL OR until > ?2)",
            rusqlite::params![device_id, to_sql(now), by],
        )?)
    }

    /// Whether the device is off the list at `now`: it has a kick that has started,
    /// has not run out and has not been lifted.
    pub fn is_kicked(&self, device_id: i64, now: u64) -> Result<bool, StoreError> {
        device_kicked(&self.conn, device_id, now)
    }

    /// Every kick a device ever had, oldest first.
    pub fn kicks(&self, device_id: i64) -> Result<Vec<Kick>, StoreError> {
        let mut query = self.conn.prepare(&format!(
            "SELECT {KICK_COLUMNS} FROM kicks WHERE device_id = ?1 ORDER BY id"
        ))?;
        let rows = query.query_map([device_id], kick_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Every kick on any device of one account, removed devices included, oldest first, with
    /// the device's name and whether it was removed.
    pub fn kicks_of_account(
        &self,
        account_id: i64,
    ) -> Result<Vec<(Kick, String, bool)>, StoreError> {
        let columns = KICK_COLUMNS.replace(", ", ", kicks.");
        let mut query = self.conn.prepare(&format!(
            "SELECT kicks.{columns}, devices.name, devices.removed_at IS NOT NULL
             FROM kicks JOIN devices ON devices.id = kicks.device_id
             WHERE devices.account_id = ?1
             ORDER BY kicks.id"
        ))?;
        let rows = query.query_map([account_id], |row| {
            Ok((kick_from_row(row)?, row.get(8)?, row.get(9)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Kicks of one device, or of every device when `device_id` is `None`, oldest first.
    /// Each comes with its device's name and whether that device has been removed: a
    /// removed device's kicks are kept.
    pub fn kick_history(
        &self,
        device_id: Option<i64>,
    ) -> Result<Vec<(Kick, String, bool)>, StoreError> {
        let columns = KICK_COLUMNS.replace(", ", ", kicks.");
        let mut query = self.conn.prepare(&format!(
            "SELECT kicks.{columns}, devices.name, devices.removed_at IS NOT NULL
             FROM kicks JOIN devices ON devices.id = kicks.device_id
             WHERE ?1 IS NULL OR kicks.device_id = ?1
             ORDER BY kicks.id"
        ))?;
        let rows = query.query_map([device_id], |row| {
            Ok((kick_from_row(row)?, row.get(8)?, row.get(9)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The peer list for the nodes at `now`: every device that is not kicked, each with
    /// its one address.
    ///
    /// The version goes up by one each time the list differs from the last one this
    /// returned, whatever the cause: a device added or removed, a kick, a lift, or a
    /// kick running out. The agents refuse versions that go backwards, so the last list
    /// and its version are kept in the database.
    pub fn publish(&mut self, now: u64) -> Result<PeerList, StoreError> {
        // Immediate first, then read: the list is worked out while holding the write
        // lock, so another program cannot kick a device between the reading and the
        // writing and have its newer list overwritten by this older one.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (list, content) = next_list(&tx, now)?;
        // Only a changed list is written: the poller asks every few seconds, and an
        // unchanged one would otherwise cost a write and a sync each time.
        if let Some(content) = content {
            tx.execute(
                "INSERT INTO published_list (id, version, content) VALUES (1, ?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET version = excluded.version,
                                                content = excluded.content",
                rusqlite::params![to_sql(list.version), content],
            )?;
        }
        tx.commit()?;
        Ok(list)
    }

    /// What `publish` would return now, without writing anything: for commands that only
    /// look.
    pub fn peek_list(&self, now: u64) -> Result<PeerList, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        Ok(next_list(&tx, now)?.0)
    }

    /// Every device that has not been removed, oldest first.
    pub fn devices(&self) -> Result<Vec<Device>, StoreError> {
        let mut query = self.conn.prepare(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices WHERE removed_at IS NULL ORDER BY id"
        ))?;
        let rows = query.query_map([], device_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The devices of one account that have not been removed, oldest first.
    pub fn devices_of(&self, account_id: i64) -> Result<Vec<Device>, StoreError> {
        let mut query = self.conn.prepare(&format!(
            "SELECT {DEVICE_COLUMNS} FROM devices
             WHERE account_id = ?1 AND removed_at IS NULL ORDER BY id"
        ))?;
        let rows = query.query_map([account_id], device_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Opens the database at `path`, creating it and bringing its schema up to date.
    ///
    /// A new file is created readable by its owner only (mode 0600): it holds account
    /// labels and kick reasons, and SQLite gives its journal the same mode. A file that
    /// already exists keeps the mode it has.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        create_private(path)?;
        Self::prepare(Connection::open(path)?)
    }

    /// A database that lives only as long as this value. For tests and dry runs.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Self::prepare(Connection::open_in_memory()?)
    }

    fn prepare(mut conn: Connection) -> Result<Store, StoreError> {
        conn.pragma_update(None, "foreign_keys", true)?;
        migrate(&mut conn)?;
        Ok(Store {
            conn,
            pool_first: POOL_FIRST,
            pool_last: POOL_LAST,
            open_signup: None,
        })
    }

    /// Uses another address pool (both ends included) for devices made from now on.
    pub fn with_pool(mut self, first: Ipv4Addr, last: Ipv4Addr) -> Store {
        self.pool_first = first;
        self.pool_last = last;
        self
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }
}

/// The list at `now` and its version, and the text to store when it differs from the last
/// one published (`None` when it is the same and nothing needs writing).
fn next_list(conn: &Connection, now: u64) -> Result<(PeerList, Option<String>), StoreError> {
    let peers = peers_at(conn, now)?;
    let content = serde_json::to_string(&peers)
        .map_err(|e| StoreError::Database(format!("cannot write the list: {e}")))?;
    let last: Option<(u64, String)> = conn
        .query_row(
            "SELECT version, content FROM published_list WHERE id = 1",
            [],
            |row| Ok((from_sql(row.get(0)?), row.get(1)?)),
        )
        .optional()?;
    let (version, write) = match last {
        Some((version, last_content)) if last_content == content => (version, None),
        Some((version, _)) => (version + 1, Some(content)),
        None => (1, Some(content)),
    };
    Ok((PeerList { version, peers }, write))
}

/// The peers at `now`, sorted by key, so the same devices always give the same list.
fn peers_at(conn: &Connection, now: u64) -> Result<Vec<PeerSpec>, StoreError> {
    let mut query = conn.prepare(
        "SELECT public_key, address, tracker_filter FROM devices
         WHERE removed_at IS NULL AND NOT EXISTS (SELECT 1 FROM kicks
                           WHERE kicks.device_id = devices.id AND started_at <= ?1
                             AND lifted_at IS NULL AND (until IS NULL OR until > ?1))
         ORDER BY public_key",
    )?;
    let rows = query.query_map([to_sql(now)], |row| {
        let address = Ipv4Addr::from(row.get::<_, u32>(1)?);
        Ok(PeerSpec {
            public_key: row.get(0)?,
            allowed_ips: vec![format!("{address}/32")],
            trackers: row.get::<_, i64>(2)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Whether the device has a kick at `now` that has started, has not run out and has not
/// been lifted.
fn device_kicked(conn: &Connection, device_id: i64, now: u64) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM kicks
                        WHERE device_id = ?1 AND started_at <= ?2
                          AND lifted_at IS NULL AND (until IS NULL OR until > ?2))",
        rusqlite::params![device_id, to_sql(now)],
        |row| row.get(0),
    )?)
}

/// Fails with `NoSuchDevice` unless the device exists and has not been removed.
fn require_live_device(conn: &Connection, device_id: i64) -> Result<(), StoreError> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM devices WHERE id = ?1 AND removed_at IS NULL)",
        [device_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(StoreError::NoSuchDevice)
    }
}

/// Makes an empty file at `path` that only its owner can read, unless one is there.
fn create_private(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(StoreError::Database(format!(
            "cannot create {}: {e}",
            path.display()
        ))),
    }
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(found));
    }
    if found < 1 {
        // Immediate, and look again inside it: two programs opening a new database at
        // the same moment must not both build the schema.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if now_found < 1 {
            // Version 0 with tables in it is somebody else's database: leave it be.
            let objects: u32 =
                tx.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))?;
            if objects > 0 {
                return Err(StoreError::NotOurs);
            }
            tx.execute_batch(SCHEMA_1)?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }
    }
    // A foreign database can carry the same `user_version`: ours has all four tables.
    let ours: u32 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
         AND name IN ('accounts', 'devices', 'kicks', 'published_list')",
        [],
        |row| row.get(0),
    )?;
    if ours != 4 {
        return Err(StoreError::NotOurs);
    }
    let current: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('devices') WHERE name = 'removed_at')",
        [],
        |row| row.get(0),
    )?;
    if !current {
        return Err(StoreError::StaleDraft);
    }
    upgrade_to_2(conn)?;
    upgrade_to_3(conn)?;
    upgrade_to_4(conn)?;
    upgrade_to_5(conn)?;
    upgrade_to_6(conn)?;
    upgrade_to_7(conn)
}

/// Version 6 to 7: a maintenance note for a node and the uptime history table. Immediate, and
/// look again inside it, like version 2.
fn upgrade_to_7(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found >= 7 {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if now_found < 7 {
        tx.execute_batch(crate::nodes::SCHEMA_7)?;
        tx.pragma_update(None, "user_version", 7)?;
    }
    tx.commit()?;
    Ok(())
}

/// Version 5 to 6: where each node's server is. Immediate, and look again inside it, like
/// version 2.
fn upgrade_to_6(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found >= 6 {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if now_found < 6 {
        tx.execute_batch(crate::nodes::SCHEMA_6)?;
        tx.pragma_update(None, "user_version", 6)?;
    }
    tx.commit()?;
    Ok(())
}

/// Version 4 to 5: a protocol for each node, and two nodes may share an address (the two
/// agents of one server). SQLite cannot drop a UNIQUE, so the table is rebuilt; ids are
/// copied and the id counter is carried over, so no id is ever given out twice.
/// Immediate, and look again inside it, like version 2.
fn upgrade_to_5(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found >= 5 {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if now_found < 5 {
        let counter: Option<i64> = tx
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'nodes'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute_batch(crate::nodes::SCHEMA_5)?;
        if let Some(counter) = counter {
            tx.execute(
                "UPDATE sqlite_sequence SET seq = max(seq, ?1) WHERE name = 'nodes'",
                [counter],
            )?;
            tx.execute(
                "INSERT INTO sqlite_sequence (name, seq)
                 SELECT 'nodes', ?1 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'nodes')",
                [counter],
            )?;
        }
        tx.pragma_update(None, "user_version", 5)?;
    }
    tx.commit()?;
    Ok(())
}

/// Version 3 to 4: `sessions.keep`. Immediate, and look again inside it, like version 2.
fn upgrade_to_4(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found >= 4 {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if now_found < 4 {
        tx.execute_batch(crate::signin::SCHEMA_4)?;
        tx.pragma_update(None, "user_version", 4)?;
    }
    tx.commit()?;
    Ok(())
}

/// Version 1 to 2: the sign-in tables and the admin columns. Immediate, and look again
/// inside it, so two programs opening the same old database build the new tables once.
fn upgrade_to_2(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found >= 2 {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if now_found < 2 {
        tx.execute_batch(crate::signin::SCHEMA_2)?;
        tx.pragma_update(None, "user_version", 2)?;
    }
    tx.commit()?;
    Ok(())
}

/// Version 2 to 3: the node registry. Immediate, and look again inside it, like version 2.
fn upgrade_to_3(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found >= 3 {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now_found: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if now_found < 3 {
        tx.execute_batch(crate::nodes::SCHEMA_3)?;
        tx.pragma_update(None, "user_version", 3)?;
    }
    tx.commit()?;
    Ok(())
}

/// Version 1. `docs/SCHEMA.md` describes every column. The ids are `AUTOINCREMENT`, so
/// an id is never given out twice and an old `kick 3` cannot reach a newer device.
pub(crate) const SCHEMA_1: &str = "
CREATE TABLE accounts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT    NOT NULL,
    email_fp     BLOB    UNIQUE,
    device_limit INTEGER NOT NULL DEFAULT 3 CHECK (device_limit >= 0),
    created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    public_key     TEXT    NOT NULL UNIQUE,
    address        INTEGER NOT NULL,
    tracker_filter INTEGER NOT NULL DEFAULT 1 CHECK (tracker_filter IN (0, 1)),
    created_at     INTEGER NOT NULL,
    removed_at     INTEGER
) STRICT;
CREATE INDEX devices_by_account ON devices (account_id);
CREATE UNIQUE INDEX devices_address_active ON devices (address) WHERE removed_at IS NULL;

CREATE TABLE kicks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kicked_by  TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    started_at INTEGER NOT NULL,
    until      INTEGER,
    lifted_at  INTEGER,
    lifted_by  TEXT
) STRICT;
CREATE INDEX kicks_by_device ON kicks (device_id);

CREATE TABLE published_list (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    content TEXT    NOT NULL
) STRICT;
";

fn kick_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Kick> {
    Ok(Kick {
        id: row.get(0)?,
        device_id: row.get(1)?,
        by: row.get(2)?,
        reason: row.get(3)?,
        started_at: from_sql(row.get(4)?),
        until: row.get::<_, Option<i64>>(5)?.map(from_sql),
        lifted_at: row.get::<_, Option<i64>>(6)?.map(from_sql),
        lifted_by: row.get(7)?,
    })
}

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: row.get(0)?,
        account_id: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        address: Ipv4Addr::from(row.get::<_, u32>(4)?),
        tracker_filter: row.get(5)?,
        created_at: from_sql(row.get(6)?),
        removed_at: row.get::<_, Option<i64>>(7)?.map(from_sql),
    })
}

/// A character that must not be stored in a name, label or reason: a control character,
/// or one that reorders, hides or splits text where it is shown (the bidirectional
/// controls, the line and paragraph separators, zero-width space, word joiner and byte
/// order mark). The zero-width joiner and non-joiner stay allowed, because real scripts
/// and emoji sequences need them.
pub(crate) fn is_unsafe_in_text(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

pub(crate) fn check_name(name: &str) -> Result<(), StoreError> {
    let too_long = name.chars().count() > 64;
    if name.trim().is_empty() || too_long || name.chars().any(is_unsafe_in_text) {
        return Err(StoreError::BadName);
    }
    Ok(())
}

pub(crate) fn account_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: row.get(0)?,
        label: row.get(1)?,
        device_limit: row.get(2)?,
        created_at: from_sql(row.get(3)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ---- deleting an account ----

    fn count_in(store: &Store, sql: &str) -> i64 {
        store.conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    /// lao (with an address, two devices, one removed, a kick, a session, a pending code and
    /// mail log lines) and sam (a device and a session).
    fn two_to_delete() -> (Store, i64, i64) {
        let key = |n: u8| crate::keys::KeyPair::from_private([n; 32]).public_key;
        let mut store = Store::open_in_memory().unwrap();
        let lao = store
            .add_account_with_email("lao", Some(&[7; 32]), 1_000)
            .unwrap();
        let sam = store.add_account("sam", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 1_001).unwrap();
        let old = store.add_device(lao.id, "old", &key(2), 1_002).unwrap();
        store.remove_device(old.id, 1_003).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "admin", "", 1_004)
            .unwrap();
        store.add_device(sam.id, "laptop", &key(3), 1_005).unwrap();
        store
            .conn
            .execute_batch(&format!(
                "INSERT INTO sessions (id, secret_hash, account_id, csrf, created_at, expires_at)
                   VALUES ('a', x'00', {lao}, 'c', 1, 9999999999), ('b', x'00', {sam}, 'c', 1, 9999999999);
                 INSERT INTO login_codes (email_fp, code_mac, created_at, expires_at)
                   VALUES (x'{fp}', x'00', 1, 9999999999), (x'{other}', x'00', 1, 9999999999);
                 INSERT INTO mail_log (sent_at, email_fp, kind) VALUES (1, x'{fp}', 'sent'), (1, x'{other}', 'sent');",
                lao = lao.id,
                sam = sam.id,
                fp = "07".repeat(32),
                other = "09".repeat(32),
            ))
            .unwrap();
        (store, lao.id, sam.id)
    }

    #[test]
    fn deleting_an_account_removes_everything_it_owns_and_nothing_else() {
        let (mut store, lao, sam) = two_to_delete();
        let before = store.publish(2_000).unwrap();
        assert_eq!(
            before.peers.len(),
            1,
            "the kicked phone is off; sam's laptop is on"
        );

        let gone = store.delete_account(lao).unwrap();
        assert_eq!(gone.devices, 2, "the live phone and the removed one");

        assert_eq!(store.account(lao).unwrap(), None);
        assert_eq!(
            count_in(
                &store,
                &format!("SELECT COUNT(*) FROM devices WHERE account_id = {lao}")
            ),
            0
        );
        assert_eq!(count_in(&store, "SELECT COUNT(*) FROM kicks"), 0);
        assert_eq!(
            count_in(
                &store,
                &format!("SELECT COUNT(*) FROM sessions WHERE account_id = {lao}")
            ),
            0
        );
        assert_eq!(
            count_in(
                &store,
                &format!(
                    "SELECT COUNT(*) FROM login_codes WHERE email_fp = x'{}'",
                    "07".repeat(32)
                )
            ),
            0
        );
        // The day's mail counts stay; only the link to the address goes.
        assert_eq!(count_in(&store, "SELECT COUNT(*) FROM mail_log"), 2);
        assert_eq!(
            count_in(
                &store,
                &format!(
                    "SELECT COUNT(*) FROM mail_log WHERE email_fp = x'{}'",
                    "07".repeat(32)
                )
            ),
            0
        );

        // sam is untouched.
        assert!(store.account(sam).unwrap().is_some());
        assert_eq!(store.devices_of(sam).unwrap().len(), 1);
        assert_eq!(
            count_in(
                &store,
                &format!("SELECT COUNT(*) FROM sessions WHERE account_id = {sam}")
            ),
            1
        );
        assert_eq!(
            count_in(
                &store,
                &format!(
                    "SELECT COUNT(*) FROM login_codes WHERE email_fp = x'{}'",
                    "09".repeat(32)
                )
            ),
            1
        );
    }

    #[test]
    fn a_deleted_accounts_addresses_are_free_again_and_the_next_list_has_none_of_its_devices() {
        let (mut store, lao, sam) = two_to_delete();
        let key = |n: u8| crate::keys::KeyPair::from_private([n; 32]).public_key;
        // A live, unkicked device of lao's, so the list does change (the kick is lifted
        // first: a kicked account cannot add a device, decision 012).
        let phone = store.devices_of(lao).unwrap()[0].id;
        store.lift(phone, "admin", 1_899).unwrap();
        store.add_device(lao, "tablet", &key(5), 1_900).unwrap();
        let before = store.publish(2_000).unwrap();
        store.delete_account(lao).unwrap();
        let after = store.publish(2_001).unwrap();
        assert!(
            after.version > before.version,
            "the list changed, so its version goes up"
        );
        assert_eq!(after.peers.len(), 1, "only sam's laptop");
        let new = store.add_device(sam, "desk", &key(4), 2_002).unwrap();
        assert_eq!(
            new.address,
            std::net::Ipv4Addr::new(10, 77, 0, 2),
            "lao's first address is free"
        );
    }

    #[test]
    fn deleting_an_account_that_is_not_there_says_so() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(matches!(
            store.delete_account(42),
            Err(StoreError::NoSuchAccount)
        ));
    }

    /// A database path in a fresh directory of its own.
    fn temp_db(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-control-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("control.db")
    }

    #[test]
    fn a_new_database_gets_the_current_schema_version_and_opening_it_again_changes_nothing() {
        let path = temp_db("schema");

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 7);
        drop(store);

        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 7);
    }

    #[test]
    fn the_devices_of_one_account_are_only_its_own_and_only_the_live_ones() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1).unwrap();
        let sam = store.add_account("sam", 1).unwrap();
        let key = |n: u8| crate::keys::KeyPair::from_private([n; 32]).public_key;
        let phone = store.add_device(lao.id, "phone", &key(1), 2).unwrap();
        let laptop = store.add_device(lao.id, "laptop", &key(2), 3).unwrap();
        store.add_device(sam.id, "tablet", &key(3), 4).unwrap();
        store.remove_device(phone.id, 5).unwrap();

        let mine = store.devices_of(lao.id).unwrap();
        assert_eq!(mine.iter().map(|d| d.id).collect::<Vec<_>>(), [laptop.id]);
        assert_eq!(store.devices_of(sam.id).unwrap().len(), 1);
        assert!(store.devices_of(999).unwrap().is_empty());
    }

    #[test]
    fn an_account_is_added_listed_and_still_there_after_reopening() {
        let path = temp_db("accounts");
        let mut store = Store::open(&path).unwrap();

        let made = store.add_account("lao", 1_000).unwrap();
        assert_eq!(made.label, "lao");
        assert_eq!(made.created_at, 1_000);
        assert_eq!(made.device_limit, 3);
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.accounts().unwrap(), vec![made]);
    }

    #[test]
    fn a_label_must_be_1_to_64_characters_with_no_control_characters() {
        let mut store = Store::open_in_memory().unwrap();

        for bad in ["", "   ", "a\nb", "tab\there", &"x".repeat(65)] {
            assert_eq!(
                store.add_account(bad, 1_000),
                Err(StoreError::BadName),
                "{bad:?}"
            );
        }
        assert!(store.accounts().unwrap().is_empty());

        assert!(store.add_account(&"x".repeat(64), 1_000).is_ok());
        assert!(store.add_account("Lao's phone account", 1_000).is_ok());
    }

    /// Characters that move, hide or break text without being control characters: the
    /// bidirectional controls, line and paragraph separators, and invisible joiners.
    const HIDING: [&str; 7] = [
        "\u{202e}fdp.exe",
        "a\u{2066}b\u{2069}",
        "a\u{200f}b",
        "a\u{061c}b",
        "a\u{2028}b",
        "a\u{200b}b",
        "\u{feff}name",
    ];

    #[test]
    fn names_and_reasons_refuse_characters_that_reorder_hide_or_split_text() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let phone = store
            .add_device(account.id, "phone", &key(0), 1_000)
            .unwrap();

        for bad in HIDING {
            assert_eq!(store.add_account(bad, 1_000), Err(StoreError::BadName));
            assert_eq!(
                store.add_device(account.id, bad, &key(1), 1_000),
                Err(StoreError::BadName)
            );
            assert_eq!(
                store.kick(phone.id, KickEnd::UntilLifted, bad, "", 2_000),
                Err(StoreError::BadName)
            );
            assert_eq!(
                store.kick(phone.id, KickEnd::UntilLifted, "lao", bad, 2_000),
                Err(StoreError::BadReason)
            );
            assert_eq!(store.lift(phone.id, bad, 2_000), Err(StoreError::BadName));
        }

        // Ordinary text in other scripts, with accents or emoji, is still welcome. The
        // joiners that real scripts and emoji sequences need are not on the list.
        for fine in [
            "José",
            "日本語",
            "عربى",
            "Mom's 📱",
            "👨\u{200d}👩\u{200d}👧",
            "می\u{200c}خواهم",
        ] {
            assert!(store.add_account(fine, 1_000).is_ok(), "{fine:?}");
        }
    }

    /// One of 26 different well-formed WireGuard public keys.
    fn key(n: u8) -> String {
        let first = (b'A' + n) as char;
        let key = format!("{first}{}=", "A".repeat(42));
        assert!(bf_common::peers::is_valid_key(&key), "{key}");
        key
    }

    #[test]
    fn devices_get_addresses_from_10_77_0_2_upward_and_tracker_blocking_by_default() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();

        let phone = store
            .add_device(account.id, "phone", &key(0), 1_001)
            .unwrap();
        let laptop = store
            .add_device(account.id, "laptop", &key(1), 1_002)
            .unwrap();

        assert_eq!(phone.address, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(laptop.address, Ipv4Addr::new(10, 77, 0, 3));
        assert_eq!(phone.account_id, account.id);
        assert_eq!(phone.public_key, key(0));
        assert!(phone.tracker_filter);
        assert_eq!(store.devices().unwrap(), vec![phone, laptop]);
    }

    #[test]
    fn a_removed_devices_address_is_used_again_before_a_higher_one() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let a = store.add_device(account.id, "a", &key(0), 1_001).unwrap();
        store.add_device(account.id, "b", &key(1), 1_002).unwrap();
        let c = store.add_device(account.id, "c", &key(2), 1_003).unwrap();
        assert_eq!(c.address, Ipv4Addr::new(10, 77, 0, 4));

        store.remove_device(a.id, 1_004).unwrap();
        let d = store.add_device(account.id, "d", &key(3), 1_005).unwrap();

        assert_eq!(d.address, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(
            store.remove_device(9_999, 1_006),
            Err(StoreError::NoSuchDevice)
        );
    }

    #[test]
    fn a_device_needs_a_real_account_a_good_name_and_a_wireguard_key() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();

        assert_eq!(
            store.add_device(account.id + 1, "phone", &key(0), 1_001),
            Err(StoreError::NoSuchAccount)
        );
        assert_eq!(
            store.add_device(account.id, "", &key(0), 1_001),
            Err(StoreError::BadName)
        );
        let not_canonical = format!("{}B=", "A".repeat(42));
        for bad_key in ["", "not a key", &key(0)[..43], &not_canonical] {
            assert_eq!(
                store.add_device(account.id, "phone", bad_key, 1_001),
                Err(StoreError::BadKey),
                "{bad_key:?}"
            );
        }
        assert!(store.devices().unwrap().is_empty());
    }

    #[test]
    fn a_key_can_belong_to_one_device_only_even_across_accounts() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let friend = store.add_account("friend", 1_000).unwrap();
        store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();

        assert_eq!(
            store.add_device(friend.id, "copy", &key(0), 1_002),
            Err(StoreError::KeyInUse)
        );
        assert_eq!(store.devices().unwrap().len(), 1);
    }

    #[test]
    fn an_account_holds_at_most_its_limit_of_devices() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let first = store.add_device(account.id, "1", &key(0), 1_001).unwrap();
        store.add_device(account.id, "2", &key(1), 1_001).unwrap();
        store.add_device(account.id, "3", &key(2), 1_001).unwrap();

        assert_eq!(
            store.add_device(account.id, "4", &key(3), 1_001),
            Err(StoreError::DeviceLimit(3))
        );

        store.remove_device(first.id, 1_002).unwrap();
        assert!(store.add_device(account.id, "4", &key(3), 1_003).is_ok());
    }

    #[test]
    fn an_account_with_a_kicked_device_cannot_add_another_until_the_kick_ends() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let sam = store.add_account("sam", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();
        store
            .kick(phone.id, KickEnd::At(2_000), "admin", "", 1_500)
            .unwrap();

        assert_eq!(
            store.add_device(lao.id, "new phone", &key(1), 1_600),
            Err(StoreError::Kicked)
        );
        assert_eq!(store.devices_of(lao.id).unwrap().len(), 1);
        assert!(
            store.add_device(sam.id, "tablet", &key(2), 1_600).is_ok(),
            "another account is not touched"
        );
        assert!(
            store
                .add_device(lao.id, "new phone", &key(1), 2_000)
                .is_ok(),
            "the kick has run out"
        );
    }

    #[test]
    fn a_kick_is_named_even_at_the_limit_and_a_lift_lets_the_account_add_again() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();
        store.add_device(lao.id, "laptop", &key(1), 1_001).unwrap();
        let tablet = store.add_device(lao.id, "tablet", &key(2), 1_001).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "admin", "", 1_500)
            .unwrap();

        assert_eq!(
            store.add_device(lao.id, "fourth", &key(3), 1_600),
            Err(StoreError::Kicked),
            "at the limit, the kick is the reason that matters"
        );
        store.remove_device(tablet.id, 1_650).unwrap();
        assert_eq!(
            store.add_device(lao.id, "fourth", &key(3), 1_660),
            Err(StoreError::Kicked)
        );

        store.lift(phone.id, "admin", 1_700).unwrap();
        assert!(store.add_device(lao.id, "fourth", &key(3), 1_800).is_ok());
    }

    #[test]
    fn a_kick_that_has_not_started_does_not_hold_the_account_yet() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "admin", "", 1_500)
            .unwrap();

        // The clock stepped back before the kick began: the same rule as the peer list.
        assert!(store.add_device(lao.id, "laptop", &key(1), 1_400).is_ok());
    }

    #[test]
    fn a_kicked_device_the_admin_removed_still_holds_its_account_until_lifted() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "admin", "", 1_500)
            .unwrap();

        store.remove_device(phone.id, 1_600).unwrap();

        assert_eq!(
            store.add_device(lao.id, "laptop", &key(1), 1_700),
            Err(StoreError::Kicked),
            "tidying up a kicked device does not end the kick"
        );
        assert_eq!(store.lift(phone.id, "admin", 1_800), Ok(1));
        assert!(store.add_device(lao.id, "laptop", &key(1), 1_900).is_ok());
    }

    #[test]
    fn an_owner_can_remove_only_their_own_devices_and_not_a_kicked_one() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let sam = store.add_account("sam", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();
        let laptop = store.add_device(lao.id, "laptop", &key(1), 1_001).unwrap();
        let tablet = store.add_device(sam.id, "tablet", &key(2), 1_001).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "admin", "", 1_500)
            .unwrap();

        assert_eq!(
            store.remove_own_device(lao.id, phone.id, 1_600),
            Err(StoreError::Kicked)
        );
        for other in [tablet.id, 99] {
            assert_eq!(
                store.remove_own_device(lao.id, other, 1_600),
                Err(StoreError::NoSuchDevice),
                "{other}"
            );
        }
        assert_eq!(store.devices().unwrap().len(), 3);

        let gone = store.remove_own_device(lao.id, laptop.id, 1_600).unwrap();
        assert_eq!((gone.id, gone.removed_at), (laptop.id, Some(1_600)));
        assert_eq!(
            store.remove_own_device(lao.id, laptop.id, 1_601),
            Err(StoreError::NoSuchDevice),
            "already removed"
        );

        store.lift(phone.id, "admin", 1_700).unwrap();
        assert!(store.remove_own_device(lao.id, phone.id, 1_800).is_ok());
    }

    #[test]
    fn a_full_address_pool_is_reported_and_nothing_outside_it_is_given_out() {
        let mut store = Store::open_in_memory()
            .unwrap()
            .with_pool(Ipv4Addr::new(10, 77, 0, 2), Ipv4Addr::new(10, 77, 0, 3));
        let account = store.add_account("lao", 1_000).unwrap();
        store.add_device(account.id, "1", &key(0), 1_001).unwrap();
        store.add_device(account.id, "2", &key(1), 1_001).unwrap();

        assert_eq!(
            store.add_device(account.id, "3", &key(2), 1_001),
            Err(StoreError::PoolFull)
        );
        assert_eq!(store.devices().unwrap().len(), 2);
    }

    /// A store holding one account with one device.
    fn store_with_device() -> (Store, Device) {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let phone = store
            .add_device(account.id, "phone", &key(0), 1_001)
            .unwrap();
        (store, phone)
    }

    #[test]
    fn a_kick_with_an_end_lasts_until_that_time_and_is_recorded() {
        let (mut store, phone) = store_with_device();
        assert!(!store.is_kicked(phone.id, 2_000).unwrap());

        let kick = store
            .kick(phone.id, KickEnd::At(2_600), "lao", "testing", 2_000)
            .unwrap();

        assert!(store.is_kicked(phone.id, 2_000).unwrap());
        assert!(store.is_kicked(phone.id, 2_599).unwrap());
        assert!(!store.is_kicked(phone.id, 2_600).unwrap());
        assert_eq!(kick.by, "lao");
        assert_eq!(kick.reason, "testing");
        assert_eq!(kick.started_at, 2_000);
        assert_eq!(kick.until, Some(2_600));
        assert_eq!(kick.lifted_at, None);
        assert_eq!(store.kicks(phone.id).unwrap(), vec![kick]);
    }

    #[test]
    fn a_kick_until_lifted_lasts_until_somebody_lifts_it() {
        let (mut store, phone) = store_with_device();
        store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "", 2_000)
            .unwrap();
        assert!(store.is_kicked(phone.id, 2_000_000_000).unwrap());

        assert_eq!(store.lift(phone.id, "friend", 3_000).unwrap(), 1);

        assert!(!store.is_kicked(phone.id, 3_000).unwrap());
        let kicks = store.kicks(phone.id).unwrap();
        assert_eq!(kicks[0].lifted_at, Some(3_000));
        assert_eq!(kicks[0].lifted_by.as_deref(), Some("friend"));
        assert_eq!(store.lift(phone.id, "friend", 3_001).unwrap(), 0);
    }

    #[test]
    fn a_kick_needs_a_real_device_an_end_in_the_future_and_a_name_for_who_did_it() {
        let (mut store, phone) = store_with_device();
        let forever = KickEnd::UntilLifted;

        assert_eq!(
            store.kick(9_999, forever, "lao", "", 2_000),
            Err(StoreError::NoSuchDevice)
        );
        assert_eq!(
            store.lift(9_999, "lao", 2_000),
            Err(StoreError::NoSuchDevice)
        );
        for not_later in [2_000, 1_999, 0] {
            assert_eq!(
                store.kick(phone.id, KickEnd::At(not_later), "lao", "", 2_000),
                Err(StoreError::BadKickEnd)
            );
        }
        assert_eq!(
            store.kick(phone.id, forever, "", "", 2_000),
            Err(StoreError::BadName)
        );
        for bad_reason in ["line\nbreak", &"x".repeat(201)] {
            assert_eq!(
                store.kick(phone.id, forever, "lao", bad_reason, 2_000),
                Err(StoreError::BadReason)
            );
        }
        assert!(store.kicks(phone.id).unwrap().is_empty());
        assert!(!store.is_kicked(phone.id, 2_000).unwrap());
    }

    #[test]
    fn the_peer_list_holds_every_device_that_is_not_kicked_and_the_agent_would_accept_it() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let phone = store
            .add_device(account.id, "phone", &key(1), 1_001)
            .unwrap();
        let laptop = store
            .add_device(account.id, "laptop", &key(0), 1_002)
            .unwrap();
        store
            .kick(laptop.id, KickEnd::At(3_000), "lao", "", 2_000)
            .unwrap();

        let list = store.publish(2_500).unwrap();

        assert_eq!(
            list.peers,
            vec![PeerSpec {
                public_key: phone.public_key.clone(),
                allowed_ips: vec!["10.77.0.2/32".to_string()],
                trackers: true,
            }]
        );
        assert!(list.check().is_ok());
    }

    #[test]
    fn the_published_list_carries_each_devices_tracker_switch_and_a_flip_raises_the_version() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 1_001).unwrap();
        assert!(phone.tracker_filter, "on for a new device");
        let first = store.publish(1_100).unwrap();
        assert!(first.peers[0].trackers);

        let off = store.set_tracker_filter(lao.id, phone.id, false).unwrap();
        assert!(!off.tracker_filter);
        let second = store.publish(1_200).unwrap();
        assert!(!second.peers[0].trackers);
        assert!(second.version > first.version);
        assert!(!store.devices_of(lao.id).unwrap()[0].tracker_filter);

        store.set_tracker_filter(lao.id, phone.id, true).unwrap();
        let third = store.publish(1_300).unwrap();
        assert!(third.peers[0].trackers);
        assert!(third.version > second.version);
    }

    #[test]
    fn only_the_owner_can_switch_trackers_on_a_live_device_kicked_or_not() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let friend = store.add_account("friend", 1_000).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 1_001).unwrap();
        let laptop = store.add_device(lao.id, "laptop", &key(2), 1_002).unwrap();
        let theirs = store
            .add_device(friend.id, "tablet", &key(3), 1_003)
            .unwrap();
        store.remove_own_device(lao.id, laptop.id, 1_100).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "", 1_200)
            .unwrap();

        for (device, why) in [
            (theirs.id, "another account's"),
            (laptop.id, "removed"),
            (999, "unknown"),
        ] {
            assert_eq!(
                store.set_tracker_filter(lao.id, device, false),
                Err(StoreError::NoSuchDevice),
                "{why}"
            );
        }
        assert!(
            store.devices_of(friend.id).unwrap()[0].tracker_filter,
            "untouched"
        );
        assert!(
            store.set_tracker_filter(lao.id, phone.id, false).is_ok(),
            "a kicked device can still be switched"
        );
    }

    #[test]
    fn the_list_version_goes_up_only_when_the_list_itself_changes() {
        let path = temp_db("version");
        let mut store = Store::open(&path).unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let version = |store: &mut Store, now: u64| store.publish(now).unwrap().version;

        assert_eq!(
            version(&mut store, 1_000),
            1,
            "the first list, though empty"
        );
        assert_eq!(version(&mut store, 1_001), 1, "nothing changed");

        let phone = store
            .add_device(account.id, "phone", &key(0), 1_002)
            .unwrap();
        assert_eq!(version(&mut store, 1_002), 2, "a device was added");

        store
            .kick(phone.id, KickEnd::At(2_000), "lao", "", 1_500)
            .unwrap();
        assert_eq!(version(&mut store, 1_500), 3, "it was kicked");
        assert_eq!(version(&mut store, 1_999), 3, "still kicked");
        assert_eq!(version(&mut store, 2_000), 4, "the kick ran out");

        drop(store);
        let mut store = Store::open(&path).unwrap();
        assert_eq!(version(&mut store, 2_001), 4, "kept across a restart");

        store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "", 2_100)
            .unwrap();
        assert_eq!(version(&mut store, 2_100), 5, "kicked until lifted");
        store.lift(phone.id, "lao", 2_200).unwrap();
        assert_eq!(version(&mut store, 2_200), 6, "it was lifted");
    }

    #[test]
    fn a_database_made_by_a_newer_program_is_refused() {
        let path = temp_db("newer");
        Store::open(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 8).unwrap();
        drop(conn);

        assert!(matches!(
            Store::open(&path),
            Err(StoreError::NewerSchema(8))
        ));
        assert!(
            StoreError::NewerSchema(8)
                .to_string()
                .contains("newer than this program's 7")
        );
    }

    #[test]
    fn a_version_3_database_is_upgraded_to_4_and_every_session_stays_unkept() {
        let path = temp_db("upgrade4");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_1).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_2).unwrap();
        conn.execute_batch(crate::nodes::SCHEMA_3).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (label, created_at) VALUES ('lao', 1000);
             INSERT INTO sessions (id, secret_hash, account_id, csrf, created_at, expires_at)
                 VALUES ('aa', x'bb', 1, 'cc', 1000, 5185000);",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
        drop(conn);

        let store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), 7);
        let (keep, created, expires): (i64, i64, i64) = store
            .conn
            .query_row(
                "SELECT keep, created_at, expires_at FROM sessions WHERE id = 'aa'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (keep, created, expires),
            (0, 1000, 5_185_000),
            "an old session keeps its expiry and is not a kept one"
        );
        assert!(
            store
                .conn
                .execute("UPDATE sessions SET keep = 2 WHERE id = 'aa'", [])
                .is_err(),
            "keep is 0 or 1"
        );
        drop(store);

        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 7);
        let rows: i64 = again
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "opening twice upgrades once");
    }

    /// The names of the columns of `table`, in order.
    fn columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut query = conn
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
            .unwrap();
        query
            .query_map([table], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<String>, _>>()
            .unwrap()
    }

    #[test]
    fn a_version_1_database_is_upgraded_to_the_current_schema_and_keeps_every_row() {
        let path = temp_db("upgrade");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (label, email_fp, created_at) VALUES ('lao', x'aabb', 1000);
             INSERT INTO devices (account_id, name, public_key, address, created_at)
                 VALUES (1, 'phone', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 168230914, 1001);
             INSERT INTO kicks (device_id, kicked_by, started_at) VALUES (1, 'admin', 1002);
             INSERT INTO published_list (id, version, content) VALUES (1, 7, '[]');",
        )
        .unwrap();
        drop(conn);

        let store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), 7);
        let accounts = store.accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, "lao");
        assert_eq!(store.devices().unwrap().len(), 1);
        assert_eq!(store.kicks(1).unwrap().len(), 1);
        let (fp, admin, failures, locked, hash): (Vec<u8>, i64, i64, Option<i64>, Option<String>) =
            store
                .conn
                .query_row(
                    "SELECT email_fp, is_admin, admin_fail_count, admin_locked_until, admin_pw_hash
                     FROM accounts WHERE id = 1",
                    [],
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
        assert_eq!(fp, vec![0xaa, 0xbb], "the stored fingerprint is untouched");
        assert_eq!((admin, failures, locked, hash), (0, 0, None, None));
        let version: i64 = store
            .conn
            .query_row("SELECT version FROM published_list WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 7, "the list version a node has seen is not reset");
        drop(store);

        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 7);
        assert_eq!(again.accounts().unwrap().len(), 1);
    }

    #[test]
    fn schema_2_has_the_columns_and_checks_the_spec_names() {
        let store = Store::open_in_memory().unwrap();
        let conn = &store.conn;

        assert_eq!(
            columns(conn, "login_codes"),
            [
                "id",
                "email_fp",
                "code_mac",
                "created_at",
                "expires_at",
                "tries",
                "used_at"
            ]
        );
        assert_eq!(
            columns(conn, "sessions"),
            [
                "id",
                "secret_hash",
                "account_id",
                "csrf",
                "created_at",
                "expires_at",
                "admin_until",
                "keep"
            ]
        );
        assert_eq!(
            columns(conn, "mail_log"),
            ["id", "sent_at", "email_fp", "ip_fp", "kind", "outcome"]
        );
        let accounts = columns(conn, "accounts");
        for added in [
            "is_admin",
            "admin_pw_hash",
            "admin_fail_count",
            "admin_locked_until",
        ] {
            assert!(accounts.contains(&added.to_string()), "{added}");
        }

        assert!(
            conn.execute(
                "INSERT INTO accounts (label, created_at, is_admin) VALUES ('x', 1, 2)",
                []
            )
            .is_err(),
            "is_admin is 0 or 1"
        );
        assert!(
            conn.execute(
                "INSERT INTO mail_log (sent_at, kind) VALUES (1, 'bogus')",
                []
            )
            .is_err(),
            "a kind we do not know is refused"
        );
        assert!(
            conn.execute(
                "INSERT INTO sessions (id, secret_hash, account_id, csrf, created_at, expires_at)
                 VALUES ('a', x'00', 99, 'c', 1, 2)",
                [],
            )
            .is_err(),
            "a session needs a real account"
        );
    }

    #[test]
    fn deleting_an_account_deletes_its_sessions_and_nothing_else_leaks() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO sessions (id, secret_hash, account_id, csrf, created_at, expires_at)
                 VALUES ('a', x'00', ?1, 'c', 1, 2)",
                [account.id],
            )
            .unwrap();

        store
            .conn
            .execute("DELETE FROM accounts WHERE id = ?1", [account.id])
            .unwrap();

        let left: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn a_file_that_is_some_other_database_is_left_alone() {
        let path = temp_db("foreign");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE notes (text TEXT);")
            .unwrap();
        drop(conn);

        assert!(matches!(Store::open(&path), Err(StoreError::NotOurs)));

        let conn = Connection::open(&path).unwrap();
        let tables: u32 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert_eq!(tables, 1, "no table of ours was added beside theirs");
    }

    #[cfg(unix)]
    #[test]
    fn a_new_database_file_can_be_read_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db("private");

        let mut store = Store::open(&path).unwrap();
        store.add_account("lao", 1_000).unwrap();
        drop(store);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {:o}", mode & 0o777);
    }

    #[test]
    fn the_real_pool_runs_from_10_77_0_2_to_10_77_255_254() {
        assert_eq!(POOL_FIRST, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(POOL_LAST, Ipv4Addr::new(10, 77, 255, 254));
        let store = Store::open_in_memory().unwrap();
        assert_eq!((store.pool_first, store.pool_last), (POOL_FIRST, POOL_LAST));
    }

    #[test]
    fn removing_a_device_keeps_its_kicks_and_takes_it_off_the_list() {
        let (mut store, phone) = store_with_device();
        assert_eq!(store.publish(1_002).unwrap().version, 1);
        store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "too loud", 1_003)
            .unwrap();
        assert_eq!(store.publish(1_003).unwrap().version, 2);

        let removed = store.remove_device(phone.id, 1_004).unwrap();

        assert_eq!(removed.removed_at, Some(1_004));
        let kicks = store.kicks(phone.id).unwrap();
        assert_eq!(kicks.len(), 1, "the history stays");
        assert_eq!(
            (kicks[0].by.as_str(), kicks[0].reason.as_str()),
            ("lao", "too loud")
        );
        assert!(store.devices().unwrap().is_empty());
        // The list was empty already (the device was kicked), so removing it changes
        // nothing; a removal of a device that was on the list does.
        assert_eq!(store.publish(1_004).unwrap().version, 2);

        // The kick still holds the account (decision 012) until it is lifted; the device
        // is gone, so lifting it changes no list.
        assert_eq!(store.lift(phone.id, "lao", 1_005), Ok(1));
        assert_eq!(store.publish(1_005).unwrap().version, 2);
        let account = store.accounts().unwrap()[0].id;
        store.add_device(account, "laptop", &key(1), 1_005).unwrap();
        assert_eq!(store.publish(1_005).unwrap().version, 3);
        let laptop = store.devices().unwrap()[0].id;
        store.remove_device(laptop, 1_006).unwrap();
        assert_eq!(
            store.publish(1_006).unwrap().version,
            4,
            "a device left the list"
        );
    }

    #[test]
    fn a_removed_device_frees_its_slot_and_address_but_not_its_key_and_cannot_be_kicked() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let sam = store.add_account("sam", 1_000).unwrap();
        let a = store.add_device(lao.id, "a", &key(0), 1_001).unwrap();
        store.add_device(lao.id, "b", &key(1), 1_001).unwrap();
        store.add_device(lao.id, "c", &key(2), 1_001).unwrap();
        store.remove_device(a.id, 1_002).unwrap();

        // Its slot and its address are free at once.
        let d = store.add_device(lao.id, "d", &key(3), 1_003).unwrap();
        assert_eq!(d.address, a.address);
        let counted = store.accounts_with_device_counts().unwrap();
        assert_eq!(counted[0].1, 3, "the removed device is not counted");
        assert_eq!(store.devices().unwrap().len(), 3);

        // Its key is not: remove and re-add must not shed a kick.
        assert_eq!(
            store.add_device(sam.id, "x", &key(0), 1_004),
            Err(StoreError::KeyInUse)
        );
        // It cannot be kicked or removed twice. A lift still finds it, because a removed
        // device's kicks still hold its account (decision 012); it had none to end.
        assert_eq!(
            store.kick(a.id, KickEnd::UntilLifted, "lao", "", 1_005),
            Err(StoreError::NoSuchDevice)
        );
        assert_eq!(store.lift(a.id, "lao", 1_005), Ok(0));
        assert_eq!(
            store.lift(a.id + 100, "lao", 1_005),
            Err(StoreError::NoSuchDevice),
            "a device that never existed"
        );
        assert_eq!(
            store.remove_device(a.id, 1_006),
            Err(StoreError::NoSuchDevice)
        );
    }

    #[test]
    fn a_lift_ends_every_running_kick_and_leaves_the_ended_ones_as_they_were() {
        let (mut store, phone) = store_with_device();
        store
            .kick(phone.id, KickEnd::At(1_100), "lao", "short", 1_050)
            .unwrap();
        store
            .kick(phone.id, KickEnd::At(9_000), "lao", "long", 1_060)
            .unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "sam", "forever", 1_070)
            .unwrap();

        assert_eq!(store.lift(phone.id, "lao", 2_000).unwrap(), 2);
        assert!(!store.is_kicked(phone.id, 2_000).unwrap());

        let kicks = store.kicks(phone.id).unwrap();
        assert_eq!(kicks[0].lifted_at, None, "it had run out already");
        assert_eq!(kicks[1].lifted_at, Some(2_000));
        assert_eq!(kicks[2].lifted_at, Some(2_000));
        assert_eq!(kicks[2].lifted_by.as_deref(), Some("lao"));

        // A kick that ends at exactly this second has ended: nothing to lift.
        store
            .kick(phone.id, KickEnd::At(3_000), "lao", "", 2_500)
            .unwrap();
        assert_eq!(store.lift(phone.id, "lao", 3_000).unwrap(), 0);
    }

    #[test]
    fn a_kick_does_nothing_before_its_start_time() {
        let (mut store, phone) = store_with_device();
        store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "", 1_500)
            .unwrap();

        assert!(!store.is_kicked(phone.id, 1_499).unwrap());
        assert!(store.is_kicked(phone.id, 1_500).unwrap());
        assert_eq!(store.publish(1_499).unwrap().peers.len(), 1);
    }

    #[test]
    fn the_list_is_sorted_by_key_whatever_order_the_devices_came_in() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        for (n, name) in [(2, "c"), (0, "a"), (1, "b")] {
            store.add_device(account.id, name, &key(n), 1_001).unwrap();
        }

        let list = store.publish(1_002).unwrap();

        let keys: Vec<&str> = list.peers.iter().map(|p| p.public_key.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
        assert_eq!(keys.len(), 3);
        assert!(list.check().is_ok());
    }

    #[test]
    fn two_programs_publishing_and_kicking_at_once_never_leave_a_stale_list() {
        let path = temp_db("race");
        let device = {
            let mut store = Store::open(&path).unwrap();
            let account = store.add_account("lao", 1_000).unwrap();
            let device = store
                .add_device(account.id, "phone", &key(0), 1_001)
                .unwrap();
            store.publish(1_002).unwrap();
            device
        };
        let now = 5_000_000_000;

        let publisher = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(&path).unwrap();
                for _ in 0..300 {
                    store.publish(now).unwrap();
                }
            })
        };
        let kicker = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(&path).unwrap();
                for _ in 0..300 {
                    store
                        .kick(device.id, KickEnd::UntilLifted, "lao", "", 1_003)
                        .unwrap();
                    store.publish(now).unwrap();
                    store.lift(device.id, "lao", 1_004).unwrap();
                    store.publish(now).unwrap();
                }
            })
        };
        publisher.join().unwrap();
        kicker.join().unwrap();

        // Whoever published last saw the final state: the device is lifted and on the list.
        let mut store = Store::open(&path).unwrap();
        let stored: String = store
            .conn
            .query_row("SELECT content FROM published_list WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let expected = serde_json::to_string(&peers_at(&store.conn, now).unwrap()).unwrap();
        assert_eq!(stored, expected);
        let version = store.publish(now).unwrap().version;
        assert_eq!(store.publish(now).unwrap().version, version);
    }

    #[test]
    fn an_id_is_never_given_out_twice_even_after_its_row_is_deleted() {
        let mut store = Store::open_in_memory().unwrap();
        let first = store.add_account("lao", 1_000).unwrap();
        let phone = store.add_device(first.id, "phone", &key(0), 1_001).unwrap();
        let kick = store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "", 1_002)
            .unwrap();

        // Delete the newest row of each kind (deleting the device takes its kick too;
        // `remove_device` would only mark it).
        store
            .conn
            .execute("DELETE FROM devices WHERE id = ?1", [phone.id])
            .unwrap();
        store
            .conn
            .execute("DELETE FROM accounts WHERE id = ?1", [first.id])
            .unwrap();

        let second = store.add_account("sam", 1_003).unwrap();
        let laptop = store
            .add_device(second.id, "laptop", &key(1), 1_004)
            .unwrap();
        let next_kick = store
            .kick(laptop.id, KickEnd::UntilLifted, "lao", "", 1_005)
            .unwrap();

        assert_ne!(second.id, first.id, "account id");
        assert_ne!(laptop.id, phone.id, "device id");
        assert_ne!(next_kick.id, kick.id, "kick id");
        // The address is a different matter: a free address is used again.
        assert_eq!(laptop.address, phone.address);
    }

    #[test]
    fn a_device_is_kept_only_if_the_step_before_the_commit_succeeds() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();

        let mut seen = None;
        let refused = store.add_device_with(account.id, "phone", &key(0), 1_001, |device| {
            seen = Some(device.address);
            Err("the pipe is closed".to_string())
        });

        assert_eq!(
            refused,
            Err(StoreError::NotKept("the pipe is closed".to_string()))
        );
        assert_eq!(seen, Some(Ipv4Addr::new(10, 77, 0, 2)), "it saw the device");
        assert!(store.devices().unwrap().is_empty(), "nothing was kept");
        let again = store
            .add_device(account.id, "phone", &key(0), 1_002)
            .unwrap();
        assert_eq!(
            again.address,
            Ipv4Addr::new(10, 77, 0, 2),
            "address is free"
        );
    }

    #[test]
    fn a_database_of_another_program_with_version_1_is_refused_too() {
        let path = temp_db("foreign-v1");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE notes (text TEXT); PRAGMA user_version = 1;")
            .unwrap();
        drop(conn);

        assert!(matches!(Store::open(&path), Err(StoreError::NotOurs)));
    }

    #[test]
    fn removing_a_device_hands_back_what_was_removed_with_the_time() {
        let (mut store, phone) = store_with_device();

        let removed = store.remove_device(phone.id, 1_005).unwrap();

        assert_eq!(removed.removed_at, Some(1_005));
        assert_eq!(
            Device {
                removed_at: None,
                ..removed
            },
            phone
        );
    }

    #[test]
    fn the_accounts_come_with_the_number_of_devices_each_holds() {
        let mut store = Store::open_in_memory().unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let sam = store.add_account("sam", 1_000).unwrap();
        store.add_device(lao.id, "phone", &key(0), 1_001).unwrap();
        store.add_device(lao.id, "laptop", &key(1), 1_002).unwrap();

        let counted = store.accounts_with_device_counts().unwrap();

        assert_eq!(counted, vec![(lao, 2), (sam, 0)]);
    }

    #[test]
    fn a_publish_waits_for_a_writer_in_progress_and_then_shows_its_change() {
        let path = temp_db("publish-waits");
        let (mut publisher, device) = {
            let mut store = Store::open(&path).unwrap();
            let account = store.add_account("lao", 1_000).unwrap();
            let device = store
                .add_device(account.id, "phone", &key(0), 1_001)
                .unwrap();
            store.publish(1_002).unwrap();
            (store, device)
        };
        let now = 5_000_000_000;

        // Another program is half way through kicking the device: its write is not yet
        // committed. A publish started now must wait and read after the commit.
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        writer
            .execute(
                "INSERT INTO kicks (device_id, kicked_by, started_at) VALUES (?1, 'lao', 1003)",
                [device.id],
            )
            .unwrap();
        let publishing = std::thread::spawn(move || publisher.publish(now).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(300));
        writer.execute_batch("COMMIT").unwrap();

        let list = publishing.join().unwrap();
        assert!(
            list.peers.is_empty(),
            "the kick was committed before the read"
        );
        assert_eq!(list.version, 2);
    }

    #[test]
    fn the_kick_history_covers_every_device_including_removed_ones() {
        let mut store = Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 1_000).unwrap();
        let phone = store
            .add_device(account.id, "phone", &key(0), 1_001)
            .unwrap();
        let laptop = store
            .add_device(account.id, "laptop", &key(1), 1_001)
            .unwrap();
        let first = store
            .kick(phone.id, KickEnd::UntilLifted, "lao", "too loud", 1_010)
            .unwrap();
        let second = store
            .kick(laptop.id, KickEnd::At(2_000), "sam", "", 1_020)
            .unwrap();
        store.lift(phone.id, "lao", 1_030).unwrap();
        store.remove_device(phone.id, 1_040).unwrap();

        let all = store.kick_history(None).unwrap();

        let seen: Vec<(i64, &str, bool)> = all
            .iter()
            .map(|(kick, name, removed)| (kick.id, name.as_str(), *removed))
            .collect();
        assert_eq!(
            seen,
            vec![(first.id, "phone", true), (second.id, "laptop", false)]
        );
        assert_eq!(all[0].0.lifted_by.as_deref(), Some("lao"));
        let one = store.kick_history(Some(laptop.id)).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0.id, second.id);
        assert!(store.kick_history(Some(9_999)).unwrap().is_empty());
    }

    #[test]
    fn a_kick_waits_for_a_removal_in_progress_and_then_finds_no_device() {
        let path = temp_db("kick-waits");
        let (mut kicker, device) = {
            let mut store = Store::open(&path).unwrap();
            let account = store.add_account("lao", 1_000).unwrap();
            let device = store
                .add_device(account.id, "phone", &key(0), 1_001)
                .unwrap();
            (store, device)
        };

        // Another program is half way through removing the device. A kick started now
        // must wait for it and then see the device is gone, not add a kick to it.
        let remover = Connection::open(&path).unwrap();
        remover.execute_batch("BEGIN IMMEDIATE").unwrap();
        remover
            .execute(
                "UPDATE devices SET removed_at = 1002 WHERE id = ?1",
                [device.id],
            )
            .unwrap();
        let kicking = std::thread::spawn(move || {
            kicker.kick(device.id, KickEnd::UntilLifted, "lao", "", 1_003)
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        remover.execute_batch("COMMIT").unwrap();

        assert_eq!(kicking.join().unwrap(), Err(StoreError::NoSuchDevice));
        let store = Store::open(&path).unwrap();
        assert!(store.kicks(device.id).unwrap().is_empty());
    }

    #[test]
    fn a_database_from_an_earlier_draft_of_schema_1_is_refused_with_a_clear_message() {
        let path = temp_db("old-draft");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY);
             CREATE TABLE devices (id INTEGER PRIMARY KEY, address INTEGER UNIQUE);
             CREATE TABLE kicks (id INTEGER PRIMARY KEY);
             CREATE TABLE published_list (id INTEGER PRIMARY KEY);
             PRAGMA user_version = 1;",
        )
        .unwrap();
        drop(conn);

        assert!(matches!(Store::open(&path), Err(StoreError::StaleDraft)));
        assert!(StoreError::StaleDraft.to_string().contains("delete"));
    }
}
