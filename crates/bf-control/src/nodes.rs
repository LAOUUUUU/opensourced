//! The node registry: which VPN nodes exist and where to reach them.
//!
//! A node is a row in `nodes`. Its signing secret and its pinned root certificate are not
//! here: they are files in the nodes directory (`link.rs`), so a backup of the database
//! never carries a node's key. Everything is a method on [`Store`], as in `signin.rs`.

/// Schema version 3, applied on top of version 2. `docs/SCHEMA.md` describes every column.
pub(crate) const SCHEMA_3: &str = "
CREATE TABLE nodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    title      TEXT    NOT NULL,
    place      TEXT    NOT NULL,
    address    TEXT    NOT NULL UNIQUE,
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL
) STRICT;
";

/// Version 4 to 5: the table again, with `protocol` and with `address` no longer unique on
/// its own (the two agents of one server share it), only together with the protocol.
pub(crate) const SCHEMA_5: &str = "
CREATE TABLE nodes_5 (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    title      TEXT    NOT NULL,
    place      TEXT    NOT NULL,
    address    TEXT    NOT NULL,
    protocol   TEXT    CHECK (protocol IN ('wireguard', 'amneziawg')),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    UNIQUE (address, protocol)
) STRICT;
INSERT INTO nodes_5 (id, name, title, place, address, protocol, enabled, created_at)
    SELECT id, name, title, place, address, NULL, enabled, created_at FROM nodes;
DROP TABLE nodes;
ALTER TABLE nodes_5 RENAME TO nodes;
";

/// Version 5 to 6: where each server is, for "Closest to you" (decision 014). Both or
/// neither are set, in degrees.
pub(crate) const SCHEMA_6: &str = "
ALTER TABLE nodes ADD COLUMN lat REAL CHECK (lat IS NULL OR lat BETWEEN -90 AND 90);
ALTER TABLE nodes ADD COLUMN lon REAL
    CHECK ((lat IS NULL) = (lon IS NULL) AND (lon IS NULL OR lon BETWEEN -180 AND 180));
";

/// Version 7: a maintenance note for a disabled node, and the status page's uptime history
/// (hourly counts of passes in which a server was working or down, per server).
pub(crate) const SCHEMA_7: &str = "
ALTER TABLE nodes ADD COLUMN note TEXT CHECK (note IS NULL OR length(note) BETWEEN 1 AND 100);
CREATE TABLE uptime_hours (
    title TEXT NOT NULL,
    place TEXT NOT NULL,
    hour  INTEGER NOT NULL CHECK (hour >= 0),
    up    INTEGER NOT NULL DEFAULT 0 CHECK (up >= 0),
    down  INTEGER NOT NULL DEFAULT 0 CHECK (down >= 0),
    PRIMARY KEY (title, place, hour)
) STRICT, WITHOUT ROWID;
";

use std::net::SocketAddr;

use rusqlite::{OptionalExtension, TransactionBehavior};

use crate::closest::Location;
use crate::protocol::Protocol;
use crate::store::{Store, StoreError, from_sql, is_unsafe_in_text, to_sql};

/// One registered node.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub id: i64,
    /// 1 to 32 characters of `a-z`, `0-9` and `-`. It is the node's name inside the
    /// pinned certificate (`<name>.agent.internal`) and the stem of its two files.
    pub name: String,
    /// What the site calls it ("Toronto").
    pub title: String,
    /// Where it is ("Canada").
    pub place: String,
    /// Where its agent is reached: Caddy's HTTPS port on the node's IP address.
    pub address: SocketAddr,
    pub enabled: bool,
    pub created_at: u64,
    /// What its interface speaks. `None` for a node registered before schema 5, until
    /// `node set-protocol`: the poller sends it the list as published, as before, and the
    /// site offers it for nothing.
    pub protocol: Option<Protocol>,
    /// Where the server is (`node set-location`), for "Closest to you". `None` until set:
    /// such a server is treated as further than any whose location is known.
    pub location: Option<Location>,
    /// Why it is disabled, for the status page ("back at 20:00"); set by `disable --note`,
    /// cleared by `enable`.
    pub note: Option<String>,
}

/// The highest version `raise_version_floor` accepts. A version that big is a typo or a
/// lie; the numbers a real list reaches are in the thousands.
pub const MAX_VERSION_FLOOR: u64 = 1_000_000_000_000;

/// Checks a node name: 1 to 32 characters of `a-z`, `0-9` and `-`, starting with a letter
/// and not ending with `-`.
pub fn check_node_name(name: &str) -> Result<(), StoreError> {
    let bytes = name.as_bytes();
    let shape = !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if shape {
        Ok(())
    } else {
        Err(StoreError::BadNodeName)
    }
}

/// An IP address and a non-zero port, written the way `SocketAddr` reads it.
fn parse_node_address(text: &str) -> Result<SocketAddr, StoreError> {
    match text.parse::<SocketAddr>() {
        Ok(addr) if addr.port() != 0 => Ok(addr),
        _ => Err(StoreError::BadNodeAddress),
    }
}

fn check_node_text(text: &str) -> Result<(), StoreError> {
    if text.trim().is_empty() || text.chars().count() > 40 || text.chars().any(is_unsafe_in_text) {
        return Err(StoreError::BadNodeText);
    }
    Ok(())
}

const NODE_COLUMNS: &str =
    "id, name, title, place, address, enabled, created_at, protocol, lat, lon, note";

/// The longest maintenance note, in characters.
pub const MAX_NOTE_CHARS: usize = 100;

/// A maintenance note: 1 to 100 characters, not only spaces, no control characters and none
/// that reorder or hide text. It is public text, so it is held to the same plain-text rule as
/// a node's title.
pub fn check_node_note(text: &str) -> Result<(), StoreError> {
    if text.trim().is_empty()
        || text.chars().count() > MAX_NOTE_CHARS
        || text.chars().any(is_unsafe_in_text)
    {
        return Err(StoreError::BadNodeNote);
    }
    Ok(())
}

fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let address: String = row.get(4)?;
    Ok(Node {
        id: row.get(0)?,
        name: row.get(1)?,
        title: row.get(2)?,
        place: row.get(3)?,
        // Only `add_node` writes this column, and only a parsed address.
        address: address.parse().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                "not a socket address".into(),
            )
        })?,
        enabled: row.get(5)?,
        created_at: from_sql(row.get(6)?),
        // The CHECK allows only the two words (or null).
        protocol: match row.get::<_, Option<String>>(7)? {
            None => None,
            Some(text) => Some(Protocol::parse(&text).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Text,
                    "not a protocol".into(),
                )
            })?),
        },
        // The CHECKs keep both or neither, in range.
        location: match (row.get::<_, Option<f64>>(8)?, row.get::<_, Option<f64>>(9)?) {
            (Some(lat), Some(lon)) => Location::new(lat, lon),
            _ => None,
        },
        note: row.get(10)?,
    })
}

impl Store {
    /// Registers a node. `address` is an IP address and a non-zero port; it is kept in
    /// its canonical spelling, so `192.0.2.7:8443` cannot be added twice.
    pub fn add_node(
        &mut self,
        name: &str,
        address: &str,
        title: &str,
        place: &str,
        now: u64,
    ) -> Result<Node, StoreError> {
        self.add_node_with(name, address, title, place, None, now)
    }

    /// Registers a node that speaks `protocol`. Two nodes may share an address when the new
    /// one has a protocol that no node at that address has (the two agents of one server,
    /// including an older node whose protocol is not set yet); a new node with no protocol
    /// needs an address of its own.
    pub fn add_node_with(
        &mut self,
        name: &str,
        address: &str,
        title: &str,
        place: &str,
        protocol: Option<Protocol>,
        now: u64,
    ) -> Result<Node, StoreError> {
        check_node_name(name)?;
        let address = parse_node_address(address)?;
        check_node_text(title)?;
        check_node_text(place)?;
        let address = address.to_string();
        // Immediate: the check for a taken name or address and the insert are one step.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let protocol = protocol.map(Protocol::as_str);
        let taken: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM nodes WHERE name = ?1
                 OR (address = ?2 AND (?3 IS NULL OR protocol = ?3)))",
            rusqlite::params![name, address, protocol],
            |row| row.get(0),
        )?;
        if taken {
            return Err(StoreError::NodeTaken);
        }
        tx.execute(
            "INSERT INTO nodes (name, title, place, address, protocol, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![name, title, place, address, protocol, to_sql(now)],
        )?;
        let id = tx.last_insert_rowid();
        let node = tx.query_row(
            &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?1"),
            [id],
            node_from_row,
        )?;
        tx.commit()?;
        Ok(node)
    }

    /// Every node, oldest first.
    pub fn nodes(&self) -> Result<Vec<Node>, StoreError> {
        let mut query = self
            .conn
            .prepare(&format!("SELECT {NODE_COLUMNS} FROM nodes ORDER BY id"))?;
        let rows = query.query_map([], node_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The nodes the poller visits, oldest first.
    pub fn enabled_nodes(&self) -> Result<Vec<Node>, StoreError> {
        let mut query = self.conn.prepare(&format!(
            "SELECT {NODE_COLUMNS} FROM nodes WHERE enabled = 1 ORDER BY id"
        ))?;
        let rows = query.query_map([], node_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn node(&self, name: &str) -> Result<Option<Node>, StoreError> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE name = ?1"),
                [name],
                node_from_row,
            )
            .optional()?)
    }

    /// Says what a node's interface speaks. Refused if another node at the same address
    /// already speaks it. A change makes the next published list a new version.
    pub fn set_node_protocol(&mut self, name: &str, protocol: Protocol) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let address: Option<String> = tx
            .query_row("SELECT address FROM nodes WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(address) = address else {
            return Err(StoreError::NoSuchNode);
        };
        let taken: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM nodes WHERE address = ?1 AND protocol = ?2 AND name != ?3)",
            rusqlite::params![address, protocol.as_str(), name],
            |row| row.get(0),
        )?;
        if taken {
            return Err(StoreError::NodeTaken);
        }
        let changed = tx.execute(
            "UPDATE nodes SET protocol = ?2 WHERE name = ?1 AND protocol IS NOT ?2",
            rusqlite::params![name, protocol.as_str()],
        )?;
        if changed > 0 {
            // The agent now gets a different list (another range) under the same version,
            // which it would never be sent: blank the stored list, so the next publish is a
            // new version and every agent is sent it.
            tx.execute("UPDATE published_list SET content = '' WHERE id = 1", [])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Says where a node's server is. The agents are not told: it only steers new devices,
    /// so the published list does not change.
    pub fn set_node_location(&mut self, name: &str, at: Location) -> Result<(), StoreError> {
        let at = Location::new(at.lat, at.lon).ok_or(StoreError::BadLocation)?;
        let changed = self.conn.execute(
            "UPDATE nodes SET lat = ?2, lon = ?3 WHERE name = ?1",
            rusqlite::params![name, at.lat, at.lon],
        )?;
        if changed == 0 {
            return Err(StoreError::NoSuchNode);
        }
        Ok(())
    }

    /// Enables or disables a node. Either way an old maintenance note goes (see
    /// [`Store::disable_node`] to disable with one).
    pub fn set_node_enabled(&mut self, name: &str, enabled: bool) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE nodes SET enabled = ?2, note = NULL WHERE name = ?1",
            rusqlite::params![name, enabled],
        )?;
        if changed == 0 {
            return Err(StoreError::NoSuchNode);
        }
        Ok(())
    }

    /// Disables a node (the poller stops visiting it and the website says it is being fixed),
    /// with an optional note for the status page. Without a note, an old one is cleared.
    pub fn disable_node(&mut self, name: &str, note: Option<&str>) -> Result<(), StoreError> {
        if let Some(text) = note {
            check_node_note(text)?;
        }
        let changed = self.conn.execute(
            "UPDATE nodes SET enabled = 0, note = ?2 WHERE name = ?1",
            rusqlite::params![name, note],
        )?;
        if changed == 0 {
            return Err(StoreError::NoSuchNode);
        }
        Ok(())
    }

    /// Removes the node's row. Its files stay where they are.
    pub fn remove_node(&mut self, name: &str) -> Result<(), StoreError> {
        let changed = self
            .conn
            .execute("DELETE FROM nodes WHERE name = ?1", [name])?;
        if changed == 0 {
            return Err(StoreError::NoSuchNode);
        }
        Ok(())
    }

    /// The version of the list `publish` last returned, `None` before the first.
    pub fn list_version(&self) -> Result<Option<u64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT version FROM published_list WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(from_sql))
    }

    /// Makes the next list `publish` returns have a version above `floor`, even if the list
    /// has not changed. Returns whether anything changed: a database already at or above
    /// `floor` is left alone.
    ///
    /// It sets the stored version to `floor` and blanks the stored list, which no real
    /// list equals, so the next `publish` sees a change and adds one.
    pub fn raise_version_floor(&mut self, floor: u64) -> Result<bool, StoreError> {
        if floor == 0 || floor > MAX_VERSION_FLOOR {
            return Err(StoreError::BadVersionFloor);
        }
        let changed = self.conn.execute(
            "INSERT INTO published_list (id, version, content) VALUES (1, ?1, '')
             ON CONFLICT (id) DO UPDATE SET version = excluded.version, content = ''
             WHERE published_list.version < excluded.version",
            [to_sql(floor)],
        )?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::path::PathBuf;

    use crate::protocol::Protocol;
    use crate::store::Store;

    fn temp_db(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bf-control-nodes-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("control.db")
    }

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn toronto(store: &mut Store) -> Node {
        store
            .add_node("toronto", "192.0.2.7:8443", "Toronto", "Canada", 1_000)
            .unwrap()
    }

    // ---- schema 3 ----

    #[test]
    fn a_version_2_database_is_upgraded_to_3_and_keeps_every_row() {
        let path = temp_db("upgrade");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL, email_fp BLOB UNIQUE,
                device_limit INTEGER NOT NULL DEFAULT 3 CHECK (device_limit >= 0),
                created_at INTEGER NOT NULL) STRICT;
             CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                name TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE, address INTEGER NOT NULL,
                tracker_filter INTEGER NOT NULL DEFAULT 1 CHECK (tracker_filter IN (0, 1)),
                created_at INTEGER NOT NULL, removed_at INTEGER) STRICT;
             CREATE TABLE kicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                kicked_by TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
                started_at INTEGER NOT NULL, until INTEGER, lifted_at INTEGER, lifted_by TEXT)
                STRICT;
             CREATE TABLE published_list (
                id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL,
                content TEXT NOT NULL) STRICT;",
        )
        .unwrap();
        conn.execute_batch(crate::signin::SCHEMA_2).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (label, created_at) VALUES ('lao', 1000);
             INSERT INTO published_list (id, version, content) VALUES (1, 7, '[]');",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        drop(conn);

        let mut store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), 7);
        assert_eq!(store.accounts().unwrap().len(), 1);
        assert_eq!(store.nodes().unwrap(), Vec::new());
        assert_eq!(store.publish(2_000).unwrap().version, 7);
        toronto(&mut store);
        drop(store);

        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 7);
        assert_eq!(
            again.nodes().unwrap().len(),
            1,
            "opening twice builds it once"
        );
    }

    #[test]
    fn the_nodes_table_has_the_columns_and_checks_the_spec_names() {
        let store = store();
        let conn = &store.conn;
        let names: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('nodes') ORDER BY cid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            names,
            [
                "id",
                "name",
                "title",
                "place",
                "address",
                "protocol",
                "enabled",
                "created_at",
                "lat",
                "lon",
                "note"
            ]
        );
        let strict: bool = conn
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name = 'nodes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(strict);
        let bad = conn.execute(
            "INSERT INTO nodes (name, title, place, address, enabled, created_at)
             VALUES ('x', 't', 'p', '192.0.2.1:1', 2, 1)",
            [],
        );
        assert!(bad.is_err(), "enabled is 0 or 1");
    }

    // ---- schema 5: protocols (specs/dual-protocol.md) ----

    #[test]
    fn a_version_4_database_is_upgraded_to_5_and_keeps_every_node_its_id_and_the_id_counter() {
        let path = temp_db("upgrade5");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(crate::store::SCHEMA_1).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_2).unwrap();
        conn.execute_batch(SCHEMA_3).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_4).unwrap();
        conn.execute_batch(
            "INSERT INTO nodes (id, name, title, place, address, enabled, created_at)
                 VALUES (1, 'toronto', 'Toronto', 'Canada', '192.0.2.7:8443', 1, 1000),
                        (3, 'dallas', 'Dallas', 'United States', '192.0.2.8:8443', 0, 1001);
             UPDATE sqlite_sequence SET seq = 5 WHERE name = 'nodes';",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 4).unwrap();
        drop(conn);

        let mut store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), 7);
        let nodes = store.nodes().unwrap();
        let summary: Vec<_> = nodes
            .iter()
            .map(|n| {
                (
                    n.id,
                    n.name.as_str(),
                    n.address.to_string(),
                    n.enabled,
                    n.protocol,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (1, "toronto", "192.0.2.7:8443".to_string(), true, None),
                (3, "dallas", "192.0.2.8:8443".to_string(), false, None),
            ],
            "every node kept, with no protocol until one is set"
        );
        let next = store
            .add_node("vancouver", "192.0.2.9:8443", "Vancouver", "Canada", 2_000)
            .unwrap();
        assert_eq!(next.id, 6, "ids are never reused, removed ones included");
        drop(store);
        assert_eq!(
            Store::open(&path).unwrap().nodes().unwrap().len(),
            3,
            "upgraded once"
        );
    }

    #[test]
    fn two_agents_of_one_server_share_its_address_but_never_a_protocol() {
        let mut store = store();
        let awg = store
            .add_node_with(
                "toronto",
                "192.0.2.7:8443",
                "Toronto",
                "Canada",
                Some(Protocol::AmneziaWg),
                1_000,
            )
            .unwrap();
        let wg = store
            .add_node_with(
                "toronto-wg",
                "192.0.2.7:8443",
                "Toronto",
                "Canada",
                Some(Protocol::WireGuard),
                1_000,
            )
            .unwrap();
        assert_eq!(awg.protocol, Some(Protocol::AmneziaWg));
        assert_eq!(wg.protocol, Some(Protocol::WireGuard));

        assert_eq!(
            store.add_node_with(
                "toronto-wg2",
                "192.0.2.7:8443",
                "Toronto",
                "Canada",
                Some(Protocol::WireGuard),
                1_000
            ),
            Err(StoreError::NodeTaken),
            "one WireGuard agent per address"
        );
        assert_eq!(
            store.add_node_with(
                "toronto-wg",
                "192.0.2.99:8443",
                "Toronto",
                "Canada",
                Some(Protocol::AmneziaWg),
                1_000
            ),
            Err(StoreError::NodeTaken),
            "names are still unique"
        );
        assert_eq!(
            store.add_node("again", "192.0.2.7:8443", "Toronto", "Canada", 1_000),
            Err(StoreError::NodeTaken),
            "a node with no protocol (the old way) still needs an address of its own"
        );
        assert_eq!(store.nodes().unwrap().len(), 2);
    }

    #[test]
    fn a_nodes_protocol_is_set_by_name_and_never_to_one_its_address_already_has() {
        let mut store = store();
        toronto(&mut store);
        assert_eq!(store.node("toronto").unwrap().unwrap().protocol, None);
        store
            .add_node_with(
                "toronto-wg",
                "192.0.2.7:8443",
                "Toronto",
                "Canada",
                Some(Protocol::WireGuard),
                1_000,
            )
            .unwrap();

        assert_eq!(
            store.set_node_protocol("toronto", Protocol::WireGuard),
            Err(StoreError::NodeTaken),
            "toronto-wg already speaks WireGuard at that address"
        );
        assert_eq!(
            store.node("toronto").unwrap().unwrap().protocol,
            None,
            "unchanged"
        );
        store
            .set_node_protocol("toronto", Protocol::AmneziaWg)
            .unwrap();
        assert_eq!(
            store.node("toronto").unwrap().unwrap().protocol,
            Some(Protocol::AmneziaWg)
        );
        store
            .set_node_protocol("toronto", Protocol::AmneziaWg)
            .unwrap();
        assert_eq!(
            store.set_node_protocol("nowhere", Protocol::WireGuard),
            Err(StoreError::NoSuchNode)
        );
    }

    #[test]
    fn setting_a_protocol_makes_the_next_list_a_new_version_so_every_agent_is_sent_it() {
        // An agent that already holds version N compares only the version: without a new
        // one it would keep its old ranges until some device changed.
        let mut store = store();
        toronto(&mut store);
        let before = store.publish(1_000).unwrap().version;
        assert_eq!(
            store.publish(1_001).unwrap().version,
            before,
            "nothing changed"
        );

        store
            .set_node_protocol("toronto", Protocol::WireGuard)
            .unwrap();

        assert_eq!(store.publish(1_002).unwrap().version, before + 1);
        assert_eq!(store.publish(1_003).unwrap().version, before + 1, "once");
        // A refused change changes nothing, the version included.
        store
            .add_node_with(
                "toronto-awg",
                "192.0.2.7:8443",
                "Toronto",
                "Canada",
                Some(Protocol::AmneziaWg),
                1_000,
            )
            .unwrap();
        assert_eq!(
            store.set_node_protocol("toronto", Protocol::AmneziaWg),
            Err(StoreError::NodeTaken)
        );
        assert_eq!(store.publish(1_004).unwrap().version, before + 1);
    }

    #[test]
    fn the_database_itself_refuses_two_agents_of_one_protocol_at_one_address() {
        let store = store();
        store
            .conn
            .execute_batch(
                "INSERT INTO nodes (name, title, place, address, protocol, created_at)
                     VALUES ('a', 'A', 'B', '192.0.2.7:8443', 'wireguard', 1)",
            )
            .unwrap();
        for bad in [
            "INSERT INTO nodes (name, title, place, address, protocol, created_at)
                 VALUES ('b', 'A', 'B', '192.0.2.7:8443', 'wireguard', 1)",
            "INSERT INTO nodes (name, title, place, address, protocol, created_at)
                 VALUES ('c', 'A', 'B', '192.0.2.8:8443', 'openvpn', 1)",
        ] {
            assert!(store.conn.execute_batch(bad).is_err(), "{bad}");
        }
    }

    // ---- schema 6: where each server is (decision 014) ----

    use crate::closest::Location;

    const TORONTO_AT: Location = Location {
        lat: 43.65,
        lon: -79.38,
    };

    #[test]
    fn a_version_5_database_is_upgraded_to_6_and_every_node_starts_with_no_location() {
        let path = temp_db("upgrade6");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(crate::store::SCHEMA_1).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_2).unwrap();
        conn.execute_batch(SCHEMA_3).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_4).unwrap();
        conn.execute_batch(SCHEMA_5).unwrap();
        conn.execute_batch(
            "INSERT INTO nodes (id, name, title, place, address, protocol, enabled, created_at)
                 VALUES (2, 'toronto', 'Toronto', 'Canada', '192.0.2.7:8443', 'amneziawg', 1, 1000),
                        (4, 'toronto-wg', 'Toronto', 'Canada', '192.0.2.7:8443', 'wireguard', 1, 1001);
             INSERT INTO published_list (id, version, content) VALUES (1, 9, '[]');",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 5).unwrap();
        drop(conn);

        let mut store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), 7);
        let nodes = store.nodes().unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|n| (n.id, n.name.as_str(), n.protocol, n.location))
                .collect::<Vec<_>>(),
            [
                (2, "toronto", Some(Protocol::AmneziaWg), None),
                (4, "toronto-wg", Some(Protocol::WireGuard), None),
            ]
        );
        assert_eq!(
            store.publish(2_000).unwrap().version,
            9,
            "the agents' list is untouched"
        );
        drop(store);
        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 7, "upgraded once");
        assert_eq!(again.nodes().unwrap().len(), 2);
    }

    #[test]
    fn a_nodes_location_is_set_by_name_kept_and_listed() {
        let path = temp_db("location");
        let mut store = Store::open(&path).unwrap();
        toronto(&mut store);
        let before = store.publish(1_000).unwrap().version;

        store.set_node_location("toronto", TORONTO_AT).unwrap();

        assert_eq!(
            store.node("toronto").unwrap().unwrap().location,
            Some(TORONTO_AT)
        );
        assert_eq!(
            store.publish(1_001).unwrap().version,
            before,
            "the agents do not need to know where they are"
        );
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.nodes().unwrap()[0].location, Some(TORONTO_AT), "kept");
        let mut store = store;
        let moved = Location {
            lat: -33.87,
            lon: 151.21,
        };
        store.set_node_location("toronto", moved).unwrap();
        assert_eq!(
            store.node("toronto").unwrap().unwrap().location,
            Some(moved)
        );
        assert_eq!(
            store.set_node_location("nowhere", TORONTO_AT),
            Err(StoreError::NoSuchNode)
        );
    }

    #[test]
    fn the_database_itself_refuses_a_location_out_of_range_or_half_set() {
        let store = store();
        store
            .conn
            .execute_batch(
                "INSERT INTO nodes (name, title, place, address, created_at)
                     VALUES ('a', 'A', 'B', '192.0.2.7:8443', 1)",
            )
            .unwrap();
        for bad in [
            "UPDATE nodes SET lat = 90.5, lon = 0",
            "UPDATE nodes SET lat = -91, lon = 0",
            "UPDATE nodes SET lat = 0, lon = 180.5",
            "UPDATE nodes SET lat = 0, lon = -181",
            "UPDATE nodes SET lat = 10",
            "UPDATE nodes SET lon = 10",
            "UPDATE nodes SET lat = 'north', lon = 0",
        ] {
            assert!(store.conn.execute_batch(bad).is_err(), "{bad}");
        }
        store
            .conn
            .execute_batch("UPDATE nodes SET lat = 90, lon = -180")
            .unwrap();
    }

    // ---- adding ----

    #[test]
    fn a_node_is_added_listed_and_still_there_after_reopening() {
        let path = temp_db("add");
        let mut store = Store::open(&path).unwrap();

        let made = toronto(&mut store);

        assert_eq!(made.name, "toronto");
        assert_eq!(made.title, "Toronto");
        assert_eq!(made.place, "Canada");
        assert_eq!(made.address, "192.0.2.7:8443".parse().unwrap());
        assert!(made.enabled);
        assert_eq!(made.created_at, 1_000);
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.nodes().unwrap(), vec![made.clone()]);
        assert_eq!(store.node("toronto").unwrap(), Some(made));
        assert_eq!(store.node("dallas").unwrap(), None);
    }

    #[test]
    fn nodes_come_back_oldest_first_and_ids_are_never_reused() {
        let mut store = store();
        let first = toronto(&mut store);
        let second = store
            .add_node(
                "dallas",
                "198.51.100.9:8443",
                "Dallas",
                "United States",
                2_000,
            )
            .unwrap();
        assert!(second.id > first.id);
        assert_eq!(
            store
                .nodes()
                .unwrap()
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>(),
            ["toronto", "dallas"]
        );

        store.remove_node("dallas").unwrap();
        let third = store
            .add_node("paris", "203.0.113.4:8443", "Paris", "France", 3_000)
            .unwrap();
        assert!(third.id > second.id, "AUTOINCREMENT");
    }

    #[test]
    fn good_names_are_kept_and_bad_ones_refused() {
        for good in ["a", "toronto", "dallas-2", "n1", "a-b-c", &"a".repeat(32)] {
            assert_eq!(check_node_name(good), Ok(()), "{good:?}");
        }
        for bad in [
            "",
            "Toronto",
            "TORONTO",
            "toRonto",
            "1toronto",
            "-toronto",
            "toronto-",
            "to ronto",
            "to_ronto",
            "a.b",
            "a/b",
            "a:b",
            "tórónto",
            "to\nronto",
            "a\u{200b}b",
            &"a".repeat(33),
        ] {
            assert_eq!(
                check_node_name(bad),
                Err(StoreError::BadNodeName),
                "{bad:?}"
            );
        }
        let mut store = store();
        assert_eq!(
            store.add_node("Bad", "192.0.2.7:8443", "t", "p", 1),
            Err(StoreError::BadNodeName)
        );
        assert!(store.nodes().unwrap().is_empty());
    }

    #[test]
    fn an_address_must_be_an_ip_and_a_non_zero_port() {
        let mut store = store();
        for bad in [
            "",
            "192.0.2.7",
            "192.0.2.7:",
            "192.0.2.7:0",
            "192.0.2.7:65536",
            "192.0.2.7:-1",
            "toronto.example.com:8443",
            "localhost:8443",
            "192.0.2.7:8443 ",
            " 192.0.2.7:8443",
            "https://192.0.2.7:8443",
            "192.0.2.7:8443/x",
            "192.0.2.256:8443",
            "::1:8443",
        ] {
            assert_eq!(
                store.add_node("n", bad, "t", "p", 1),
                Err(StoreError::BadNodeAddress),
                "{bad:?}"
            );
        }
        assert!(store.nodes().unwrap().is_empty());
    }

    #[test]
    fn ipv6_and_loopback_addresses_are_fine_and_kept_in_one_spelling() {
        let mut store = store();
        let v6 = store
            .add_node("six", "[2001:db8::1]:8443", "Six", "Somewhere", 1)
            .unwrap();
        assert_eq!(v6.address, "[2001:db8::1]:8443".parse().unwrap());
        let local = store
            .add_node("local", "127.0.0.1:9", "Local", "Here", 2)
            .unwrap();
        assert!(local.address.ip().is_loopback());
        let stored: String = store
            .conn
            .query_row("SELECT address FROM nodes WHERE name = 'six'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stored, "[2001:db8::1]:8443");

        assert_eq!(
            store.add_node("again", "[2001:0db8:0:0:0:0:0:1]:8443", "A", "B", 3),
            Err(StoreError::NodeTaken),
            "the same address spelled another way is the same address"
        );
    }

    #[test]
    fn a_title_or_place_must_be_short_plain_text() {
        let mut store = store();
        let long = "x".repeat(41);
        let fine = "x".repeat(40);
        for bad in [
            "",
            "   ",
            &long,
            "a\nb",
            "a\u{0}b",
            "a\u{202e}b",
            "a\u{200b}b",
        ] {
            assert_eq!(
                store.add_node("n1", "192.0.2.1:1", bad, "p", 1),
                Err(StoreError::BadNodeText),
                "title {bad:?}"
            );
            assert_eq!(
                store.add_node("n1", "192.0.2.1:1", "t", bad, 1),
                Err(StoreError::BadNodeText),
                "place {bad:?}"
            );
        }
        assert!(store.add_node("n1", "192.0.2.1:1", &fine, &fine, 1).is_ok());
        let odd = store
            .add_node("n2", "192.0.2.2:1", "<script>x</script>", "Zürich", 1)
            .unwrap();
        assert_eq!(
            odd.title, "<script>x</script>",
            "stored as typed; pages escape it"
        );
    }

    #[test]
    fn a_name_or_an_address_cannot_be_registered_twice() {
        let mut store = store();
        toronto(&mut store);

        assert_eq!(
            store.add_node("toronto", "198.51.100.1:8443", "T2", "C2", 2),
            Err(StoreError::NodeTaken)
        );
        assert_eq!(
            store.add_node("other", "192.0.2.7:8443", "T3", "C3", 3),
            Err(StoreError::NodeTaken)
        );
        assert_eq!(store.nodes().unwrap().len(), 1);
        assert!(
            store
                .add_node("other", "192.0.2.7:8444", "T3", "C3", 3)
                .is_ok(),
            "another port is another address"
        );
    }

    // ---- enabling, disabling, removing ----

    #[test]
    fn a_node_can_be_disabled_and_enabled_and_only_enabled_ones_are_visited() {
        let mut store = store();
        toronto(&mut store);
        store
            .add_node("dallas", "198.51.100.9:8443", "Dallas", "US", 2)
            .unwrap();
        assert_eq!(store.enabled_nodes().unwrap().len(), 2);

        store.set_node_enabled("toronto", false).unwrap();

        let enabled = store.enabled_nodes().unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "dallas");
        assert_eq!(
            store.nodes().unwrap().len(),
            2,
            "disabled ones are still listed"
        );
        assert!(!store.node("toronto").unwrap().unwrap().enabled);

        store.set_node_enabled("toronto", true).unwrap();
        assert_eq!(store.enabled_nodes().unwrap().len(), 2);
        assert_eq!(
            store.set_node_enabled("nowhere", true),
            Err(StoreError::NoSuchNode)
        );
    }

    #[test]
    fn a_node_is_removed_and_its_name_and_address_can_be_used_again() {
        let mut store = store();
        toronto(&mut store);

        store.remove_node("toronto").unwrap();

        assert!(store.nodes().unwrap().is_empty());
        assert_eq!(store.remove_node("toronto"), Err(StoreError::NoSuchNode));
        assert!(
            store
                .add_node("toronto", "192.0.2.7:8443", "Toronto", "Canada", 5)
                .is_ok()
        );
    }

    #[test]
    fn removing_a_node_touches_no_device_and_no_list() {
        let mut store = store();
        toronto(&mut store);
        let account = store.add_account("lao", 1).unwrap();
        store
            .add_device(
                account.id,
                "phone",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                1,
            )
            .unwrap();
        let before = store.publish(10).unwrap();

        store.remove_node("toronto").unwrap();

        assert_eq!(store.devices().unwrap().len(), 1);
        assert_eq!(store.publish(11).unwrap(), before);
    }

    // ---- the version floor ----

    #[test]
    fn raising_the_floor_makes_the_next_version_higher_even_if_the_list_is_the_same() {
        let mut store = store();
        let first = store.publish(1).unwrap();
        assert_eq!(first.version, 1);

        assert_eq!(store.raise_version_floor(9), Ok(true));

        let next = store.publish(2).unwrap();
        assert_eq!(next.version, 10);
        assert_eq!(next.peers, first.peers);
        assert_eq!(store.publish(3).unwrap().version, 10, "and it stays there");
    }

    #[test]
    fn raising_the_floor_before_anything_was_published_also_works() {
        let mut store = store();

        assert_eq!(store.raise_version_floor(41), Ok(true));

        assert_eq!(store.publish(1).unwrap().version, 42);
    }

    #[test]
    fn a_floor_at_or_below_the_current_version_changes_nothing() {
        let mut store = store();
        let account = store.add_account("lao", 1).unwrap();
        store
            .conn
            .execute("UPDATE accounts SET device_limit = 100", [])
            .unwrap();
        for n in 0..4u64 {
            let key = crate::keys::KeyPair::generate().unwrap().public_key;
            store.add_device(account.id, "d", &key, 1).unwrap();
            store.publish(n + 2).unwrap();
        }
        let current = store.publish(100).unwrap().version;
        assert_eq!(current, 4);

        assert_eq!(store.raise_version_floor(current), Ok(false));
        assert_eq!(store.raise_version_floor(1), Ok(false));
        assert_eq!(store.publish(101).unwrap().version, current);
    }

    #[test]
    fn the_list_version_is_none_before_the_first_publish_and_follows_it_after() {
        let mut store = store();
        assert_eq!(store.list_version(), Ok(None));

        store.publish(1).unwrap();
        assert_eq!(store.list_version(), Ok(Some(1)));

        store.raise_version_floor(9).unwrap();
        assert_eq!(store.list_version(), Ok(Some(9)));
        store.publish(2).unwrap();
        assert_eq!(store.list_version(), Ok(Some(10)));
    }

    #[test]
    fn a_floor_of_zero_or_a_silly_size_is_refused() {
        let mut store = store();
        assert_eq!(
            store.raise_version_floor(0),
            Err(StoreError::BadVersionFloor)
        );
        assert_eq!(
            store.raise_version_floor(MAX_VERSION_FLOOR + 1),
            Err(StoreError::BadVersionFloor)
        );
        assert_eq!(
            store.raise_version_floor(u64::MAX),
            Err(StoreError::BadVersionFloor)
        );
        assert_eq!(store.raise_version_floor(MAX_VERSION_FLOOR), Ok(true));
        assert_eq!(store.publish(1).unwrap().version, MAX_VERSION_FLOOR + 1);
    }

    #[test]
    fn programs_publishing_at_the_same_time_never_store_an_older_list_over_a_newer_one() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let path = temp_db("race");
        let mut writer = Store::open(&path).unwrap();
        let account = writer.add_account("lao", 1).unwrap();
        writer
            .conn
            .execute("UPDATE accounts SET device_limit = 1000", [])
            .unwrap();
        let seen: Arc<Mutex<Vec<(u64, usize)>>> = Arc::default();

        let readers: Vec<_> = (0..3)
            .map(|_| {
                let path = path.clone();
                let seen = seen.clone();
                thread::spawn(move || {
                    let mut store = Store::open(&path).unwrap();
                    let mut last = 0;
                    for step in 0..40 {
                        let list = store.publish(10 + step).unwrap();
                        assert!(list.version >= last, "a version went backwards");
                        last = list.version;
                        seen.lock().unwrap().push((list.version, list.peers.len()));
                    }
                })
            })
            .collect();
        for n in 0..25 {
            let key = crate::keys::KeyPair::generate().unwrap().public_key;
            writer
                .add_device(account.id, &format!("d{n}"), &key, 5 + n)
                .unwrap();
        }
        for reader in readers {
            reader.join().unwrap();
        }

        let seen = seen.lock().unwrap();
        for (version, peers) in seen.iter() {
            let same: Vec<_> = seen.iter().filter(|(v, _)| v == version).collect();
            assert!(
                same.iter().all(|(_, p)| p == peers),
                "version {version} was handed out for two different lists"
            );
        }
        let final_list = writer.publish(1_000).unwrap();
        assert_eq!(final_list.peers.len(), 25);
        assert!(seen.iter().all(|(v, _)| *v <= final_list.version));
    }

    // ---- schema 7: the maintenance note ----

    #[test]
    fn a_version_6_database_is_upgraded_to_7_with_no_notes_and_an_empty_history_table() {
        let path = temp_db("upgrade7");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(crate::store::SCHEMA_1).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_2).unwrap();
        conn.execute_batch(SCHEMA_3).unwrap();
        conn.execute_batch(crate::signin::SCHEMA_4).unwrap();
        conn.execute_batch(SCHEMA_5).unwrap();
        conn.execute_batch(SCHEMA_6).unwrap();
        conn.execute_batch(
            "INSERT INTO nodes (id, name, title, place, address, protocol, enabled, created_at)
                 VALUES (2, 'toronto', 'Toronto', 'Canada', '192.0.2.7:8443', 'amneziawg', 0, 1000);
             INSERT INTO published_list (id, version, content) VALUES (1, 9, '[]');",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 6).unwrap();
        drop(conn);

        let mut store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), 7);
        let nodes = store.nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            (nodes[0].id, nodes[0].enabled, &nodes[0].note),
            (2, false, &None)
        );
        assert_eq!(
            store.publish(2_000).unwrap().version,
            9,
            "the list is untouched"
        );
        let tables: Vec<String> = {
            let mut q = store
                .conn
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'uptime_hours'",
                )
                .unwrap();
            q.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(tables, ["uptime_hours"], "the history table exists");
        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM uptime_hours", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        drop(store);
        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 7, "upgraded once");
        assert_eq!(again.nodes().unwrap().len(), 1);
    }

    #[test]
    fn a_note_goes_with_a_disabled_node_and_enabling_or_disabling_without_one_clears_it() {
        let mut store = Store::open_in_memory().unwrap();
        toronto(&mut store);

        store
            .disable_node("toronto", Some("back at 20:00"))
            .unwrap();
        let node = store.node("toronto").unwrap().unwrap();
        assert!(!node.enabled);
        assert_eq!(node.note.as_deref(), Some("back at 20:00"));

        store.set_node_enabled("toronto", true).unwrap();
        let node = store.node("toronto").unwrap().unwrap();
        assert!(node.enabled);
        assert_eq!(node.note, None, "enabling clears the note");

        store
            .disable_node("toronto", Some("kernel update"))
            .unwrap();
        store.disable_node("toronto", None).unwrap();
        assert_eq!(
            store.node("toronto").unwrap().unwrap().note,
            None,
            "disabling again without a note clears the old one"
        );
        store.disable_node("toronto", Some("new words")).unwrap();
        store.disable_node("toronto", Some("newer words")).unwrap();
        assert_eq!(
            store.node("toronto").unwrap().unwrap().note.as_deref(),
            Some("newer words")
        );
    }

    #[test]
    fn a_note_is_1_to_100_characters_without_control_or_reordering_characters() {
        let mut store = Store::open_in_memory().unwrap();
        toronto(&mut store);
        let hundred = "n".repeat(100);
        let too_long = "n".repeat(101);
        for bad in [
            "",
            "   ",
            "\t",
            too_long.as_str(),
            "a\nb",
            "a\u{0}b",
            "a\u{202e}b",
            "a\u{200b}b",
        ] {
            assert_eq!(
                store.disable_node("toronto", Some(bad)),
                Err(StoreError::BadNodeNote),
                "{bad:?}"
            );
        }
        assert!(
            store.node("toronto").unwrap().unwrap().enabled,
            "a refused note changes nothing"
        );
        store.disable_node("toronto", Some(&hundred)).unwrap();
        assert_eq!(
            store.node("toronto").unwrap().unwrap().note.as_deref(),
            Some(hundred.as_str())
        );
        store
            .disable_node(
                "toronto",
                Some("Back at 20:00 \u{2014} d\u{e9}j\u{e0} vu & <b>"),
            )
            .unwrap();
    }

    #[test]
    fn a_note_for_a_node_nobody_registered_is_refused() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(
            store.disable_node("nowhere", Some("hello")),
            Err(StoreError::NoSuchNode)
        );
        assert_eq!(
            store.disable_node("nowhere", None),
            Err(StoreError::NoSuchNode)
        );
    }
}
