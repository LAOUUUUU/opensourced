//! `bf-control backup <file>`: a consistent copy of the database, taken while the website
//! runs. Spec: `specs/backup.md`.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

/// What a finished copy holds.
#[derive(Debug, PartialEq)]
pub struct Copy {
    pub schema_version: u32,
    pub bytes: u64,
}

/// How long the copy waits for a writer to finish before it gives up.
const BUSY_WAIT: Duration = Duration::from_secs(10);

/// Copies the database at `db` into the new file `out` with `VACUUM INTO`: one consistent
/// snapshot, with nothing deleted left in it and without the short-lived sign-in records. The database is opened read-only, so it is
/// never made, upgraded or changed. `out` must be new, in a folder only its owner can
/// open; it is made 0600 before anything is written, checked with `integrity_check`
/// afterwards, and removed again on any failure.
pub fn backup(db: &Path, out: &Path) -> Result<Copy, String> {
    if !db.is_file() {
        return Err(format!("there is no database at {}", db.display()));
    }
    let folder = match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    check_folder(folder)?;
    make_private(out)?;
    copy_into(db, out).inspect_err(|_| {
        let _ = std::fs::remove_file(out);
    })
}

fn check_folder(folder: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(folder)
        .map_err(|e| format!("cannot use the folder {}: {e}", folder.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a folder", folder.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "the folder {} is open to others (mode {mode:o}); a backup goes only into a folder its owner alone can open",
                folder.display()
            ));
        }
    }
    Ok(())
}

/// An empty file only its owner can read. `VACUUM INTO` writes into an empty file and
/// keeps its mode.
fn make_private(out: &Path) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(out) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
            "{} already exists, and a backup never writes over a file",
            out.display()
        )),
        Err(e) => Err(format!("cannot make {}: {e}", out.display())),
    }
}

fn copy_into(db: &Path, out: &Path) -> Result<Copy, String> {
    let failed = |e: rusqlite::Error| format!("the copy failed: {e}");
    let target = out
        .to_str()
        .ok_or_else(|| format!("{} is not a name SQLite can take", out.display()))?;
    let source =
        Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(failed)?;
    source.busy_timeout(BUSY_WAIT).map_err(failed)?;
    source.execute("VACUUM INTO ?1", [target]).map_err(failed)?;
    drop(source);
    without_sign_in_records(out)?;

    let schema_version = checked(out)?;
    let bytes = std::fs::metadata(out)
        .map_err(|e| format!("cannot read {}: {e}", out.display()))?
        .len();
    Ok(Copy {
        schema_version,
        bytes,
    })
}

/// The tables of short-lived sign-in records: codes and the mail log, with their email and
/// network-address fingerprints. The database deletes their rows after a day; the copy is
/// kept for 30 nights next to the key that made the fingerprints, so it leaves them out.
pub(crate) const SIGN_IN_RECORDS: [&str; 2] = ["mail_log", "login_codes"];

/// Empties the sign-in tables in the copy (an older database may not have them), then
/// rebuilds the copy so no deleted row lingers in its free pages. Temporary data stays in
/// memory, never in a file somewhere else.
fn without_sign_in_records(copy: &Path) -> Result<(), String> {
    let failed = |e: rusqlite::Error| format!("could not leave the sign-in records out: {e}");
    let conn =
        Connection::open_with_flags(copy, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(failed)?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(failed)?;
    for table in SIGN_IN_RECORDS {
        let exists: bool = conn
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(failed)?;
        if exists {
            conn.execute(&format!("DELETE FROM {table}"), [])
                .map_err(failed)?;
        }
    }
    conn.execute_batch("VACUUM").map_err(failed)
}

/// Opens a copy read-only and runs SQLite's own check on it. Gives its schema version.
fn checked(copy: &Path) -> Result<u32, String> {
    let failed = |e: rusqlite::Error| format!("the copy did not pass its check: {e}");
    let copy =
        Connection::open_with_flags(copy, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(failed)?;
    let check: String = copy
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(failed)?;
    if check != "ok" {
        return Err(format!("the copy did not pass its check: {check}"));
    }
    copy.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(failed)
}

/// Where the nightly script writes its status, unless `BC_BACKUP_STATUS` says otherwise.
/// `deploy/bf-backup.sh` has the same default (`tests/backup_units.rs` holds them together).
pub const STATUS_FILE: &str = "/var/lib/barely-free/backup-status";

/// The outcome of the last nightly run, as `deploy/bf-backup.sh` writes it.
#[derive(Debug, PartialEq)]
pub struct Status {
    pub finished: u64,
    pub file: String,
    pub sent: Vec<String>,
    pub failed: Vec<String>,
    pub error: String,
}

/// After this long without a backup, the admin overview warns.
pub const STALE_AFTER: u64 = 36 * 3600;

/// One line for the admin overview, and whether it is a warning.
#[derive(Debug, PartialEq)]
pub struct Line {
    pub text: String,
    pub warn: bool,
}

/// Reads a status file's text: the five `name=value` lines the script writes, each once.
pub fn parse_status(text: &str) -> Result<Status, String> {
    let mut fields: [Option<&str>; 5] = [None; 5];
    const NAMES: [&str; 5] = ["finished", "file", "sent", "failed", "error"];
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("a line without '=': {line:?}"))?;
        let slot = NAMES
            .iter()
            .position(|known| *known == name)
            .ok_or_else(|| format!("an unknown field {name:?}"))?;
        if fields[slot].replace(value).is_some() {
            return Err(format!("{name} is there twice"));
        }
    }
    let [
        Some(finished),
        Some(file),
        Some(sent),
        Some(failed),
        Some(error),
    ] = fields
    else {
        return Err("a field is missing".to_string());
    };
    let words = |value: &str| value.split_whitespace().map(str::to_string).collect();
    Ok(Status {
        finished: finished
            .parse()
            .map_err(|_| format!("finished is not a time: {finished:?}"))?,
        file: file.to_string(),
        sent: words(sent),
        failed: words(failed),
        error: error.to_string(),
    })
}

/// What the overview says about backups, given the status file as it was read.
pub fn status_line(read: std::io::Result<String>, now: u64) -> Line {
    let warn = |text: String| Line { text, warn: true };
    let text = match read {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return warn("No backup has run yet.".to_string());
        }
        Err(e) => return warn(format!("The backup status cannot be read: {e}.")),
    };
    let status = match parse_status(&text) {
        Ok(status) => status,
        Err(why) => return warn(format!("The backup status is not as expected: {why}.")),
    };
    let when = format!("{} UTC", crate::app::utc_minute(status.finished));
    let total = status.sent.len() + status.failed.len();
    if !status.error.is_empty() {
        let mut text = format!(
            "The last backup, {when}, failed: {}.",
            status.error.trim_end_matches('.')
        );
        if !status.sent.is_empty() {
            text.push_str(&format!(
                " It reached {} of {total} servers.",
                status.sent.len()
            ));
        }
        return warn(text);
    }
    let age = now.saturating_sub(status.finished);
    if age > STALE_AFTER {
        return warn(format!(
            "The last backup was {when}, {} hours ago; one should run every night.",
            age / 3600
        ));
    }
    Line {
        text: format!(
            "Last backup {when}, sent to {} of {total} servers.",
            status.sent.len()
        ),
        warn: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::store::{KickEnd, Store};
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-backup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn key(n: u8) -> String {
        KeyPair::from_private([n; 32]).public_key
    }

    /// A database with two accounts, three devices (one removed), a kick and a published list.
    fn filled(dir: &Path) -> PathBuf {
        let db = dir.join("control.db");
        let mut store = Store::open(&db).unwrap();
        let lao = store.add_account("lao", 1_000).unwrap();
        let sam = store.add_account("sam", 1_001).unwrap();
        let phone = store.add_device(lao.id, "phone", &key(1), 1_002).unwrap();
        store.add_device(sam.id, "laptop", &key(2), 1_003).unwrap();
        let old = store.add_device(sam.id, "old", &key(3), 1_004).unwrap();
        store.remove_device(old.id, 1_005).unwrap();
        store
            .kick(phone.id, KickEnd::UntilLifted, "admin", "testing", 1_006)
            .unwrap();
        store.publish(1_007).unwrap();
        db
    }

    fn snapshot(db: &Path) -> String {
        let store = Store::open(db).unwrap();
        format!(
            "{:?}\n{:?}\n{:?}",
            store.accounts().unwrap(),
            store.devices().unwrap(),
            store.peek_list(1_008).unwrap()
        )
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_copy_holds_the_same_accounts_devices_kicks_and_list() {
        let dir = temp_dir("same");
        let db = filled(&dir);
        let out = dir.join("copy.db");
        let copy = backup(&db, &out).unwrap();
        assert_eq!(copy.schema_version, 6);
        assert_eq!(copy.bytes, std::fs::metadata(&out).unwrap().len());
        assert!(copy.bytes > 0);
        assert_eq!(snapshot(&out), snapshot(&db));
        let list = Store::open(&out).unwrap().peek_list(1_008).unwrap();
        assert_eq!(
            list.peers.len(),
            1,
            "the kicked and the removed device are off it"
        );
    }

    #[test]
    fn deleted_text_is_not_in_the_copy() {
        let dir = temp_dir("forensic");
        let db = filled(&dir);
        let marker = "forgotten-label-7c1d";
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute(
                "INSERT INTO accounts (label, created_at) VALUES (?1, 2000)",
                [marker],
            )
            .unwrap();
            conn.execute("DELETE FROM accounts WHERE label = ?1", [marker])
                .unwrap();
        }
        let has = |path: &Path| {
            let bytes = std::fs::read(path).unwrap();
            bytes.windows(marker.len()).any(|w| w == marker.as_bytes())
        };
        assert!(
            has(&db),
            "the test needs the deleted text to linger in the original"
        );
        let out = dir.join("copy.db");
        backup(&db, &out).unwrap();
        assert!(!has(&out));
    }

    #[test]
    fn the_copy_leaves_out_the_sign_in_records_and_no_trace_of_them() {
        // The privacy policy says sign-in records (codes and the mail log, with their email
        // and network-address fingerprints) are gone after a day. The copy is kept 30 nights
        // next to the key that made the fingerprints, so it must not hold them at all.
        let dir = temp_dir("signin-records");
        let db = filled(&dir);
        let email_fp = [0xe1u8; 32];
        let ip_fp = [0x1bu8; 32];
        let code_mac = [0xc0u8; 32];
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute(
                "INSERT INTO mail_log (sent_at, email_fp, ip_fp, kind) VALUES (2000, ?1, ?2, 'request')",
                rusqlite::params![&email_fp[..], &ip_fp[..]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO login_codes (email_fp, code_mac, created_at, expires_at) VALUES (?1, ?2, 2000, 2600)",
                rusqlite::params![&email_fp[..], &code_mac[..]],
            )
            .unwrap();
        }
        let count = |path: &Path, table: &str| -> i64 {
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };
        let out = dir.join("copy.db");
        backup(&db, &out).unwrap();

        assert_eq!(count(&out, "mail_log"), 0);
        assert_eq!(count(&out, "login_codes"), 0);
        let bytes = std::fs::read(&out).unwrap();
        for marker in [email_fp, ip_fp, code_mac] {
            assert!(
                !bytes.windows(32).any(|w| w == marker),
                "a fingerprint lingers in the copy's free pages"
            );
        }
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("copy.db") && name != "copy.db")
            .collect();
        assert!(
            left.is_empty(),
            "no journal or other file is left: {left:?}"
        );
        assert_eq!(snapshot(&out), snapshot(&db), "everything else is copied");
        assert_eq!(count(&db, "mail_log"), 1, "the database itself keeps them");
        assert_eq!(count(&db, "login_codes"), 1);
    }

    #[test]
    fn every_table_with_a_fingerprint_but_the_accounts_is_a_sign_in_record() {
        // So a later table that keeps an email or network-address fingerprint cannot slip
        // into the 30-night copies unnoticed.
        let dir = temp_dir("fingerprint-tables");
        let db = filled(&dir);
        let conn = rusqlite::Connection::open(&db).unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut with_fingerprints: Vec<String> = tables
            .into_iter()
            .filter(|table| {
                conn.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                    .unwrap()
                    .query_map([], |row| row.get::<_, String>(0))
                    .unwrap()
                    .map(Result::unwrap)
                    .any(|column| column == "email_fp" || column == "ip_fp")
            })
            .filter(|table| table != "accounts")
            .collect();
        with_fingerprints.sort();
        let mut records = SIGN_IN_RECORDS.to_vec();
        records.sort_unstable();
        assert_eq!(with_fingerprints, records);
    }

    #[test]
    fn a_missing_database_is_refused_and_not_made() {
        let dir = temp_dir("missing");
        let db = dir.join("control.db");
        let out = dir.join("copy.db");
        let why = backup(&db, &out).unwrap_err();
        assert!(why.contains("no database"), "{why}");
        assert!(!db.exists());
        assert!(!out.exists());
    }

    #[test]
    fn an_older_database_is_copied_as_it_is_and_not_upgraded() {
        let dir = temp_dir("older");
        let db = dir.join("control.db");
        {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch("CREATE TABLE notes (text TEXT); PRAGMA user_version = 1;")
                .unwrap();
        }
        let out = dir.join("copy.db");
        assert_eq!(backup(&db, &out).unwrap().schema_version, 1);
        let version = |path: &Path| -> u32 {
            rusqlite::Connection::open(path)
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&db), 1);
        assert_eq!(version(&out), 1);
    }

    #[test]
    fn an_existing_file_is_refused_and_left_alone() {
        let dir = temp_dir("existing");
        let db = filled(&dir);
        let out = dir.join("copy.db");
        std::fs::write(&out, "keep me").unwrap();
        let why = backup(&db, &out).unwrap_err();
        assert!(why.contains("already exists"), "{why}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep me");
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_others_can_open_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("open");
        let db = filled(&dir);
        let shared = dir.join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = shared.join("copy.db");
        let why = backup(&db, &out).unwrap_err();
        assert!(why.contains("others"), "{why}");
        assert!(!out.exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_is_readable_by_its_owner_only() {
        let dir = temp_dir("private");
        let db = filled(&dir);
        let out = dir.join("copy.db");
        backup(&db, &out).unwrap();
        assert_eq!(mode(&out), 0o600);
    }

    #[test]
    fn a_file_that_is_not_a_database_is_refused_and_leaves_no_copy() {
        let dir = temp_dir("garbage");
        let db = dir.join("control.db");
        std::fs::write(&db, vec![b'x'; 4096]).unwrap();
        let out = dir.join("copy.db");
        assert!(backup(&db, &out).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn a_backup_waits_for_a_writer_to_finish() {
        let dir = temp_dir("busy");
        let db = filled(&dir);
        let writer = rusqlite::Connection::open(&db).unwrap();
        writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
        writer
            .execute(
                "INSERT INTO accounts (label, created_at) VALUES ('late', 3000)",
                [],
            )
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            writer.execute_batch("COMMIT").unwrap();
        });
        let out = dir.join("copy.db");
        backup(&db, &out).unwrap();
        release.join().unwrap();
        let labels: Vec<String> = Store::open(&out)
            .unwrap()
            .accounts()
            .unwrap()
            .into_iter()
            .map(|a| a.label)
            .collect();
        assert!(labels.contains(&"late".to_string()), "{labels:?}");
    }

    #[test]
    fn a_damaged_copy_fails_its_check() {
        let dir = temp_dir("damaged");
        let db = filled(&dir);
        let good = dir.join("good.db");
        backup(&db, &good).unwrap();
        assert_eq!(checked(&good), Ok(6));
        // Scribble over the second page, where the tables' rows are.
        let mut bytes = std::fs::read(&good).unwrap();
        let page = 4096;
        assert!(bytes.len() > 2 * page, "the copy is {} bytes", bytes.len());
        for b in &mut bytes[page + 8..2 * page] {
            *b = 0xA5;
        }
        let damaged = dir.join("damaged.db");
        std::fs::write(&damaged, bytes).unwrap();
        let why = checked(&damaged).unwrap_err();
        assert!(why.contains("did not pass its check"), "{why}");
    }

    #[test]
    fn the_database_itself_is_not_changed() {
        let dir = temp_dir("untouched");
        let db = filled(&dir);
        let before = std::fs::read(&db).unwrap();
        backup(&db, &dir.join("copy.db")).unwrap();
        assert_eq!(std::fs::read(&db).unwrap(), before);
    }

    // ---- the status the admin overview shows ----

    const NOV_12_0341: u64 = 1_794_454_860; // 2026-11-12 03:41 UTC

    fn status_text(sent: &str, failed: &str, error: &str) -> String {
        format!(
            "finished={NOV_12_0341}\nfile=control-20261112T034100Z.tar.age\nsent={sent}\nfailed={failed}\nerror={error}\n"
        )
    }

    #[test]
    fn a_status_file_is_read_field_by_field() {
        let status = parse_status(&status_text("192.0.2.176 198.51.100.185", "", "")).unwrap();
        assert_eq!(
            status,
            Status {
                finished: NOV_12_0341,
                file: "control-20261112T034100Z.tar.age".to_string(),
                sent: vec!["192.0.2.176".to_string(), "198.51.100.185".to_string()],
                failed: vec![],
                error: String::new(),
            }
        );
    }

    #[test]
    fn a_status_file_that_is_not_as_written_is_refused() {
        let good = status_text("a", "", "");
        for bad in [
            String::new(),
            good.replace("finished=1794454860\n", ""),
            good.replace("finished=1794454860", "finished=soon"),
            good.clone() + "finished=1\n",
            good.clone() + "colour=blue\n",
            good.replace("sent=a", "sent a"),
        ] {
            assert!(parse_status(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_good_night_is_one_quiet_line() {
        let line = status_line(
            Ok(status_text("192.0.2.176 198.51.100.185", "", "")),
            NOV_12_0341 + 3_600,
        );
        assert_eq!(
            line,
            Line {
                text: "Last backup 2026-11-12 03:41 UTC, sent to 2 of 2 servers.".to_string(),
                warn: false,
            }
        );
    }

    #[test]
    fn no_status_file_means_no_backup_has_run() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let line = status_line(Err(missing), NOV_12_0341);
        assert_eq!(line.text, "No backup has run yet.");
        assert!(line.warn);
    }

    #[test]
    fn a_status_that_cannot_be_read_or_understood_is_a_warning() {
        let line = status_line(Err(std::io::Error::other("permission denied")), NOV_12_0341);
        assert!(line.warn);
        assert!(line.text.contains("permission denied"), "{}", line.text);
        let line = status_line(Ok("rubbish".to_string()), NOV_12_0341);
        assert!(line.warn);
        assert!(line.text.contains("not as expected"), "{}", line.text);
    }

    #[test]
    fn a_failed_night_says_why_and_how_far_it_got() {
        let line = status_line(
            Ok(status_text(
                "198.51.100.185",
                "192.0.2.176",
                "could not send it to 192.0.2.176 (Connection timed out)",
            )),
            NOV_12_0341 + 60,
        );
        assert!(line.warn);
        assert_eq!(
            line.text,
            "The last backup, 2026-11-12 03:41 UTC, failed: could not send it to 192.0.2.176 (Connection timed out). It reached 1 of 2 servers."
        );
    }

    #[test]
    fn a_backup_older_than_36_hours_is_a_warning() {
        let text = status_text("192.0.2.176 198.51.100.185", "", "");
        assert!(!status_line(Ok(text.clone()), NOV_12_0341 + STALE_AFTER).warn);
        let line = status_line(Ok(text), NOV_12_0341 + STALE_AFTER + 1);
        assert!(line.warn);
        assert_eq!(
            line.text,
            "The last backup was 2026-11-12 03:41 UTC, 36 hours ago; one should run every night."
        );
    }
}
