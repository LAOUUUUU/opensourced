//! The server's recent SSH logins, for the website's "new login" email
//! (`specs/login-alerts.md`). The agent cannot read the journal or `/root/.ssh` (it is a
//! dynamic user with no home), so a root timer, `bf-logins.timer`, writes them once a
//! minute into a folder the agents' group `bf-logins` may read, and the agent only reads
//! two small files. Nothing is stored here.

use std::path::PathBuf;

use bf_common::logins::{KEYS_FILE, LOGINS_FILE, Login, from_files};

/// Where the logins come from: the real files, or a fake in tests.
pub trait LoginLog: Send + Sync {
    /// The logins of the last 15 minutes before `now`, or why they cannot be read.
    fn recent(&self, now: u64) -> Result<Vec<Login>, String>;
}

/// The timer's folder (`bf_common::logins::DIR` unless `BF_LOGINS_DIR` says otherwise).
pub struct LoginFiles {
    pub dir: PathBuf,
}

impl LoginLog for LoginFiles {
    fn recent(&self, now: u64) -> Result<Vec<Login>, String> {
        let path = self.dir.join(LOGINS_FILE);
        let read = |e: std::io::Error| format!("cannot read {}: {}", path.display(), e.kind());
        let written = std::fs::metadata(&path)
            .map_err(read)?
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let logins = std::fs::read_to_string(&path).map_err(read)?;
        // No names is still a report: the email then says the key is not in authorized_keys.
        let keys = std::fs::read_to_string(self.dir.join(KEYS_FILE)).unwrap_or_default();
        from_files(&logins, &keys, written, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn the_files_are_read_and_named_and_missing_or_stale_ones_are_errors() {
        let dir = crate::testutil::TempDir::new("logins");
        let files = LoginFiles {
            dir: dir.path().to_path_buf(),
        };
        // Judged by the file's modification time, so the real clock is used.
        let t = now();
        let missing = files.recent(t).unwrap_err();
        assert!(missing.contains("cannot read"), "{missing}");
        std::fs::write(
            dir.path().join(LOGINS_FILE),
            format!(
                "{}.1 node sshd-session[1]: Accepted publickey for root from 203.0.113.7 port 1 ssh2: ED25519 {FP}\n",
                t - 60
            ),
        )
        .unwrap();
        let unnamed = files.recent(t).unwrap();
        assert_eq!(unnamed.len(), 1);
        assert_eq!(unnamed[0].key_name, None, "no keys file, no names");
        std::fs::write(
            dir.path().join(KEYS_FILE),
            format!("256 {FP} lao-test-key (ED25519)\n"),
        )
        .unwrap();
        assert_eq!(
            files.recent(t).unwrap()[0].key_name.as_deref(),
            Some("lao-test-key")
        );
        let stale = files.recent(t + 600).unwrap_err();
        assert!(stale.contains("older than"), "{stale}");
    }
}
