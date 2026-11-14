//! The peer list the agent was last given, kept on disk as `peers.json` in the state
//! directory so it survives a restart.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use bf_common::peers::PeerList;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Io(io::ErrorKind),
    /// The file is there but is not a peer list.
    Corrupt,
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Store {
        Store { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.join("peers.json")
    }

    /// The stored list, or `None` if there never was one.
    pub fn load(&self) -> Result<Option<PeerList>, StoreError> {
        let bytes = match fs::read(self.path()) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e.kind())),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| StoreError::Corrupt)
    }

    /// Replaces the stored list. Readers see the old list or the new one, never half of it.
    pub fn save(&self, list: &PeerList) -> Result<(), StoreError> {
        let json =
            serde_json::to_vec(list).map_err(|_| StoreError::Io(io::ErrorKind::InvalidData))?;
        self.write_atomically("peers.json", &json, true)
    }

    /// The highest request time the agent had accepted when it last wrote the mark, or
    /// `None` if it never did. A file that is there but is not a plain whole number is
    /// reported, never read as zero: zero would switch the protection off.
    pub fn load_replay_mark(&self) -> Result<Option<u64>, StoreError> {
        let bytes = match fs::read(self.dir.join("replay-mark")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e.kind())),
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| StoreError::Corrupt)?;
        let digits = text.strip_suffix('\n').unwrap_or(text);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(StoreError::Corrupt);
        }
        digits.parse().map(Some).map_err(|_| StoreError::Corrupt)
    }

    /// Replaces the replay mark. This runs on the way to answering a request, so it is not
    /// synced to disk: a restart of the agent keeps it, and only a power cut that loses
    /// the file's last write could bring the replay gap back for under a minute.
    pub fn save_replay_mark(&self, time: u64) -> Result<(), StoreError> {
        self.write_atomically("replay-mark", format!("{time}\n").as_bytes(), false)
    }

    /// Writes `bytes` to `name` in the state directory through a private temporary file and
    /// a rename, so readers see the old content or the new one, never half of it.
    fn write_atomically(&self, name: &str, bytes: &[u8], sync: bool) -> Result<(), StoreError> {
        let io_error = |e: io::Error| StoreError::Io(e.kind());
        fs::create_dir_all(&self.dir).map_err(io_error)?;
        let tmp = self.dir.join(format!("{name}.tmp"));
        // A leftover file from a crash could have any mode, or be a symlink: start clean,
        // and refuse to reuse anything that is still there.
        let _ = fs::remove_file(&tmp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        if sync {
            file.sync_all().map_err(io_error)?;
        }
        fs::rename(&tmp, self.dir.join(name)).map_err(io_error)?;
        // Make the rename itself survive a crash. Best effort: the new content is already
        // in place, so a filesystem that cannot sync a directory must not turn a saved file
        // into an error.
        if sync && let Err(e) = File::open(&self.dir).and_then(|dir| dir.sync_all()) {
            crate::log::line(&format!("cannot sync the state directory: {:?}", e.kind()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use bf_common::peers::PeerSpec;

    use super::*;
    use crate::testutil::{K1, TempDir};

    fn list(version: u64) -> PeerList {
        PeerList {
            version,
            peers: vec![PeerSpec {
                public_key: K1.to_string(),
                allowed_ips: vec!["10.77.0.5/32".to_string()],
                trackers: true,
            }],
        }
    }

    #[test]
    fn a_saved_list_is_loaded_back_and_a_newer_save_replaces_it_cleanly() {
        let dir = TempDir::new("store");
        let state = dir.path().join("state"); // does not exist yet: saving creates it
        let store = Store::new(state.clone());
        assert_eq!(store.load(), Ok(None));

        store.save(&list(7)).unwrap();
        assert_eq!(store.load(), Ok(Some(list(7))));

        store.save(&list(8)).unwrap();
        assert_eq!(store.load(), Ok(Some(list(8))));

        let names: Vec<_> = std::fs::read_dir(&state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["peers.json"]);
        let mode = std::fs::metadata(state.join("peers.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_leftover_temporary_file_with_loose_permissions_does_not_decide_the_lists_mode() {
        let dir = TempDir::new("store-leftover");
        let state = dir.path().to_path_buf();
        let leftover = state.join("peers.json.tmp");
        std::fs::write(&leftover, "left behind by a crash").unwrap();
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o644)).unwrap();

        Store::new(state.clone()).save(&list(7)).unwrap();

        let mode = std::fs::metadata(state.join("peers.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(Store::new(state).load(), Ok(Some(list(7))));
    }

    #[test]
    fn the_replay_mark_is_kept_across_restarts_and_a_missing_file_means_none() {
        let dir = TempDir::new("store-mark");
        let state = dir.path().join("state"); // does not exist yet: saving creates it
        let store = Store::new(state.clone());
        assert_eq!(store.load_replay_mark(), Ok(None));

        store.save_replay_mark(1_794_280_123).unwrap();
        assert_eq!(
            Store::new(state.clone()).load_replay_mark(),
            Ok(Some(1_794_280_123))
        );
        store.save_replay_mark(1_794_280_200).unwrap();
        assert_eq!(store.load_replay_mark(), Ok(Some(1_794_280_200)));

        let names: Vec<_> = std::fs::read_dir(&state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["replay-mark"]);
        let mode = std::fs::metadata(state.join("replay-mark"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(store.load(), Ok(None), "the peer list is a separate file");
    }

    #[test]
    fn a_damaged_replay_mark_is_reported_and_never_read_as_zero() {
        let dir = TempDir::new("store-mark-damaged");
        for damaged in [
            "",
            "banana",
            "-5",
            "+5",
            "12 34",
            "1.5",
            "99999999999999999999999",
        ] {
            std::fs::write(dir.path().join("replay-mark"), damaged).unwrap();
            assert_eq!(
                Store::new(dir.path().to_path_buf()).load_replay_mark(),
                Err(StoreError::Corrupt),
                "{damaged:?}"
            );
        }
    }

    #[test]
    fn a_leftover_temporary_mark_file_with_loose_permissions_does_not_decide_the_marks_mode() {
        let dir = TempDir::new("store-mark-leftover");
        let state = dir.path().to_path_buf();
        let leftover = state.join("replay-mark.tmp");
        std::fs::write(&leftover, "left behind by a crash").unwrap();
        std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o644)).unwrap();

        Store::new(state.clone()).save_replay_mark(42).unwrap();

        let mode = std::fs::metadata(state.join("replay-mark"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(Store::new(state).load_replay_mark(), Ok(Some(42)));
    }

    #[test]
    fn a_damaged_file_is_reported_and_not_mistaken_for_an_empty_list() {
        let dir = TempDir::new("store-damaged");
        std::fs::write(dir.path().join("peers.json"), "{ not json").unwrap();

        assert_eq!(
            Store::new(dir.path().to_path_buf()).load(),
            Err(StoreError::Corrupt)
        );
    }
}
