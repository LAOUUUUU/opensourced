//! Which (key, network) pairs have logged in to a server before, so a new one can be emailed
//! (`specs/login-alerts.md`). Kept in one small file next to the database.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use bf_common::logins::{KEYS_FILE, LOGINS_FILE, Login, from_files, network, parse_line};

/// Where the pairs are kept, unless `BC_KNOWN_LOGINS` says otherwise.
pub const KNOWN_FILE: &str = "/var/lib/barely-free/known-logins";
/// The VM's name in the emails.
pub const VM_SERVER: &str = "the website server";

/// The pair a login is remembered by: its key (or `password`) and its network.
pub fn pair(login: &Login) -> (String, String) {
    (
        login.key.clone().unwrap_or_else(|| "password".to_string()),
        network(login.from),
    )
}

/// The remembered pairs and their file.
#[derive(Debug)]
pub struct Known {
    path: PathBuf,
    pairs: BTreeSet<(String, String)>,
    /// No file yet: the first look learns what it sees instead of alerting.
    learning: bool,
    /// Pairs were added since the file was last written.
    dirty: bool,
}

impl Known {
    /// The pairs in `path`; a missing file means learning at the first look. A line that is
    /// not `<key>\t<network>` is skipped.
    pub fn open(path: &Path) -> Result<Known, String> {
        let on_disk = read_pairs(path)?;
        Ok(Known {
            path: path.to_path_buf(),
            learning: on_disk.is_none(),
            pairs: on_disk.unwrap_or_default(),
            dirty: false,
        })
    }

    /// The logins (with their server) whose pair was not known, remembering them; while
    /// learning, nothing is new and everything is remembered. [`Known::save`] writes them.
    pub fn news(&mut self, seen: &[(String, Login)]) -> Vec<(String, Login)> {
        let news: Vec<(String, Login)> = if self.learning {
            Vec::new()
        } else {
            seen.iter()
                .filter(|(_, login)| !self.pairs.contains(&pair(login)))
                .cloned()
                .collect()
        };
        self.add(seen.iter().map(|(_, login)| login));
        news
    }

    /// Adds these logins' pairs without alerting; gives how many were new.
    pub fn learn<'a>(&mut self, logins: impl IntoIterator<Item = &'a Login>) -> usize {
        self.add(logins)
    }

    /// Writes the file if anything changed since it was last written, or learning just
    /// ended; after a failure the next call tries again.
    pub fn save(&mut self) -> Result<(), String> {
        if self.dirty {
            self.write()?;
            self.dirty = false;
        }
        Ok(())
    }

    fn add<'a>(&mut self, logins: impl IntoIterator<Item = &'a Login>) -> usize {
        let added = logins
            .into_iter()
            .filter(|login| self.pairs.insert(pair(login)))
            .count();
        // The first look ends learning, and its (maybe empty) list becomes the file.
        self.dirty |= added > 0 || self.learning;
        self.learning = false;
        added
    }

    /// Writes every pair, with any another writer (`bf-control logins learn`) put in the
    /// file meanwhile, to a new file only its owner may read, then puts it in place.
    fn write(&mut self) -> Result<(), String> {
        if let Some(on_disk) = read_pairs(&self.path)? {
            self.pairs.extend(on_disk);
        }
        let text: String = self
            .pairs
            .iter()
            .map(|(key, net)| format!("{key}\t{net}\n"))
            .collect();
        let new = self.path.with_extension("new");
        let failed =
            |e: std::io::Error| format!("cannot write {}: {}", self.path.display(), e.kind());
        let _ = std::fs::remove_file(&new);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&new).map_err(failed)?;
        std::io::Write::write_all(&mut file, text.as_bytes()).map_err(failed)?;
        file.sync_all().map_err(failed)?;
        std::fs::rename(&new, &self.path).map_err(failed)
    }
}

/// The pairs in the file at `path`, or `None` when there is no file. A line that is not
/// `<key>\t<network>` is skipped.
fn read_pairs(path: &Path) -> Result<Option<BTreeSet<(String, String)>>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {}", path.display(), e.kind())),
    };
    Ok(Some(
        text.lines()
            .filter_map(|line| line.split_once('\t'))
            .filter(|(key, net)| !key.is_empty() && net.contains('/'))
            .map(|(key, net)| (key.to_string(), net.to_string()))
            .collect(),
    ))
}

const USAGE: &str = "usage: bf-control logins learn < journal-lines\n\
    (lines from `journalctl -u ssh -o short-unix`; their key and network pairs are added to\n\
    the known-logins file, so they never cause an email)\n";

/// `bf-control logins learn`: the known pairs of `path` plus those of the journal lines on
/// `input`, written back. Gives the exit code: 0 done, 1 failed, 2 not understood.
pub fn run(
    args: &[String],
    path: &Path,
    input: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> u8 {
    if args != ["learn"] {
        let _ = err.write_all(USAGE.as_bytes());
        return 2;
    }
    let learned = (|| -> Result<(usize, usize, usize), String> {
        let mut known = Known::open(path)?;
        let mut logins = Vec::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = input
                .read_until(b'\n', &mut line)
                .map_err(|e| format!("cannot read the journal lines: {}", e.kind()))?;
            if read == 0 {
                break;
            }
            if let Some(login) = parse_line(String::from_utf8_lossy(&line).trim_end()) {
                logins.push(login);
            }
        }
        let added = known.learn(logins.iter());
        known.save()?;
        Ok((logins.len(), added, known.pairs.len()))
    })();
    match learned {
        Ok((read, added, all)) => {
            let _ = writeln!(
                out,
                "{read} logins read, {added} new pairs learned, {all} known in all"
            );
            0
        }
        Err(why) => {
            let _ = writeln!(err, "{why}");
            1
        }
    }
}

/// The VM's own logins of the window before `now`, from the folder `bf-logins.timer`
/// writes: `Ok(None)` when there is no logins file, an error when it is stale or unreadable.
pub fn vm_logins(dir: &Path, now: u64) -> Result<Option<Vec<Login>>, String> {
    let path = dir.join(LOGINS_FILE);
    let read = |e: std::io::Error| format!("cannot read {}: {}", path.display(), e.kind());
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(read(e)),
    };
    let written = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    let logins = std::fs::read_to_string(&path).map_err(read)?;
    let keys = std::fs::read_to_string(dir.join(KEYS_FILE)).unwrap_or_default();
    from_files(&logins, &keys, written, now).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_794_510_900;
    const FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-logins-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn login(from: &str, key: Option<&str>) -> Login {
        Login {
            at: NOW - 30,
            user: "root".to_string(),
            from: from.parse().unwrap(),
            key: key.map(str::to_string),
            key_name: None,
        }
    }

    fn seen(server: &str, login: Login) -> (String, Login) {
        (server.to_string(), login)
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn with_no_file_the_first_look_learns_silently_and_writes_the_file() {
        let path = dir("first").join("known-logins");
        let mut known = Known::open(&path).unwrap();
        let news = known.news(&[seen("Dallas", login("203.0.113.7", Some(FP)))]);
        assert!(news.is_empty(), "nothing is new before anything was known");
        assert!(!path.exists(), "written only when saved");
        known.save().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{FP}\t203.0.113.0/24\n")
        );
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn a_new_pair_is_news_once_and_survives_a_restart() {
        let path = dir("news").join("known-logins");
        std::fs::write(&path, format!("{FP}\t203.0.113.0/24\n")).unwrap();
        let mut known = Known::open(&path).unwrap();
        assert!(
            known
                .news(&[seen("Dallas", login("203.0.113.99", Some(FP)))])
                .is_empty(),
            "same /24"
        );
        let elsewhere = seen("Toronto", login("198.51.100.4", Some(FP)));
        let password = seen("Toronto", login("203.0.113.7", None));
        let news = known.news(&[elsewhere.clone(), password.clone(), elsewhere.clone()]);
        assert_eq!(
            news,
            vec![elsewhere.clone(), password.clone(), elsewhere.clone()],
            "every login of a new pair in this look"
        );
        assert!(
            known
                .news(&[elsewhere.clone(), password.clone()])
                .is_empty(),
            "never twice"
        );
        known.save().unwrap();
        let mut again = Known::open(&path).unwrap();
        assert!(
            again.news(&[elsewhere, password]).is_empty(),
            "the file kept them"
        );
    }

    #[test]
    fn a_bad_line_in_the_file_is_skipped_and_learn_counts_the_new_pairs() {
        let path = dir("learn").join("known-logins");
        std::fs::write(&path, format!("garbage\n{FP}\t203.0.113.0/24\n\n")).unwrap();
        let mut known = Known::open(&path).unwrap();
        let logins = [
            login("203.0.113.7", Some(FP)),
            login("198.51.100.4", Some(FP)),
            login("198.51.100.5", Some(FP)),
            login("2001:db8:1:2::5", None),
        ];
        assert_eq!(known.learn(logins.iter()), 2);
        assert!(
            known
                .news(&[seen("Dallas", login("198.51.100.200", Some(FP)))])
                .is_empty()
        );
    }

    #[test]
    fn saving_keeps_the_pairs_another_writer_added_meanwhile() {
        let path = dir("merge").join("known-logins");
        std::fs::write(&path, format!("{FP}\t203.0.113.0/24\n")).unwrap();
        let mut website = Known::open(&path).unwrap();
        let mut seeding = Known::open(&path).unwrap();
        seeding.learn([login("198.51.100.4", Some(FP))].iter());
        seeding.save().unwrap();
        assert_eq!(
            website
                .news(&[seen("Dallas", login("192.0.2.9", None))])
                .len(),
            1
        );
        website.save().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{FP}\t198.51.100.0/24\n{FP}\t203.0.113.0/24\npassword\t192.0.2.0/24\n"),
            "the seeded pair is kept"
        );
        assert!(
            website
                .news(&[seen("Dallas", login("198.51.100.9", Some(FP)))])
                .is_empty(),
            "and now known in memory too"
        );
    }

    fn command(args: &[&str], path: &Path, input: &str) -> (u8, String, String) {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, path, &mut input.as_bytes(), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn logins_learn_reads_journal_lines_and_adds_their_pairs_without_alerting() {
        let path = dir("cli").join("known-logins");
        let journal = format!(
            "-- Boot 1234 --\n\
             1700000000.1 dallas sshd-session[5]: Accepted publickey for root from 203.0.113.7 port 1 ssh2: ED25519 {FP}\n\
             1700000100.1 dallas sshd-session[6]: Accepted publickey for root from 203.0.113.8 port 1 ssh2: ED25519 {FP}\n\
             1700000200.1 vm sshd[7]: Accepted password for root from 198.51.100.4 port 1 ssh2\n\
             1700000300.1 vm sshd[8]: Failed password for root from 192.0.2.1 port 1 ssh2\n"
        );
        let (code, out, err) = command(&["learn"], &path, &journal);
        assert_eq!((code, err.as_str()), (0, ""));
        assert_eq!(out, "3 logins read, 2 new pairs learned, 2 known in all\n");
        let (code, out, _) = command(&["learn"], &path, &journal);
        assert_eq!(code, 0);
        assert_eq!(out, "3 logins read, 0 new pairs learned, 2 known in all\n");
        let mut known = Known::open(&path).unwrap();
        assert!(
            known
                .news(&[seen("Toronto", login("198.51.100.77", None))])
                .is_empty(),
            "learned pairs are known to the website"
        );
    }

    #[test]
    fn logins_without_learn_or_with_an_unwritable_file_say_so() {
        let path = dir("cli-bad").join("known-logins");
        for args in [&[][..], &["learn", "extra"][..], &["forget"][..]] {
            let (code, _, err) = command(args, &path, "");
            assert_eq!(code, 2, "{args:?}");
            assert!(err.contains("bf-control logins learn"), "{err}");
        }
        let nowhere = path.join("not-a-dir").join("known-logins");
        let (code, _, err) = command(&["learn"], &nowhere, "");
        assert_eq!(code, 1);
        assert!(err.contains("cannot write"), "{err}");
    }

    #[test]
    fn the_vm_files_are_read_when_fresh_and_refused_when_stale() {
        let d = dir("vm");
        // The files' age is judged by their modification time, so use the real clock.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(vm_logins(&d, now).unwrap(), None, "no file, nothing to say");
        std::fs::write(
            d.join(LOGINS_FILE),
            format!(
                "{}.1 lao sshd-session[5]: Accepted publickey for root from 203.0.113.7 port 1 ssh2: ED25519 {FP}\n\
                 {}.1 lao sshd-session[6]: Accepted password for root from 203.0.113.8 port 1 ssh2\n",
                now - 60,
                now - 5_000,
            ),
        )
        .unwrap();
        std::fs::write(
            d.join(KEYS_FILE),
            format!("256 {FP} lao mac key (ED25519)\n"),
        )
        .unwrap();
        let read = vm_logins(&d, now).unwrap().unwrap();
        assert_eq!(read.len(), 1, "inside the window: {read:?}");
        assert_eq!(read[0].key_name.as_deref(), Some("lao mac key"));
        let stale = vm_logins(&d, now + 600).unwrap_err();
        assert!(stale.contains("older than"), "{stale}");
    }
}
