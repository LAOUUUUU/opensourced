//! Runs the real `deploy/bf-backup.sh` (the VM's nightly backup) with the real `bf-control`
//! and stand-ins for `age` and `ssh`. The stand-in `age` records its arguments and what it
//! was asked to encrypt and writes `AGE:` plus those bytes; the stand-in `ssh` records each
//! call and what each server was sent, and fails for the servers named in `SSH_FAILS`.
//! Spec: `specs/backup.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bf_control::store::Store;

const KEY_TEXT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RECIPIENT: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const TORONTO: &str = "192.0.2.176";
const DALLAS: &str = "198.51.100.185";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/bf-backup.sh")
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn private(path: &Path, text: &str, mode: u32) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-backupsh-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["bin", "etc/backup-ssh", "var", "work", "record"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::set_permissions(dir.join("work"), std::fs::Permissions::from_mode(0o700)).unwrap();
        executable(
            &dir.join("bin/age"),
            r#"#!/bin/bash
printf '%s\n' "$@" > "$RECORD/age_args"
[ -z "$AGE_FAILS" ] || { echo "age: failed" >&2; exit 1; }
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; *) shift ;; esac; done
cat > "$RECORD/plain.tar"
{ printf 'AGE:'; cat "$RECORD/plain.tar"; } > "$out"
"#,
        );
        executable(
            &dir.join("bin/ssh"),
            r#"#!/bin/bash
printf '%s\n' "$@" > "$RECORD/ssh_args_$#_$RANDOM"
echo "ssh $*" >> "$RECORD/ssh_calls"
target=""
for word in "$@"; do case "$word" in bf-backup@*) target=${word#bf-backup@} ;; esac; done
case " $SSH_FAILS " in *" $target "*) echo "ssh: connect to host $target port 22: Connection timed out" >&2; exit 255 ;; esac
cat > "$RECORD/sent_$target"
echo "kept"
"#,
        );
        // The database: one account, made by the real program.
        let db = dir.join("var/control.db");
        let mut store = Store::open(&db).unwrap();
        store.add_account("lao", 1_000).unwrap();
        drop(store);
        private(&dir.join("etc/control.key"), KEY_TEXT, 0o600);
        private(
            &dir.join("etc/backup.recipients"),
            &format!("# Lao's backup key\n{RECIPIENT}\n"),
            0o644,
        );
        private(
            &dir.join("etc/backup-targets"),
            &format!("bf-backup@{TORONTO}\nbf-backup@{DALLAS}\n"),
            0o644,
        );
        private(
            &dir.join("etc/backup-ssh/id_ed25519"),
            "not a real key\n",
            0o600,
        );
        private(&dir.join("etc/backup-ssh/known_hosts"), "", 0o644);
        World { dir }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    fn run(&self, extra: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.path("bin").display()
        );
        let mut command = Command::new("/bin/bash");
        command
            .arg(script())
            .env_clear()
            .env("PATH", path)
            .env("RECORD", self.path("record"))
            .env("BF_CONTROL", env!("CARGO_BIN_EXE_bf-control"))
            .env("BC_DB", self.path("var/control.db"))
            .env("BC_KEY_FILE", self.path("etc/control.key"))
            .env("BACKUP_RECIPIENTS", self.path("etc/backup.recipients"))
            .env("BACKUP_TARGETS", self.path("etc/backup-targets"))
            .env("BACKUP_SSH_DIR", self.path("etc/backup-ssh"))
            .env("BACKUP_STATUS", self.path("var/backup-status"))
            .env("BACKUP_WORK", self.path("work"))
            .env("SSH_FAILS", "")
            .env("AGE_FAILS", "");
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn status(&self) -> Vec<(String, String)> {
        std::fs::read_to_string(self.path("var/backup-status"))
            .unwrap()
            .lines()
            .map(|line| {
                let (name, value) = line.split_once('=').unwrap();
                (name.to_string(), value.to_string())
            })
            .collect()
    }

    fn field(&self, name: &str) -> String {
        self.status()
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("no {name} in the status"))
    }

    fn ssh_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("record/ssh_calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn work_is_empty(&self) -> bool {
        std::fs::read_dir(self.path("work"))
            .unwrap()
            .next()
            .is_none()
    }

    /// Every argument any stand-in was given.
    fn all_arguments(&self) -> String {
        let mut all = String::new();
        for entry in std::fs::read_dir(self.path("record")).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if name.starts_with("ssh_args") || name == "age_args" || name == "ssh_calls" {
                all.push_str(&std::fs::read_to_string(entry.path()).unwrap());
            }
        }
        all
    }
}

fn said(output: &Output) -> String {
    format!(
        "status {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_night_sends_one_encrypted_file_holding_database_key_and_manifest_to_every_server() {
    let world = World::new("night");
    let output = world.run(&[]);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));

    let file = world.field("file");
    assert!(
        file.starts_with("control-") && file.ends_with("Z.tar.age") && file.len() == 32,
        "{file}"
    );
    assert_eq!(world.field("sent"), format!("{TORONTO} {DALLAS}"));
    assert_eq!(world.field("failed"), "");
    assert_eq!(world.field("error"), "");

    // Both servers got exactly what age wrote.
    let plain = std::fs::read(world.path("record/plain.tar")).unwrap();
    let mut encrypted = b"AGE:".to_vec();
    encrypted.extend_from_slice(&plain);
    for ip in [TORONTO, DALLAS] {
        assert_eq!(
            std::fs::read(world.path(&format!("record/sent_{ip}"))).unwrap(),
            encrypted,
            "{ip}"
        );
    }

    // What was encrypted: the manifest, the copy and the key, with matching hashes.
    let unpacked = world.path("unpacked");
    std::fs::create_dir_all(&unpacked).unwrap();
    let tar = Command::new("tar")
        .arg("-xf")
        .arg(world.path("record/plain.tar"))
        .arg("-C")
        .arg(&unpacked)
        .output()
        .unwrap();
    assert!(tar.status.success(), "{}", said(&tar));
    let mut names: Vec<String> = std::fs::read_dir(&unpacked)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["control.db", "control.key", "manifest"]);
    assert_eq!(
        std::fs::read_to_string(unpacked.join("control.key")).unwrap(),
        KEY_TEXT
    );
    let accounts = Store::open(&unpacked.join("control.db"))
        .unwrap()
        .accounts()
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].label, "lao");

    let manifest = std::fs::read_to_string(unpacked.join("manifest")).unwrap();
    let lines: Vec<&str> = manifest.lines().collect();
    assert_eq!(lines.len(), 3, "{manifest}");
    let made = &file["control-".len()..file.len() - ".tar.age".len()];
    assert_eq!(lines[0], format!("made={made}"));
    for (line, name) in lines[1..].iter().zip(["control.db", "control.key"]) {
        let bytes = std::fs::read(unpacked.join(name)).unwrap();
        assert_eq!(*line, format!("sha256 {} {name}", sha256(&bytes)));
    }
}

#[test]
fn age_and_ssh_get_the_right_arguments_and_no_secret() {
    let world = World::new("arguments");
    let output = world.run(&[]);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let file = world.field("file");

    let age_args = std::fs::read_to_string(world.path("record/age_args")).unwrap();
    let age_args: Vec<&str> = age_args.lines().collect();
    assert_eq!(age_args.len(), 4, "{age_args:?}");
    assert_eq!(age_args[0], "-R");
    assert_eq!(
        age_args[1],
        world.path("etc/backup.recipients").to_str().unwrap()
    );
    assert_eq!(age_args[2], "-o");
    assert!(age_args[3].ends_with(&format!("/{file}")), "{age_args:?}");

    let calls = world.ssh_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let ssh_dir = world.path("etc/backup-ssh");
    for (call, ip) in calls.iter().zip([TORONTO, DALLAS]) {
        for wanted in [
            format!("-i {}/id_ed25519", ssh_dir.display()),
            "-o IdentitiesOnly=yes".to_string(),
            format!("-o UserKnownHostsFile={}/known_hosts", ssh_dir.display()),
            "-o StrictHostKeyChecking=yes".to_string(),
            "-o BatchMode=yes".to_string(),
            "-F /dev/null".to_string(),
        ] {
            assert!(call.contains(&wanted), "{wanted} missing from {call}");
        }
        assert!(
            call.ends_with(&format!("bf-backup@{ip} put {file}")),
            "{call}"
        );
    }
    assert!(!world.all_arguments().contains(KEY_TEXT));
}

#[test]
fn one_server_failing_still_sends_to_the_other_and_says_which() {
    let world = World::new("partial");
    let output = world.run(&[("SSH_FAILS", TORONTO)]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert_eq!(world.field("sent"), DALLAS);
    assert_eq!(world.field("failed"), TORONTO);
    let error = world.field("error");
    assert!(error.contains(TORONTO), "{error}");
    assert!(error.contains("timed out"), "{error}");
    assert!(world.path(&format!("record/sent_{DALLAS}")).exists());
    assert!(world.work_is_empty());
}

#[test]
fn every_server_failing_fails_and_leaves_nothing_behind() {
    let world = World::new("allfail");
    let output = world.run(&[("SSH_FAILS", &format!("{TORONTO} {DALLAS}"))]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert_eq!(world.field("sent"), "");
    assert_eq!(world.field("failed"), format!("{TORONTO} {DALLAS}"));
    assert!(world.work_is_empty());
}

#[test]
fn the_work_folder_is_empty_after_a_good_night() {
    let world = World::new("clean");
    let output = world.run(&[]);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    assert!(world.work_is_empty());
}

#[test]
fn a_failing_age_sends_nothing_and_leaves_nothing() {
    let world = World::new("agefails");
    let output = world.run(&[("AGE_FAILS", "1")]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(world.ssh_calls().is_empty());
    assert!(world.work_is_empty());
    assert_eq!(world.field("sent"), "");
    assert!(!world.field("error").is_empty());
}

#[test]
fn a_missing_database_sends_nothing_and_says_so() {
    let world = World::new("nodb");
    std::fs::remove_file(world.path("var/control.db")).unwrap();
    let output = world.run(&[]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(world.ssh_calls().is_empty());
    assert!(world.work_is_empty());
    let error = world.field("error");
    assert!(error.contains("no database"), "{error}");
    assert!(
        !world.path("var/control.db").exists(),
        "a backup never makes a database"
    );
}

#[test]
fn a_bad_recipients_file_is_refused_before_anything_is_done() {
    for (case, text, mode) in [
        ("empty", "# nothing here\n\n", 0o644),
        ("not-a-key", "age1good\nssh-ed25519 AAAA\n", 0o644),
        ("group-writable", "age1good\n", 0o664),
        ("world-writable", "age1good\n", 0o646),
    ] {
        let world = World::new(&format!("recipients-{case}"));
        private(&world.path("etc/backup.recipients"), text, mode);
        let output = world.run(&[]);
        assert_eq!(output.status.code(), Some(1), "{case}: {}", said(&output));
        assert!(world.ssh_calls().is_empty(), "{case}");
        assert!(!world.path("record/age_args").exists(), "{case}");
        let error = world.field("error");
        assert!(error.contains("recipients"), "{case}: {error}");
    }
    let world = World::new("recipients-missing");
    std::fs::remove_file(world.path("etc/backup.recipients")).unwrap();
    let output = world.run(&[]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(world.field("error").contains("recipients"));
}

#[test]
fn a_bad_targets_file_is_refused_before_anything_is_done() {
    for (case, text) in [
        ("empty", "\n# none\n"),
        ("root", "root@192.0.2.176\n"),
        ("name", "bf-backup@toronto.example\n"),
        ("extra", "bf-backup@192.0.2.176 -oProxyCommand=x\n"),
        ("option", "-oProxyCommand=x\n"),
    ] {
        let world = World::new(&format!("targets-{case}"));
        private(&world.path("etc/backup-targets"), text, 0o644);
        let output = world.run(&[]);
        assert_eq!(output.status.code(), Some(1), "{case}: {}", said(&output));
        assert!(world.ssh_calls().is_empty(), "{case}");
        let error = world.field("error");
        assert!(error.contains("targets"), "{case}: {error}");
    }
}

#[test]
fn the_status_is_one_line_per_field_and_finished_is_now() {
    let world = World::new("status");
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    world.run(&[("SSH_FAILS", TORONTO)]);
    let names: Vec<String> = world.status().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["finished", "file", "sent", "failed", "error"]);
    let finished: u64 = world.field("finished").parse().unwrap();
    assert!(finished >= before && finished <= before + 60);
    assert!(!world.field("error").contains('\n'));
}
