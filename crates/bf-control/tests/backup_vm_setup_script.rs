//! Runs the real `deploy/setup-backup.sh` with a stand-in `ssh` that runs the VM's half
//! right here, with the VM's folders moved into a scratch folder, and stand-ins for what needs
//! root or Debian. It proves what the VM ends with after the first step (age, the script and
//! units unchanged, one SSH key made as `barely-free`, the recipients file) and after
//! `--finish` (known_hosts, targets, one backup run, the timer on), and that bad input never
//! reaches the VM. Spec: `specs/backup.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RECIPIENT: &str = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const TORONTO_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAITorontoHostKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const DALLAS_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIDallasHostKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Where each VM folder lives in the scratch folder.
const MOVES: [(&str, &str); 4] = [
    ("/etc/barely-free", "vm/etc/barely-free"),
    ("/etc/systemd/system", "vm/etc/systemd/system"),
    ("/usr/local/lib/barely-free", "vm/usr/local/lib/barely-free"),
    ("/var/lib/barely-free", "vm/var/lib/barely-free"),
];

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-vmbackup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "bin",
            "mac",
            "vm/etc/barely-free",
            "vm/etc/systemd/system",
            "vm/usr/local/lib",
            "vm/var/lib/barely-free",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let sed: String = MOVES
            .iter()
            .map(|(from, to)| format!(" -e \"s#{from}#$RECORD/{to}#g\""))
            .collect();
        executable(
            &dir.join("bin/ssh"),
            &format!(
                "#!/bin/bash\necho \"ssh $*\" >> \"$RECORD/ssh_calls\"\nsed{sed} | tee \"$RECORD/vm_stdin\" | bash -s\n"
            ),
        );
        executable(
            &dir.join("bin/apt-get"),
            "#!/bin/sh\necho \"apt-get $*\" >> \"$RECORD/calls\"\n",
        );
        executable(
            &dir.join("bin/chown"),
            "#!/bin/sh\necho \"chown $*\" >> \"$RECORD/calls\"\n",
        );
        executable(
            &dir.join("bin/install"),
            r#"#!/bin/bash
echo "install $*" >> "$RECORD/calls"
mode=""; dir=""
while [ $# -gt 0 ]; do case $1 in -d) shift ;; -m) mode=$2; shift 2 ;; -o|-g) shift 2 ;; *) dir=$1; shift ;; esac; done
mkdir -p "$dir" && chmod "$mode" "$dir"
"#,
        );
        // `runuser -u USER -- COMMAND...`: records who, then runs the command.
        executable(
            &dir.join("bin/runuser"),
            "#!/bin/sh\necho \"runuser $1 $2\" >> \"$RECORD/calls\"\nshift 3\nexec \"$@\"\n",
        );
        // `ssh-keygen ... -C COMMENT -f FILE`: a made-up key pair.
        executable(
            &dir.join("bin/ssh-keygen"),
            r#"#!/bin/bash
echo "ssh-keygen $*" >> "$RECORD/calls"
f=""; c=""
while [ $# -gt 0 ]; do case $1 in -f) f=$2; shift 2 ;; -C) c=$2; shift 2 ;; *) shift ;; esac; done
echo "PRIVATE KEY" > "$f"; chmod 600 "$f"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIVmBackupKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX $c" > "$f.pub"
"#,
        );
        // `systemctl`: records; starting the backup writes a status like the real one.
        executable(
            &dir.join("bin/systemctl"),
            r#"#!/bin/bash
echo "systemctl $*" >> "$RECORD/calls"
if [ "$1" = start ] && [ "$2" = bf-backup.service ]; then
  printf 'finished=1\nfile=control-x.tar.age\nsent=%s\nfailed=\nerror=%s\n' "$BACKUP_SENT" "$BACKUP_ERROR" > "$RECORD/vm/var/lib/barely-free/backup-status"
  [ -z "$BACKUP_ERROR" ]
fi
"#,
        );
        World { dir }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    fn run(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.path("bin").display()
        );
        let mut command = Command::new("/bin/bash");
        command
            .arg(repo().join("deploy/setup-backup.sh"))
            .args(args)
            .args(["-o", "Port=2222"])
            .env_clear()
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("BACKUP_LOCAL_DIR", self.path("mac"))
            .env("BACKUP_SENT", "192.0.2.176 198.51.100.185")
            .env("BACKUP_ERROR", "");
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn first(&self) -> Output {
        self.run(&["root@203.0.113.50", RECIPIENT], &[])
    }

    fn read(&self, sub: &str) -> String {
        std::fs::read_to_string(self.path(sub)).unwrap_or_default()
    }

    fn mode(&self, sub: &str) -> u32 {
        std::fs::metadata(self.path(sub))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    /// A file from the repo as it would read with the VM's folders moved.
    fn moved(&self, repo_file: &str) -> String {
        let mut text = std::fs::read_to_string(repo().join(repo_file)).unwrap();
        for (from, to) in MOVES {
            text = text.replace(from, &format!("{}/{to}", self.dir.display()));
        }
        text
    }

    fn known_hosts(&self) -> PathBuf {
        let file = self.path("mac/known_hosts");
        std::fs::write(
            &file,
            format!(
                "192.0.2.176 ssh-ed25519 {TORONTO_KEY}\n198.51.100.185 ssh-ed25519 {DALLAS_KEY}\n"
            ),
        )
        .unwrap();
        file
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

#[test]
fn the_first_step_installs_age_the_script_the_units_a_key_and_the_recipient() {
    let world = World::new("first");
    let output = world.first();
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));

    let calls = world.read("calls");
    assert!(calls.contains("apt-get install -y age"), "{calls}");
    for (installed, original) in [
        (
            "vm/usr/local/lib/barely-free/bf-backup.sh",
            "deploy/bf-backup.sh",
        ),
        (
            "vm/etc/systemd/system/bf-backup.service",
            "deploy/bf-backup.service",
        ),
        (
            "vm/etc/systemd/system/bf-backup.timer",
            "deploy/bf-backup.timer",
        ),
    ] {
        assert_eq!(world.read(installed), world.moved(original), "{installed}");
    }
    assert_eq!(
        world.mode("vm/usr/local/lib/barely-free/bf-backup.sh"),
        0o755
    );
    assert!(calls.contains("systemctl daemon-reload"), "{calls}");
    assert!(
        !calls.contains("enable"),
        "the timer waits for --finish: {calls}"
    );

    // The key is made by barely-free itself, in a folder only it can open.
    assert!(calls.contains("runuser -u barely-free"), "{calls}");
    assert!(calls.contains("-t ed25519"), "{calls}");
    assert_eq!(world.mode("vm/etc/barely-free/backup-ssh"), 0o700);
    assert!(
        calls.contains("-o barely-free -g barely-free")
            && calls.contains("etc/barely-free/backup-ssh"),
        "{calls}"
    );

    let recipients = world.read("vm/etc/barely-free/backup.recipients");
    let keys: Vec<&str> = recipients
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(keys, [RECIPIENT]);
    assert_eq!(world.mode("vm/etc/barely-free/backup.recipients"), 0o644);

    assert_eq!(
        world.read("mac/vm-backup-key.pub"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIVmBackupKeyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX barely-free-backup\n"
    );
}

#[test]
fn running_the_first_step_again_keeps_the_key_and_skips_age_when_installed() {
    let world = World::new("again");
    assert_eq!(world.first().status.code(), Some(0));
    executable(&world.path("bin/age"), "#!/bin/sh\nexit 0\n");
    let output = world.first();
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let calls = world.read("calls");
    assert_eq!(calls.matches("ssh-keygen").count(), 1, "{calls}");
    assert_eq!(calls.matches("apt-get").count(), 1, "{calls}");
}

#[test]
fn a_bad_age_key_never_reaches_the_vm() {
    for key in [
        "",
        "age1short",
        "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8b",
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p extra",
        "--finish",
    ] {
        let world = World::new("badkey");
        let output = world.run(&["root@203.0.113.50", key], &[]);
        assert_ne!(output.status.code(), Some(0), "{key:?}: {}", said(&output));
        assert!(!world.path("ssh_calls").exists(), "{key:?}");
    }
}

#[test]
fn finishing_pins_the_nodes_runs_one_backup_and_starts_the_timer() {
    let world = World::new("finish");
    assert_eq!(world.first().status.code(), Some(0));
    let hosts = world.known_hosts();
    let output = world.run(
        &["root@203.0.113.50", "--finish", hosts.to_str().unwrap()],
        &[],
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));

    assert_eq!(
        world.read("vm/etc/barely-free/backup-ssh/known_hosts"),
        world.read("mac/known_hosts")
    );
    assert_eq!(
        world.read("vm/etc/barely-free/backup-targets"),
        "bf-backup@192.0.2.176\nbf-backup@198.51.100.185\n"
    );
    let calls = world.read("calls");
    let start = calls.find("systemctl start bf-backup.service").unwrap();
    let timer = calls
        .find("systemctl enable --now bf-backup.timer")
        .unwrap();
    assert!(start < timer, "{calls}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sent=192.0.2.176 198.51.100.185"),
        "{stdout}"
    );
}

#[test]
fn a_first_backup_that_fails_is_reported_and_the_timer_still_starts() {
    let world = World::new("finish-fails");
    assert_eq!(world.first().status.code(), Some(0));
    let hosts = world.known_hosts();
    let output = world.run(
        &["root@203.0.113.50", "--finish", hosts.to_str().unwrap()],
        &[("BACKUP_ERROR", "could not send to 192.0.2.176")],
    );
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("could not send"));
    assert!(
        world
            .read("calls")
            .contains("systemctl enable --now bf-backup.timer")
    );
}

#[test]
fn finishing_before_the_first_step_is_refused() {
    let world = World::new("finish-early");
    let hosts = world.known_hosts();
    let output = world.run(
        &["root@203.0.113.50", "--finish", hosts.to_str().unwrap()],
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(!world.read("calls").contains("systemctl start"));
}

#[test]
fn a_bad_known_hosts_file_never_reaches_the_vm() {
    for (case, text) in [
        ("empty", String::new()),
        (
            "name",
            format!("toronto.example ssh-ed25519 {TORONTO_KEY}\n"),
        ),
        ("rsa", format!("192.0.2.176 ssh-rsa {TORONTO_KEY}\n")),
        (
            "marker",
            format!("@revoked 192.0.2.176 ssh-ed25519 {TORONTO_KEY}\n"),
        ),
        (
            "junk-key",
            "192.0.2.176 ssh-ed25519 AAAA$(reboot)\n".to_string(),
        ),
    ] {
        let world = World::new(&format!("hosts-{case}"));
        let file = world.path("mac/bad_known_hosts");
        std::fs::write(&file, text).unwrap();
        let output = world.run(
            &["root@203.0.113.50", "--finish", file.to_str().unwrap()],
            &[],
        );
        assert_ne!(output.status.code(), Some(0), "{case}: {}", said(&output));
        assert!(!world.path("ssh_calls").exists(), "{case}");
    }
}
