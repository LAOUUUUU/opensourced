//! Runs the real `deploy/node-backup-receiver.sh` with a stand-in `ssh` that runs the node's
//! half right here, with the node's folders moved into a scratch folder, and stand-ins for
//! the commands that need root. It proves the node ends with one `bf-backup` user whose only
//! key is pinned to the receiver, files owned the way sshd and the receiver need, and that
//! the node's host key reaches `known_hosts` on the Mac. Bad input never reaches a node.
//! Spec: `specs/backup.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VM_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBackupKeyOfTheWebVmXXXXXXXXXXXXXXXXXXXXX";
const HOST_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyOfTorontoXXXXXXXXXXXXXXXXXXXXXXXXXX";
const NODE: &str = "192.0.2.176";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-nodebackup-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "bin",
            "mac",
            "node/usr/local/bin",
            "node/home",
            "node/var/lib",
            "node/etc/ssh",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(
            dir.join("node/etc/ssh/ssh_host_ed25519_key.pub"),
            format!("ssh-ed25519 {HOST_KEY} root@vps157750-kzp\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join("mac/vm-backup-key.pub"),
            format!("ssh-ed25519 {VM_KEY} barely-free-backup\n"),
        )
        .unwrap();
        // `ssh`: runs the node's half here, with the node's folders moved into `node/`.
        executable(
            &dir.join("bin/ssh"),
            r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/ssh_calls"
if command -v dash >/dev/null 2>&1; then shell=dash; else shell=sh; fi
sed -e "s#/usr/local/bin/#$RECORD/node/usr/local/bin/#g" \
    -e "s#/home/bf-backup#$RECORD/node/home/bf-backup#g" \
    -e "s#/var/lib/bf-backup#$RECORD/node/var/lib/bf-backup#g" \
    -e "s#/etc/ssh/#$RECORD/node/etc/ssh/#g" | tee "$RECORD/node_stdin" | $shell -s
"#,
        );
        executable(
            &dir.join("bin/id"),
            "#!/bin/sh\n[ -e \"$RECORD/user_exists\" ]\n",
        );
        executable(
            &dir.join("bin/useradd"),
            r#"#!/bin/bash
echo "useradd $*" >> "$RECORD/calls"
home=""; while [ $# -gt 1 ]; do case $1 in --home-dir) home=$2; shift 2 ;; *) shift ;; esac; done
mkdir -p "$home"; touch "$RECORD/user_exists"
"#,
        );
        for tool in ["passwd", "chown"] {
            executable(
                &dir.join("bin").join(tool),
                &format!("#!/bin/sh\necho \"{tool} $*\" >> \"$RECORD/calls\"\n"),
            );
        }
        // `install -d -m MODE [-o U -g G] DIR`: makes the folder, records the owner.
        executable(
            &dir.join("bin/install"),
            r#"#!/bin/bash
echo "install $*" >> "$RECORD/calls"
mode=""; dir=""
while [ $# -gt 0 ]; do case $1 in -d) shift ;; -m) mode=$2; shift 2 ;; -o|-g) shift 2 ;; *) dir=$1; shift ;; esac; done
mkdir -p "$dir" && chmod "$mode" "$dir"
"#,
        );
        // `sshd -T ...`: the settings in SSHD_SETTINGS.
        executable(
            &dir.join("bin/sshd"),
            "#!/bin/sh\necho \"sshd $*\" >> \"$RECORD/calls\"\nprintf '%s\\n' \"port 22\" \"pubkeyauthentication yes\" \"$SSHD_SETTINGS\"\n",
        );
        World { dir }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    fn run(&self, host: &str, key_file: &Path, sshd: &str) -> Output {
        let path = format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.path("bin").display()
        );
        Command::new("/bin/bash")
            .arg(repo().join("deploy/node-backup-receiver.sh"))
            .arg(host)
            .arg(key_file)
            .args(["-i", "/nowhere/key", "-o", "IdentitiesOnly=yes"])
            .env_clear()
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("BACKUP_LOCAL_DIR", self.path("mac"))
            .env("SSHD_SETTINGS", sshd)
            .output()
            .unwrap()
    }

    fn good(&self) -> Output {
        self.run(
            &format!("root@{NODE}"),
            &self.path("mac/vm-backup-key.pub"),
            "",
        )
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
fn a_node_gets_the_user_the_receiver_and_one_pinned_key() {
    let world = World::new("good");
    let output = world.good();
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));

    let installed = world.read("node/usr/local/bin/bf-backup-receive");
    let original = std::fs::read_to_string(repo().join("deploy/bf-backup-receive")).unwrap();
    let moved = original.replace(
        "/var/lib/bf-backup",
        &format!("{}/node/var/lib/bf-backup", world.dir.display()),
    );
    let moved = moved.replace(
        "/usr/local/bin/",
        &format!("{}/node/usr/local/bin/", world.dir.display()),
    );
    assert_eq!(installed, moved, "the receiver arrives unchanged");
    assert_eq!(world.mode("node/usr/local/bin/bf-backup-receive"), 0o755);

    let keys = world.read("node/home/bf-backup/.ssh/authorized_keys");
    let receiver = format!(
        "{}/node/usr/local/bin/bf-backup-receive",
        world.dir.display()
    );
    assert_eq!(
        keys,
        format!("restrict,command=\"{receiver}\" ssh-ed25519 {VM_KEY} barely-free-backup\n")
    );
    assert_eq!(
        world.mode("node/home/bf-backup/.ssh/authorized_keys"),
        0o644
    );
    assert_eq!(world.mode("node/home/bf-backup/.ssh"), 0o755);
    assert_eq!(world.mode("node/var/lib/bf-backup"), 0o700);

    let calls = world.read("calls");
    assert!(
        calls.contains("useradd --system --create-home --home-dir"),
        "{calls}"
    );
    assert!(calls.contains("--shell /bin/sh bf-backup"), "{calls}");
    assert!(calls.contains("passwd -l bf-backup"), "{calls}");
    assert!(
        calls.contains("-o bf-backup -g bf-backup") && calls.contains("var/lib/bf-backup"),
        "the backups folder belongs to bf-backup: {calls}"
    );
    for owned_by_root in [
        "chown root:root",
        "home/bf-backup/.ssh/authorized_keys",
        "usr/local/bin/bf-backup-receive",
    ] {
        assert!(calls.contains(owned_by_root), "{owned_by_root}: {calls}");
    }
    assert!(
        !calls.contains("chown bf-backup"),
        "nothing sshd or the receiver trusts may belong to bf-backup: {calls}"
    );

    assert_eq!(
        world.read("mac/known_hosts"),
        format!("{NODE} ssh-ed25519 {HOST_KEY}\n")
    );
}

#[test]
fn running_it_again_keeps_one_user_one_key_and_one_known_hosts_line() {
    let world = World::new("again");
    assert_eq!(world.good().status.code(), Some(0));
    std::fs::write(
        world.path("mac/known_hosts"),
        format!("198.51.100.185 ssh-ed25519 OTHER\n{NODE} ssh-ed25519 OLDKEY\n"),
    )
    .unwrap();
    let output = world.good();
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    assert_eq!(world.read("calls").matches("useradd").count(), 1);
    assert_eq!(
        world
            .read("node/home/bf-backup/.ssh/authorized_keys")
            .lines()
            .count(),
        1
    );
    assert_eq!(
        world.read("mac/known_hosts"),
        format!("198.51.100.185 ssh-ed25519 OTHER\n{NODE} ssh-ed25519 {HOST_KEY}\n")
    );
}

#[test]
fn a_bad_key_file_never_reaches_the_node() {
    for (case, text) in [
        (
            "two-keys",
            format!("ssh-ed25519 {VM_KEY} a\nssh-ed25519 {VM_KEY} b\n"),
        ),
        ("rsa", format!("ssh-rsa {VM_KEY} a\n")),
        (
            "options",
            format!("command=\"sh\" ssh-ed25519 {VM_KEY} a\n"),
        ),
        (
            "not-base64",
            "ssh-ed25519 AAAA\"$(reboot)\" a\n".to_string(),
        ),
        ("empty", String::new()),
    ] {
        let world = World::new(&format!("key-{case}"));
        let key = world.path("mac/bad.pub");
        std::fs::write(&key, text).unwrap();
        let output = world.run(&format!("root@{NODE}"), &key, "");
        assert_ne!(output.status.code(), Some(0), "{case}: {}", said(&output));
        assert!(!world.path("ssh_calls").exists(), "{case}");
    }
    let world = World::new("key-missing");
    let output = world.run(&format!("root@{NODE}"), &world.path("mac/none.pub"), "");
    assert_ne!(output.status.code(), Some(0));
    assert!(!world.path("ssh_calls").exists());
}

#[test]
fn a_host_that_is_not_user_at_an_ip_never_reaches_a_node() {
    for host in [
        "192.0.2.176",
        "root@toronto.example",
        "root@1.2.3",
        "-oProxyCommand=x",
    ] {
        let world = World::new("host");
        let output = world.run(host, &world.path("mac/vm-backup-key.pub"), "");
        assert_ne!(output.status.code(), Some(0), "{host}: {}", said(&output));
        assert!(!world.path("ssh_calls").exists(), "{host}");
    }
}

#[test]
fn an_sshd_that_would_keep_bf_backup_out_is_reported_and_no_host_key_is_kept() {
    for settings in [
        "allowusers root",
        "allowusers root\nallowusers lao",
        "denyusers bf-backup",
        "denyusers root\ndenyusers bf-backup",
        "allowgroups admins",
    ] {
        let world = World::new("sshd");
        let output = world.run(
            &format!("root@{NODE}"),
            &world.path("mac/vm-backup-key.pub"),
            settings,
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{settings}: {}",
            said(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("bf-backup"),
            "{settings}: {}",
            said(&output)
        );
        assert!(!world.path("mac/known_hosts").exists(), "{settings}");
    }
    let world = World::new("sshd-allowed");
    let output = world.run(
        &format!("root@{NODE}"),
        &world.path("mac/vm-backup-key.pub"),
        "allowusers root\nallowusers bf-backup",
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
}
