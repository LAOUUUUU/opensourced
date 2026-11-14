//! Runs the real `deploy/restore-backup.sh` with stand-ins for `ssh` and `age`.
//!
//! `fetch` must take the newest backup from a node, decrypt and unpack it, check every
//! sum in its manifest and the database's own check, refuse anything else in the archive,
//! and change nothing anywhere. `put` must stop the website before it touches the
//! database, keep the old one, put the restored database and key in place, start the
//! website again and show where each node stands. Spec: `specs/backup.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bf_control::store::Store;

const KEY_TEXT: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const NEWEST: &str = "control-20261112T083500Z.tar.age";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-restore-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [
            "bin",
            "mac",
            "node",
            "pack",
            "vm/var/lib/barely-free",
            "vm/etc/barely-free",
            "vm/root",
        ] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        // The node's backups: `ls` lists the folder `node`, `cat` gives one file.
        // The VM: everything else runs here with its folders moved into `vm/`.
        executable(
            &dir.join("bin/ssh"),
            r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/ssh_calls"
last="${!#}"
case "$*" in
  *node.example*)
    case "$last" in
      "ls -1 /var/lib/bf-backup") ls -1 "$RECORD/node" ;;
      "cat /var/lib/bf-backup/"*) echo "${last#cat /var/lib/bf-backup/}" >> "$RECORD/fetched"; cat "$RECORD/node/${last#cat /var/lib/bf-backup/}" ;;
      *) echo "unexpected node command: $last" >&2; exit 9 ;;
    esac ;;
  *vm.example*)
    if [ "$last" = "bash -s" ]; then
      sed -e "s#/var/lib/barely-free#$RECORD/vm/var/lib/barely-free#g" \
          -e "s#/etc/barely-free#$RECORD/vm/etc/barely-free#g" \
          -e "s#/root/#$RECORD/vm/root/#g" | bash -s
    else
      # Anything else gets its standard input untouched (a tar stream).
      bash -c "$(printf '%s' "$last" | sed -e "s#/root/#$RECORD/vm/root/#g")"
    fi ;;
  *) echo "unexpected host: $*" >&2; exit 9 ;;
esac
"#,
        );
        // `age -d -i IDENTITY -o OUT IN`: the stand-in's "encryption" is the prefix AGE:.
        executable(
            &dir.join("bin/age"),
            r#"#!/bin/bash
printf '%s\n' "$@" > "$RECORD/age_args"
out=""; in=""
while [ $# -gt 0 ]; do case $1 in -d) shift ;; -i|-o) [ "$1" = -o ] && out=$2; shift 2 ;; *) in=$1; shift ;; esac; done
head -c 4 "$in" | grep -q '^AGE:' || { echo "age: no identity matched" >&2; exit 1; }
tail -c +5 "$in" > "$out"
"#,
        );
        // The VM's commands that need root.
        executable(
            &dir.join("bin/systemctl"),
            "#!/bin/sh\necho \"systemctl $*\" >> \"$RECORD/vm_calls\"\n",
        );
        executable(
            &dir.join("bin/chown"),
            "#!/bin/sh\necho \"chown $*\" >> \"$RECORD/vm_calls\"\n",
        );
        executable(
            &dir.join("bin/runuser"),
            "#!/bin/sh\nshift 3\nexec \"$@\"\n",
        );
        // `bf-control node list` and `node check NAME`, as the VM's program would answer.
        executable(
            &dir.join("bin/bf-control"),
            r#"#!/bin/sh
echo "bf-control $*" >> "$RECORD/vm_calls"
case "$1 $2" in
  "node list") printf 'toronto  192.0.2.176:8443  amneziawg  enabled\ndallas  198.51.100.185:8443  wireguard  enabled\n' ;;
  "node check") echo "$3: answered"; [ "$3" = toronto ] && echo "  list: the node holds version 20, AHEAD of the database's version 14; run \`bf-control list raise 20\`" || echo "  list: the node holds version 14, the database is at version 14 (in step)" ;;
esac
"#,
        );
        std::fs::write(dir.join("mac/identity.txt"), "AGE-SECRET-KEY-1TEST\n").unwrap();
        std::fs::write(
            dir.join("vm/var/lib/barely-free/control.db"),
            "the old database",
        )
        .unwrap();
        std::fs::write(
            dir.join("vm/var/lib/barely-free/control.db-journal"),
            "old journal",
        )
        .unwrap();
        std::fs::write(dir.join("vm/etc/barely-free/control.key"), "the old key").unwrap();
        World { dir }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.dir.join(sub)
    }

    /// Puts a backup on the node: a tar of `members` (name, bytes), "encrypted".
    fn backup(&self, name: &str, members: &[(&str, Vec<u8>)]) {
        let pack = self.path("pack");
        let _ = std::fs::remove_dir_all(&pack);
        std::fs::create_dir_all(&pack).unwrap();
        let mut names = Vec::new();
        for (member, bytes) in members {
            let file = pack.join(member);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, bytes).unwrap();
            names.push(member.to_string());
        }
        let tar = Command::new("tar")
            .arg("-cf")
            .arg(self.path("pack.tar"))
            .arg("-C")
            .arg(&pack)
            .args(&names)
            .env("COPYFILE_DISABLE", "1")
            .output()
            .unwrap();
        assert!(tar.status.success());
        let mut sealed = b"AGE:".to_vec();
        sealed.extend(std::fs::read(self.path("pack.tar")).unwrap());
        std::fs::write(self.path("node").join(name), sealed).unwrap();
    }

    /// A good backup: a real database with one account, the key, a right manifest.
    fn good_backup(&self, name: &str) {
        let db_path = self.path("made.db");
        let _ = std::fs::remove_file(&db_path);
        let mut store = Store::open(&db_path).unwrap();
        store.add_account("lao", 1_000).unwrap();
        drop(store);
        let db = std::fs::read(&db_path).unwrap();
        let stamp = &name["control-".len()..name.len() - ".tar.age".len()];
        let manifest = format!(
            "made={stamp}\nsha256 {} control.db\nsha256 {} control.key\n",
            sha256(&db),
            sha256(KEY_TEXT.as_bytes())
        );
        self.backup(
            name,
            &[
                ("manifest", manifest.into_bytes()),
                ("control.db", db),
                ("control.key", KEY_TEXT.as_bytes().to_vec()),
            ],
        );
    }

    fn run(&self, args: &[&str]) -> Output {
        let path = format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.path("bin").display()
        );
        Command::new("/bin/bash")
            .arg(repo().join("deploy/restore-backup.sh"))
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("BACKUP_LOCAL_DIR", self.path("mac/restore"))
            .output()
            .unwrap()
    }

    fn fetch(&self) -> Output {
        let identity = self.path("mac/identity.txt");
        self.run(&["fetch", "root@node.example", identity.to_str().unwrap()])
    }

    fn fetched_folder(&self) -> PathBuf {
        self.path("mac/restore")
            .join(&NEWEST[..NEWEST.len() - ".tar.age".len()])
    }

    fn read(&self, sub: &str) -> String {
        std::fs::read_to_string(self.path(sub)).unwrap_or_default()
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
fn fetch_takes_the_newest_backup_checks_it_and_says_what_is_in_it() {
    let world = World::new("fetch");
    world.good_backup("control-20261110T083000Z.tar.age");
    world.good_backup(NEWEST);
    world.good_backup("control-20261111T090000Z.tar.age");
    std::fs::write(world.path("node/notes.txt"), "not a backup").unwrap();

    let output = world.fetch();
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    assert_eq!(world.read("fetched"), format!("{NEWEST}\n"));
    let folder = world.fetched_folder();
    let mode = std::fs::metadata(&folder).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let mut names: Vec<String> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [NEWEST, "control.db", "control.key", "manifest"]);
    assert_eq!(
        std::fs::read_to_string(folder.join("control.key")).unwrap(),
        KEY_TEXT
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for wanted in [
        "schema version 7",
        "1 accounts",
        "0 devices",
        "integrity ok",
    ] {
        assert!(stdout.contains(wanted), "{wanted}: {stdout}");
    }
    assert!(
        !world.path("vm_calls").exists(),
        "fetch changes nothing on any server"
    );
}

#[test]
fn fetch_refuses_a_backup_whose_sums_do_not_match() {
    let world = World::new("badsum");
    world.good_backup(NEWEST);
    // Same archive, but the key changed after the manifest was written.
    let pack = world.path("pack");
    std::fs::write(pack.join("control.key"), "a different key").unwrap();
    world.backup(
        NEWEST,
        &[
            ("manifest", std::fs::read(pack.join("manifest")).unwrap()),
            (
                "control.db",
                std::fs::read(pack.join("control.db")).unwrap(),
            ),
            ("control.key", b"a different key".to_vec()),
        ],
    );
    let output = world.fetch();
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("control.key"));
}

#[test]
fn fetch_refuses_an_archive_with_anything_else_in_it() {
    for extra in ["notes.txt", "sub/control.db"] {
        let world = World::new("extra");
        world.good_backup(NEWEST);
        let pack = world.path("pack");
        let mut members: Vec<(&str, Vec<u8>)> = ["manifest", "control.db", "control.key"]
            .iter()
            .map(|name| (*name, std::fs::read(pack.join(name)).unwrap()))
            .collect();
        members.push((extra, b"surprise".to_vec()));
        world.backup(NEWEST, &members);
        let output = world.fetch();
        assert_eq!(output.status.code(), Some(1), "{extra}: {}", said(&output));
        assert!(
            !world.fetched_folder().join("control.db").exists(),
            "{extra}: nothing is unpacked from an archive that holds more"
        );
    }
}

#[test]
fn fetch_with_no_backup_on_the_node_says_so() {
    let world = World::new("none");
    std::fs::write(world.path("node/notes.txt"), "not a backup").unwrap();
    let output = world.fetch();
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no backup"));
}

#[test]
fn fetch_with_the_wrong_identity_fails_and_keeps_nothing_plain() {
    let world = World::new("wrongkey");
    world.good_backup(NEWEST);
    let mut sealed = std::fs::read(world.path("node").join(NEWEST)).unwrap();
    sealed[0] = b'X';
    std::fs::write(world.path("node").join(NEWEST), sealed).unwrap();
    let output = world.fetch();
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(!world.fetched_folder().join("control.db").exists());
}

#[test]
fn put_stops_the_website_keeps_the_old_database_restores_and_shows_the_nodes() {
    let world = World::new("put");
    world.good_backup(NEWEST);
    assert_eq!(world.fetch().status.code(), Some(0));
    let folder = world.fetched_folder();
    let output = world.run(&["put", "root@vm.example", folder.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));

    let restored = std::fs::read(world.path("vm/var/lib/barely-free/control.db")).unwrap();
    assert_eq!(restored, std::fs::read(folder.join("control.db")).unwrap());
    assert_eq!(world.read("vm/etc/barely-free/control.key"), KEY_TEXT);
    assert!(
        !world
            .path("vm/var/lib/barely-free/control.db-journal")
            .exists()
    );
    let mut kept: Vec<String> = std::fs::read_dir(world.path("vm/var/lib/barely-free"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("control.db.before-restore-"))
        .collect();
    kept.sort();
    // The old database and, beside it, its old journal (never left next to the new one).
    assert_eq!(kept.len(), 2, "{kept:?}");
    assert_eq!(kept[1], format!("{}-journal", kept[0]));
    assert_eq!(
        world.read(&format!("vm/var/lib/barely-free/{}", kept[1])),
        "old journal"
    );
    assert_eq!(
        world.read(&format!("vm/var/lib/barely-free/{}", kept[0])),
        "the old database"
    );

    let calls = world.read("vm_calls");
    let stop = calls.find("systemctl stop bf-control").unwrap();
    let start = calls.find("systemctl start bf-control").unwrap();
    let check = calls.find("bf-control node check toronto").unwrap();
    assert!(stop < start && start < check, "{calls}");
    assert!(calls.contains("bf-control node check dallas"), "{calls}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bf-control list raise 20"), "{stdout}");
    assert!(
        !world.path("vm/root/bf-restore").exists(),
        "the staging folder is removed"
    );
}

#[test]
fn put_refuses_a_folder_that_does_not_match_its_manifest() {
    let world = World::new("put-bad");
    world.good_backup(NEWEST);
    assert_eq!(world.fetch().status.code(), Some(0));
    let folder = world.fetched_folder();
    std::fs::write(folder.join("control.key"), "edited").unwrap();
    let output = world.run(&["put", "root@vm.example", folder.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(!world.read("ssh_calls").contains("vm.example"));
    assert_eq!(
        world.read("vm/var/lib/barely-free/control.db"),
        "the old database"
    );
}
