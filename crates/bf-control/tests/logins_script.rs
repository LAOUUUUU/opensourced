//! Runs the real `deploy/bf-logins.sh` (each server's recent logins, for the login alerts)
//! with a stand-in `journalctl` and the real `ssh-keygen`, then reads what it wrote the way
//! the website and the agents do. Also pins its unit, its timer and how both deploy scripts
//! install it. Spec: `specs/login-alerts.md`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bf_common::logins::{DIR, KEYS_FILE, LOGINS_FILE};

const KEY_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEU9OL2rG4vZ3V6K4O3ufzIfdJZqR+pyyaK1rquK1CoB lao-test-key";
const FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";

fn deploy(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(name)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-loginsh-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["bin", "state", "root/.ssh", "home/lao/.ssh"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let journalctl = dir.join("bin/journalctl");
        std::fs::write(
            &journalctl,
            r#"#!/bin/bash
printf '%s\n' "$@" > "$RECORD/journalctl_args"
[ -z "$JOURNAL_FAILS" ] || { echo "journalctl: no access" >&2; exit 1; }
cat "$RECORD/journal"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&journalctl, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.join("root/.ssh/authorized_keys"),
            format!("# Lao\n{KEY_LINE}\n"),
        )
        .unwrap();
        World { dir }
    }

    fn run(&self, journal: &str, fails: bool) -> Output {
        std::fs::write(self.dir.join("journal"), journal).unwrap();
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        Command::new("bash")
            .arg(deploy("bf-logins.sh"))
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("JOURNAL_FAILS", if fails { "1" } else { "" })
            .env("BF_LOGINS_DIR", self.dir.join("state"))
            .env(
                "BF_KEY_FILES",
                format!(
                    "{} {}/home/*/.ssh/authorized_keys",
                    self.dir.join("root/.ssh/authorized_keys").display(),
                    self.dir.display()
                ),
            )
            .output()
            .unwrap()
    }

    fn state(&self, name: &str) -> PathBuf {
        self.dir.join("state").join(name)
    }
}

#[test]
fn it_writes_the_accepted_lines_and_the_key_names_for_the_readers() {
    let world = World::new("ok");
    let t = now();
    let journal = format!(
        "{}.1 vm sshd-session[5]: Accepted publickey for root from 203.0.113.7 port 1 ssh2: ED25519 {FP}\n\
         {}.1 vm sshd-session[6]: Failed password for root from 192.0.2.66 port 1 ssh2\n\
         {}.1 vm sshd-session[7]: Invalid user admin from 192.0.2.66 port 1\n",
        t - 60,
        t - 50,
        t - 40
    );
    let out = world.run(&journal, false);
    assert!(out.status.success(), "{out:?}");

    let args = std::fs::read_to_string(world.dir.join("journalctl_args")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(
        &args[..6],
        ["-u", "ssh", "-o", "short-unix", "--no-pager", "--quiet"]
    );
    let since: u64 = args[6].strip_prefix("--since=@").unwrap().parse().unwrap();
    assert!(since.abs_diff(t - 900) <= 5, "the last 15 minutes: {since}");

    let logins = std::fs::read_to_string(world.state(LOGINS_FILE)).unwrap();
    assert!(
        !logins.contains("192.0.2.66"),
        "only Accepted lines: {logins}"
    );
    for name in [LOGINS_FILE, KEYS_FILE] {
        let meta = std::fs::metadata(world.state(name)).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o640, "{name}");
    }
    let leftovers: Vec<_> = std::fs::read_dir(world.dir.join("state"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    let read = bf_control::logins::vm_logins(&world.dir.join("state"), now())
        .unwrap()
        .unwrap();
    assert_eq!(read.len(), 1, "{read:?}");
    assert_eq!(read[0].key.as_deref(), Some(FP));
    assert_eq!(
        read[0].key_name.as_deref(),
        Some("lao-test-key"),
        "named through ssh-keygen -lf"
    );
}

#[test]
fn when_the_journal_cannot_be_read_the_old_files_stay_and_nothing_is_left_behind() {
    let world = World::new("fails");
    std::fs::write(world.state(LOGINS_FILE), "old\n").unwrap();
    let out = world.run("", true);
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        std::fs::read_to_string(world.state(LOGINS_FILE)).unwrap(),
        "old\n",
        "left to go stale, which the readers log"
    );
    let names: Vec<_> = std::fs::read_dir(world.dir.join("state"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [LOGINS_FILE]);
}

// The timer runs every minute: a few missed runs pass before a reader calls the file stale.
const _: () = assert!(bf_common::logins::STALE_SECS >= 4 * 60);

/// The values of every uncommented `key=` line, in file order.
fn values(text: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    text.lines()
        .filter_map(|line| line.trim().strip_prefix(&prefix).map(str::to_string))
        .collect()
}

fn one(text: &str, key: &str) -> String {
    let found = values(text, key);
    assert_eq!(found.len(), 1, "{key}= should be set once, found {found:?}");
    found[0].clone()
}

#[test]
fn the_unit_runs_it_as_root_in_group_bf_logins_writing_only_its_own_folder_with_no_network() {
    let unit = std::fs::read_to_string(deploy("bf-logins.service")).unwrap();
    assert_eq!(one(&unit, "Type"), "oneshot");
    assert_eq!(
        one(&unit, "ExecStart"),
        "/usr/local/lib/barely-free/bf-logins.sh"
    );
    assert!(values(&unit, "User").is_empty(), "root reads the journal");
    assert_eq!(
        one(&unit, "Group"),
        "bf-logins",
        "so the files are the group's"
    );
    assert_eq!(
        one(&unit, "StateDirectory"),
        Path::new(DIR).file_name().unwrap().to_str().unwrap(),
        "the folder the agents and the website read"
    );
    assert_eq!(one(&unit, "StateDirectoryMode"), "0750");
    assert_eq!(one(&unit, "UMask"), "0027");
    assert_eq!(one(&unit, "ProtectSystem"), "strict");
    assert!(
        values(&unit, "ReadWritePaths").is_empty(),
        "only its own folder"
    );
    assert_eq!(one(&unit, "ProtectHome"), "read-only");
    assert_eq!(one(&unit, "PrivateNetwork"), "yes");
    assert_eq!(one(&unit, "NoNewPrivileges"), "yes");
    assert_eq!(one(&unit, "CapabilityBoundingSet"), "CAP_DAC_READ_SEARCH");
    let timer = std::fs::read_to_string(deploy("bf-logins.timer")).unwrap();
    assert_eq!(one(&timer, "OnUnitActiveSec"), "1min");
    let script = std::fs::read_to_string(deploy("bf-logins.sh")).unwrap();
    assert!(
        script.contains(DIR),
        "the script's default folder is the readers'"
    );
}

#[test]
fn both_deploy_scripts_install_it_make_the_group_and_run_it_before_the_readers_restart() {
    for (name, reader_restart, joins) in [
        (
            "deploy-web.sh",
            "systemctl restart bf-control.service",
            "usermod -a -G bf-logins barely-free",
        ),
        (
            "deploy-agent.sh",
            "systemctl restart bf-agent.service",
            "SupplementaryGroups=bf-logins",
        ),
    ] {
        let text = std::fs::read_to_string(deploy(name)).unwrap();
        for needle in [
            "bf-logins.sh",
            "bf-logins.service",
            "bf-logins.timer",
            "groupadd --system bf-logins",
            joins,
            "systemctl start bf-logins.service",
            "systemctl enable --now bf-logins.timer",
        ] {
            assert!(text.contains(needle), "{name} lacks {needle:?}");
        }
        let group = text.find("groupadd --system bf-logins").unwrap();
        let start = text.find("systemctl start bf-logins.service").unwrap();
        let restart = text.find(reader_restart).unwrap();
        assert!(
            group < start && start < restart,
            "{name}: the group, then the files, then the reader restarts"
        );
    }
}

#[test]
fn the_agent_deploy_opens_at_most_three_ssh_connections() {
    // The nodes' ufw lets an address open 6 new SSH connections in 30 s. The deploy used 5
    // once, and with any other connection in the same half minute the last one was refused
    // (2026-11-12). Every connection names "$host.
    let text = std::fs::read_to_string(deploy("deploy-agent.sh")).unwrap();
    let connections = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.contains("\"$host"))
        .count();
    assert_eq!(
        connections, 3,
        "the binary, the other files, the remote part"
    );
    for name in [
        "bf-agent.service",
        "bf-logins.sh",
        "bf-logins.service",
        "bf-logins.timer",
    ] {
        assert!(text.contains(name), "deploy-agent.sh sends {name}");
    }
}
