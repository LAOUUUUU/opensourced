//! Runs the real `deploy/seed-known-logins.sh` with a stand-in `ssh`: for a journal command it
//! prints that server's lines, and for the learn command it runs the real
//! `bf-control logins learn`. Spec: `specs/login-alerts.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";
const VM: &str = "root@web.example.ts.net";
const DALLAS: &str = "root@dallas.example.ts.net";
const TORONTO: &str = "root@toronto.example.ts.net";

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-seed-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["bin", "record", "home", "tmp", "vm"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let ssh = dir.join("bin/ssh");
        std::fs::write(
            &ssh,
            r#"#!/bin/bash
host=""
for word in "$@"; do case "$word" in *@*) host=$word ;; esac; done
command=${!#}
printf '%s\n' "$@" > "$RECORD/args_${host}_$RANDOM"
case "$command" in
  *"logins learn"*)
    BC_KNOWN_LOGINS="$KNOWN" "$BF_CONTROL" logins learn || exit 1
    case "$command" in *"systemctl try-restart bf-control.service"*) echo restarted >> "$RECORD/restarts" ;; esac
    ;;
  *journalctl*)
    case " $SSH_FAILS " in *" $host "*) echo "ssh: connect to host $host: timed out" >&2; exit 255 ;; esac
    cat "$RECORD/journal_$host"
    ;;
  *) echo "unexpected command: $command" >&2; exit 1 ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let line = |at: u64, from: &str| {
            format!(
                "{at}.1 h sshd-session[1]: Accepted publickey for root from {from} port 1 ssh2: ED25519 {FP}\n"
            )
        };
        for (host, text) in [
            (VM, line(1_790_000_000, "203.0.113.7")),
            (
                DALLAS,
                line(1_790_000_100, "203.0.113.8") + &line(1_790_000_200, "198.51.100.4"),
            ),
            (TORONTO, line(1_790_000_300, "2001:db8:1:2::5")),
        ] {
            std::fs::write(dir.join("record").join(format!("journal_{host}")), text).unwrap();
        }
        World { dir }
    }

    fn run(&self, env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut command = Command::new("bash");
        command
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/seed-known-logins.sh"))
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.dir.join("home"))
            .env("TMPDIR", self.dir.join("tmp"))
            .env("RECORD", self.dir.join("record"))
            .env("KNOWN", self.dir.join("vm/known-logins"))
            .env("BF_CONTROL", env!("CARGO_BIN_EXE_bf-control"))
            .env("SSH_FAILS", "")
            .current_dir(self.dir.join("home"));
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.join("record"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("args_")
            })
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect()
    }
}

#[test]
fn every_server_s_logins_go_into_the_known_file_and_the_website_restarts() {
    let world = World::new("ok");
    let out = world.run(&[]);
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        said.contains("4 logins read, 3 new pairs learned, 3 known in all"),
        "{said}"
    );
    assert_eq!(
        std::fs::read_to_string(world.dir.join("vm/known-logins")).unwrap(),
        format!("{FP}\t198.51.100.0/24\n{FP}\t2001:db8:1::/48\n{FP}\t203.0.113.0/24\n")
    );
    assert_eq!(
        std::fs::read_to_string(world.dir.join("record/restarts")).unwrap(),
        "restarted\n"
    );

    let calls = world.calls();
    assert_eq!(calls.len(), 4, "three journals and one learn: {calls:#?}");
    for call in &calls {
        let args: Vec<&str> = call.lines().collect();
        let command = args.last().unwrap();
        if args.contains(&VM) {
            assert!(
                args.contains(&"Port=22"),
                "SSH reaches the VM over Tailscale, on 22: {call}"
            );
        } else {
            assert!(
                call.contains("IdentitiesOnly=yes") && call.contains(".ssh/your_key"),
                "{call}"
            );
        }
        if command.contains("journalctl") {
            assert!(
                command.contains("--since=-90d") && command.contains("Accepted"),
                "only Accepted lines leave a server: {command}"
            );
        } else {
            assert!(
                command.starts_with("runuser -u barely-free -- "),
                "the file stays the website's: {command}"
            );
        }
    }
    for empty in ["home", "tmp"] {
        assert_eq!(
            std::fs::read_dir(world.dir.join(empty)).unwrap().count(),
            0,
            "nothing is written on the Mac ({empty})"
        );
    }
}

#[test]
fn a_server_that_cannot_be_reached_fails_the_run_and_bad_days_are_refused() {
    let world = World::new("fails");
    let out = world.run(&[("SSH_FAILS", TORONTO)]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("timed out"),
        "{out:?}"
    );

    let world = World::new("days");
    let out = world.run(&[("BF_SEED_DAYS", "90; rm -rf /")]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(world.calls().is_empty());
}
