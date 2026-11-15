//! Runs the real `deploy/bf-attention.sh` (what on a server needs Lao's attention, for the
//! admin overview) with a stand-in `apt-get` and a scratch `/run`, then reads what it wrote
//! the way the agent does. Also pins its unit, its timer and how `deploy-agent.sh` installs
//! it. Decision 031, `research/needs-attention/RESEARCH.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bf_common::attention::{FILE, MAX_ITEMS, from_file};

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

/// What `apt-get -s dist-upgrade` printed on Toronto on 2026-11-15 (one upgrade), plus a
/// new package and the lines around them.
const APT_SIM: &str = "Reading package lists...
Building dependency tree...
Calculating upgrade...
The following packages will be upgraded:
  amneziawg-dkms
1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst amneziawg-dkms [1.0.0-0~202609061402+4569c4c~ubuntu20.04.1] (1.0.0-0~202611131431+63ed35d~ubuntu20.04.1 Launchpad:20.04/focal [all])
Inst libnew1 (2.0-1 Debian:13.2/stable [amd64])
Conf amneziawg-dkms (1.0.0-0~202611131431+63ed35d~ubuntu20.04.1 Launchpad:20.04/focal [all])
";

struct World {
    dir: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        let dir = std::env::temp_dir().join(format!("bf-attn-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["bin", "state", "run"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let apt = dir.join("bin/apt-get");
        std::fs::write(
            &apt,
            r#"#!/bin/bash
printf '%s\n' "$@" > "$RECORD/apt_args"
if [ -n "$(cat)" ]; then echo read-stdin > "$RECORD/apt_stdin"; fi
[ -z "$APT_FAILS" ] || { echo "E: The package lists are broken" >&2; exit 100; }
cat "$RECORD/apt_out"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&apt, std::fs::Permissions::from_mode(0o755)).unwrap();
        World { dir }
    }

    fn run(&self, apt_out: &str, fails: bool) -> Output {
        std::fs::write(self.dir.join("apt_out"), apt_out).unwrap();
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        Command::new("bash")
            .arg(deploy("bf-attention.sh"))
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("APT_FAILS", if fails { "1" } else { "" })
            .env("BF_ATTENTION_DIR", self.dir.join("state"))
            .env("BF_RUN_DIR", self.dir.join("run"))
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    fn file(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("state").join(FILE)).ok()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ok(out: &Output) {
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn it_writes_the_reboot_flag_with_its_packages_and_the_updates_waiting_for_the_agent() {
    let w = World::new("full");
    std::fs::write(w.dir.join("run/reboot-required"), "").unwrap();
    std::fs::write(
        w.dir.join("run/reboot-required.pkgs"),
        "linux-image-6.12.117+deb13-amd64\namneziawg-dkms\namneziawg-dkms\n",
    )
    .unwrap();

    ok(&w.run(APT_SIM, false));

    let text = w.file().unwrap();
    assert_eq!(
        text,
        "reboot amneziawg-dkms\n\
         reboot linux-image-6.12.117+deb13-amd64\n\
         waiting amneziawg-dkms 1.0.0-0~202611131431+63ed35d~ubuntu20.04.1\n\
         waiting libnew1 2.0-1\n"
    );
    let news = from_file(&text, now(), now()).unwrap();
    assert!(news.reboot);
    assert_eq!(news.waiting.len(), 2);

    let mode = std::fs::metadata(w.dir.join("state").join(FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640, "the group bf-logins reads it");

    // Simulation only: no lock taken from apt-daily, no cache written, nothing read from
    // the script's own standard input.
    let args = std::fs::read_to_string(w.dir.join("apt_args")).unwrap();
    for arg in [
        "-s",
        "Debug::NoLocking=1",
        "Dir::Cache::pkgcache=",
        "dist-upgrade",
    ] {
        assert!(args.lines().any(|l| l.ends_with(arg)), "{arg}: {args}");
    }
    assert!(!w.dir.join("apt_stdin").exists());
}

#[test]
fn a_clean_server_gets_an_empty_file_and_a_flag_without_names_still_counts() {
    let w = World::new("clean");
    ok(&w.run(
        "Reading package lists...\n0 upgraded, 0 newly installed\n",
        false,
    ));
    assert_eq!(w.file().as_deref(), Some(""));

    std::fs::write(w.dir.join("run/reboot-required"), "").unwrap();
    ok(&w.run("", false));
    assert_eq!(w.file().as_deref(), Some("reboot\n"));
}

#[test]
fn at_most_fifty_lines_are_written() {
    let w = World::new("many");
    let many: String = (0..80)
        .map(|i| format!("Inst pkg{i} [1.0] (1.{i} Debian:13/stable [amd64])\n"))
        .collect();
    ok(&w.run(&many, false));
    assert_eq!(w.file().unwrap().lines().count(), MAX_ITEMS);
}

#[test]
fn when_apt_fails_the_old_file_stays_and_nothing_is_left_behind() {
    let w = World::new("aptfails");
    ok(&w.run(APT_SIM, false));
    let before = w.file().unwrap();

    let out = w.run("", true);

    assert!(!out.status.success());
    assert_eq!(
        w.file().unwrap(),
        before,
        "the old file stays (it goes stale)"
    );
    let left: Vec<_> = std::fs::read_dir(w.dir.join("state"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left.len(), 1, "no temporary file left: {left:?}");
}

#[test]
fn the_unit_runs_it_as_root_in_group_bf_logins_in_the_logins_folder_with_no_network() {
    let unit = std::fs::read_to_string(deploy("bf-attention.service")).unwrap();
    for line in [
        "Type=oneshot",
        "ExecStart=/usr/local/lib/barely-free/bf-attention.sh",
        "Group=bf-logins",
        "StateDirectory=barely-free-logins",
        "StateDirectoryMode=0750",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateNetwork=yes",
        "CapabilityBoundingSet=",
        "NoNewPrivileges=yes",
    ] {
        assert!(unit.lines().any(|l| l == line), "missing {line}:\n{unit}");
    }
    assert!(
        !unit.contains("User="),
        "root, to read apt's lists and /run"
    );
    let timer = std::fs::read_to_string(deploy("bf-attention.timer")).unwrap();
    for line in ["OnUnitActiveSec=1h", "WantedBy=timers.target"] {
        assert!(timer.lines().any(|l| l == line), "missing {line}:\n{timer}");
    }
    let script = std::fs::read_to_string(deploy("bf-attention.sh")).unwrap();
    assert!(script.contains(bf_common::logins::DIR), "{script}");
}

#[test]
fn the_agent_deploy_installs_it_and_runs_it_once_before_the_agents_restart_in_the_same_three_connections()
 {
    let text = std::fs::read_to_string(deploy("deploy-agent.sh")).unwrap();
    for needle in [
        "bf-attention.sh bf-attention.service bf-attention.timer",
        "install -m 0755 /tmp/bf-logins/bf-attention.sh /usr/local/lib/barely-free/",
        "/tmp/bf-logins/bf-attention.service /tmp/bf-logins/bf-attention.timer /etc/systemd/system/",
        "systemctl start bf-attention.service",
        "systemctl enable --now bf-attention.timer",
    ] {
        assert!(text.contains(needle), "deploy-agent.sh lacks {needle:?}");
    }
    let start = text.find("systemctl start bf-attention.service").unwrap();
    let restart = text.find("systemctl restart bf-agent.service").unwrap();
    assert!(start < restart, "written before the agents restart");
}
