//! Runs the real `deploy/node-tune.sh` with stand-ins for `ssh` and every program it calls on
//! a node (`sysctl`, `ethtool`, `ufw`, `timedatectl`, `systemctl`, `apt-get`, ...), on a node
//! whose `/etc` is a scratch folder. It proves what the script writes (the hand-written sysctl
//! file now kept in the repository, a boot unit for UDP GRO forwarding, a note of what it
//! changed), what it runs, that a second run changes nothing, that a failing command changes
//! no file, and that it refuses a node without an active firewall. Decision 029.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/node-tune.sh")
}

fn executable(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `/etc/sysctl.d/99-vpn.conf` exactly as Dallas and Toronto had it by hand (read 2026-11-15).
const SYSCTL_CONF: &str = include_str!("../../../deploy/node-sysctl.conf");
const SYSCTL_FILE: &str = "/etc/sysctl.d/99-vpn.conf";
const GRO_UNIT: &str = "/etc/systemd/system/bf-udp-gro.service";
const BEFORE: &str = "/etc/barely-free/node-tune.before";
const GRO_ON: &str = "ethtool -K eth0 rx-udp-gro-forwarding on rx-gro-list off";
const MODULES: &str = "/etc/modules-load.d/bf-conntrack.conf";
/// The file both servers ran before the conntrack lines (210 bytes, sha256 d083e766...).
const SERVERS_BEFORE_CONNTRACK: &str = "net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_mtu_probing = 1
";

struct Node {
    dir: PathBuf,
}

/// A node as Dallas and Toronto were on 2026-11-15, before this script: no `ethtool`, ufw
/// active and logging at `low`, the clock in India's time, and the sysctl values in force
/// (from a file the script does not know yet, so none in the scratch `/etc`).
fn node(name: &str) -> Node {
    let dir = std::env::temp_dir().join(format!("bf-tune-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("node/etc")).unwrap();
    std::fs::write(dir.join("tz"), "Asia/Kolkata\n").unwrap();
    std::fs::write(dir.join("ufw-logging"), "on (low)\n").unwrap();
    std::fs::write(dir.join("gro"), "off\n").unwrap();
    // The values in force: the same as the file, as the read-only check found them.
    std::fs::write(dir.join("sysctl-live"), live_values(SYSCTL_CONF)).unwrap();

    let bin = dir.join("bin");
    // `ssh`: runs the script it is given on stdin right here, under dash like Debian, with
    // the node's /etc moved into the scratch folder. The sysctl file sent ahead of the script
    // (up to its end marker) is passed as it is, so it arrives byte for byte.
    executable(
        &bin.join("ssh"),
        r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/calls"
if command -v dash >/dev/null 2>&1; then shell=dash; else shell=sh; fi
sed -e "/^BF_SYSCTL_END\$/,\$ s#/etc/#$RECORD/node/etc/#g" | $shell -s
"#,
    );
    let record = r#"echo "$(basename "$0") $*" >> "$RECORD/calls""#;
    executable(
        &bin.join("id"),
        &format!("#!/bin/bash\n{record}\necho \"${{FAKE_UID:-0}}\"\n"),
    );
    executable(
        &bin.join("dpkg"),
        &format!("#!/bin/bash\n{record}\n[ -e \"$RECORD/ethtool-installed\" ]\n"),
    );
    executable(
        &bin.join("apt-get"),
        &format!(
            "#!/bin/bash\n{record}\nif [ -n \"$(cat)\" ]; then echo 'apt-get read the rest of the script' >> \"$RECORD/calls\"; fi\n\
             case \" $* \" in *' install '*) touch \"$RECORD/ethtool-installed\"; \
             cp \"$RECORD/ethtool.real\" \"$RECORD/bin/ethtool\" ;; esac\n"
        ),
    );
    // `ip -o route get 1.1.1.1`: the internet is behind eth0.
    executable(
        &bin.join("ip"),
        &format!(
            "#!/bin/bash\n{record}\n[ \"$*\" = '-o route get 1.1.1.1' ] || {{ echo \"unexpected ip $*\" >&2; exit 9; }}\n\
             echo '1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.10 uid 0 \\    cache '\n"
        ),
    );
    // `sysctl`: the values in force live in a file; `-p FILE` loads one, `-n KEY` reads one.
    executable(
        &bin.join("sysctl"),
        &format!(
            r#"#!/bin/bash
{record}
live="$RECORD/sysctl-live"
case $1 in
  -p) [ -z "$SYSCTL_FAILS" ] || {{ echo "sysctl: cannot stat /proc/sys/net/foo: No such file or directory" >&2; exit 255; }}
      grep -v '^[[:space:]]*#' "$2" | grep '=' | sed 's/[[:space:]]*=[[:space:]]*/=/' >> "$live" ;;
  -n) grep "^$2=" "$live" | tail -n 1 | cut -d= -f2- ;;
  *) echo "unexpected sysctl $*" >&2; exit 9 ;;
esac
"#
        ),
    );
    // `ethtool`, once installed: `-k` shows the feature (or `[fixed]` with GRO_FIXED), `-K`
    // changes it (or fails with ETHTOOL_FAILS). Until apt-get installs it there is none.
    std::fs::write(
        dir.join("ethtool.real"),
        format!(
            r#"#!/bin/bash
{record}
case $1 in
  -k) gro=$(cat "$RECORD/gro"); [ -z "$GRO_FIXED" ] || gro="off [fixed]"
      list=off; [ ! -e "$RECORD/gro-list-on" ] || list=on
      printf 'Features for %s:\nrx-checksumming: on [fixed]\ngeneric-receive-offload: on\nrx-gro-list: %s\nrx-udp-gro-forwarding: %s\n' "$2" "$list" "$gro" ;;
  -K) [ -z "$ETHTOOL_FAILS" ] || {{ echo "Cannot change rx-udp-gro-forwarding" >&2; exit 1; }}
      [ "$*" = "-K eth0 rx-udp-gro-forwarding on rx-gro-list off" ] || {{ echo "unexpected ethtool $*" >&2; exit 9; }}
      echo on > "$RECORD/gro"; rm -f "$RECORD/gro-list-on" ;;
  *) echo "unexpected ethtool $*" >&2; exit 9 ;;
esac
"#
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        dir.join("ethtool.real"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    // `ufw status verbose` and `ufw logging off`.
    executable(
        &bin.join("ufw"),
        &format!(
            r#"#!/bin/bash
{record}
case "$*" in
  "status verbose")
    if [ -n "$UFW_INACTIVE" ]; then echo 'Status: inactive'; exit 0; fi
    printf 'Status: active\nLogging: %s\nDefault: deny (incoming), allow (outgoing), deny (routed)\n' "$(cat "$RECORD/ufw-logging")" ;;
  "logging off") [ -z "$UFW_FAILS" ] || {{ echo "ERROR: problem running" >&2; exit 1; }}
    echo off > "$RECORD/ufw-logging"; echo 'Logging disabled' ;;
  *) echo "unexpected ufw $*" >&2; exit 9 ;;
esac
"#
        ),
    );
    executable(
        &bin.join("modprobe"),
        &format!(
            "#!/bin/bash\n{record}\n[ -z \"$MODPROBE_FAILS\" ] || {{ echo 'modprobe: FATAL: Module nf_conntrack not found' >&2; exit 1; }}\n"
        ),
    );
    executable(
        &bin.join("timedatectl"),
        &format!(
            r#"#!/bin/bash
{record}
case "$*" in
  "show -p Timezone --value") cat "$RECORD/tz" ;;
  "set-timezone Etc/UTC") echo Etc/UTC > "$RECORD/tz" ;;
  *) echo "unexpected timedatectl $*" >&2; exit 9 ;;
esac
"#
        ),
    );
    // `systemctl`: records; `is-enabled` is true once `enable` ran.
    executable(
        &bin.join("systemctl"),
        &format!(
            r#"#!/bin/bash
{record}
case $1 in
  is-enabled) [ -e "$RECORD/enabled-${{@: -1}}" ] ;;
  enable) touch "$RECORD/enabled-${{@: -1}}" ;;
  *) exit 0 ;;
esac
"#
        ),
    );
    Node { dir }
}

/// `key = value` lines as the `sysctl` stand-in keeps them (`key=value`).
fn live_values(conf: &str) -> String {
    conf.lines()
        .filter(|l| !l.trim_start().starts_with('#') && l.contains('='))
        .map(|l| {
            let (k, v) = l.split_once('=').unwrap();
            format!("{}={}\n", k.trim(), v.trim())
        })
        .collect()
}

impl Node {
    fn run(&self, extra: &[(&str, &str)]) -> Output {
        // The stand-ins and the system's own folders only, so no real tool of this Mac's
        // (its own `sysctl`, a `tailscale`) is reached by a name the stand-ins lack.
        let path = format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.dir.join("bin").display()
        );
        let mut command = Command::new("bash");
        command
            .arg(script())
            .args(["root@node.example", "-i", "~/.ssh/key"])
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("TMPDIR", &self.dir)
            .env("SYSCTL_FAILS", "")
            .env("ETHTOOL_FAILS", "")
            .env("MODPROBE_FAILS", "")
            .env("GRO_FIXED", "")
            .env("UFW_FAILS", "")
            .env("UFW_INACTIVE", "")
            .stdin(std::process::Stdio::null());
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("bash starts")
    }

    /// A file on the node, with the scratch folder written back as `/`.
    fn file(&self, path: &str) -> Option<String> {
        let on_disk = self.dir.join("node").join(path.trim_start_matches('/'));
        std::fs::read_to_string(on_disk)
            .ok()
            .map(|text| text.replace(&format!("{}/node/", self.dir.display()), "/"))
    }

    fn put(&self, path: &str, text: &str) {
        let on_disk = self.dir.join("node").join(path.trim_start_matches('/'));
        std::fs::create_dir_all(on_disk.parent().unwrap()).unwrap();
        std::fs::write(on_disk, text).unwrap();
    }

    fn mode(&self, path: &str) -> u32 {
        let on_disk = self.dir.join("node").join(path.trim_start_matches('/'));
        std::fs::metadata(on_disk).unwrap().permissions().mode() & 0o777
    }

    /// Every file under the node's `/etc`, with its text, in order.
    fn etc(&self) -> Vec<(String, String)> {
        fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            let mut entries: Vec<_> = entries.map(|e| e.unwrap().path()).collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    out.push((path.display().to_string(), text));
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.dir.join("node/etc"), &mut out);
        out
    }

    fn state(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("calls"))
            .unwrap_or_default()
            .replace(&format!("{}/node/", self.dir.display()), "/")
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn called(&self, prefix: &str) -> bool {
        self.calls().iter().any(|c| c.starts_with(prefix))
    }

    fn position(&self, call: &str) -> usize {
        let calls = self.calls();
        calls
            .iter()
            .position(|c| c.starts_with(call))
            .unwrap_or_else(|| panic!("no call {call:?} in {calls:#?}"))
    }

    fn forget_calls(&self) {
        let _ = std::fs::remove_file(self.dir.join("calls"));
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn ok(out: &Output) {
    assert!(out.status.success(), "{}", said(out));
}

#[test]
fn the_sysctl_file_in_the_repository_is_the_one_the_servers_run() {
    // Brought under version control unchanged, byte for byte (the servers' 210 bytes):
    // forwarding, BBR with fq, 7.5 MB socket buffers for UDP (WireGuard), a longer input
    // queue, MTU probing. Then one change with a reason (decision 029): connection tracking,
    // which every connection through the VPN's NAT needs, from the 1 GB default of 8,192
    // entries to 65,536, with as many hash buckets as entries (the kernel's own ratio).
    assert!(
        SYSCTL_CONF.starts_with(SERVERS_BEFORE_CONNTRACK),
        "the servers' lines stay first and unchanged:\n{SYSCTL_CONF}"
    );
    let added: Vec<&str> = SYSCTL_CONF[SERVERS_BEFORE_CONNTRACK.len()..]
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert_eq!(
        added,
        [
            "net.netfilter.nf_conntrack_buckets = 65536",
            "net.netfilter.nf_conntrack_max = 65536",
        ]
    );
}

#[test]
fn a_node_gets_the_sysctl_file_udp_gro_forwarding_quiet_ufw_and_utc() {
    let node = node("fresh");

    let out = node.run(&[]);

    ok(&out);
    assert_eq!(
        node.calls()
            .iter()
            .filter(|c| c.starts_with("ssh "))
            .count(),
        1,
        "one SSH connection"
    );

    // The sysctl file, exactly the repository's, applied before it is put in place, with
    // nf_conntrack loaded first so its settings exist (now, and at boot before systemd-sysctl).
    assert_eq!(node.file(SYSCTL_FILE).as_deref(), Some(SYSCTL_CONF));
    assert_eq!(node.mode(SYSCTL_FILE), 0o644);
    assert!(node.position("modprobe nf_conntrack") < node.position("sysctl -p "));
    let modules = node.file(MODULES).unwrap();
    assert!(modules.lines().any(|l| l == "nf_conntrack"), "{modules}");
    assert_eq!(node.mode(MODULES), 0o644);

    // ethtool from Debian, without reading the rest of the script from standard input.
    let install = node.position("apt-get install -y -q ethtool");
    assert!(node.position("apt-get update -q") < install);
    assert!(
        !node.called("apt-get read the rest of the script"),
        "{:#?}",
        node.calls()
    );

    // UDP GRO forwarding on the interface that reaches the internet: now, and at every boot.
    let live = node.position(GRO_ON);
    assert_eq!(node.state("gro"), "on");
    let unit = node.file(GRO_UNIT).unwrap();
    let exec = unit
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .unwrap_or_else(|| panic!("{unit}"));
    assert!(
        exec.starts_with("ExecStart=/") && exec.ends_with(&format!("/{GRO_ON}")),
        "{unit}"
    );
    for line in [
        "Type=oneshot",
        "RemainAfterExit=yes",
        "WantedBy=multi-user.target",
    ] {
        assert!(unit.lines().any(|l| l == line), "missing {line}:\n{unit}");
    }
    assert_eq!(node.mode(GRO_UNIT), 0o644);
    assert!(live < node.position("systemctl daemon-reload"));
    assert!(
        node.position("systemctl daemon-reload")
            < node.position("systemctl enable --now bf-udp-gro.service")
    );

    // ufw keeps its rules and stops logging the internet's scans; the clock goes to UTC.
    node.position("ufw logging off");
    assert_eq!(node.state("ufw-logging"), "off");
    node.position("timedatectl set-timezone Etc/UTC");
    assert_eq!(node.state("tz"), "Etc/UTC");

    // What was there before, for the way back.
    let before = node.file(BEFORE).unwrap();
    for line in ["timezone=Asia/Kolkata", "ufw-logging=low"] {
        assert!(
            before.lines().any(|l| l == line),
            "missing {line}:\n{before}"
        );
    }

    // The checks at the end say the values in force match the file.
    let text = said(&out);
    assert!(
        text.contains("sysctl:    every value in force matches"),
        "{text}"
    );
}

#[test]
fn on_the_servers_as_they_are_the_sysctl_file_is_left_alone() {
    let node = node("servers");
    node.put(SYSCTL_FILE, SYSCTL_CONF);

    ok(&node.run(&[]));

    assert_eq!(node.file(SYSCTL_FILE).as_deref(), Some(SYSCTL_CONF));
    assert!(!node.called("sysctl -p"), "{:#?}", node.calls());
    assert!(
        node.file(&format!("{SYSCTL_FILE}.before-node-tune"))
            .is_none(),
        "nothing to keep a copy of"
    );
}

#[test]
fn a_different_sysctl_file_is_kept_as_a_copy_and_replaced() {
    let node = node("different");
    node.put(SYSCTL_FILE, "net.core.rmem_max = 212992\n");

    ok(&node.run(&[]));

    assert_eq!(node.file(SYSCTL_FILE).as_deref(), Some(SYSCTL_CONF));
    assert_eq!(
        node.file(&format!("{SYSCTL_FILE}.before-node-tune"))
            .as_deref(),
        Some("net.core.rmem_max = 212992\n")
    );
    node.position("sysctl -p ");
}

#[test]
fn the_servers_file_from_before_the_conntrack_lines_gets_them_and_keeps_a_copy() {
    let node = node("conntrack");
    node.put(SYSCTL_FILE, SERVERS_BEFORE_CONNTRACK);
    // As on the servers: the earlier run's note, unit and settings are in place.
    std::fs::write(
        node.dir.join("sysctl-live"),
        live_values(SERVERS_BEFORE_CONNTRACK),
    )
    .unwrap();

    let out = node.run(&[]);

    ok(&out);
    assert_eq!(node.file(SYSCTL_FILE).as_deref(), Some(SYSCTL_CONF));
    assert_eq!(
        node.file(&format!("{SYSCTL_FILE}.before-node-tune"))
            .as_deref(),
        Some(SERVERS_BEFORE_CONNTRACK)
    );
    assert!(node.position("modprobe nf_conntrack") < node.position("sysctl -p "));
    assert!(node.file(MODULES).is_some());
    assert!(
        said(&out).contains("sysctl:    every value in force matches"),
        "{}",
        said(&out)
    );
}

#[test]
fn running_it_again_changes_nothing_and_keeps_the_first_note_of_what_was_there() {
    let node = node("again");
    ok(&node.run(&[]));
    let before = node.etc();
    node.forget_calls();

    let out = node.run(&[]);

    ok(&out);
    assert_eq!(node.etc(), before);
    for call in [
        "apt-get",
        "sysctl -p",
        "modprobe",
        "ethtool -K",
        "ufw logging",
        "timedatectl set-timezone",
        "systemctl daemon-reload",
        "systemctl enable",
        "systemctl restart",
    ] {
        assert!(!node.called(call), "{call}: {:#?}", node.calls());
    }
    let note = node.file(BEFORE).unwrap();
    assert!(
        note.contains("timezone=Asia/Kolkata") && note.contains("ufw-logging=low"),
        "the note still says what was there before the first run:\n{note}"
    );
}

#[test]
fn a_failing_sysctl_or_ethtool_command_changes_no_file_and_nothing_else() {
    for (name, env) in [
        ("sysctlfails", "SYSCTL_FAILS"),
        ("ethtoolfails", "ETHTOOL_FAILS"),
        ("modprobefails", "MODPROBE_FAILS"),
    ] {
        let node = node(name);

        let out = node.run(&[(env, "1")]);

        assert!(!out.status.success(), "{env}: {}", said(&out));
        assert_eq!(node.etc(), Vec::new(), "{env}: no file under /etc");
        assert!(!node.called("ufw logging"), "{env}: {:#?}", node.calls());
        assert!(
            !node.called("timedatectl set-timezone"),
            "{env}: {:#?}",
            node.calls()
        );
        assert!(!node.called("systemctl"), "{env}: {:#?}", node.calls());
        assert_eq!(node.state("tz"), "Asia/Kolkata");
        assert_eq!(node.state("ufw-logging"), "on (low)");
    }
}

#[test]
fn it_refuses_without_an_active_firewall_or_root_and_changes_nothing() {
    for (name, env) in [
        ("noufw", ("UFW_INACTIVE", "1")),
        ("notroot", ("FAKE_UID", "1000")),
    ] {
        let node = node(name);

        let out = node.run(&[env]);

        assert_eq!(out.status.code(), Some(1), "{name}: {}", said(&out));
        assert_eq!(node.etc(), Vec::new(), "{name}");
        for call in [
            "apt-get",
            "sysctl -p",
            "ethtool",
            "ufw logging",
            "timedatectl set",
            "systemctl",
        ] {
            assert!(!node.called(call), "{name} {call}: {:#?}", node.calls());
        }
    }
    let node = node("noufw-says");
    let out = node.run(&[("UFW_INACTIVE", "1")]);
    assert!(said(&out).contains("ufw is not active"), "{}", said(&out));
}

#[test]
fn where_the_feature_is_fixed_it_is_left_out_and_the_rest_is_done() {
    let node = node("fixed");

    let out = node.run(&[("GRO_FIXED", "1")]);

    ok(&out);
    assert!(said(&out).contains("left out"), "{}", said(&out));
    assert!(!node.called("ethtool -K"), "{:#?}", node.calls());
    assert!(node.file(GRO_UNIT).is_none());
    assert!(!node.called("systemctl enable"), "{:#?}", node.calls());
    assert_eq!(node.file(SYSCTL_FILE).as_deref(), Some(SYSCTL_CONF));
    assert_eq!(node.state("tz"), "Etc/UTC");
    assert_eq!(node.state("ufw-logging"), "off");
}

#[test]
fn a_value_in_force_that_differs_from_the_file_fails_the_check() {
    let node = node("drift");
    node.put(SYSCTL_FILE, SYSCTL_CONF);
    // Something else set a smaller buffer after boot.
    let mut live = node.state("sysctl-live");
    live.push_str("\nnet.core.rmem_max=212992\n");
    std::fs::write(node.dir.join("sysctl-live"), live).unwrap();

    let out = node.run(&[]);

    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(
        said(&out).contains("net.core.rmem_max is 212992 here, the file says 7500000"),
        "{}",
        said(&out)
    );
}
