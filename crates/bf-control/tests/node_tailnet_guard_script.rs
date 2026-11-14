//! Runs the real `deploy/node-tailnet-guard.sh` with stand-ins for `ssh`, `ip`, `iptables`,
//! `ip6tables` and `wg-quick`/`awg-quick`, on a node whose files and firewall are a scratch
//! folder. It proves what the script adds (a raw-table DROP for traffic from each VPN
//! interface to Tailscale's ranges, live and in each interface's file so a restart keeps it),
//! what it leaves alone, and that a failing firewall command changes no file. Decision 024.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/node-tailnet-guard.sh")
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Dallas's AmneziaWG file as `deploy/node-add-protocol.sh` writes it (shortened).
const AWG0_CONF: &str = "[Interface]
Address = 10.77.0.1/16
ListenPort = 443
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT
PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o %i -j DROP

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.77.0.2/32
";

/// Dallas's WireGuard file: one long PostUp and PostDown line naming the interface.
const WG0_CONF: &str = "[Interface]
Address = 10.78.0.1/16
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -i wg0 -o wg0 -j DROP
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -o wg0 -j DROP
";

const ADDED_UP: [&str; 2] = [
    "PostUp = iptables -t raw -A PREROUTING -i %i -d 100.64.0.0/10 -j DROP",
    "PostUp = ip6tables -t raw -A PREROUTING -i %i -d fd7a:115c:a1e0::/48 -j DROP",
];
const ADDED_DOWN: [&str; 2] = [
    "PostDown = iptables -t raw -D PREROUTING -i %i -d 100.64.0.0/10 -j DROP",
    "PostDown = ip6tables -t raw -D PREROUTING -i %i -d fd7a:115c:a1e0::/48 -j DROP",
];

struct Node {
    dir: PathBuf,
}

impl Node {
    fn new(name: &str) -> Node {
        let dir = std::env::temp_dir().join(format!("bf-tsguard-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        for (path, text) in [
            ("node/etc/amnezia/amneziawg/awg0.conf", AWG0_CONF),
            ("node/etc/wireguard/wg0.conf", WG0_CONF),
        ] {
            let path = dir.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // `ssh`: runs the script from stdin here, /etc moved into the folder; dash if present.
        executable(
            &dir.join("bin/ssh"),
            r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/ssh_calls"
if command -v dash >/dev/null 2>&1; then shell=dash; else shell=sh; fi
sed "s#/etc/#$RECORD/node/etc/#g" | $shell -s
"#,
        );
        // `ip link show dev X`: the interfaces in $DEVS exist.
        executable(
            &dir.join("bin/ip"),
            r#"#!/bin/bash
if [ "$1 $2 $3" = "link show dev" ]; then
  case " $DEVS " in *" $4 "*) echo "5: $4: <POINTOPOINT,UP> mtu 1420"; exit 0 ;; esac
  echo "Device \"$4\" does not exist." >&2; exit 1
fi
echo "unexpected ip $*" >&2; exit 9
"#,
        );
        // `iptables` / `ip6tables -t raw`: the raw table's PREROUTING kept in a file.
        for (tool, file) in [("iptables", "raw4"), ("ip6tables", "raw6")] {
            executable(
                &dir.join("bin").join(tool),
                &format!(
                    r#"#!/bin/bash
fw="$RECORD/{file}"; touch "$fw"
echo "{tool} $*" >> "$RECORD/fw_calls"
[ "$1 $2" = "-t raw" ] || {{ echo "unexpected {tool} $*" >&2; exit 9; }}
op=$3; chain=$4; shift 4
case $op in
  -S) echo "-P $chain ACCEPT"; grep "^-A $chain " "$fw" || true ;;
  -C) grep -qxF -- "-A $chain $*" "$fw" ;;
  -A) [ -z "$FW_FAILS" ] || {{ echo "{tool}: can't initialize table raw" >&2; exit 4; }}
      echo "-A $chain $*" >> "$fw" ;;
  *) echo "unexpected {tool} $op" >&2; exit 9 ;;
esac
"#
                ),
            );
        }
        for tool in ["wg-quick", "awg-quick"] {
            executable(
                &dir.join("bin").join(tool),
                r#"#!/bin/bash
echo "$(basename "$0") $*" >> "$RECORD/quick_calls"
[ "$1" = strip ] || exit 9
case $2 in *.conf) ;; *) echo "not a .conf: $2" >&2; exit 1 ;; esac
[ -z "$QUICK_REJECTS" ] || { echo "parse error" >&2; exit 1; }
grep -v '^PrivateKey' "$2"
"#,
            );
        }
        Node { dir }
    }

    fn run(&self, env: &[(&str, &str)]) -> Output {
        // The stand-ins and the system's own folders only, so no real firewall tool is used.
        let path = format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.dir.join("bin").display()
        );
        for real in ["/usr/bin/iptables", "/usr/sbin/iptables", "/sbin/iptables"] {
            assert!(!Path::new(real).exists(), "refusing to run: {real} is real");
        }
        let mut command = Command::new("bash");
        command
            .arg(script())
            .args(["root@node.example", "-i", "~/.ssh/key"])
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("DEVS", "wg0 awg0")
            .env("TMPDIR", &self.dir)
            .stdin(std::process::Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn conf(&self, dev: &str) -> PathBuf {
        match dev {
            "awg0" => self.dir.join("node/etc/amnezia/amneziawg/awg0.conf"),
            _ => self.dir.join("node/etc/wireguard/wg0.conf"),
        }
    }

    fn read(&self, path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    fn rules(&self, file: &str) -> Vec<String> {
        self.read(&self.dir.join(file))
            .lines()
            .map(str::to_string)
            .collect()
    }
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The file with the four lines in place: the two PostUp after the last PostUp, the two
/// PostDown after the last PostDown, nothing else changed.
fn expected(original: &str) -> String {
    let lines: Vec<&str> = original.lines().collect();
    let last_up = lines
        .iter()
        .rposition(|l| l.starts_with("PostUp = "))
        .unwrap();
    let last_down = lines
        .iter()
        .rposition(|l| l.starts_with("PostDown = "))
        .unwrap();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        out.push(line.to_string());
        if i == last_up {
            out.extend(ADDED_UP.iter().map(|s| s.to_string()));
        }
        if i == last_down {
            out.extend(ADDED_DOWN.iter().map(|s| s.to_string()));
        }
    }
    out.join("\n") + "\n"
}

#[test]
fn it_drops_vpn_traffic_to_the_tailnet_now_and_after_a_restart_on_both_interfaces() {
    let node = Node::new("both");
    let out = node.run(&[]);
    assert!(out.status.success(), "{}", said(&out));

    for dev in ["wg0", "awg0"] {
        assert!(
            node.rules("raw4")
                .contains(&format!("-A PREROUTING -i {dev} -d 100.64.0.0/10 -j DROP")),
            "{dev}: {:?}",
            node.rules("raw4")
        );
        assert!(
            node.rules("raw6").contains(&format!(
                "-A PREROUTING -i {dev} -d fd7a:115c:a1e0::/48 -j DROP"
            )),
            "{dev}: {:?}",
            node.rules("raw6")
        );
    }
    assert_eq!(node.read(&node.conf("awg0")), expected(AWG0_CONF));
    assert_eq!(node.read(&node.conf("wg0")), expected(WG0_CONF));
    for dev in ["wg0", "awg0"] {
        let conf = node.conf(dev);
        let mode = std::fs::metadata(&conf).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{dev} keeps its mode");
        let mut backup = conf.into_os_string();
        backup.push(".before-tailnet-guard");
        assert!(Path::new(&backup).exists(), "{dev} keeps a copy");
    }
    let quick = node.read(&node.dir.join("quick_calls"));
    assert!(
        quick.contains("awg-quick strip") && quick.contains("wg-quick strip"),
        "{quick}"
    );
    assert_eq!(
        node.read(&node.dir.join("ssh_calls")).lines().count(),
        1,
        "one SSH connection"
    );
}

#[test]
fn running_it_again_adds_nothing() {
    let node = Node::new("again");
    assert!(node.run(&[]).status.success());
    let (raw4, raw6) = (node.rules("raw4"), node.rules("raw6"));
    let out = node.run(&[]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(node.rules("raw4"), raw4);
    assert_eq!(node.rules("raw6"), raw6);
    assert_eq!(node.read(&node.conf("awg0")), expected(AWG0_CONF));
    assert_eq!(node.read(&node.conf("wg0")), expected(WG0_CONF));
}

#[test]
fn a_firewall_command_that_fails_or_a_file_the_tool_refuses_changes_no_file() {
    let node = Node::new("fwfails");
    let out = node.run(&[("FW_FAILS", "1")]);
    assert!(!out.status.success());
    assert_eq!(node.read(&node.conf("awg0")), AWG0_CONF);
    assert_eq!(node.read(&node.conf("wg0")), WG0_CONF);

    let node = Node::new("rejects");
    let out = node.run(&[("QUICK_REJECTS", "1")]);
    assert!(!out.status.success());
    assert_eq!(node.read(&node.conf("awg0")), AWG0_CONF);
    assert_eq!(node.read(&node.conf("wg0")), WG0_CONF);
}

#[test]
fn a_node_with_one_vpn_interface_is_guarded_on_that_one() {
    let node = Node::new("one");
    let out = node.run(&[("DEVS", "awg0")]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(node.read(&node.conf("awg0")), expected(AWG0_CONF));
    assert_eq!(node.read(&node.conf("wg0")), WG0_CONF, "no wg0 here");
    let out = node.run(&[("DEVS", "")]);
    assert!(!out.status.success(), "no VPN interface: nothing to guard");
}
