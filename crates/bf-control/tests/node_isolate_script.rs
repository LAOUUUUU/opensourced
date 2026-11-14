//! Runs the real `deploy/node-isolate-clients.sh` with stand-ins for `ssh`, `ip`, `iptables`
//! and `wg-quick`/`awg-quick`, on a node whose files and firewall are a scratch folder. It
//! proves what the script changes (one DROP rule for traffic that comes in and goes back out
//! of the VPN interface, first in FORWARD, and the same two lines in the interface's file so
//! a restart keeps it) and what it leaves alone (everything else, byte for byte), and that it
//! refuses to touch a node it does not understand.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/node-isolate-clients.sh")
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Toronto's file as `deploy/switch-toronto-to-amneziawg.sh` writes it, plus a peer block.
const AWG0_CONF: &str = "[Interface]
Address = 10.77.0.1/16
ListenPort = 443
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Jc = 4
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT
PostUp = iptables -I FORWARD 1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.77.0.2/32
";

/// Dallas's file: one long `PostUp` and one long `PostDown` line, the interface named in them.
const WG0_CONF: &str = "[Interface]
Address = 10.66.2.1/24, 10.77.0.1/16
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE
";

const UP: &str = "PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP";
const DOWN: &str = "PostDown = iptables -D FORWARD -i %i -o %i -j DROP";

/// A node: `dev` is the interface that has 10.77.0.1/16, `conf` its file.
struct Node {
    dir: PathBuf,
    dev: String,
    conf: PathBuf,
}

fn forward_before(dev: &str) -> Vec<String> {
    vec![
        format!("-A FORWARD -o {dev} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"),
        format!("-A FORWARD -i {dev} -j ACCEPT"),
        "-A FORWARD -j ufw-before-logging-forward".to_string(),
    ]
}

fn node(name: &str, dev: &str, conf_text: &str) -> Node {
    let dir = std::env::temp_dir().join(format!("bf-isolate-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    let conf = match dev {
        "awg0" => dir.join("node/etc/amnezia/amneziawg/awg0.conf"),
        _ => dir.join("node/etc/wireguard/wg0.conf"),
    };
    std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
    std::fs::write(&conf, conf_text).unwrap();
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("fw"), forward_before(dev).join("\n") + "\n").unwrap();

    // `ssh`: runs the script it is given on stdin right here, with /etc moved into the folder.
    // The nodes are Debian, where `sh` is dash, so dash runs it when this machine has it
    // (a Mac's `sh` is bash and forgives what dash does not).
    executable(
        &dir.join("bin/ssh"),
        r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/ssh_calls"
if command -v dash >/dev/null 2>&1; then shell=dash; else shell=sh; fi
sed "s#/etc/#$RECORD/node/etc/#g" | $shell -s
"#,
    );
    // `ip -4 addr show dev X`: only the interface the node is set up on has the address.
    executable(
        &dir.join("bin/ip"),
        r#"#!/bin/bash
if [ "$1 $2 $3 $4" = "-4 addr show dev" ]; then
  if [ "$5" = "$UP_DEV" ]; then echo "    inet 10.77.0.1/16 scope global $5"; exit 0; fi
  echo "Device \"$5\" does not exist." >&2; exit 1
fi
echo "unexpected ip $*" >&2; exit 9
"#,
    );
    // `iptables`: a chain kept in a file, one rule per line, in the format of `iptables -S`.
    executable(
        &dir.join("bin/iptables"),
        r#"#!/bin/bash
fw="$RECORD/fw"; touch "$fw"
echo "iptables $*" >> "$RECORD/iptables_calls"
op=$1; chain=$2; shift 2
case $op in
  -S) echo "-P $chain ACCEPT"; grep "^-A $chain " "$fw" || true ;;
  -C) grep -qxF -- "-A $chain $*" "$fw" ;;
  -D) line="-A $chain $*"; grep -qxF -- "$line" "$fw" || exit 1
      awk -v l="$line" '!d && $0 == l { d = 1; next } { print }' "$fw" > "$fw.new" && mv "$fw.new" "$fw" ;;
  -I) shift; { echo "-A $chain $*"; cat "$fw"; } > "$fw.new" && mv "$fw.new" "$fw" ;;
  *) echo "unexpected iptables $op" >&2; exit 9 ;;
esac
"#,
    );
    // `wg-quick strip FILE` and `awg-quick strip FILE`: like the real ones, they want a path
    // that ends in `.conf` with a short name, and they say what they were given.
    for tool in ["wg-quick", "awg-quick"] {
        executable(
            &dir.join("bin").join(tool),
            r#"#!/bin/bash
echo "$(basename "$0") $*" >> "$RECORD/quick_calls"
[ "$1" = strip ] || exit 9
case $2 in *.conf) ;; *) echo "not a .conf: $2" >&2; exit 1 ;; esac
base=$(basename "$2" .conf); [ ${#base} -le 15 ] || { echo "name too long" >&2; exit 1; }
cp -- "$2" "$RECORD/validated.conf"
[ -z "$QUICK_REJECTS" ] || { echo "parse error" >&2; exit 1; }
grep -v '^PrivateKey' "$2"
"#,
        );
    }
    Node {
        dir,
        dev: dev.to_string(),
        conf,
    }
}

impl Node {
    fn run(&self, extra: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut command = Command::new("bash");
        command
            .arg(script())
            .args(["root@node.example", "-i", "~/.ssh/key"])
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("UP_DEV", &self.dev)
            .env("TMPDIR", &self.dir)
            .stdin(std::process::Stdio::null());
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("bash starts")
    }

    fn conf_text(&self) -> String {
        std::fs::read_to_string(&self.conf).unwrap()
    }

    fn backup(&self) -> Option<String> {
        let mut name = self.conf.clone().into_os_string();
        name.push(".before-isolation");
        std::fs::read_to_string(name).ok()
    }

    fn rules(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("fw"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn mode(&self, path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn leftovers(&self) -> Vec<String> {
        std::fs::read_dir(&self.dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("tmp."))
            .collect()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn drop_rule(dev: &str) -> String {
    format!("-A FORWARD -i {dev} -o {dev} -j DROP")
}

/// `new` is `old` with exactly `UP` after its last `PostUp` line and `DOWN` after its last
/// `PostDown` line, nothing else added, moved or lost.
fn assert_only_the_two_lines_were_added(old: &str, new: &str) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    assert_eq!(new_lines.len(), old_lines.len() + 2, "{new}");

    let without: Vec<&str> = new_lines
        .iter()
        .copied()
        .filter(|l| *l != UP && *l != DOWN)
        .collect();
    assert_eq!(without, old_lines, "something else changed:\n{new}");

    let at = |line: &str| new_lines.iter().position(|l| *l == line).expect(line);
    let last = |prefix: &str, lines: &[&str]| {
        lines
            .iter()
            .rposition(|l| l.starts_with(prefix) && *l != UP && *l != DOWN)
            .unwrap()
    };
    assert!(
        at(UP) > last("PostUp = ", &new_lines),
        "the new PostUp must run after every existing one, or the ACCEPT inserted later would sit in front of it:\n{new}"
    );
    assert!(at(DOWN) > last("PostDown = ", &new_lines), "{new}");
    if let Some(peer) = new_lines.iter().position(|l| *l == "[Peer]") {
        assert!(
            at(UP) < peer && at(DOWN) < peer,
            "inside [Interface]:\n{new}"
        );
    }
}

#[test]
fn an_amneziawg_node_gets_the_rule_first_in_forward_and_in_its_file() {
    let node = node("awg", "awg0", AWG0_CONF);

    let out = node.run(&[]);

    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    let mut expected = vec![drop_rule("awg0")];
    expected.extend(forward_before("awg0"));
    assert_eq!(node.rules(), expected, "the DROP first, the rest as it was");
    assert_only_the_two_lines_were_added(AWG0_CONF, &node.conf_text());
    assert_eq!(
        node.backup().as_deref(),
        Some(AWG0_CONF),
        "a copy of the original"
    );
    assert_eq!(node.mode(&node.conf), 0o600, "the key file stays private");
    let backup = format!("{}.before-isolation", node.conf.display());
    assert_eq!(node.mode(Path::new(&backup)), 0o600, "so does its copy");
    assert!(node.leftovers().is_empty(), "{:?}", node.leftovers());
}

#[test]
fn a_plain_wireguard_node_with_long_postup_lines_gets_the_same() {
    let node = node("wg", "wg0", WG0_CONF);

    let out = node.run(&[]);

    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert_eq!(node.rules()[0], drop_rule("wg0"));
    assert_eq!(node.rules().len(), 4);
    assert_only_the_two_lines_were_added(WG0_CONF, &node.conf_text());
    let calls = std::fs::read_to_string(node.dir.join("quick_calls")).unwrap();
    assert!(calls.contains("wg-quick strip"), "{calls}");
    assert!(!calls.contains("awg-quick"), "{calls}");
}

#[test]
fn the_new_file_is_checked_before_it_replaces_the_old() {
    let node = node("order", "awg0", AWG0_CONF);

    let out = node.run(&[]);

    assert!(out.status.success(), "{}", text(&out.stderr));
    let validated = std::fs::read_to_string(node.dir.join("validated.conf")).unwrap();
    assert_eq!(
        validated,
        node.conf_text(),
        "awg-quick strip was given the text that was then installed"
    );
    assert!(validated.contains(UP));
}

#[test]
fn running_it_again_changes_nothing() {
    let node = node("again", "awg0", AWG0_CONF);
    assert!(node.run(&[]).status.success());
    let conf_once = node.conf_text();
    let rules_once = node.rules();

    let out = node.run(&[]);

    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(node.conf_text(), conf_once);
    assert_eq!(node.rules(), rules_once);
    assert_eq!(
        node.rules()
            .iter()
            .filter(|r| **r == drop_rule("awg0"))
            .count(),
        1
    );
    assert_eq!(
        node.backup().as_deref(),
        Some(AWG0_CONF),
        "the first copy is kept"
    );
    assert!(
        text(&out.stdout).contains("already"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn a_rule_that_is_there_but_not_first_is_moved_to_the_front() {
    let node = node("late", "awg0", AWG0_CONF);
    let mut late = forward_before("awg0");
    late.push(drop_rule("awg0"));
    std::fs::write(node.dir.join("fw"), late.join("\n") + "\n").unwrap();

    let out = node.run(&[]);

    assert!(out.status.success(), "{}", text(&out.stderr));
    let mut expected = vec![drop_rule("awg0")];
    expected.extend(forward_before("awg0"));
    assert_eq!(node.rules(), expected, "one copy, in front of the ACCEPT");
}

#[test]
fn a_node_without_the_vpn_address_is_refused_and_left_alone() {
    let node = node("none", "awg0", AWG0_CONF);

    let out = node.run(&[("UP_DEV", "eth0")]);

    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("10.77.0.1/16"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(node.conf_text(), AWG0_CONF);
    assert_eq!(node.rules(), forward_before("awg0"));
    assert!(node.backup().is_none());
}

#[test]
fn a_file_without_postup_and_postdown_lines_is_refused_and_left_alone() {
    let bare = "[Interface]\nAddress = 10.77.0.1/16\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n";
    let node = node("bare", "awg0", bare);

    let out = node.run(&[]);

    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("PostUp"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(node.conf_text(), bare);
    assert_eq!(
        node.rules(),
        forward_before("awg0"),
        "the live firewall too"
    );
    assert!(node.leftovers().is_empty(), "{:?}", node.leftovers());
}

#[test]
fn a_file_the_wireguard_tools_reject_is_not_installed_and_the_firewall_is_untouched() {
    let node = node("reject", "awg0", AWG0_CONF);

    let out = node.run(&[("QUICK_REJECTS", "1")]);

    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("nothing was changed"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(node.conf_text(), AWG0_CONF);
    assert_eq!(node.rules(), forward_before("awg0"));
    assert!(node.leftovers().is_empty(), "{:?}", node.leftovers());
}

#[test]
fn the_node_address_is_required() {
    let out = Command::new("bash")
        .arg(script())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();

    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("usage"), "{}", text(&out.stderr));
}
