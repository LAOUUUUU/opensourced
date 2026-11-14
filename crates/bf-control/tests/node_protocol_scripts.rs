//! Runs the real `deploy/node-add-protocol.sh` and `deploy/node-wireguard-range.sh` against a
//! stand-in server: `ssh` runs the script's server part under `sh` with every `/etc/` and
//! `/sys/` path moved into a folder of its own, and the commands that would change the real
//! machine (`ip`, `iptables`, `systemctl`, `apt-get`, ...) are stand-ins that keep a record.
//! Two servers are modelled on the real ones (specs/dual-protocol.md): Toronto (AmneziaWG on
//! awg0, its old wg0 switched off) and Dallas (WireGuard on wg0 with 10.66 and 10.77, no
//! AmneziaWG module).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FPR: &str = "75C9DD72C799870E310542E24166F2C257290828";

fn deploy(script: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../deploy/{script}"))
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// `text` as the relocated server sees it: every `/etc/` inside `dir/node`.
fn moved(dir: &Path, text: &str) -> String {
    text.replace("/etc/", &format!("{}/node/etc/", dir.display()))
}

const AGENT_UNIT: &str = include_str!("../../../deploy/bf-agent.service");

const DALLAS_WG0: &str = "[Interface]
Address = 10.66.2.1/24, 10.77.0.1/16
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.66.2.0/24 -o eth0 -j MASQUERADE; iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.66.2.0/24 -o eth0 -j MASQUERADE; iptables -t nat -D POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
AllowedIPs = 10.66.2.2/32
";

const TORONTO_OLD_WG0: &str = "[Interface]
Address = 10.66.1.1/24, 10.77.0.1/16
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
";

const TORONTO_AWG0: &str = "[Interface]
Address = 10.77.0.1/16
ListenPort = 443
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Jc = 4
";

const CADDYFILE: &str = "{\n\timport /etc/caddy/barely-free-agent.global\n}\n\nimport /etc/caddy/barely-free-agent.caddy\n";

struct Server {
    dir: PathBuf,
}

/// A stand-in server: "toronto" or "dallas".
fn server(name: &str, which: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("bf-dual-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let node = dir.join("node");
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::create_dir_all(node.join("etc/apt/sources.list.d")).unwrap();
    std::fs::create_dir_all(node.join("etc/barely-free")).unwrap();
    write(&node.join("etc/caddy/Caddyfile"), &moved(&dir, CADDYFILE));
    let unit = node.join("etc/systemd/system/bf-agent.service");
    match which {
        "toronto" => {
            let toronto_unit = AGENT_UNIT
                .replace("wg-quick@wg0", "awg-quick@awg0")
                .replace(
                    "Environment=BF_INTERFACE=wg0",
                    "Environment=BF_INTERFACE=awg0",
                )
                .replace(
                    "Environment=BF_WG_BIN=/usr/bin/wg",
                    "Environment=BF_WG_BIN=/usr/bin/awg",
                );
            write(&unit, &moved(&dir, &toronto_unit));
            write(&node.join("etc/amnezia/amneziawg/awg0.conf"), TORONTO_AWG0);
            write(&node.join("etc/wireguard/wg0.conf"), TORONTO_OLD_WG0);
            std::fs::create_dir_all(node.join("sys/module/amneziawg")).unwrap();
            std::fs::write(dir.join("addrs"), "awg0 10.77.0.1/16\n").unwrap();
            std::fs::write(
                dir.join("active"),
                "awg-quick@awg0\nbf-agent.service\ncaddy\n",
            )
            .unwrap();
            std::fs::write(dir.join("udp"), "443\n").unwrap();
            std::fs::write(
                dir.join("nat"),
                "-A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE\n",
            )
            .unwrap();
        }
        _ => {
            write(&unit, &moved(&dir, AGENT_UNIT));
            write(&node.join("etc/wireguard/wg0.conf"), DALLAS_WG0);
            std::fs::write(dir.join("addrs"), "wg0 10.66.2.1/24\nwg0 10.77.0.1/16\n").unwrap();
            std::fs::write(
                dir.join("active"),
                "wg-quick@wg0\nbf-agent.service\ncaddy\n",
            )
            .unwrap();
            std::fs::write(dir.join("udp"), "51820\n").unwrap();
            std::fs::write(
                dir.join("nat"),
                "-A POSTROUTING -s 10.66.2.0/24 -o eth0 -j MASQUERADE\n-A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE\n",
            )
            .unwrap();
        }
    }

    let bin = dir.join("bin");
    executable(
        &bin.join("ssh"),
        r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/calls"
last="${!#}"
case "$last" in
  "sh -s") vars="" ;;
  *" sh -s") vars=${last% sh -s} ;;
  *) echo "unexpected remote command: $last" >&2; exit 9 ;;
esac
if command -v dash >/dev/null 2>&1; then shell=dash; else shell=sh; fi
sed -e "s#/etc/#$RECORD/node/etc/#g" -e "s#/sys/#$RECORD/node/sys/#g" | env $vars $shell -s
"#,
    );
    executable(
        &bin.join("ip"),
        r#"#!/bin/bash
echo "ip $*" >> "$RECORD/calls"
a="$RECORD/addrs"
case "$*" in
  "-o route get 1.1.1.1") echo "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.7 uid 0" ;;
  "-4 -o addr show") while read -r dev addr; do echo "3: $dev    inet $addr scope global $dev"; done < "$a" ;;
  "-4 addr show dev "*) grep "^$5 " "$a" | while read -r dev addr; do echo "    inet $addr scope global $dev"; done ;;
  "-brief -4 addr show dev "*) echo "$5 UNKNOWN $(grep "^$5 " "$a" | cut -d' ' -f2 | tr '\n' ' ')" ;;
  "addr add "*) [ -z "$IP_FAILS" ] || exit 1; echo "$5 $3" >> "$a" ;;
  "addr del "*) grep -vx "$5 $3" "$a" > "$a.new"; mv "$a.new" "$a" ;;
  *) echo "unexpected ip $*" >&2; exit 9 ;;
esac
"#,
    );
    executable(
        &bin.join("iptables"),
        r#"#!/bin/bash
echo "iptables $*" >> "$RECORD/calls"
[ "$1 $2" = "-t nat" ] || { echo "unexpected iptables $*" >&2; exit 9; }
f="$RECORD/nat"; op=$3; shift 3
case $op in
  -S) cat "$f" ;;
  -C) grep -qxF -- "-A $*" "$f" ;;
  -A) echo "-A $*" >> "$f" ;;
  -D) line="-A $*"; grep -qxF -- "$line" "$f" || exit 1
      awk -v l="$line" '!d && $0 == l { d = 1; next } { print }' "$f" > "$f.new" && mv "$f.new" "$f" ;;
  *) echo "unexpected iptables $op" >&2; exit 9 ;;
esac
"#,
    );
    executable(
        &bin.join("systemctl"),
        r#"#!/bin/bash
echo "systemctl $*" >> "$RECORD/calls"
a="$RECORD/active"
case "$1" in
  is-active) unit=${!#}; if [ "$2" = --quiet ]; then grep -qx "$unit" "$a"; else grep -qx "$unit" "$a" && echo active || echo inactive; fi ;;
  enable) [ -z "$ENABLE_FAILS" ] || exit 1; if [ "$2" = --now ]; then grep -qx "$3" "$a" || echo "$3" >> "$a"; fi ;;
  daemon-reload | restart | reload | start) ;;
  *) echo "unexpected systemctl $*" >&2; exit 9 ;;
esac
"#,
    );
    executable(
        &bin.join("getent"),
        r#"#!/bin/bash
echo "getent $*" >> "$RECORD/calls"
[ "$1" = group ] && grep -q "^$2:" "$RECORD/groups" 2>/dev/null
"#,
    );
    executable(
        &bin.join("groupadd"),
        r#"#!/bin/bash
echo "groupadd $*" >> "$RECORD/calls"
echo "${!#}:x:999:" >> "$RECORD/groups"
"#,
    );
    executable(
        &bin.join("ss"),
        r#"#!/bin/bash
echo "ss $*" >> "$RECORD/calls"
port=${2##*:}
grep -qx "$port" "$RECORD/udp" && echo "UNCONN 0 0 *:$port *:*" || true
"#,
    );
    executable(
        &bin.join("modprobe"),
        r#"#!/bin/bash
echo "modprobe $*" >> "$RECORD/calls"
[ -f "$RECORD/installed" ] && [ -z "$APT_BREAKS" ] || exit 1
# A modprobe that says it worked but loaded nothing.
[ -n "$MODPROBE_LIES" ] && exit 0
mkdir -p "$RECORD/node/sys/module/amneziawg"
"#,
    );
    executable(
        &bin.join("apt-get"),
        "#!/bin/bash\necho \"apt-get $*\" >> \"$RECORD/calls\"\ncase \"$*\" in *install*amneziawg-dkms*) [ -z \"$APT_INSTALL_FAILS\" ] || exit 100; touch \"$RECORD/installed\" ;; esac\n",
    );
    executable(
        &bin.join("gpg"),
        r#"#!/bin/bash
echo "gpg $*" >> "$RECORD/calls"
case "$*" in
  *--recv-keys*) ;;
  *--fingerprint*) echo "pub:-:4096:1:4166F2C257290828:1:::-:::scSC::::::23::0:"; echo "fpr:::::::::${GPG_FPR:-75C9DD72C799870E310542E24166F2C257290828}:" ;;
  *--export*) echo "THE-KEY" ;;
esac
"#,
    );
    executable(&bin.join("uname"), "#!/bin/sh\necho 6.12.116+deb13-amd64\n");
    executable(&bin.join("gpgconf"), "#!/bin/sh\nexit 0\n");
    executable(&bin.join("sleep"), "#!/bin/sh\nexit 0\n");
    executable(
        &bin.join("ufw"),
        "#!/bin/sh\necho \"ufw $*\" >> \"$RECORD/calls\"\n",
    );
    for tool in ["wg", "awg"] {
        executable(
            &bin.join(tool),
            &format!(
                "#!/bin/sh\necho \"{tool} $*\" >> \"$RECORD/calls\"\n[ \"$1\" = genkey ] && echo \"KEY-FROM-{tool}=\"\n"
            ),
        );
    }
    for quick in ["wg-quick", "awg-quick"] {
        executable(
            &bin.join(quick),
            &format!(
                "#!/bin/sh\necho \"{quick} $*\" >> \"$RECORD/calls\"\n[ -z \"$STRIP_FAILS\" ] || exit 1\n"
            ),
        );
    }
    executable(
        &bin.join("runuser"),
        "#!/bin/sh\necho \"runuser $*\" >> \"$RECORD/calls\"\n[ -z \"$CADDY_REJECTS\" ]\n",
    );
    executable(
        &bin.join("bf-agent"),
        r#"#!/bin/sh
echo "bf-agent $* listen=$BF_LISTEN" >> "$RECORD/calls"
[ "$BF_LISTEN" = 127.0.0.1:9871 ] && [ -s "$BF_SECRET_FILE" ]
"#,
    );
    Server { dir }
}

impl Server {
    fn run(&self, script: &str, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut command = Command::new("sh");
        command
            .arg(deploy(script))
            .args(args)
            .env("PATH", path)
            .env("RECORD", &self.dir)
            .env("TMPDIR", &self.dir)
            .env_remove("APT_BREAKS")
            .env_remove("MODPROBE_LIES")
            .env_remove("ENABLE_FAILS")
            .env_remove("IP_FAILS")
            .env_remove("APT_INSTALL_FAILS")
            .env_remove("CADDY_REJECTS")
            .env_remove("STRIP_FAILS")
            .env_remove("GPG_FPR");
        for (name, value) in extra {
            command.env(name, value);
        }
        command.output().expect("sh starts")
    }

    /// A file on the server, with its paths as the real server would have them.
    fn file(&self, path: &str) -> String {
        std::fs::read_to_string(self.dir.join("node").join(path.trim_start_matches('/')))
            .unwrap_or_default()
            .replace(&format!("{}/node/etc/", self.dir.display()), "/etc/")
    }

    fn exists(&self, path: &str) -> bool {
        self.dir
            .join("node")
            .join(path.trim_start_matches('/'))
            .exists()
    }

    fn record(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const DALLAS: [&str; 1] = ["root@dallas.example"];

// ---- node-wireguard-range.sh ----

#[test]
fn dallas_wireguard_moves_to_10_78_in_place_and_in_its_file_and_10_66_is_untouched() {
    let dallas = server("range", "dallas");

    let out = dallas.run("node-wireguard-range.sh", &DALLAS, &[]);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let conf = dallas.file("/etc/wireguard/wg0.conf");
    assert!(
        conf.contains("Address = 10.66.2.1/24, 10.78.0.1/16"),
        "{conf}"
    );
    assert!(
        conf.contains("-s 10.78.0.0/16 -o eth0 -j MASQUERADE"),
        "{conf}"
    );
    assert!(!conf.contains("10.77."), "{conf}");
    assert!(conf.contains("10.66.2.0/24") && conf.contains("AllowedIPs = 10.66.2.2/32"));
    assert_eq!(
        dallas.file("/etc/wireguard/wg0.conf.before-dual"),
        DALLAS_WG0
    );
    assert_eq!(
        dallas.record("addrs"),
        "wg0 10.66.2.1/24\nwg0 10.78.0.1/16\n"
    );
    assert_eq!(
        dallas.record("nat"),
        "-A POSTROUTING -s 10.66.2.0/24 -o eth0 -j MASQUERADE\n-A POSTROUTING -s 10.78.0.0/16 -o eth0 -j MASQUERADE\n"
    );
    let calls = dallas.record("calls");
    assert!(
        !calls.contains("restart"),
        "nobody is disconnected: {calls}"
    );
    assert!(
        text(&out).contains("node set-protocol"),
        "says what is next"
    );

    let again = dallas.run("node-wireguard-range.sh", &DALLAS, &[]);
    assert_eq!(again.status.code(), Some(0));
    assert!(
        text(&again).contains("already on 10.78"),
        "{}",
        text(&again)
    );
    assert_eq!(
        dallas.file("/etc/wireguard/wg0.conf"),
        conf,
        "unchanged the second time"
    );
}

#[test]
fn the_range_is_not_moved_when_wg0_is_not_running_has_no_10_77_or_would_not_parse() {
    let toronto = server("range-toronto", "toronto");
    let out = toronto.run("node-wireguard-range.sh", &["root@toronto.example"], &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "Toronto's wg0 is switched off: {}",
        text(&out)
    );
    assert_eq!(toronto.file("/etc/wireguard/wg0.conf"), TORONTO_OLD_WG0);

    let dallas = server("range-broken", "dallas");
    let out = dallas.run("node-wireguard-range.sh", &DALLAS, &[("STRIP_FAILS", "1")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert_eq!(
        dallas.file("/etc/wireguard/wg0.conf"),
        DALLAS_WG0,
        "nothing was changed"
    );
    assert_eq!(
        dallas.record("addrs"),
        "wg0 10.66.2.1/24\nwg0 10.77.0.1/16\n"
    );
    assert!(!dallas.exists("/etc/wireguard/wg0.conf.new"));
}

// ---- node-add-protocol.sh: AmneziaWG on Dallas ----

#[test]
fn amneziawg_is_refused_on_dallas_until_its_wireguard_has_moved_and_nothing_is_installed() {
    let dallas = server("awg-early", "dallas");
    let out = dallas.run(
        "node-add-protocol.sh",
        &["root@dallas.example", "amneziawg", "dallas-awg"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("node-wireguard-range.sh"),
        "{}",
        text(&out)
    );
    assert!(!dallas.exists("/etc/amnezia/amneziawg/awg0.conf"));
    assert!(!dallas.exists("/etc/systemd/system/bf-agent-amneziawg.service"));
}

#[test]
fn dallas_gets_amneziawg_on_10_77_udp_443_with_a_second_agent_and_its_caddy_name() {
    let dallas = server("awg", "dallas");
    assert_eq!(
        dallas
            .run("node-wireguard-range.sh", &DALLAS, &[])
            .status
            .code(),
        Some(0)
    );

    let out = dallas.run(
        "node-add-protocol.sh",
        &[
            "root@dallas.example",
            "amneziawg",
            "dallas-awg",
            "-i",
            "key",
        ],
        &[],
    );

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let calls = dallas.record("calls");
    assert!(calls.contains(&format!("--recv-keys {FPR}")), "{calls}");
    assert_eq!(dallas.file("/etc/apt/keyrings/amnezia.gpg"), "THE-KEY\n");
    assert!(
        dallas
            .file("/etc/apt/sources.list.d/amnezia.list")
            .contains("signed-by=")
    );
    assert!(calls.contains("amneziawg-dkms amneziawg-tools"), "{calls}");

    let conf = dallas.file("/etc/amnezia/amneziawg/awg0.conf");
    for line in [
        "Address = 10.77.0.1/16",
        "ListenPort = 443",
        "PrivateKey = KEY-FROM-awg=",
        "PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP",
        "PostUp = iptables -t nat -A POSTROUTING -s 10.77.0.0/16 -o eth0 -j MASQUERADE",
    ] {
        assert!(conf.lines().any(|l| l == line), "{line} in {conf}");
    }
    // The same parameters as every AmneziaWG config the website writes.
    let app = include_str!("../src/app.rs");
    for (conf_line, constant) in [
        ("Jc = 4", "jc: 4,"),
        ("Jmin = 40", "jmin: 40,"),
        ("Jmax = 70", "jmax: 70,"),
        ("S1 = 15", "s1: 15,"),
        ("S2 = 20", "s2: 20,"),
        ("H1 = 1000000001", "h1: 1_000_000_001,"),
        ("H2 = 1000000002", "h2: 1_000_000_002,"),
        ("H3 = 1000000003", "h3: 1_000_000_003,"),
        ("H4 = 1000000004", "h4: 1_000_000_004,"),
    ] {
        assert!(conf.lines().any(|l| l == conf_line), "{conf_line}");
        assert!(app.contains(constant), "AMNEZIA_PARAMS has {constant}");
    }
    assert!(calls.contains("ufw allow 443/udp"), "{calls}");
    assert!(dallas.record("active").contains("awg-quick@awg0"));

    let unit = dallas.file("/etc/systemd/system/bf-agent-amneziawg.service");
    for line in [
        "Environment=BF_LISTEN=127.0.0.1:9871",
        "Environment=BF_INTERFACE=awg0",
        "Environment=BF_WG_BIN=/usr/bin/awg",
        "Environment=BF_STATE_DIR=/var/lib/barely-free-dallas-awg",
        "StateDirectory=barely-free-dallas-awg",
        "LoadCredential=agent.secret:/etc/barely-free/agent-dallas-awg.secret",
        "Wants=awg-quick@awg0.service",
        "DynamicUser=yes",
        "CapabilityBoundingSet=CAP_NET_ADMIN",
    ] {
        assert!(unit.lines().any(|l| l == line), "{line} in {unit}");
    }
    assert_eq!(
        dallas.file("/etc/systemd/system/bf-agent.service"),
        AGENT_UNIT,
        "the first agent is not touched"
    );
    let secret = dallas.file("/etc/barely-free/agent-dallas-awg.secret");
    assert_eq!(secret.len(), 64, "{secret:?}");
    assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));
    let mode = std::fs::metadata(
        dallas
            .dir
            .join("node/etc/barely-free/agent-dallas-awg.secret"),
    )
    .unwrap()
    .permissions()
    .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let site = dallas.file("/etc/caddy/barely-free-agent-dallas-awg.caddy");
    assert!(site.contains("dallas-awg.agent.internal:8443 {"), "{site}");
    assert!(site.contains("reverse_proxy 127.0.0.1:9871"), "{site}");
    assert!(site.contains("tls internal"), "{site}");
    let caddyfile = dallas.file("/etc/caddy/Caddyfile");
    assert_eq!(
        caddyfile
            .matches("barely-free-agent-dallas-awg.caddy")
            .count(),
        1
    );
    assert!(
        calls.contains("bf-agent probe listen=127.0.0.1:9871"),
        "{calls}"
    );
    assert!(
        text(&out).contains("node add dallas-awg") && text(&out).contains("--protocol amneziawg"),
        "{}",
        text(&out)
    );

    // Again: everything is already there, nothing is installed or made twice.
    let before = conf.clone();
    let out = dallas.run(
        "node-add-protocol.sh",
        &["root@dallas.example", "amneziawg", "dallas-awg"],
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("already set up"), "{}", text(&out));
    assert_eq!(dallas.file("/etc/amnezia/amneziawg/awg0.conf"), before);
    assert_eq!(dallas.record("calls").matches("apt-get install").count(), 1);
    assert_eq!(
        dallas
            .file("/etc/caddy/Caddyfile")
            .matches("barely-free-agent-dallas-awg.caddy")
            .count(),
        1
    );
    assert_eq!(
        dallas.file("/etc/barely-free/agent-dallas-awg.secret"),
        secret,
        "kept"
    );
}

#[test]
fn a_wrong_signing_key_a_module_that_will_not_load_or_a_held_port_stop_it() {
    let moved = |name: &str| {
        let dallas = server(name, "dallas");
        assert_eq!(
            dallas
                .run("node-wireguard-range.sh", &DALLAS, &[])
                .status
                .code(),
            Some(0)
        );
        dallas
    };
    let args = ["root@dallas.example", "amneziawg", "dallas-awg"];

    let dallas = moved("badkey");
    let out = dallas.run(
        "node-add-protocol.sh",
        &args,
        &[("GPG_FPR", "0000000000000000000000000000000057290828")],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        !dallas.exists("/etc/apt/keyrings/amnezia.gpg"),
        "no keyring from the wrong key"
    );
    assert!(!dallas.record("calls").contains("apt-get install"));

    let dallas = moved("nomodule");
    let out = dallas.run("node-add-protocol.sh", &args, &[("APT_BREAKS", "1")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        !dallas.exists("/etc/amnezia/amneziawg/awg0.conf"),
        "no userspace fallback"
    );

    let dallas = moved("nomodule2");
    let out = dallas.run("node-add-protocol.sh", &args, &[("MODPROBE_LIES", "1")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("kernel module is not loaded"),
        "{}",
        text(&out)
    );
    assert!(
        !dallas.exists("/etc/amnezia/amneziawg/awg0.conf"),
        "no userspace fallback"
    );

    let dallas = moved("port");
    std::fs::write(dallas.dir.join("udp"), "51820\n443\n").unwrap();
    let out = dallas.run("node-add-protocol.sh", &args, &[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("UDP 443"), "{}", text(&out));
    assert!(!dallas.exists("/etc/amnezia/amneziawg/awg0.conf"));

    let dallas = moved("caddy");
    let out = dallas.run("node-add-protocol.sh", &args, &[("CADDY_REJECTS", "1")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert_eq!(
        dallas.file("/etc/caddy/Caddyfile"),
        CADDYFILE,
        "put back as it was"
    );
}

// ---- node-add-protocol.sh: WireGuard on Toronto ----

#[test]
fn toronto_gets_wireguard_on_10_78_udp_51820_with_its_own_agent_and_its_old_wg0_kept() {
    let toronto = server("wg", "toronto");

    let out = toronto.run(
        "node-add-protocol.sh",
        &["root@toronto.example", "wireguard", "toronto-wg"],
        &[],
    );

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let conf = toronto.file("/etc/wireguard/wg0.conf");
    for line in [
        "Address = 10.78.0.1/16",
        "ListenPort = 51820",
        "PrivateKey = KEY-FROM-wg=",
        "PostUp = iptables -t nat -A POSTROUTING -s 10.78.0.0/16 -o eth0 -j MASQUERADE",
        "PostUp = iptables -I FORWARD 1 -i %i -o %i -j DROP",
    ] {
        assert!(conf.lines().any(|l| l == line), "{line} in {conf}");
    }
    assert!(!conf.contains("Jc ="), "plain WireGuard");
    assert_eq!(
        toronto.file("/etc/wireguard/wg0.conf.before-dual"),
        TORONTO_OLD_WG0
    );
    assert_eq!(
        toronto.file("/etc/amnezia/amneziawg/awg0.conf"),
        TORONTO_AWG0,
        "untouched"
    );
    let calls = toronto.record("calls");
    assert!(
        !calls.contains("apt-get"),
        "WireGuard is in the kernel already"
    );
    assert!(calls.contains("ufw allow 51820/udp"), "{calls}");
    assert!(toronto.record("active").contains("wg-quick@wg0"));

    let unit = toronto.file("/etc/systemd/system/bf-agent-wireguard.service");
    for line in [
        "Environment=BF_LISTEN=127.0.0.1:9871",
        "Environment=BF_INTERFACE=wg0",
        "Environment=BF_WG_BIN=/usr/bin/wg",
        "StateDirectory=barely-free-toronto-wg",
        "Wants=wg-quick@wg0.service",
        "After=network.target wg-quick@wg0.service",
    ] {
        assert!(unit.lines().any(|l| l == line), "{line} in {unit}");
    }
    assert!(
        toronto
            .file("/etc/caddy/barely-free-agent-toronto-wg.caddy")
            .contains("toronto-wg.agent.internal:8443")
    );
}

#[test]
fn a_server_that_already_speaks_the_protocol_or_bad_arguments_change_nothing() {
    let dallas = server("same", "dallas");
    let out = dallas.run(
        "node-add-protocol.sh",
        &["root@dallas.example", "wireguard", "dallas-wg"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("already drives wg0"), "{}", text(&out));
    assert!(!dallas.exists("/etc/systemd/system/bf-agent-wireguard.service"));

    for args in [
        &["root@x.example", "openvpn", "x-wg"][..],
        &["root@x.example", "wireguard", "Toronto-WG"],
        &["root@x.example", "wireguard", "-x"],
        &["root@x.example", "wireguard"],
    ] {
        let out = dallas.run("node-add-protocol.sh", args, &[]);
        assert_ne!(out.status.code(), Some(0), "{args:?}");
    }
    assert!(
        !dallas.record("calls").contains("ssh root@x.example"),
        "no ssh was started"
    );
}

// ---- after the review (2026-11-10) ----

#[test]
fn an_interface_that_did_not_start_is_finished_by_running_again() {
    let toronto = server("enable-fails", "toronto");
    let args = ["root@toronto.example", "wireguard", "toronto-wg"];
    let out = toronto.run("node-add-protocol.sh", &args, &[("ENABLE_FAILS", "1")]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        !toronto.exists("/etc/systemd/system/bf-agent-wireguard.service"),
        "no agent for an interface that is not up"
    );

    let out = toronto.run("node-add-protocol.sh", &args, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        toronto.record("active").contains("wg-quick@wg0"),
        "started this time"
    );
    assert!(
        toronto
            .record("calls")
            .matches("ufw allow 51820/udp")
            .count()
            >= 2,
        "the port is opened again too"
    );
    assert!(toronto.exists("/etc/systemd/system/bf-agent-wireguard.service"));
}

#[test]
fn a_range_move_that_stopped_half_way_is_finished_by_running_again() {
    let dallas = server("range-half", "dallas");
    let out = dallas.run("node-wireguard-range.sh", &DALLAS, &[("IP_FAILS", "1")]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        dallas.record("addrs").contains("wg0 10.77.0.1/16"),
        "still on 10.77 live"
    );

    let out = dallas.run("node-wireguard-range.sh", &DALLAS, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        dallas.record("addrs"),
        "wg0 10.66.2.1/24\nwg0 10.78.0.1/16\n"
    );
    assert!(
        !dallas.record("nat").contains("10.77.0.0/16"),
        "{}",
        dallas.record("nat")
    );
}

#[test]
fn the_module_keeps_building_after_a_kernel_upgrade_and_a_failed_build_is_cleaned_up() {
    let dallas = server("headers", "dallas");
    assert_eq!(
        dallas
            .run("node-wireguard-range.sh", &DALLAS, &[])
            .status
            .code(),
        Some(0)
    );
    let args = ["root@dallas.example", "amneziawg", "dallas-awg"];
    let out = dallas.run("node-add-protocol.sh", &args, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        dallas.record("calls").contains("linux-headers-amd64"),
        "the headers follow new kernels"
    );
    let pin = dallas.file("/etc/apt/preferences.d/amnezia");
    assert!(
        pin.contains("Package: amneziawg*") && pin.contains("Pin-Priority: 1\n"),
        "{pin}"
    );

    let broken = server("headers-broken", "dallas");
    assert_eq!(
        broken
            .run("node-wireguard-range.sh", &DALLAS, &[])
            .status
            .code(),
        Some(0)
    );
    let out = broken.run("node-add-protocol.sh", &args, &[("APT_INSTALL_FAILS", "1")]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        broken.record("calls").contains("apt-get purge"),
        "{}",
        broken.record("calls")
    );
    assert!(
        !broken.exists("/etc/apt/sources.list.d/amnezia.list"),
        "no half-made source left"
    );
    assert!(!broken.exists("/etc/amnezia/amneziawg/awg0.conf"));
}

#[test]
fn an_agent_name_follows_the_same_rule_as_everywhere_else() {
    let toronto = server("names", "toronto");
    for bad in ["1wg", "toronto-", "Toronto-wg", &"a".repeat(33)] {
        let out = toronto.run(
            "node-add-protocol.sh",
            &["root@x.example", "wireguard", bad],
            &[],
        );
        assert_eq!(out.status.code(), Some(2), "{bad}");
    }
    assert!(
        !toronto.record("calls").contains("ssh "),
        "no ssh was started"
    );
}

#[test]
fn a_rerun_that_caddy_refuses_keeps_later_edits_to_the_caddyfile() {
    let toronto = server("caddy-rerun", "toronto");
    let args = ["root@toronto.example", "wireguard", "toronto-wg"];
    assert_eq!(
        toronto
            .run("node-add-protocol.sh", &args, &[])
            .status
            .code(),
        Some(0)
    );
    let path = toronto.dir.join("node/etc/caddy/Caddyfile");
    let edited = std::fs::read_to_string(&path).unwrap() + "# a later edit by hand\n";
    std::fs::write(&path, &edited).unwrap();

    let out = toronto.run("node-add-protocol.sh", &args, &[("CADDY_REJECTS", "1")]);

    assert_ne!(out.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        edited,
        "this run's starting point, not the first run's"
    );
}

#[test]
fn new_interfaces_clamp_tcp_and_take_the_extra_ports_from_outside_only() {
    let toronto = server("ports-wg", "toronto");
    assert_eq!(
        toronto
            .run(
                "node-add-protocol.sh",
                &["root@toronto.example", "wireguard", "toronto-wg"],
                &[]
            )
            .status
            .code(),
        Some(0)
    );
    let conf = toronto.file("/etc/wireguard/wg0.conf");
    for line in [
        "PostUp = iptables -t mangle -A FORWARD -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "PostUp = iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 51820",
        "PostUp = iptables -t nat -A PREROUTING -i eth0 -p udp --dport 123 -j REDIRECT --to-ports 51820",
        "PostDown = iptables -t nat -D PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 51820",
        "PostDown = iptables -t nat -D PREROUTING -i eth0 -p udp --dport 123 -j REDIRECT --to-ports 51820",
    ] {
        assert!(conf.lines().any(|l| l == line), "{line} in {conf}");
    }

    let dallas = server("ports-awg", "dallas");
    assert_eq!(
        dallas
            .run("node-wireguard-range.sh", &DALLAS, &[])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        dallas
            .run(
                "node-add-protocol.sh",
                &["root@dallas.example", "amneziawg", "dallas-awg"],
                &[]
            )
            .status
            .code(),
        Some(0)
    );
    let conf = dallas.file("/etc/amnezia/amneziawg/awg0.conf");
    assert!(conf.lines().any(|l| l == "PostUp = iptables -t nat -A PREROUTING -i eth0 -p udp --dport 4500 -j REDIRECT --to-ports 443"), "{conf}");
    assert!(
        !conf.contains("--dport 53 "),
        "AmneziaWG takes 4500 only: {conf}"
    );
}

#[test]
fn the_extra_ports_are_added_to_interfaces_made_before_live_and_in_their_files() {
    // Toronto's awg0 and Dallas's wg0 were made by earlier scripts.
    let toronto = server("extra-toronto", "toronto");
    let out = toronto.run("node-extra-ports.sh", &["root@toronto.example"], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let conf = toronto.file("/etc/amnezia/amneziawg/awg0.conf");
    assert!(conf.lines().any(|l| l == "PostUp = iptables -t nat -A PREROUTING -i eth0 -p udp --dport 4500 -j REDIRECT --to-ports 443"), "{conf}");
    assert!(conf.lines().any(|l| l == "PostDown = iptables -t nat -D PREROUTING -i eth0 -p udp --dport 4500 -j REDIRECT --to-ports 443"), "{conf}");
    assert!(
        toronto
            .record("nat")
            .contains("-A PREROUTING -i eth0 -p udp --dport 4500 -j REDIRECT --to-ports 443"),
        "live too"
    );
    assert!(
        !toronto.file("/etc/wireguard/wg0.conf").contains("REDIRECT"),
        "Toronto's wg0 is switched off: left alone"
    );
    assert_eq!(
        toronto.file("/etc/amnezia/amneziawg/awg0.conf.before-ports"),
        TORONTO_AWG0
    );

    let dallas = server("extra-dallas", "dallas");
    let out = dallas.run("node-extra-ports.sh", &DALLAS, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let nat = dallas.record("nat");
    for port in ["53", "123"] {
        assert!(
            nat.contains(&format!(
                "-A PREROUTING -i eth0 -p udp --dport {port} -j REDIRECT --to-ports 51820"
            )),
            "{nat}"
        );
    }

    // Again: nothing doubles.
    let out = dallas.run("node-extra-ports.sh", &DALLAS, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(dallas.record("nat").matches("--dport 53 ").count(), 1);
    assert_eq!(
        dallas
            .file("/etc/wireguard/wg0.conf")
            .matches("--dport 53 ")
            .count(),
        2,
        "one PostUp, one PostDown"
    );
}

/// Runs the server part of `deploy/deploy-agent.sh` (what follows the build and the copies)
/// against a stand-in server, with `/usr/local/bin` moved too.
fn deploy_agent_remote(server: &Server, new_unit: &str) -> Output {
    let script = std::fs::read_to_string(deploy("deploy-agent.sh")).unwrap();
    let remote = script
        .split("<<'REMOTE'\n")
        .nth(1)
        .and_then(|rest| rest.split("\nREMOTE").next())
        .expect("a REMOTE part");
    let node = server.dir.join("node");
    let moved = remote
        .replace("/etc/", &format!("{}/etc/", node.display()))
        .replace(
            "/usr/local/bin/",
            &format!("{}/usr/local/bin/", node.display()),
        )
        .replace(
            "/usr/local/lib/",
            &format!("{}/usr/local/lib/", node.display()),
        )
        .replace(
            "/tmp/bf-logins",
            &format!("{}/tmp/bf-logins", node.display()),
        );
    std::fs::create_dir_all(node.join("usr/local/bin")).unwrap();
    // What the copies put in /tmp before the remote part runs.
    for name in ["bf-logins.sh", "bf-logins.service", "bf-logins.timer"] {
        write(
            &node.join("tmp/bf-logins").join(name),
            &format!("# {name}\n"),
        );
    }
    executable(
        &node.join("usr/local/bin/bf-agent.new"),
        "#!/bin/sh\necho probed\n",
    );
    write(
        &node.join("etc/systemd/system/bf-agent.service.new"),
        &new_unit.replace("/etc/", &format!("{}/etc/", node.display())),
    );
    std::fs::write(node.join("etc/barely-free/agent.secret"), "ab".repeat(32)).unwrap();
    // Only what this deploy does counts.
    std::fs::write(server.dir.join("calls"), "").unwrap();
    let path = format!(
        "{}:{}",
        server.dir.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    let mut child = Command::new("sh")
        .arg("-s")
        .env("PATH", path)
        .env("RECORD", &server.dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(moved.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn updating_the_agent_keeps_the_interface_each_server_drives_and_restarts_both_agents() {
    // Toronto: its first agent drives awg0, and it has a WireGuard agent too.
    let toronto = server("deploy-toronto", "toronto");
    assert_eq!(
        toronto
            .run(
                "node-add-protocol.sh",
                &["root@toronto.example", "wireguard", "toronto-wg"],
                &[]
            )
            .status
            .code(),
        Some(0)
    );
    let new_unit = format!("# from this deploy\n{AGENT_UNIT}");
    let out = deploy_agent_remote(&toronto, &new_unit);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let unit = toronto.file("/etc/systemd/system/bf-agent.service");
    assert!(
        unit.starts_with("# from this deploy\n"),
        "the new unit was installed: {unit}"
    );
    for line in [
        "Environment=BF_INTERFACE=awg0",
        "Environment=BF_WG_BIN=/usr/bin/awg",
        "Wants=awg-quick@awg0.service",
        "After=network.target awg-quick@awg0.service",
    ] {
        assert!(unit.lines().any(|l| l == line), "{line} in {unit}");
    }
    let calls = toronto.record("calls");
    assert!(
        calls.contains("systemctl restart bf-agent.service"),
        "{calls}"
    );
    // The login alerts: the group, the timer, and both agents in the group before restarting.
    let group = calls
        .find("groupadd --system bf-logins")
        .expect("the group is made");
    let start = calls
        .find("systemctl start bf-logins.service")
        .expect("the timer's job runs once");
    assert!(group < start && start < calls.find("systemctl restart bf-agent.service").unwrap());
    assert!(
        calls.contains("systemctl enable --now bf-logins.timer"),
        "{calls}"
    );
    for agent in ["bf-agent.service", "bf-agent-wireguard.service"] {
        assert_eq!(
            toronto.file(&format!("/etc/systemd/system/{agent}.d/logins.conf")),
            "[Service]\nSupplementaryGroups=bf-logins\n",
            "{agent} may read the logins"
        );
    }
    assert_eq!(
        toronto.file("/usr/local/lib/barely-free/bf-logins.sh"),
        "# bf-logins.sh\n"
    );
    assert_eq!(
        toronto.file("/etc/systemd/system/bf-logins.timer"),
        "# bf-logins.timer\n"
    );
    assert!(
        calls.contains("systemctl restart bf-agent-wireguard.service"),
        "the second agent runs the new build too: {calls}"
    );

    // Dallas: the repo's unit as it is.
    let dallas = server("deploy-dallas", "dallas");
    std::fs::write(dallas.dir.join("groups"), "bf-logins:x:999:\n").unwrap();
    let out = deploy_agent_remote(&dallas, &new_unit);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        !dallas.record("calls").contains("groupadd"),
        "a group that is there is kept"
    );
    assert_eq!(
        dallas.file("/etc/systemd/system/bf-agent.service"),
        new_unit
    );
}

#[test]
fn the_scripts_are_valid_shell() {
    for script in [
        "node-add-protocol.sh",
        "node-wireguard-range.sh",
        "node-extra-ports.sh",
    ] {
        let status = Command::new("sh")
            .arg("-n")
            .arg(deploy(script))
            .status()
            .unwrap();
        assert!(status.success(), "{script}");
    }
}
