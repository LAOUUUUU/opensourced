//! Runs the real `deploy/node-resolver.sh` with stand-ins for `ssh` and for every program
//! it calls on a node, on a node whose `/etc`, `/var/lib` and `/usr/local` are a scratch
//! folder (`specs/trackers.md`). It proves what the script writes (the resolver's
//! configuration, the redirect table, the daily list update, the switch in every agent),
//! what it runs and in which order, that a second run changes and restarts nothing, and
//! that it refuses to touch a node it cannot set up.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/node-resolver.sh")
}

fn executable(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Node {
    dir: PathBuf,
}

/// A Debian node with both protocols' agents (`specs/dual-protocol.md`), Debian's own
/// unbound remote-control file, and no resolver installed yet.
fn node(name: &str) -> Node {
    let dir = std::env::temp_dir().join(format!("bf-resolver-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let n = dir.join("node");
    for unit in ["bf-agent.service", "bf-agent-wireguard.service"] {
        let path = n.join("etc/systemd/system").join(unit);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "[Service]\nExecStart=/usr/local/bin/bf-agent\n").unwrap();
    }
    std::fs::create_dir_all(n.join("etc/unbound/unbound.conf.d")).unwrap();
    std::fs::write(
        n.join("etc/unbound/unbound.conf.d/remote-control.conf"),
        "remote-control:\n  control-enable: yes\n  control-interface: /run/unbound.ctl\n",
    )
    .unwrap();
    // An agent new enough to build the list.
    executable(
        &n.join("usr/local/bin/bf-agent"),
        "#!/bin/sh\necho \"bf-agent $*\" >> \"$RECORD/calls\"\n\
         echo 'usage: bf-agent [probe | trackers build <list> <allow file> <zone file>]' >&2\nexit 2\n",
    );

    let bin = dir.join("bin");
    // `ssh`: runs the script it is given on stdin right here, under dash like Debian, with
    // the node's folders moved into the scratch folder.
    executable(
        &bin.join("ssh"),
        r#"#!/bin/bash
echo "ssh $*" >> "$RECORD/calls"
sed -e "s#/etc/#$RECORD/node/etc/#g" -e "s#/var/lib/#$RECORD/node/var/lib/#g" \
    -e "s#/usr/local/#$RECORD/node/usr/local/#g" | dash -s
"#,
    );
    // Every other program records what it was asked, in one list, in order.
    let record = r#"echo "$(basename "$0") $*" >> "$RECORD/calls""#;
    executable(
        &bin.join("id"),
        &format!("#!/bin/bash\n{record}\necho \"${{FAKE_UID:-0}}\"\n"),
    );
    executable(
        &bin.join("dpkg"),
        &format!("#!/bin/bash\n{record}\n[ -e \"$RECORD/installed\" ]\n"),
    );
    executable(
        &bin.join("apt-get"),
        &format!(
            "#!/bin/bash\n{record}\nif [ -n \"$(cat)\" ]; then echo 'apt-get read the rest of the script' >> \"$RECORD/calls\"; fi\n\
             case \" $* \" in *' install '*) touch \"$RECORD/installed\" ;; esac\n"
        ),
    );
    // `systemctl start bf-trackers-update.service` stands for a fetch that worked: two names
    // land in the zone. With RESTART_FAILS set, the first `restart unbound` fails.
    executable(
        &bin.join("systemctl"),
        &format!(
            "#!/bin/bash\n{record}\nif [ \"$1 $2\" = 'start bf-trackers-update.service' ]; then\n  \
             printf 'dead.example CNAME .\\n*.dead.example CNAME .\\ntracker.example CNAME .\\n*.tracker.example CNAME .\\n' \
             >> \"$RECORD/node/var/lib/unbound/barely-free-trackers.rpz\"\nfi\n\
             if [ \"$1 $2\" = 'restart unbound' ] && [ -n \"$RESTART_FAILS\" ] && [ ! -e \"$RECORD/failed-once\" ]; then\n  \
             touch \"$RECORD/failed-once\"; exit 1\nfi\nexit 0\n"
        ),
    );
    executable(
        &bin.join("unbound-checkconf"),
        &format!(
            "#!/bin/bash\n{record}\n[ -z \"$CHECKCONF_FAILS\" ] || {{ echo 'syntax error' >&2; exit 1; }}\n"
        ),
    );
    executable(
        &bin.join("unbound-control"),
        &format!("#!/bin/bash\n{record}\n"),
    );
    executable(&bin.join("nft"), &format!("#!/bin/bash\n{record}\n"));
    executable(
        &bin.join("ufw"),
        &format!(
            "#!/bin/bash\n{record}\n[ \"$1\" != status ] || {{ [ -n \"$UFW_INACTIVE\" ] && echo 'Status: inactive' || echo 'Status: active'; }}\n"
        ),
    );
    // Both in-tunnel addresses are up.
    executable(
        &bin.join("ip"),
        "#!/bin/bash\nprintf '4: awg0    inet 10.77.0.1/16 scope global awg0\\n'\n\
         printf '5: wg0    inet 10.78.0.1/16 scope global wg0\\n'\n",
    );
    // `dig`: `dead.example` does not exist anywhere; any other listed name exists upstream
    // (localhost, which has no tag), is NXDOMAIN on 53 and resolves on 5300, unless
    // DIG_5300_BLOCKS makes 5300 block too (the two ports sharing the tag).
    executable(
        &bin.join("dig"),
        &format!(
            r#"#!/bin/bash
{record}
args=" $* "
case $args in
  *' +short '*) echo 192.0.2.10; exit 0 ;;
esac
case $args in
  *' dead.example '*) status=NXDOMAIN ;;
  *' @127.0.0.1 '*) status=NOERROR ;;
  *' -p 5300 '*) if [ -n "$DIG_5300_BLOCKS" ]; then status=NXDOMAIN; else status=NOERROR; fi ;;
  *) status=NXDOMAIN ;;
esac
echo ";; ->>HEADER<<- opcode: QUERY, status: $status, id: 1"
"#
        ),
    );
    executable(&bin.join("chown"), &format!("#!/bin/bash\n{record}\n"));
    Node { dir }
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
            .env("TMPDIR", &self.dir)
            .env("CHECKCONF_FAILS", "")
            .env("RESTART_FAILS", "")
            .env("UFW_INACTIVE", "")
            .env("DIG_5300_BLOCKS", "")
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

    fn mode(&self, path: &str) -> u32 {
        let on_disk = self.dir.join("node").join(path.trim_start_matches('/'));
        std::fs::metadata(on_disk).unwrap().permissions().mode() & 0o777
    }

    /// Every call, with the scratch folder written back as `/`.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("calls"))
            .unwrap_or_default()
            .replace(&format!("{}/node/", self.dir.display()), "/")
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn forget_calls(&self) {
        let _ = std::fs::remove_file(self.dir.join("calls"));
    }

    fn position(&self, call: &str) -> usize {
        let calls = self.calls();
        calls
            .iter()
            .position(|c| c == call)
            .unwrap_or_else(|| panic!("no call {call:?} in {calls:#?}"))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn ok(out: &Output) {
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

const UNBOUND_CONF: &str = "/etc/unbound/unbound.conf.d/barely-free.conf";
const NFT_FILE: &str = "/etc/barely-free/dns-redirect.nft";
const ZONE: &str = "/var/lib/unbound/barely-free-trackers.rpz";

#[test]
fn a_fresh_node_gets_the_resolver_the_redirect_the_daily_list_and_the_switch_in_every_agent() {
    let node = node("fresh");

    let out = node.run(&[]);

    ok(&out);
    // unbound from Debian, with dig for the checks.
    let install = node.position("apt-get install -y -q unbound bind9-dnsutils");
    assert!(
        !node
            .calls()
            .iter()
            .any(|c| c == "apt-get read the rest of the script"),
        "apt-get must not read the script from standard input"
    );
    assert!(node.position("apt-get update -q") < install);

    // The resolver: only on localhost and the two in-tunnel addresses; the tracker tag on
    // port 53, none on 5300; nothing about queries logged; the zone limited to the tag.
    let conf = node.file(UNBOUND_CONF).unwrap();
    for line in [
        "    interface: 127.0.0.1",
        "    interface: 10.77.0.1@53",
        "    interface: 10.77.0.1@5300",
        "    interface: 10.78.0.1@53",
        "    interface: 10.78.0.1@5300",
        "    ip-freebind: yes",
        "    interface-action: 10.77.0.1@53 allow",
        "    interface-action: 10.77.0.1@5300 allow",
        "    interface-action: 10.78.0.1@53 allow",
        "    interface-action: 10.78.0.1@5300 allow",
        "    define-tag: \"trackers\"",
        "    interface-tag: 10.77.0.1@53 \"trackers\"",
        "    interface-tag: 10.78.0.1@53 \"trackers\"",
        "    module-config: \"respip validator iterator\"",
        "    log-queries: no",
        "    log-replies: no",
        // RFC 8767 (decision 029): an expired name is fetched first; the stale answer is
        // used only if the fetch takes longer than 1.8 s, and never once an hour old (a longer
        // window would keep a name Quad9 has just started blocking alive, decision 022).
        "    serve-expired: yes",
        "    serve-expired-ttl: 3600",
        "    serve-expired-client-timeout: 1800",
        "    prefetch: yes",
        "    forward-tls-upstream: yes",
        // Quad9's threat-blocking resolver (decision 022): it already refused the domain that
        // delivered an infostealer, which Cloudflare's 1.1.1.1 serves.
        "    forward-addr: 9.9.9.9@853#dns.quad9.net",
        "    forward-addr: 149.112.112.112@853#dns.quad9.net",
        "    name: trackers.rpz.barely-free",
        "    zonefile: /var/lib/unbound/barely-free-trackers.rpz",
        "    tags: \"trackers\"",
        "    rpz-log: no",
    ] {
        assert!(conf.lines().any(|l| l == line), "missing {line:?}:\n{conf}");
    }
    assert!(!conf.contains("0.0.0.0"), "never on every address:\n{conf}");
    assert!(
        !conf.contains("cloudflare-dns.com") && !conf.contains("1.1.1.1@"),
        "one upstream only, so every lookup gets the same blocking:\n{conf}"
    );
    assert!(
        !conf.contains("interface-tag: 10.77.0.1@5300") && !conf.contains("@5300 \"trackers\""),
        "{conf}"
    );
    assert!(
        !conf.contains("remote-control:"),
        "Debian's own remote-control file is there already:\n{conf}"
    );
    assert_eq!(node.mode(UNBOUND_CONF), 0o644);

    // A zone exists before unbound starts with the new configuration, the configuration is
    // checked before unbound restarts, and the first list is fetched after that.
    assert!(node.file(ZONE).unwrap().contains("@ SOA "));
    let checked = node.position("unbound-checkconf ");
    let restarted = node.position("systemctl restart unbound");
    let fetched = node.position("systemctl start bf-trackers-update.service");
    assert!(
        checked < restarted && restarted < fetched,
        "{:#?}",
        node.calls()
    );
    assert!(
        node.position("systemctl daemon-reload") < fetched,
        "the update unit is known to systemd before it is started"
    );

    // The allow file, empty but explained; never overwritten (see the second-run test).
    let allow = node.file("/etc/barely-free/trackers-allow.txt").unwrap();
    assert!(
        allow.lines().all(|l| l.is_empty() || l.starts_with('#')),
        "{allow}"
    );

    // The daily update: download with limits, build, reload only this zone.
    let update = node.file("/usr/local/sbin/bf-trackers-update").unwrap();
    for part in [
        "https://easylist.to/easylist/easyprivacy.txt",
        "--fail",
        "--max-time",
        "--max-filesize",
        "--proto =https",
        "--proto-redir =https",
        "/usr/local/bin/bf-agent trackers build",
        "/etc/barely-free/trackers-allow.txt",
        "unbound-control auth_zone_reload trackers.rpz.barely-free",
    ] {
        assert!(update.contains(part), "missing {part:?}:\n{update}");
    }
    assert_eq!(node.mode("/usr/local/sbin/bf-trackers-update"), 0o755);
    let timer = node
        .file("/etc/systemd/system/bf-trackers-update.timer")
        .unwrap();
    assert!(timer.contains("OnCalendar=daily"), "{timer}");
    assert!(timer.contains("RandomizedDelaySec="), "{timer}");
    node.position("systemctl enable --now bf-trackers-update.timer");

    // The redirect: the two sets and the rules, loaded now and at every boot.
    let nft = node.file(NFT_FILE).unwrap();
    for part in [
        "set off_awg0 { type ipv4_addr; }",
        "set off_wg0 { type ipv4_addr; }",
        "type nat hook prerouting priority dstnat; policy accept;",
        "flush chain inet barely_free_dns prerouting",
        "iifname \"awg0\" ip daddr 10.77.0.1 ip saddr @off_awg0 udp dport 53 dnat ip to 10.77.0.1:5300",
        "iifname \"awg0\" ip daddr 10.77.0.1 ip saddr @off_awg0 tcp dport 53 dnat ip to 10.77.0.1:5300",
        "iifname \"wg0\" ip daddr 10.78.0.1 ip saddr @off_wg0 udp dport 53 dnat ip to 10.78.0.1:5300",
        "iifname \"wg0\" ip daddr 10.78.0.1 ip saddr @off_wg0 tcp dport 53 dnat ip to 10.78.0.1:5300",
    ] {
        assert!(nft.contains(part), "missing {part:?}:\n{nft}");
    }
    assert!(
        !nft.contains("flush set") && !nft.contains("flush table") && !nft.contains("delete"),
        "loading it again must never empty the agents' sets:\n{nft}"
    );
    // `redirect` would send to the interface's first address, which on Dallas's wg0 was
    // 10.66.2.1: the address is named instead.
    assert!(!nft.contains("redirect"), "{nft}");
    let checked_nft = node.position(&format!("nft -c -f {NFT_FILE}.next"));
    assert!(checked_nft < node.position(&format!("nft -f {NFT_FILE}")));
    let unit = node
        .file("/etc/systemd/system/bf-dns-redirect.service")
        .unwrap();
    assert!(
        unit.contains(&format!("ExecStart=/usr/sbin/nft -f {NFT_FILE}")),
        "{unit}"
    );
    let before = unit
        .lines()
        .find(|l| l.starts_with("Before="))
        .unwrap_or("");
    for agent in [
        "bf-agent.service",
        "bf-agent-wireguard.service",
        "bf-agent-amneziawg.service",
    ] {
        assert!(before.split(' ').any(|u| u.ends_with(agent)), "{unit}");
    }
    node.position("systemctl enable bf-dns-redirect.service");

    // The firewall: 53 and 5300, both protocols, on each VPN interface only.
    for (dev, address) in [("awg0", "10.77.0.1"), ("wg0", "10.78.0.1")] {
        for port in ["53", "5300"] {
            for proto in ["udp", "tcp"] {
                node.position(&format!(
                    "ufw allow in on {dev} to {address} port {port} proto {proto}"
                ));
            }
        }
    }

    // Every agent gets the switch, then a restart, after the table exists.
    let loaded = node.position(&format!("nft -f {NFT_FILE}"));
    for agent in ["bf-agent.service", "bf-agent-wireguard.service"] {
        let dropin = node
            .file(&format!("/etc/systemd/system/{agent}.d/trackers.conf"))
            .unwrap();
        assert!(dropin.contains("Environment=BF_TRACKERS=nft"), "{dropin}");
        assert!(
            dropin.contains("Environment=BF_NFT_BIN=/usr/sbin/nft"),
            "{dropin}"
        );
        assert!(dropin.contains("After=bf-dns-redirect.service"), "{dropin}");
        assert!(loaded < node.position(&format!("systemctl restart {agent}")));
    }
    node.position("systemctl daemon-reload");

    // The checks at the end, on both addresses.
    let said = text(&out.stdout);
    for address in ["10.77.0.1", "10.78.0.1"] {
        assert!(
            said.contains(&format!(
                "{address}: resolves, blocks tracker.example on 53, not on 5300"
            )),
            "{said}"
        );
    }
    let update = node
        .file("/etc/systemd/system/bf-trackers-update.service")
        .unwrap();
    for line in [
        "ProtectSystem=strict",
        "ReadWritePaths=/var/lib/unbound",
        "NoNewPrivileges=yes",
        // unbound-control lists the interfaces in the configuration (getifaddrs, netlink);
        // without AF_NETLINK it fails and the list is never reloaded (seen on Dallas).
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
    ] {
        assert!(
            update.lines().any(|l| l == line),
            "missing {line}:\n{update}"
        );
    }
}

#[test]
fn running_it_again_changes_nothing_and_restarts_nothing() {
    let node = node("again");
    ok(&node.run(&[]));
    std::fs::write(
        node.dir.join("node/etc/barely-free/trackers-allow.txt"),
        "# mine\nbroken-site.example\n",
    )
    .unwrap();
    let before: Vec<Option<String>> = [UNBOUND_CONF, NFT_FILE, ZONE]
        .iter()
        .map(|f| node.file(f))
        .collect();
    node.forget_calls();

    let out = node.run(&[]);

    ok(&out);
    let after: Vec<Option<String>> = [UNBOUND_CONF, NFT_FILE, ZONE]
        .iter()
        .map(|f| node.file(f))
        .collect();
    assert_eq!(after, before);
    assert_eq!(
        node.file("/etc/barely-free/trackers-allow.txt").unwrap(),
        "# mine\nbroken-site.example\n",
        "the allow file is Lao's once it exists"
    );
    let calls = node.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("apt-get")
            || c.starts_with("systemctl restart")
            || c.starts_with("systemctl start")),
        "{calls:#?}"
    );
}

#[test]
fn it_refuses_without_root_or_with_an_agent_too_old_to_build_the_list_and_changes_nothing() {
    let not_root = node("notroot");
    let out = not_root.run(&[("FAKE_UID", "1000")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("as root"),
        "{}",
        text(&out.stderr)
    );
    assert!(not_root.file(UNBOUND_CONF).is_none());
    assert!(!not_root.calls().iter().any(|c| c.starts_with("apt-get")));

    let old = node("oldagent");
    executable(
        &old.dir.join("node/usr/local/bin/bf-agent"),
        "#!/bin/sh\necho 'usage: bf-agent [probe]' >&2\nexit 2\n",
    );
    let out = old.run(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("deploy/deploy-agent.sh"),
        "{}",
        text(&out.stderr)
    );
    assert!(old.file(UNBOUND_CONF).is_none());
    assert!(!old.calls().iter().any(|c| c.starts_with("apt-get")));
}

#[test]
fn without_an_active_firewall_it_changes_nothing() {
    let node = node("noufw");
    let out = node.run(&[("UFW_INACTIVE", "1")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("ufw"), "{}", text(&out.stderr));
    assert!(node.file(UNBOUND_CONF).is_none());
    assert!(!node.calls().iter().any(|c| c.starts_with("apt-get")));
}

#[test]
fn if_unbound_will_not_start_on_the_new_configuration_the_old_one_comes_back() {
    let node = node("norestart");

    let out = node.run(&[("RESTART_FAILS", "1")]);

    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("would not start"),
        "{}",
        text(&out.stderr)
    );
    assert!(node.file(UNBOUND_CONF).is_none(), "a fresh node had none");
    let restarts = node
        .calls()
        .iter()
        .filter(|c| *c == "systemctl restart unbound")
        .count();
    assert_eq!(restarts, 2, "once with the new one, once with the old");
}

#[test]
fn the_check_fails_when_port_5300_blocks_too() {
    let node = node("sharedtag");

    let out = node.run(&[("DIG_5300_BLOCKS", "1")]);

    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("10.77.0.1: port 5300 blocks tracker.example too"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn a_configuration_unbound_refuses_is_taken_back_and_nothing_restarts() {
    let node = node("badconf");

    let out = node.run(&[("CHECKCONF_FAILS", "1")]);

    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("unbound-checkconf"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        node.file(UNBOUND_CONF).is_none(),
        "the new file is removed again"
    );
    assert!(
        !node
            .calls()
            .iter()
            .any(|c| c.starts_with("systemctl restart")),
        "{:#?}",
        node.calls()
    );
}

#[test]
fn the_daily_update_builds_from_the_download_and_reloads_only_after_a_good_build() {
    let node = node("update");
    ok(&node.run(&[]));
    // `curl`: writes a list where `--output` says, or fails like a dead network.
    executable(
        &node.dir.join("bin/curl"),
        r#"#!/bin/bash
echo "curl $*" >> "$RECORD/calls"
[ -z "$CURL_FAILS" ] || { echo 'curl: (6) Could not resolve host' >&2; exit 6; }
while [ $# -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done
echo '||t.example^' > "$out"
"#,
    );
    let update = |curl_fails: &str| {
        node.forget_calls();
        Command::new("dash")
            .arg(node.dir.join("node/usr/local/sbin/bf-trackers-update"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    node.dir.join("bin").display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .env("RECORD", &node.dir)
            .env("TMPDIR", &node.dir)
            .env("CURL_FAILS", curl_fails)
            .output()
            .unwrap()
    };

    let out = update("1");
    assert!(!out.status.success());
    assert!(
        !node
            .calls()
            .iter()
            .any(|c| c.starts_with("bf-agent") || c.starts_with("unbound-control")),
        "{:#?}",
        node.calls()
    );

    // The stand-in agent answers `trackers build` with its usage and exit 2, like an agent
    // that refused: nothing is reloaded.
    let out = update("");
    assert!(!out.status.success());
    let calls = node.calls();
    let build = calls
        .iter()
        .find(|c| c.starts_with("bf-agent trackers build "))
        .unwrap_or_else(|| panic!("{calls:#?}"));
    assert!(
        build.ends_with(
            " /etc/barely-free/trackers-allow.txt /var/lib/unbound/barely-free-trackers.rpz"
        ),
        "{build}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("unbound-control")),
        "{calls:#?}"
    );

    // An agent that builds (it writes a new zone): the zone goes to unbound's user and is
    // reloaded, and only it.
    executable(
        &node.dir.join("node/usr/local/bin/bf-agent"),
        "#!/bin/sh\necho \"bf-agent $*\" >> \"$RECORD/calls\"\necho 'NEW ZONE' > \"$5\"\n",
    );
    let out = update("");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let calls = node.calls();
    assert!(
        calls.contains(&format!("chown unbound:unbound {ZONE}")),
        "{calls:#?}"
    );
    assert_eq!(
        calls.last().map(String::as_str),
        Some("unbound-control auth_zone_reload trackers.rpz.barely-free")
    );

    // unbound refuses the new zone: the one before it is put back and reloaded.
    std::fs::write(node.dir.join("node").join(&ZONE[1..]), "GOOD ZONE\n").unwrap();
    executable(
        &node.dir.join("bin/unbound-control"),
        "#!/bin/bash\necho \"unbound-control $*\" >> \"$RECORD/calls\"\n\
         grep -q 'NEW ZONE' \"$RECORD/node/var/lib/unbound/barely-free-trackers.rpz\" && exit 1\nexit 0\n",
    );
    let out = update("");
    assert!(!out.status.success());
    assert_eq!(node.file(ZONE).unwrap(), "GOOD ZONE\n");
    assert!(
        text(&out.stderr).contains("previous"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn without_debians_remote_control_file_the_resolver_gets_its_own() {
    let node = node("nocontrol");
    std::fs::remove_file(
        node.dir
            .join("node/etc/unbound/unbound.conf.d/remote-control.conf"),
    )
    .unwrap();

    ok(&node.run(&[]));

    let conf = node.file(UNBOUND_CONF).unwrap();
    assert!(
        conf.contains(
            "remote-control:\n    control-enable: yes\n    control-interface: /run/unbound.ctl\n"
        ),
        "{conf}"
    );
}
