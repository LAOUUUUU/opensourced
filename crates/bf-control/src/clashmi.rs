//! An auto-switching profile for ClashMi (mihomo): one device's key on every server, app and
//! port, in a fallback group that moves on when a connection stops answering.
//! Brief: `research/clashmi/RESEARCH.md`. A trial: only admins are offered it.

use std::net::{IpAddr, Ipv4Addr};

use crate::poller::{Health, Snapshot};
use crate::protocol::Protocol;
use crate::wgconf::AmneziaParams;

/// Where every connection's health is checked: our own site, not a third party's.
pub const CHECK_URL: &str = "https://barely-free.com/healthz";
/// How often, in seconds.
pub const CHECK_EVERY: u32 = 60;
/// The group's name in the app.
pub const GROUP: &str = "Barely-free";

/// One connection: a server agent on one of its ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub server: String,
    pub protocol: Protocol,
    pub ip: IpAddr,
    pub port: u16,
    pub public_key: String,
}

/// The ports a server takes an app on: its own first, then the backups (decision 013).
pub fn ports(protocol: Protocol, listen: u16) -> Vec<u16> {
    let backups: &[u16] = match protocol {
        Protocol::WireGuard => &[53, 123],
        Protocol::AmneziaWg => &[4500],
    };
    let mut all = vec![listen];
    all.extend(backups.iter().copied().filter(|port| *port != listen));
    all
}

/// Every connection on the board, the server titled `first` before the others, and on each
/// server AmneziaWG before WireGuard. Agents that are not online, have no reading or no app
/// are left out.
pub fn entries(snapshot: &Snapshot, first: &str) -> Vec<Entry> {
    let mut titles: Vec<&str> = Vec::new();
    for node in &snapshot.nodes {
        if !titles.contains(&node.title.as_str()) {
            titles.push(&node.title);
        }
    }
    titles.sort_by_key(|title| *title != first);
    let mut all = Vec::new();
    for title in titles {
        for protocol in [Protocol::AmneziaWg, Protocol::WireGuard] {
            for node in &snapshot.nodes {
                let (Some(reading), true, true) = (
                    &node.reading,
                    node.title == title && node.protocol == Some(protocol),
                    node.health == Health::Online,
                ) else {
                    continue;
                };
                for port in ports(protocol, reading.listen_port) {
                    all.push(Entry {
                        server: node.title.clone(),
                        protocol,
                        ip: node.ip,
                        port,
                        public_key: reading.wg_public_key.clone(),
                    });
                }
            }
        }
    }
    all
}

/// What goes into one device's profile besides the connections.
pub struct Device<'a> {
    pub name: &'a str,
    pub private_key: &'a str,
    /// Its AmneziaWG address (`10.77.x.y`); its WireGuard one is worked out from it.
    pub address: Ipv4Addr,
}

/// Text with no control characters (a line break would start a new YAML line).
fn plain(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// A YAML double-quoted string.
fn quoted(text: &str) -> String {
    format!(
        "\"{}\"",
        plain(text).replace('\\', "\\\\").replace('"', "\\\"")
    )
}

/// The profile, or `None` with no connection to put in it. With `trial_dead_first` a
/// connection to a closed port on the first server goes first, so a tester can watch the
/// group skip it.
pub fn profile(
    device: &Device<'_>,
    entries: &[Entry],
    amnezia: AmneziaParams,
    trial_dead_first: bool,
) -> Option<String> {
    let first = entries.first()?;
    let mut named: Vec<(String, &Entry, u16)> = Vec::new();
    if trial_dead_first {
        named.push(("Trial: a closed port (skipped)".to_string(), first, 9));
    }
    for entry in entries {
        named.push((
            format!("{} {} {}", entry.server, entry.protocol.title(), entry.port),
            entry,
            entry.port,
        ));
    }

    let mut out = format!(
        "# Barely-free: {}. An auto-switching profile for ClashMi (mihomo), from barely-free.com.\n\
         # It holds this device's private key: keep it private, and delete the file once imported.\n\
         mode: rule\n\
         log-level: warning\n\
         ipv6: false\n\
         tun:\n  enable: true\n  stack: system\n  auto-route: true\n  auto-detect-interface: true\n  dns-hijack:\n    - any:53\n\
         dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  respect-rules: true\n  nameserver:\n    - 10.77.0.1\n  proxy-server-nameserver:\n    - 1.1.1.1\n\
         proxies:\n",
        plain(device.name)
    );
    for (name, entry, port) in &named {
        let (address, resolver) = match entry.protocol {
            Protocol::AmneziaWg => (device.address, "10.77.0.1"),
            Protocol::WireGuard => (
                crate::protocol::wireguard_address(device.address),
                "10.78.0.1",
            ),
        };
        out.push_str(&format!(
            "  - name: {}\n    type: wireguard\n    server: {}\n    port: {port}\n    ip: {address}\n    private-key: {}\n    public-key: {}\n    allowed-ips: [\"0.0.0.0/0\"]\n    udp: true\n    remote-dns-resolve: true\n    dns: [{resolver}]\n",
            quoted(name),
            entry.ip,
            quoted(device.private_key),
            quoted(&entry.public_key),
        ));
        if entry.protocol == Protocol::AmneziaWg {
            out.push_str(&format!(
                "    amnezia-wg-option:\n      jc: {}\n      jmin: {}\n      jmax: {}\n      s1: {}\n      s2: {}\n      h1: {}\n      h2: {}\n      h3: {}\n      h4: {}\n",
                amnezia.jc,
                amnezia.jmin,
                amnezia.jmax,
                amnezia.s1,
                amnezia.s2,
                amnezia.h1,
                amnezia.h2,
                amnezia.h3,
                amnezia.h4
            ));
        }
    }
    out.push_str(&format!(
        "proxy-groups:\n  - name: {}\n    type: fallback\n    url: {}\n    interval: {CHECK_EVERY}\n    timeout: 5000\n    proxies:\n",
        quoted(GROUP),
        quoted(CHECK_URL)
    ));
    for (name, _, _) in &named {
        out.push_str(&format!("      - {}\n", quoted(name)));
    }
    out.push_str(&format!("rules:\n  - MATCH,{GROUP}\n"));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::NodeReading;
    use crate::poller::NodeView;

    const TORONTO_IP: &str = "192.0.2.176";
    const DALLAS_IP: &str = "198.51.100.185";
    const AWG_KEY: &str = "AWGAWGAWGAWGAWGAWGAWGAWGAWGAWGAWGAWGAWGAWGA=";
    const WG_KEY: &str = "WGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGA=";
    const PRIVATE: &str = "cHJpdmF0ZXByaXZhdGVwcml2YXRlcHJpdmF0ZXByaXY=";

    fn agent(
        name: &str,
        title: &str,
        ip: &str,
        protocol: Option<Protocol>,
        port: u16,
        health: Health,
    ) -> NodeView {
        NodeView {
            name: name.to_string(),
            title: title.to_string(),
            place: "Somewhere".to_string(),
            protocol,
            location: None,
            ip: ip.parse().unwrap(),
            health,
            checked_at: 1,
            last_good: Some(1),
            reading: (health == Health::Online).then(|| NodeReading {
                wg_public_key: match protocol {
                    Some(Protocol::AmneziaWg) => AWG_KEY.to_string(),
                    _ => WG_KEY.to_string(),
                },
                listen_port: port,
                online: 0,
                peers_total: 0,
                desired_version: Some(1),
                load1: None,
                load_steady: None,
                peers: Vec::new(),
                logins: None,
                attention: None,
            }),
            problem: None,
            in_sync: true,
            note: None,
        }
    }

    /// Dallas listed first on the board; Toronto with both apps; Dallas with both.
    fn board() -> Snapshot {
        Snapshot {
            nodes: vec![
                agent(
                    "dallas",
                    "Dallas",
                    DALLAS_IP,
                    Some(Protocol::WireGuard),
                    51820,
                    Health::Online,
                ),
                agent(
                    "dallas-awg",
                    "Dallas",
                    DALLAS_IP,
                    Some(Protocol::AmneziaWg),
                    443,
                    Health::Online,
                ),
                agent(
                    "toronto-wg",
                    "Toronto",
                    TORONTO_IP,
                    Some(Protocol::WireGuard),
                    51820,
                    Health::Online,
                ),
                agent(
                    "toronto",
                    "Toronto",
                    TORONTO_IP,
                    Some(Protocol::AmneziaWg),
                    443,
                    Health::Online,
                ),
            ],
            list_version: Some(1),
            updated_at: Some(1),
            contacts: Default::default(),
        }
    }

    fn params() -> AmneziaParams {
        AmneziaParams {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 15,
            s2: 20,
            h1: 1_000_000_001,
            h2: 1_000_000_002,
            h3: 1_000_000_003,
            h4: 1_000_000_004,
        }
    }

    fn phone() -> Device<'static> {
        Device {
            name: "phone",
            private_key: PRIVATE,
            address: Ipv4Addr::new(10, 77, 0, 2),
        }
    }

    fn short(entry: &Entry) -> String {
        format!("{} {} {}", entry.server, entry.protocol.title(), entry.port)
    }

    #[test]
    fn each_app_gets_its_own_port_first_then_the_backups() {
        assert_eq!(ports(Protocol::WireGuard, 51820), [51820, 53, 123]);
        assert_eq!(ports(Protocol::AmneziaWg, 443), [443, 4500]);
        // A backup that is also the main port is not listed twice.
        assert_eq!(ports(Protocol::WireGuard, 53), [53, 123]);
    }

    #[test]
    fn the_picked_server_comes_first_and_amneziawg_before_wireguard() {
        let all: Vec<String> = entries(&board(), "Toronto").iter().map(short).collect();
        assert_eq!(
            all,
            [
                "Toronto AmneziaWG 443",
                "Toronto AmneziaWG 4500",
                "Toronto WireGuard 51820",
                "Toronto WireGuard 53",
                "Toronto WireGuard 123",
                "Dallas AmneziaWG 443",
                "Dallas AmneziaWG 4500",
                "Dallas WireGuard 51820",
                "Dallas WireGuard 53",
                "Dallas WireGuard 123",
            ]
        );
        let first = &entries(&board(), "Toronto")[0];
        assert_eq!(first.ip, TORONTO_IP.parse::<IpAddr>().unwrap());
        assert_eq!(first.public_key, AWG_KEY);
    }

    #[test]
    fn agents_that_are_down_or_have_no_app_are_left_out() {
        let mut snapshot = board();
        snapshot.nodes[0] = agent(
            "dallas",
            "Dallas",
            DALLAS_IP,
            Some(Protocol::WireGuard),
            51820,
            Health::NotResponding,
        );
        snapshot.nodes[1] = agent("dallas-awg", "Dallas", DALLAS_IP, None, 443, Health::Online);
        let all: Vec<String> = entries(&snapshot, "Dallas").iter().map(short).collect();
        assert_eq!(all.len(), 5, "{all:?}");
        assert!(all.iter().all(|e| e.starts_with("Toronto")), "{all:?}");

        let empty = Snapshot {
            nodes: vec![],
            list_version: None,
            updated_at: None,
            contacts: Default::default(),
        };
        assert!(entries(&empty, "Toronto").is_empty());
        assert_eq!(profile(&phone(), &[], params(), false), None);
    }

    #[test]
    fn every_connection_carries_the_right_keys_addresses_and_resolver() {
        let yaml = profile(&phone(), &entries(&board(), "Toronto"), params(), false).unwrap();
        let proxies: Vec<&str> = yaml.split("\n  - name: ").skip(1).collect();
        assert_eq!(proxies.len(), 11, "ten connections and the group: {yaml}");
        for proxy in &proxies[..10] {
            assert!(
                proxy.contains(&format!("    private-key: \"{PRIVATE}\"\n")),
                "{proxy}"
            );
            assert!(proxy.contains("    type: wireguard\n"), "{proxy}");
            assert!(proxy.contains("    udp: true\n"), "{proxy}");
            assert!(proxy.contains("    remote-dns-resolve: true\n"), "{proxy}");
        }
        let awg = proxies[0];
        assert!(awg.starts_with("\"Toronto AmneziaWG 443\"\n"), "{awg}");
        assert!(
            awg.contains(&format!("    server: {TORONTO_IP}\n    port: 443\n")),
            "{awg}"
        );
        assert!(
            awg.contains(&format!("    public-key: \"{AWG_KEY}\"\n")),
            "{awg}"
        );
        assert!(awg.contains("    ip: 10.77.0.2\n"), "{awg}");
        assert!(awg.contains("    dns: [10.77.0.1]\n"), "{awg}");
        assert!(
            awg.contains("    amnezia-wg-option:\n      jc: 4\n      jmin: 40\n      jmax: 70\n      s1: 15\n      s2: 20\n      h1: 1000000001\n      h2: 1000000002\n      h3: 1000000003\n      h4: 1000000004"),
            "{awg}"
        );
        let wg = proxies[2];
        assert!(wg.starts_with("\"Toronto WireGuard 51820\"\n"), "{wg}");
        assert!(
            wg.contains(&format!("    public-key: \"{WG_KEY}\"\n")),
            "{wg}"
        );
        assert!(wg.contains("    ip: 10.78.0.2\n"), "{wg}");
        assert!(wg.ends_with("    dns: [10.78.0.1]"), "{wg}");
        assert!(!wg.contains("amnezia"), "{wg}");
    }

    #[test]
    fn the_group_tries_them_in_order_checks_our_own_site_and_takes_all_traffic() {
        let yaml = profile(&phone(), &entries(&board(), "Toronto"), params(), false).unwrap();
        assert!(
            yaml.contains(&format!("  - name: \"{GROUP}\"\n    type: fallback\n")),
            "{yaml}"
        );
        assert!(
            yaml.contains(&format!(
                "    url: \"{CHECK_URL}\"\n    interval: {CHECK_EVERY}\n"
            )),
            "{yaml}"
        );
        let listed = yaml
            .split("    proxies:\n")
            .nth(1)
            .unwrap()
            .split("\nrules:")
            .next()
            .unwrap();
        let names: Vec<&str> = listed
            .lines()
            .map(|l| l.trim_start_matches("      - "))
            .collect();
        assert_eq!(names[0], "\"Toronto AmneziaWG 443\"");
        assert_eq!(names[9], "\"Dallas WireGuard 123\"");
        assert!(
            yaml.ends_with(&format!("rules:\n  - MATCH,{GROUP}\n")),
            "{yaml}"
        );
        assert!(yaml.starts_with("# Barely-free: phone."), "{yaml}");
        assert!(
            yaml.contains("private key"),
            "the file says it holds the key: {yaml}"
        );
    }

    #[test]
    fn a_trial_profile_puts_a_closed_port_first_to_show_the_switch() {
        let yaml = profile(&phone(), &entries(&board(), "Toronto"), params(), true).unwrap();
        let first = yaml.split("\n  - name: ").nth(1).unwrap();
        assert!(
            first.starts_with("\"Trial: a closed port (skipped)\"\n"),
            "{first}"
        );
        assert!(
            first.contains(&format!("    server: {TORONTO_IP}\n    port: 9\n")),
            "{first}"
        );
        let listed = yaml.split("    proxies:\n").nth(1).unwrap();
        assert!(
            listed.starts_with("      - \"Trial: a closed port (skipped)\"\n"),
            "{listed}"
        );
    }

    #[test]
    fn odd_titles_and_names_cannot_break_the_file() {
        let mut snapshot = board();
        for node in &mut snapshot.nodes {
            node.title = "To\"ron\\to\n- evil: yes".to_string();
        }
        let device = Device {
            name: "my\nphone",
            ..phone()
        };
        let yaml = profile(&device, &entries(&snapshot, "x"), params(), false).unwrap();
        assert!(!yaml.contains("\n- evil"), "{yaml}");
        assert!(
            yaml.contains("\"To\\\"ron\\\\to - evil: yes AmneziaWG 443\""),
            "{yaml}"
        );
        assert!(yaml.starts_with("# Barely-free: my phone."), "{yaml}");
    }
}
