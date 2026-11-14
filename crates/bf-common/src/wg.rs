//! Reading `wg show <interface> dump`.
//!
//! Layout (wg(8), checked against the Toronto node on 2026-11-09), tab separated:
//! the first line is `private-key public-key listen-port fwmark`; every later line is
//! one peer: `public-key preshared-key endpoint allowed-ips latest-handshake
//! transfer-rx transfer-tx persistent-keepalive`.
//!
//! The private key and the preshared keys are secrets. They are dropped while reading
//! and never stored in the types below.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use serde::Serialize;

/// What the dump says about the interface itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InterfaceInfo {
    pub public_key: String,
    pub listen_port: u16,
}

/// A device whose last handshake is older than this is forgotten by its server: the agent
/// removes the peer and sets it again, which clears the address and handshake time WireGuard
/// otherwise keeps until a restart. A connected device handshakes about every two minutes
/// (its file keeps the tunnel alive), so this never touches one in use. The privacy policy
/// states it (`web/privacy.html`, held to it by a test).
pub const FORGET_IDLE_AFTER_SECS: u64 = 300;

/// One peer as WireGuard reports it. Its `Debug` output hides the client address, so
/// printing a peer by accident cannot put it in a log.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerState {
    pub public_key: String,
    /// The client's address as WireGuard last saw it, without the port. Never put it in
    /// a response or a log line unmasked.
    pub endpoint: Option<IpAddr>,
    pub allowed_ips: Vec<String>,
    /// Unix seconds of the latest handshake; `None` if the peer never connected.
    pub latest_handshake: Option<u64>,
    pub rx: u64,
    pub tx: u64,
}

impl std::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerState")
            .field("public_key", &self.public_key)
            .field("endpoint", &self.endpoint.map(|_| "<hidden>"))
            .field("allowed_ips", &self.allowed_ips)
            .field("latest_handshake", &self.latest_handshake)
            .field("rx", &self.rx)
            .field("tx", &self.tx)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dump {
    pub interface: InterfaceInfo,
    pub peers: Vec<PeerState>,
}

/// The dump could not be read. Only the line number is kept, never the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpError {
    Empty,
    BadLine { line: usize, reason: &'static str },
}

impl std::fmt::Display for DumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "wg dump is empty"),
            Self::BadLine { line, reason } => write!(f, "wg dump line {line}: {reason}"),
        }
    }
}

impl std::error::Error for DumpError {}

pub fn parse_dump(text: &str) -> Result<Dump, DumpError> {
    let mut lines = text.lines();
    let first = lines.next().ok_or(DumpError::Empty)?;
    let fields: Vec<&str> = first.split('\t').collect();
    let bad = |reason| DumpError::BadLine { line: 1, reason };
    let public_key = fields
        .get(1)
        .ok_or_else(|| bad("interface line is short"))?;
    let port = fields
        .get(2)
        .ok_or_else(|| bad("interface line is short"))?;
    let listen_port = port
        .parse()
        .map_err(|_| bad("listen port is not a number"))?;
    let mut peers = Vec::new();
    for (index, line) in lines.enumerate() {
        peers.push(parse_peer(index + 2, line)?);
    }
    Ok(Dump {
        interface: InterfaceInfo {
            public_key: (*public_key).to_string(),
            listen_port,
        },
        peers,
    })
}

/// The client address in an endpoint such as `203.0.113.7:51820` or `[2001:db8::1]:51820`.
/// `wg` prints a link-local address with its interface (`[fe80::1%eth0]:51820`); the zone is
/// dropped. Anything else that cannot be read, including `(none)`, is an unknown endpoint and
/// not an error: the agent needs only keys and ranges to do its job, so a cosmetic field must
/// never make the whole dump unreadable.
fn parse_endpoint(text: &str) -> Option<IpAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    let inside = text.strip_prefix('[')?.split_once("]:")?.0;
    let address = inside
        .split_once('%')
        .map_or(inside, |(address, _zone)| address);
    address.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

fn parse_peer(number: usize, line: &str) -> Result<PeerState, DumpError> {
    let bad = |reason| DumpError::BadLine {
        line: number,
        reason,
    };
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 8 {
        return Err(bad("peer line has the wrong number of fields"));
    };
    // AmneziaWG appends its obfuscation settings to the regular eight WireGuard dump
    // fields. The agent only needs the standard peer state and safely ignores the rest.
    let public_key = fields[0];
    let endpoint = fields[2];
    let allowed_ips = fields[3];
    let handshake = fields[4];
    let rx = fields[5];
    let tx = fields[6];
    let endpoint = parse_endpoint(endpoint);
    let handshake: u64 = handshake
        .parse()
        .map_err(|_| bad("handshake is not a number"))?;
    Ok(PeerState {
        public_key: public_key.to_string(),
        endpoint,
        allowed_ips: if allowed_ips == "(none)" {
            Vec::new()
        } else {
            allowed_ips.split(',').map(str::to_string).collect()
        },
        latest_handshake: (handshake != 0).then_some(handshake),
        rx: rx
            .parse()
            .map_err(|_| bad("received bytes is not a number"))?,
        tx: tx.parse().map_err(|_| bad("sent bytes is not a number"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 bytes of 0x01, 0x02, 0x03, 0x04 in base64: valid WireGuard keys for fixtures.
    const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const K3: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const PRIVATE: &str = "c2VjcmV0LXByaXZhdGUta2V5LW5vdC1hLXJlYWwtb25lMDA=";
    const PSK: &str = "cHJlc2hhcmVkLWtleS1ub3QtYS1yZWFsLW9uZS1hdC1hbGw=";

    fn dump_text(peer_lines: &[String]) -> String {
        let mut text = format!("{PRIVATE}\t{K1}\t51820\toff\n");
        for line in peer_lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    fn peer_line(key: &str, endpoint: &str, allowed: &str, handshake: &str) -> String {
        format!("{key}\t{PSK}\t{endpoint}\t{allowed}\t{handshake}\t1234\t5678\toff")
    }

    #[test]
    fn interface_line_gives_public_key_and_port_and_drops_the_private_key() {
        let text = format!("{PRIVATE}\t{K1}\t51820\toff\n");

        let dump = parse_dump(&text).unwrap();

        assert_eq!(dump.interface.public_key, K1);
        assert_eq!(dump.interface.listen_port, 51820);
        assert!(dump.peers.is_empty());
        assert!(!format!("{dump:?}").contains(PRIVATE));
    }

    #[test]
    fn peer_line_gives_key_addresses_handshake_traffic_and_endpoint_without_port() {
        let text = dump_text(&[peer_line(
            K2,
            "203.0.113.7:40000",
            "10.66.1.2/32",
            "1794280000",
        )]);

        let dump = parse_dump(&text).unwrap();

        assert_eq!(
            dump.peers,
            vec![PeerState {
                public_key: K2.to_string(),
                endpoint: Some("203.0.113.7".parse().unwrap()),
                allowed_ips: vec!["10.66.1.2/32".to_string()],
                latest_handshake: Some(1_794_280_000),
                rx: 1234,
                tx: 5678,
            }]
        );
        assert!(!format!("{dump:?}").contains(PSK));
    }

    #[test]
    fn an_amneziawg_dump_may_append_obfuscation_fields_after_wireguard_peer_state() {
        let text = format!(
            "{PRIVATE}\t{K1}\t443\toff\n{}\t{PSK}\t203.0.113.7:40000\t10.77.0.2/32\t1794280000\t1234\t5678\toff\t4\t40\t70\t15\t20\t0\t0\t1000000001\t1000000002\t1000000003\t1000000004\n",
            K2
        );

        let dump = parse_dump(&text).unwrap();

        assert_eq!(dump.interface.listen_port, 443);
        assert_eq!(dump.peers[0].public_key, K2);
        assert_eq!(dump.peers[0].allowed_ips, ["10.77.0.2/32"]);
        assert_eq!(dump.peers[0].rx, 1234);
        assert_eq!(dump.peers[0].tx, 5678);
    }

    #[test]
    fn a_peer_that_never_connected_has_no_endpoint_and_no_handshake() {
        let text = dump_text(&[peer_line(K2, "(none)", "10.66.1.2/32", "0")]);

        let dump = parse_dump(&text).unwrap();

        assert_eq!(dump.peers[0].endpoint, None);
        assert_eq!(dump.peers[0].latest_handshake, None);
    }

    #[test]
    fn allowed_ips_may_be_several_or_none_and_the_endpoint_may_be_ipv6() {
        let text = dump_text(&[
            peer_line(K2, "[2001:db8::7]:40000", "10.66.1.2/32,fd00::2/128", "5"),
            peer_line(K3, "(none)", "(none)", "0"),
        ]);

        let dump = parse_dump(&text).unwrap();

        assert_eq!(dump.peers[0].endpoint, Some("2001:db8::7".parse().unwrap()));
        assert_eq!(
            dump.peers[0].allowed_ips,
            vec!["10.66.1.2/32", "fd00::2/128"]
        );
        assert!(dump.peers[1].allowed_ips.is_empty());
    }

    #[test]
    fn a_malformed_dump_is_an_error_naming_the_line_but_never_showing_it() {
        assert_eq!(parse_dump(""), Err(DumpError::Empty));

        let short = dump_text(&["only\tthree\tfields".to_string()]);
        assert_eq!(
            parse_dump(&short),
            Err(DumpError::BadLine {
                line: 2,
                reason: "peer line has the wrong number of fields"
            })
        );

        let bad_time = dump_text(&[peer_line(K2, "(none)", "10.66.1.2/32", "soon")]);
        assert_eq!(
            parse_dump(&bad_time),
            Err(DumpError::BadLine {
                line: 2,
                reason: "handshake is not a number"
            })
        );

        let secret = dump_text(&[peer_line("leak-me-not", "(none)", "10.66.1.2/32", "soon")]);
        let shown = parse_dump(&secret).unwrap_err().to_string();
        assert!(shown.contains("line 2"));
        assert!(!shown.contains("leak-me-not") && !shown.contains(PSK));
    }

    #[test]
    fn an_endpoint_that_cannot_be_read_is_unknown_and_does_not_fail_the_dump() {
        // wg prints a link-local address with its interface; the zone is no part of the address.
        for (endpoint, expected) in [
            ("[fe80::1%eth0]:51820", Some("fe80::1")),
            ("[fe80::1%2]:51820", Some("fe80::1")),
            ("nope", None),
            ("1.2.3.4", None),
            ("", None),
        ] {
            let text = dump_text(&[peer_line(K2, endpoint, "10.66.1.2/32", "0")]);

            let dump = parse_dump(&text).unwrap();

            let expected = expected.map(|ip| ip.parse::<IpAddr>().unwrap());
            assert_eq!(dump.peers[0].endpoint, expected, "{endpoint:?}");
        }
    }

    #[test]
    fn debug_output_of_a_peer_never_shows_the_client_address() {
        let text = dump_text(&[peer_line(K2, "203.0.113.7:40000", "10.66.1.2/32", "5")]);

        let shown = format!("{:?}", parse_dump(&text).unwrap());

        assert!(!shown.contains("203.0.113.7"), "{shown}");
        assert!(shown.contains(K2));
    }
}
