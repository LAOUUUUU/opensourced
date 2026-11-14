//! The two protocols every server offers, and where a device sits in each.
//!
//! AmneziaWG keeps `10.77.0.0/16`, the range devices are given addresses in. WireGuard runs
//! on its own interface, which cannot share that range on the same server, so it uses
//! `10.78.0.0/16`, and a device `10.77.a.b` is `10.78.a.b` there (`specs/dual-protocol.md`).

use std::net::Ipv4Addr;

use bf_common::peers::{PeerList, PeerSpec};

/// What an agent's interface speaks, and so which app a device needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    WireGuard,
    AmneziaWg,
}

impl Protocol {
    /// How it is written in the database, the command line and forms.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::WireGuard => "wireguard",
            Protocol::AmneziaWg => "amneziawg",
        }
    }

    /// Only exactly `wireguard` or `amneziawg`.
    pub fn parse(text: &str) -> Option<Protocol> {
        match text {
            "wireguard" => Some(Protocol::WireGuard),
            "amneziawg" => Some(Protocol::AmneziaWg),
            _ => None,
        }
    }

    /// What the site calls it.
    pub fn title(self) -> &'static str {
        match self {
            Protocol::WireGuard => "WireGuard",
            Protocol::AmneziaWg => "AmneziaWG",
        }
    }

    /// The other ports every server also takes it on (`deploy/node-extra-ports.sh`), for
    /// networks that block the usual one. A device's file keeps the usual port.
    pub fn backup_ports(self) -> &'static str {
        match self {
            Protocol::WireGuard => "53 or 123",
            Protocol::AmneziaWg => "4500",
        }
    }
}

/// A device's address on WireGuard: the same last two numbers in `10.78.0.0/16`. An address
/// outside `10.77.0.0/16` is left as it is.
pub fn wireguard_address(address: Ipv4Addr) -> Ipv4Addr {
    match address.octets() {
        [10, 77, c, d] => Ipv4Addr::new(10, 78, c, d),
        _ => address,
    }
}

/// The list an agent of `protocol` gets: for WireGuard every range inside `10.77.0.0/16`
/// moved to `10.78.0.0/16`; for AmneziaWG, or an agent registered before protocols, the
/// list as it was published.
pub fn list_for(protocol: Option<Protocol>, list: &PeerList) -> PeerList {
    if protocol != Some(Protocol::WireGuard) {
        return list.clone();
    }
    PeerList {
        version: list.version,
        peers: list
            .peers
            .iter()
            .map(|peer| PeerSpec {
                public_key: peer.public_key.clone(),
                allowed_ips: peer.allowed_ips.iter().map(|r| moved(r)).collect(),
                trackers: peer.trackers,
            })
            .collect(),
    }
}

/// `10.77.a.b/32` as `10.78.a.b/32`; any other range as it is.
fn moved(range: &str) -> String {
    match range
        .strip_suffix("/32")
        .and_then(|address| address.parse::<Ipv4Addr>().ok())
    {
        Some(address) => format!("{}/32", wireguard_address(address)),
        None => range.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(key: &str, ranges: &[&str]) -> PeerSpec {
        PeerSpec {
            public_key: key.to_string(),
            allowed_ips: ranges.iter().map(ToString::to_string).collect(),
            trackers: true,
        }
    }

    #[test]
    fn a_protocol_is_written_and_read_as_one_exact_word() {
        assert_eq!(Protocol::WireGuard.as_str(), "wireguard");
        assert_eq!(Protocol::AmneziaWg.as_str(), "amneziawg");
        assert_eq!(Protocol::parse("wireguard"), Some(Protocol::WireGuard));
        assert_eq!(Protocol::parse("amneziawg"), Some(Protocol::AmneziaWg));
        for other in [
            "",
            "WireGuard",
            "wg",
            "awg",
            "amnezia",
            " wireguard",
            "wireguard ",
        ] {
            assert_eq!(Protocol::parse(other), None, "{other:?}");
        }
        assert_eq!(Protocol::WireGuard.title(), "WireGuard");
        assert_eq!(Protocol::AmneziaWg.title(), "AmneziaWG");
    }

    #[test]
    fn a_device_keeps_its_last_two_numbers_on_wireguard() {
        for (amnezia, wireguard) in [
            ([10, 77, 0, 2], [10, 78, 0, 2]),
            ([10, 77, 12, 34], [10, 78, 12, 34]),
            ([10, 77, 255, 254], [10, 78, 255, 254]),
        ] {
            assert_eq!(
                wireguard_address(Ipv4Addr::from(amnezia)),
                Ipv4Addr::from(wireguard)
            );
        }
        for outside in [
            [10, 66, 1, 2],
            [10, 78, 0, 2],
            [192, 0, 2, 7],
            [10, 7, 77, 2],
        ] {
            assert_eq!(
                wireguard_address(Ipv4Addr::from(outside)),
                Ipv4Addr::from(outside),
                "{outside:?} is not in 10.77.0.0/16"
            );
        }
    }

    #[test]
    fn a_wireguard_agent_gets_the_list_moved_to_its_range_and_nothing_else_changes() {
        let published = PeerList {
            version: 7,
            peers: vec![
                spec("key-a", &["10.77.0.2/32"]),
                spec("key-b", &["10.77.3.4/32", "fd00::3/128"]),
                spec("key-c", &["10.66.1.2/32"]),
            ],
        };

        let wireguard = list_for(Some(Protocol::WireGuard), &published);

        assert_eq!(
            wireguard,
            PeerList {
                version: 7,
                peers: vec![
                    spec("key-a", &["10.78.0.2/32"]),
                    spec("key-b", &["10.78.3.4/32", "fd00::3/128"]),
                    spec("key-c", &["10.66.1.2/32"]),
                ],
            }
        );
        assert_eq!(list_for(Some(Protocol::AmneziaWg), &published), published);
        assert_eq!(list_for(None, &published), published, "not set: as today");
    }

    #[test]
    fn a_device_whose_trackers_switch_is_off_stays_off_on_wireguard() {
        let mut off = spec("key-a", &["10.77.0.2/32"]);
        off.trackers = false;
        let published = PeerList {
            version: 4,
            peers: vec![off, spec("key-b", &["10.77.0.3/32"])],
        };

        let wireguard = list_for(Some(Protocol::WireGuard), &published);

        let switches: Vec<(&str, bool)> = wireguard
            .peers
            .iter()
            .map(|p| (p.allowed_ips[0].as_str(), p.trackers))
            .collect();
        assert_eq!(switches, [("10.78.0.2/32", false), ("10.78.0.3/32", true)]);
    }

    #[test]
    fn only_a_single_address_is_moved_never_a_wider_range() {
        // A /16 or anything that is not one address is left alone: the control program
        // only ever sends /32s, and a moved subnet would mean something else.
        let published = PeerList {
            version: 1,
            peers: vec![spec("key-a", &["10.77.0.0/16", "10.77.1.0/24", "junk"])],
        };
        assert_eq!(list_for(Some(Protocol::WireGuard), &published), published);
    }
}
