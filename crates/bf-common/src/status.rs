//! The status a node reports: its peers with handshake ages, online flags and masked
//! client addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use crate::wg::{Dump, InterfaceInfo};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeerStatus {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    /// Seconds since the last handshake; `None` if the peer never connected.
    pub handshake_age: Option<u64>,
    pub online: bool,
    pub rx: u64,
    pub tx: u64,
    /// Masked with [`mask_endpoint`].
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Status {
    pub time: u64,
    pub interface: InterfaceInfo,
    pub online: usize,
    pub peers_total: usize,
    /// Version of the stored peer list; `None` when the node was never given one.
    pub desired_version: Option<u64>,
    /// One-minute load average; `None` where it cannot be read.
    pub load1: Option<f64>,
    pub peers: Vec<PeerStatus>,
    /// Successful SSH logins of the last minutes (`specs/login-alerts.md`), filled in by the
    /// agent; absent when it could not read them, so an older website sees nothing new.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logins: Option<Vec<crate::logins::Login>>,
}

/// Removes the last part of a client address so a response or log line never holds it
/// in full: IPv4 loses the last octet, IPv6 keeps the first four groups.
pub fn mask_endpoint(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Ipv4Addr::new(o[0], o[1], o[2], 0).to_string()
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0).to_string()
        }
    }
}

/// Turns a parsed dump into the status the agent reports. A peer is online while its
/// last handshake is younger than `online_secs`.
pub fn build_status(
    now: u64,
    dump: &Dump,
    online_secs: u64,
    desired_version: Option<u64>,
    load1: Option<f64>,
) -> Status {
    let peers: Vec<PeerStatus> = dump
        .peers
        .iter()
        .map(|peer| {
            let handshake_age = peer.latest_handshake.map(|t| now.saturating_sub(t));
            PeerStatus {
                public_key: peer.public_key.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                handshake_age,
                online: handshake_age.is_some_and(|age| age < online_secs),
                rx: peer.rx,
                tx: peer.tx,
                endpoint: peer.endpoint.map(mask_endpoint),
            }
        })
        .collect();
    Status {
        time: now,
        interface: dump.interface.clone(),
        online: peers.iter().filter(|p| p.online).count(),
        peers_total: peers.len(),
        desired_version,
        load1,
        peers,
        logins: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::PeerState;

    fn peer(key: &str, handshake: Option<u64>, endpoint: Option<&str>) -> PeerState {
        PeerState {
            public_key: key.to_string(),
            endpoint: endpoint.map(|e| e.parse().unwrap()),
            allowed_ips: vec!["10.66.1.2/32".to_string()],
            latest_handshake: handshake,
            rx: 10,
            tx: 20,
        }
    }

    fn dump(peers: Vec<PeerState>) -> Dump {
        Dump {
            interface: InterfaceInfo {
                public_key: "node-public-key".into(),
                listen_port: 51820,
            },
            peers,
        }
    }

    #[test]
    fn endpoints_lose_the_last_part() {
        for (given, shown) in [
            ("203.0.113.7", "203.0.113.0"),
            ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::"),
            ("2001:db8::7", "2001:db8::"),
            ("::ffff:203.0.113.7", "203.0.113.0"),
        ] {
            assert_eq!(mask_endpoint(given.parse().unwrap()), shown, "{given}");
        }
    }

    #[test]
    fn a_peer_is_online_only_while_its_last_handshake_is_younger_than_the_threshold() {
        let now = 1_000_000;
        for (age, online) in [(0, true), (179, true), (180, false), (181, false)] {
            let status = build_status(
                now,
                &dump(vec![peer("k", Some(now - age), None)]),
                180,
                None,
                None,
            );

            assert_eq!(status.peers[0].handshake_age, Some(age));
            assert_eq!(status.peers[0].online, online, "age {age}");
            assert_eq!(status.online, usize::from(online), "age {age}");
        }
    }

    #[test]
    fn the_status_shows_masked_endpoints_and_never_a_full_client_address() {
        let peers = vec![peer("k", Some(999_990), Some("203.0.113.7"))];

        let status = build_status(1_000_000, &dump(peers), 180, None, None);

        assert_eq!(status.peers[0].endpoint.as_deref(), Some("203.0.113.0"));
        assert!(
            !serde_json::to_string(&status)
                .unwrap()
                .contains("203.0.113.7")
        );
    }

    #[test]
    fn a_handshake_in_the_future_counts_as_age_zero() {
        // The node's clock can lag what WireGuard recorded; that must not panic or wrap.
        let status = build_status(
            1_000,
            &dump(vec![peer("k", Some(1_005), None)]),
            180,
            None,
            None,
        );

        assert_eq!(status.peers[0].handshake_age, Some(0));
        assert!(status.peers[0].online);
    }

    #[test]
    fn the_status_json_has_the_documented_shape() {
        let peers = vec![
            peer("k1", Some(1_794_279_988), Some("203.0.113.7")),
            peer("k2", None, None),
        ];

        let status = build_status(1_794_280_000, &dump(peers), 180, Some(7), Some(0.12));

        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "time": 1_794_280_000,
                "interface": { "public_key": "node-public-key", "listen_port": 51820 },
                "online": 1,
                "peers_total": 2,
                "desired_version": 7,
                "load1": 0.12,
                "peers": [
                    { "public_key": "k1", "allowed_ips": ["10.66.1.2/32"], "handshake_age": 12,
                      "online": true, "rx": 10, "tx": 20, "endpoint": "203.0.113.0" },
                    { "public_key": "k2", "allowed_ips": ["10.66.1.2/32"], "handshake_age": null,
                      "online": false, "rx": 10, "tx": 20, "endpoint": null }
                ]
            })
        );
    }

    #[test]
    fn logins_are_written_only_when_there_are_some_to_report() {
        let mut status = build_status(1_000, &dump(vec![]), 180, None, None);
        assert_eq!(status.logins, None, "build_status leaves them to the agent");
        let json = serde_json::to_string(&status).unwrap();
        assert!(
            !json.contains("logins"),
            "an old reader sees nothing new: {json}"
        );
        status.logins = Some(vec![crate::logins::Login {
            at: 990,
            user: "root".to_string(),
            from: "203.0.113.7".parse().unwrap(),
            key: Some("SHA256:abc".to_string()),
            key_name: Some("lao-mac".to_string()),
        }]);
        let json = serde_json::to_string(&status).unwrap();
        assert!(
            json.contains("\"logins\":[{\"at\":990,\"user\":\"root\",\"from\":\"203.0.113.7\""),
            "{json}"
        );
    }
}
