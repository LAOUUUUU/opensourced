//! Peer lists: the shape the control program sends, how they are checked, and the plan
//! for making WireGuard match one.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::wg::PeerState;

/// A WireGuard key: 32 bytes in standard base64 (44 characters ending in `=`), written the
/// one canonical way (the unused bits of the last character are zero), as `wg` demands.
pub fn is_valid_key(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 44
        && b[43] == b'='
        && b[..43].iter().all(|&c| base64_value(c).is_some())
        && base64_value(b[42]).is_some_and(|v| v & 0b11 == 0)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// An address range such as `10.66.1.2/32`. The address must have no bits set below the
/// prefix, so a range is only ever what it says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (addr, prefix) = s.split_once('/')?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let host_bits_are_clear = match addr {
            IpAddr::V4(v4) => prefix <= 32 && u32::from(v4) & host_mask_v4(prefix) == 0,
            IpAddr::V6(v6) => prefix <= 128 && u128::from(v6) & host_mask_v6(prefix) == 0,
        };
        host_bits_are_clear.then_some(Cidr { addr, prefix })
    }

    /// The address, if the range is exactly one IPv4 address (`/32`).
    pub fn ipv4_host(&self) -> Option<std::net::Ipv4Addr> {
        match self.addr {
            IpAddr::V4(v4) if self.prefix == 32 => Some(v4),
            _ => None,
        }
    }
}

fn host_mask_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
}

fn host_mask_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// One peer in the list the control program sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSpec {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    /// Whether the node's resolver blocks trackers for this peer (`specs/trackers.md`).
    /// Missing means yes, and yes is not written, so a list where every peer is filtered
    /// reads and writes exactly as it did before the field existed.
    #[serde(default = "filtered", skip_serializing_if = "is_filtered")]
    pub trackers: bool,
}

fn filtered() -> bool {
    true
}

// `serde` hands the field over by reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_filtered(trackers: &bool) -> bool {
    *trackers
}

/// The whole list, as sent in `PUT /v1/peers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerList {
    pub version: u64,
    pub peers: Vec<PeerSpec>,
}

/// A list that passed [`PeerList::check`]: keys and ranges are valid and unique, peers
/// are sorted by key and each peer's ranges are sorted, so two lists that mean the same
/// thing compare equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    pub version: u64,
    pub peers: Vec<DesiredPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredPeer {
    pub public_key: String,
    pub ranges: Vec<Cidr>,
    /// See [`PeerSpec::trackers`].
    pub trackers: bool,
}

/// Why a list was refused. `index` is the position in the list; the entry itself is never
/// repeated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    BadKey { index: usize },
    BadRange { index: usize },
    DuplicateKey { index: usize },
    DuplicateRange { index: usize },
}

impl std::fmt::Display for ListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKey { index } => write!(f, "peers[{index}]: not a valid WireGuard key"),
            Self::BadRange { index } => write!(f, "peers[{index}]: not a valid address range"),
            Self::DuplicateKey { index } => write!(f, "peers[{index}]: key is already on the list"),
            Self::DuplicateRange { index } => {
                write!(
                    f,
                    "peers[{index}]: address range is already held by another peer"
                )
            }
        }
    }
}

impl std::error::Error for ListError {}

/// What to do with a list that arrives, given the one already stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Newer than what is stored: store it, then apply it.
    Newer,
    /// The same version with the same content: a retry. Applying it again is harmless.
    Repeat,
    /// An older version, or the same version with different content: refuse it.
    Stale,
}

pub fn judge(stored: Option<&Desired>, incoming: &Desired) -> Verdict {
    match stored {
        None => Verdict::Newer,
        Some(stored) if incoming.version > stored.version => Verdict::Newer,
        Some(stored) if incoming == stored => Verdict::Repeat,
        Some(_) => Verdict::Stale,
    }
}

/// What it takes to make WireGuard match a list: peers to add, peers to remove (by key)
/// and peers whose ranges changed. Peers that already match are not in it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub add: Vec<DesiredPeer>,
    pub remove: Vec<String>,
    pub update: Vec<DesiredPeer>,
}

pub fn plan(current: &[PeerState], desired: &Desired) -> Plan {
    let have: HashMap<&str, &PeerState> = current
        .iter()
        .map(|peer| (peer.public_key.as_str(), peer))
        .collect();
    let wanted: HashSet<&str> = desired
        .peers
        .iter()
        .map(|p| p.public_key.as_str())
        .collect();

    let mut plan = Plan::default();
    for want in &desired.peers {
        match have.get(want.public_key.as_str()) {
            None => plan.add.push(want.clone()),
            Some(peer) if !has_ranges(peer, &want.ranges) => plan.update.push(want.clone()),
            Some(_) => {}
        }
    }
    plan.remove = current
        .iter()
        .filter(|peer| !wanted.contains(peer.public_key.as_str()))
        .map(|peer| peer.public_key.clone())
        .collect();
    plan
}

/// Whether the peer holds exactly these ranges (sorted, no repeats), however WireGuard
/// happens to print them. A range that cannot be read counts as different.
fn has_ranges(peer: &PeerState, want: &[Cidr]) -> bool {
    let mut have = Vec::with_capacity(peer.allowed_ips.len());
    for text in &peer.allowed_ips {
        match Cidr::parse(text) {
            Some(range) => have.push(range),
            None => return false,
        }
    }
    have.sort();
    have.dedup();
    have == want
}

impl PeerList {
    pub fn check(&self) -> Result<Desired, ListError> {
        let mut peers = Vec::with_capacity(self.peers.len());
        let mut seen_keys = HashSet::new();
        let mut seen_ranges = HashSet::new();
        for (index, spec) in self.peers.iter().enumerate() {
            if !is_valid_key(&spec.public_key) {
                return Err(ListError::BadKey { index });
            }
            let mut ranges = Vec::with_capacity(spec.allowed_ips.len());
            for text in &spec.allowed_ips {
                ranges.push(Cidr::parse(text).ok_or(ListError::BadRange { index })?);
            }
            ranges.sort();
            ranges.dedup();
            if !seen_keys.insert(spec.public_key.as_str()) {
                return Err(ListError::DuplicateKey { index });
            }
            // Two peers holding the same range would take it from each other forever.
            if ranges.iter().any(|range| !seen_ranges.insert(*range)) {
                return Err(ListError::DuplicateRange { index });
            }
            peers.push(DesiredPeer {
                public_key: spec.public_key.clone(),
                ranges,
                trackers: spec.trackers,
            });
        }
        peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        Ok(Desired {
            version: self.version,
            peers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const K3: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

    #[test]
    fn only_canonical_32_byte_base64_keys_are_valid() {
        for good in [K1, K2, K3] {
            assert!(is_valid_key(good), "{good}");
        }
        let bad = [
            String::new(),
            K1[..43].to_string(),       // padding missing
            format!("{K1}A"),           // one character too long
            format!("{} ", &K1[..43]),  // space in place of the padding
            format!("{}F=", &K1[..42]), // spare bits set: not the canonical form
            format!("{}-=", &K1[..42]), // not in the standard alphabet
            format!("{}A", &K1[..43]),  // 44 characters but no `=` at the end
        ];
        for key in &bad {
            assert!(!is_valid_key(key), "{key:?}");
        }
    }

    #[test]
    fn ranges_need_a_prefix_and_no_stray_bits() {
        for good in [
            "10.66.1.2/32",
            "10.66.1.0/24",
            "0.0.0.0/0",
            "fd00::2/128",
            "fd00::/64",
            "::/0",
        ] {
            assert!(Cidr::parse(good).is_some(), "{good}");
        }
        let bad = [
            "",
            "10.66.1.2",
            "10.66.1.2/",
            "/32",
            "10.66.1.2/33",
            "fd00::2/129",
            "10.66.1.2/24",
            "fd00::2/64",
            "10.66.1.2/+32",
            "10.66.1.2/3 2",
            " 10.66.1.2/32",
            "10.66.1.256/32",
            "10.66.1.2/32/1",
            "fe80::1%eth0/128",
            "nonsense",
        ];
        for range in bad {
            assert!(Cidr::parse(range).is_none(), "{range:?}");
        }
    }

    #[test]
    fn only_a_single_ipv4_address_is_an_ipv4_host() {
        let host = |text: &str| Cidr::parse(text).unwrap().ipv4_host();
        assert_eq!(
            host("10.77.0.5/32"),
            Some(std::net::Ipv4Addr::new(10, 77, 0, 5))
        );
        assert_eq!(host("10.77.0.4/31"), None);
        assert_eq!(host("10.77.0.0/16"), None);
        assert_eq!(host("fd00::5/128"), None);
    }

    #[test]
    fn the_same_range_written_two_ways_is_equal_and_prints_one_way() {
        let a = Cidr::parse("fd00::2/128").unwrap();
        let b = Cidr::parse("FD00:0:0::2/128").unwrap();

        assert_eq!(a, b);
        assert_eq!(b.to_string(), "fd00::2/128");
        assert_eq!(
            Cidr::parse("10.66.1.2/32").unwrap().to_string(),
            "10.66.1.2/32"
        );
    }

    fn spec(key: &str, ranges: &[&str]) -> PeerSpec {
        PeerSpec {
            public_key: key.to_string(),
            allowed_ips: ranges.iter().map(ToString::to_string).collect(),
            trackers: true,
        }
    }

    fn list(version: u64, peers: Vec<PeerSpec>) -> PeerList {
        PeerList { version, peers }
    }

    #[test]
    fn the_documented_json_reads_into_a_list_that_checks_out_sorted() {
        let json = format!(
            r#"{{ "version": 7, "peers": [
                {{ "public_key": "{K2}", "allowed_ips": ["fd00::3/128", "10.77.0.6/32"] }},
                {{ "public_key": "{K1}", "allowed_ips": ["10.77.0.5/32"] }} ] }}"#
        );

        let parsed: PeerList = serde_json::from_str(&json).unwrap();
        let desired = parsed.check().unwrap();

        assert_eq!(desired.version, 7);
        let keys: Vec<&str> = desired
            .peers
            .iter()
            .map(|p| p.public_key.as_str())
            .collect();
        assert_eq!(keys, [K1, K2]);
        let ranges: Vec<String> = desired.peers[1]
            .ranges
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(ranges, ["10.77.0.6/32", "fd00::3/128"]);
    }

    #[test]
    fn one_bad_entry_rejects_the_whole_list_and_names_its_position() {
        let ok = || spec(K1, &["10.66.1.2/32"]);
        let cases = [
            (
                spec("short", &["10.66.1.3/32"]),
                ListError::BadKey { index: 1 },
            ),
            (
                spec(K2, &["10.66.1.3/24"]),
                ListError::BadRange { index: 1 },
            ),
            (
                spec(K1, &["10.66.1.9/32"]),
                ListError::DuplicateKey { index: 1 },
            ),
            (
                spec(K2, &["10.66.1.2/32"]),
                ListError::DuplicateRange { index: 1 },
            ),
        ];
        for (bad, expected) in cases {
            assert_eq!(list(1, vec![ok(), bad]).check(), Err(expected));
        }
    }

    #[test]
    fn list_errors_name_the_position_and_never_the_entry() {
        assert_eq!(
            ListError::BadKey { index: 3 }.to_string(),
            "peers[3]: not a valid WireGuard key"
        );
        assert_eq!(
            ListError::BadRange { index: 3 }.to_string(),
            "peers[3]: not a valid address range"
        );
        assert_eq!(
            ListError::DuplicateKey { index: 3 }.to_string(),
            "peers[3]: key is already on the list"
        );
        assert_eq!(
            ListError::DuplicateRange { index: 3 }.to_string(),
            "peers[3]: address range is already held by another peer"
        );
    }

    const K4: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";

    fn state(key: &str, ranges: &[&str]) -> PeerState {
        PeerState {
            public_key: key.to_string(),
            endpoint: None,
            allowed_ips: ranges.iter().map(ToString::to_string).collect(),
            latest_handshake: Some(1),
            rx: 1,
            tx: 1,
        }
    }

    fn keys(peers: &[DesiredPeer]) -> Vec<&str> {
        peers.iter().map(|p| p.public_key.as_str()).collect()
    }

    #[test]
    fn the_plan_adds_removes_and_updates_and_leaves_the_rest_alone() {
        let current = [
            state(K1, &["10.66.1.2/32"]),
            state(K2, &["10.66.1.3/32"]),
            state(K3, &["10.66.1.4/32"]),
        ];
        let desired = list(
            5,
            vec![
                spec(K2, &["10.66.1.3/32"]),  // unchanged
                spec(K3, &["10.66.1.40/32"]), // new range
                spec(K4, &["10.66.1.5/32"]),  // new peer
            ],
        )
        .check()
        .unwrap();

        let plan = plan(&current, &desired);

        assert_eq!(plan.remove, [K1]);
        assert_eq!(keys(&plan.add), [K4]);
        assert_eq!(keys(&plan.update), [K3]);
    }

    #[test]
    fn ranges_compare_as_sets_not_as_text_so_a_matching_list_plans_nothing() {
        let current = [state(K1, &["FD00:0:0::2/128", "10.66.1.2/32"])];
        let desired = list(5, vec![spec(K1, &["10.66.1.2/32", "fd00::2/128"])])
            .check()
            .unwrap();

        assert_eq!(plan(&current, &desired), Plan::default());
    }

    #[test]
    fn only_a_newer_version_or_an_exact_retry_is_accepted() {
        let at = |version, key| {
            list(version, vec![spec(key, &["10.66.1.2/32"])])
                .check()
                .unwrap()
        };

        assert_eq!(judge(None, &at(1, K1)), Verdict::Newer);
        assert_eq!(judge(Some(&at(7, K1)), &at(8, K2)), Verdict::Newer);
        assert_eq!(judge(Some(&at(7, K1)), &at(7, K1)), Verdict::Repeat);
        assert_eq!(judge(Some(&at(7, K1)), &at(7, K2)), Verdict::Stale);
        assert_eq!(judge(Some(&at(7, K1)), &at(6, K1)), Verdict::Stale);
    }

    #[test]
    fn a_peer_is_filtered_unless_it_says_trackers_false_and_only_false_is_written() {
        let json = format!(
            r#"{{ "version": 3, "peers": [
                {{ "public_key": "{K1}", "allowed_ips": ["10.77.0.2/32"] }},
                {{ "public_key": "{K2}", "allowed_ips": ["10.77.0.3/32"], "trackers": false }},
                {{ "public_key": "{K3}", "allowed_ips": ["10.77.0.4/32"], "trackers": true }} ] }}"#
        );

        let parsed: PeerList = serde_json::from_str(&json).unwrap();
        let read: Vec<bool> = parsed.peers.iter().map(|p| p.trackers).collect();
        assert_eq!(read, [true, false, true]);

        let desired = parsed.check().unwrap();
        let checked: Vec<(&str, bool)> = desired
            .peers
            .iter()
            .map(|p| (p.public_key.as_str(), p.trackers))
            .collect();
        assert_eq!(checked, [(K1, true), (K2, false), (K3, true)]);

        // A filtered peer is written exactly as before the field existed, so lists of
        // filtered devices keep their text (and their version) and older agents see no
        // change.
        let written = serde_json::to_string(&parsed).unwrap();
        assert_eq!(written.matches("\"trackers\"").count(), 1, "{written}");
        assert!(written.contains("\"trackers\":false"), "{written}");
        let before_the_field = format!(
            r#"{{"version":3,"peers":[{{"public_key":"{K1}","allowed_ips":["10.77.0.2/32"]}}]}}"#
        );
        assert_eq!(
            serde_json::to_string(&list(3, vec![spec(K1, &["10.77.0.2/32"])])).unwrap(),
            before_the_field
        );
    }

    #[test]
    fn the_same_version_that_differs_only_in_trackers_is_refused_as_stale() {
        let at = |trackers| {
            let mut peer = spec(K1, &["10.66.1.2/32"]);
            peer.trackers = trackers;
            list(7, vec![peer]).check().unwrap()
        };

        assert_eq!(judge(Some(&at(true)), &at(true)), Verdict::Repeat);
        assert_eq!(judge(Some(&at(true)), &at(false)), Verdict::Stale);
    }

    #[test]
    fn a_range_wireguard_prints_that_we_cannot_read_gets_rewritten() {
        let current = [state(K1, &["garbage"])];
        let desired = list(5, vec![spec(K1, &["10.66.1.2/32"])]).check().unwrap();

        assert_eq!(keys(&plan(&current, &desired).update), [K1]);
    }
}
