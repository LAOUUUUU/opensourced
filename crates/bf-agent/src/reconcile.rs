//! Making WireGuard match a peer list without disturbing the peers that already match.

use std::collections::HashMap;

use bf_common::peers::{Desired, plan};
use bf_common::wg::parse_dump;
use serde::Serialize;

use crate::wgcli::{WgError, Wireguard};

/// How many peers a pass added, removed and updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Changes {
    pub added: usize,
    pub removed: usize,
    pub updated: usize,
}

/// Reads what WireGuard has, then removes the peers that are not on the list, updates
/// the ones whose ranges differ and adds the missing ones. Peers that already match are
/// not touched. Stops at the first failure; the next pass picks up where this one broke.
pub fn apply(wg: &dyn Wireguard, desired: &Desired) -> Result<Changes, WgError> {
    let text = wg.dump()?;
    let dump = parse_dump(&text).map_err(|e| WgError(e.to_string()))?;
    let plan = plan(&dump.peers, desired);
    for key in &plan.remove {
        wg.remove_peer(key)?;
    }
    for peer in plan.update.iter().chain(&plan.add) {
        wg.set_peer(&peer.public_key, &peer.ranges)?;
    }
    Ok(Changes {
        added: plan.add.len(),
        removed: plan.remove.len(),
        updated: plan.update.len(),
    })
}

/// What each peer looked like at the last forgetting pass: whether WireGuard held an address
/// for it, its latest handshake and the bytes it had sent. No address is kept here.
pub type Quiet = HashMap<String, (bool, Option<u64>, u64)>;

/// Forgets the devices on `desired` that WireGuard holds an address for, whose last
/// handshake is more than `after` seconds before `now` (or that never handshook), and that
/// looked exactly the same at the last pass (`quiet`): no new handshake, not a byte more. A
/// device that is reconnecting, or that is in use when the clock jumps, has changed, so it
/// is left alone. Each one is removed and set again with its ranges from the list, so
/// WireGuard no longer holds its address, handshake time or byte counts; it stays allowed in
/// and handshakes again when it next sends. Peers not on the list are left to [`apply`].
/// Gives how many were forgotten; stops at the first failure (a peer removed but not yet set
/// again is put back by the list pass that follows).
pub fn forget_idle(
    wg: &dyn Wireguard,
    desired: &Desired,
    now: u64,
    after: u64,
    quiet: &mut Quiet,
) -> Result<usize, WgError> {
    let text = wg.dump()?;
    let dump = parse_dump(&text).map_err(|e| WgError(e.to_string()))?;
    let listed: HashMap<&str, &bf_common::peers::DesiredPeer> = desired
        .peers
        .iter()
        .map(|spec| (spec.public_key.as_str(), spec))
        .collect();
    let mut seen = Quiet::new();
    let mut forgotten = 0;
    for peer in &dump.peers {
        let looks = (peer.endpoint.is_some(), peer.latest_handshake, peer.rx);
        let old = peer
            .latest_handshake
            .is_none_or(|at| now.saturating_sub(at) > after);
        let unchanged = quiet.get(&peer.public_key) == Some(&looks);
        match listed.get(peer.public_key.as_str()) {
            Some(spec) if peer.endpoint.is_some() && old && unchanged => {
                wg.remove_peer(&peer.public_key)?;
                wg.set_peer(&peer.public_key, &spec.ranges)?;
                forgotten += 1;
            }
            _ => {
                seen.insert(peer.public_key.clone(), looks);
            }
        }
    }
    *quiet = seen;
    Ok(forgotten)
}

#[cfg(test)]
mod tests {
    use bf_common::peers::{PeerList, PeerSpec};

    use super::*;
    use crate::testutil::{FakeWg, K1, K2, K3, K4, PRESHARED_KEY, PRIVATE_KEY};

    fn desired(version: u64, peers: &[(&str, &[&str])]) -> Desired {
        PeerList {
            version,
            peers: peers
                .iter()
                .map(|(key, ranges)| PeerSpec {
                    public_key: (*key).to_string(),
                    allowed_ips: ranges.iter().map(ToString::to_string).collect(),
                    trackers: true,
                })
                .collect(),
        }
        .check()
        .unwrap()
    }

    #[test]
    fn it_removes_updates_and_adds_and_leaves_peers_that_already_match_alone() {
        let wg = FakeWg::with_peers(&[
            (K1, &["10.66.1.2/32"]),
            (K2, &["10.66.1.3/32"]),
            (K3, &["10.66.1.4/32"]),
        ]);
        let list = desired(
            5,
            &[
                (K2, &["10.66.1.3/32"]),
                (K3, &["10.66.1.40/32"]),
                (K4, &["10.66.1.5/32"]),
            ],
        );

        let changes = apply(&wg, &list).unwrap();

        assert_eq!(
            changes,
            Changes {
                added: 1,
                removed: 1,
                updated: 1
            }
        );
        assert_eq!(
            wg.calls(),
            [
                format!("remove {K1}"),
                format!("set {K3} 10.66.1.40/32"),
                format!("set {K4} 10.66.1.5/32")
            ]
        );
        // Nothing was said about K2, and a second pass finds nothing left to do.
        assert_eq!(apply(&wg, &list).unwrap(), Changes::default());
        assert_eq!(wg.calls().len(), 3);
    }

    #[test]
    fn when_wireguard_cannot_be_read_nothing_is_changed_and_it_is_an_error() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        wg.set_down(true);

        let err = apply(&wg, &desired(1, &[])).unwrap_err();

        assert!(wg.calls().is_empty());
        assert!(!err.0.contains(PRIVATE_KEY) && !err.0.contains(PRESHARED_KEY));
    }

    #[test]
    fn a_failed_change_stops_the_pass_and_the_next_pass_finishes_it() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        let list = desired(1, &[(K2, &["10.66.1.3/32"])]);
        wg.set_changes_fail(true);
        assert!(apply(&wg, &list).is_err());
        assert_eq!(wg.peers().len(), 1);

        wg.set_changes_fail(false);

        assert_eq!(
            apply(&wg, &list).unwrap(),
            Changes {
                added: 1,
                removed: 1,
                updated: 0
            }
        );
        assert_eq!(
            wg.peers(),
            [(K2.to_string(), vec!["10.66.1.3/32".to_string()])]
        );
    }

    const NOW: u64 = 1_794_280_000;
    const AFTER: u64 = bf_common::wg::FORGET_IDLE_AFTER_SECS;

    /// The list every forgetting test uses.
    fn listed() -> Desired {
        desired(
            1,
            &[
                (K1, &["10.66.1.2/32", "10.78.1.2/32"]),
                (K2, &["10.66.1.3/32"]),
                (K3, &["10.66.1.4/32"]),
                (K4, &["10.66.1.5/32"]),
            ],
        )
    }

    #[test]
    fn a_device_quiet_for_two_passes_and_five_minutes_is_forgotten_with_its_listed_ranges() {
        // WireGuard keeps a peer's last address and handshake until the peer is removed.
        // Removing it and setting it again clears them; it handshakes again when it next
        // sends. The ranges come from the list, not from what WireGuard says.
        assert_eq!(AFTER, 300, "the privacy policy says 5 minutes");
        let wg = FakeWg::with_peers(&[
            (K1, &["10.66.1.2/32"]),
            (K2, &["10.66.1.3/32"]),
            (K3, &["10.66.1.4/32"]),
            (K4, &["10.66.1.5/32"]),
        ]);
        wg.connect(K1, NOW - AFTER - 31, "203.0.113.7:51820");
        wg.connect(K2, NOW - AFTER + 29, "198.51.100.9:4500");
        wg.connect(K3, NOW - 20, "192.0.2.44:51820");
        let mut quiet = Quiet::default();

        // The first pass only notes what each peer looks like.
        assert_eq!(
            forget_idle(&wg, &listed(), NOW - 30, AFTER, &mut quiet).unwrap(),
            0
        );
        wg.receive(K3, 92);
        assert_eq!(
            forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).unwrap(),
            1
        );

        assert_eq!(
            wg.calls(),
            [
                format!("remove {K1}"),
                format!("set {K1} 10.66.1.2/32,10.78.1.2/32")
            ],
            "only K1; K2 is not yet 5 minutes quiet, K3 is in use, K4 never connected"
        );
        let dump = parse_dump(&wg.dump().unwrap()).unwrap();
        let k1 = dump.peers.iter().find(|p| p.public_key == K1).unwrap();
        assert_eq!(k1.endpoint, None, "its address is gone");
        assert_eq!(k1.latest_handshake, None, "and so is its handshake time");
        assert_eq!(
            forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).unwrap(),
            0
        );
        // 30 s later K2 is past 5 minutes and was quiet since the last pass.
        assert_eq!(
            forget_idle(&wg, &listed(), NOW + 30, AFTER, &mut quiet).unwrap(),
            1
        );
        assert_eq!(
            wg.calls()[2..],
            [format!("remove {K2}"), format!("set {K2} 10.66.1.3/32")]
        );
    }

    #[test]
    fn a_device_that_is_reconnecting_is_not_forgotten() {
        // A forgotten device sends a handshake: the server sets its address at once but its
        // handshake time only when the first packet after it arrives. In between it looks
        // like an address with no handshake; it changed since the last pass, so it stays.
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        let mut quiet = Quiet::default();
        assert_eq!(
            forget_idle(&wg, &listed(), NOW - 30, AFTER, &mut quiet).unwrap(),
            0
        );
        wg.connect(K1, 0, "203.0.113.7:51820");
        wg.receive(K1, 148);
        assert_eq!(
            forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).unwrap(),
            0
        );
        assert!(wg.calls().is_empty());
    }

    #[test]
    fn a_jump_of_the_clock_does_not_forget_devices_in_use() {
        // Every handshake looks old after a forward jump, but a device in use keeps sending.
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        wg.connect(K1, NOW - 20, "203.0.113.7:51820");
        let mut quiet = Quiet::default();
        assert_eq!(
            forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).unwrap(),
            0
        );
        wg.receive(K1, 32);
        assert_eq!(
            forget_idle(&wg, &listed(), NOW + 86_400, AFTER, &mut quiet).unwrap(),
            0
        );
        assert!(wg.calls().is_empty());
    }

    #[test]
    fn a_peer_that_is_not_on_the_list_is_left_for_the_list_pass() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        wg.add_stray(K2, &["10.66.9.9/32"]);
        wg.connect(K2, NOW - 3_600, "203.0.113.8:51820");
        let only_k1 = desired(1, &[(K1, &["10.66.1.2/32"])]);
        let mut quiet = Quiet::default();
        forget_idle(&wg, &only_k1, NOW - 30, AFTER, &mut quiet).unwrap();
        assert_eq!(
            forget_idle(&wg, &only_k1, NOW, AFTER, &mut quiet).unwrap(),
            0
        );
        assert!(
            wg.calls().is_empty(),
            "apply removes it; forgetting never re-adds it"
        );
    }

    #[test]
    fn a_handshake_from_the_future_is_not_idle() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        wg.connect(K1, NOW + 600, "203.0.113.7:51820");
        let mut quiet = Quiet::default();
        forget_idle(&wg, &listed(), NOW - 30, AFTER, &mut quiet).unwrap();
        assert_eq!(
            forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).unwrap(),
            0
        );
        assert!(wg.calls().is_empty());
    }

    #[test]
    fn forgetting_stops_at_a_failure_and_never_reads_out_a_secret_or_an_address() {
        let wg = FakeWg::with_peers(&[(K1, &["10.66.1.2/32"])]);
        wg.connect(K1, NOW - 900, "203.0.113.7:51820");
        let mut quiet = Quiet::default();
        forget_idle(&wg, &listed(), NOW - 30, AFTER, &mut quiet).unwrap();
        wg.set_sets_fail(true);
        let err = forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).unwrap_err();
        assert!(!err.0.contains(PRIVATE_KEY) && !err.0.contains(PRESHARED_KEY));
        assert!(!err.0.contains("203.0.113.7"), "{err:?}");
        assert!(
            !wg.has_peer(K1),
            "removed, not yet set again: the list pass puts it back"
        );
        wg.set_down(true);
        assert!(forget_idle(&wg, &listed(), NOW, AFTER, &mut quiet).is_err());
    }
}
