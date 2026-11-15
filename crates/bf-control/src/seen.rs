//! When a device last used the VPN, and through which server, for its owner's account page.
//!
//! A device's key is on every server (both apps), so the servers' own handshake times say
//! which one it really uses. They come from the poller's readings and, once a server has
//! forgotten an idle device, from the newest contact the board remembers. Both are kept in
//! memory only: nothing here is stored.

use crate::poller::Snapshot;

/// What the readings say about one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// No reading to go by (the poller is not running, or no server answered).
    Unknown,
    /// Not seen since the website last started: the servers forget a device 5 minutes after
    /// its last handshake, and the website remembers only what it read since it started.
    Never,
    /// A server counts it as online now.
    Now {
        server: String,
        app: Option<&'static str>,
    },
    /// Its most recent handshake, `ago` seconds before now.
    Before {
        server: String,
        app: Option<&'static str>,
        ago: u64,
    },
}

/// What the readings in `snapshot` say about the device with `public_key`, at `now`.
pub fn seen(snapshot: Option<&Snapshot>, public_key: &str, now: u64) -> Seen {
    let Some(snapshot) = snapshot else {
        return Seen::Unknown;
    };
    // (seconds since its handshake as of now, online, server, app) for each server that saw it.
    let mut sightings = Vec::new();
    let mut any_reading = false;
    for node in &snapshot.nodes {
        let Some(reading) = &node.reading else {
            continue;
        };
        any_reading = true;
        for peer in reading.peers.iter().filter(|p| p.public_key == public_key) {
            if let Some(age) = peer.handshake_age {
                let ago = age.saturating_add(now.saturating_sub(node.checked_at));
                sightings.push((ago, peer.online, node));
            }
        }
    }
    if !any_reading {
        return Seen::Unknown;
    }
    let app = |node: &crate::poller::NodeView| node.protocol.map(|p| p.title());
    if let Some((_, _, node)) = sightings
        .iter()
        .filter(|(_, online, _)| *online)
        .min_by_key(|(ago, _, _)| *ago)
    {
        return Seen::Now {
            server: node.title.clone(),
            app: app(node),
        };
    }
    // The newest of what a server still holds and what the website remembers (servers
    // forget a device 5 minutes after its last handshake).
    let held = sightings
        .iter()
        .min_by_key(|(ago, _, _)| *ago)
        .map(|(ago, _, node)| (*ago, node.title.clone(), app(node)));
    let remembered = snapshot.contacts.get(public_key).map(|contact| {
        (
            now.saturating_sub(contact.at),
            contact.server.clone(),
            contact.protocol.map(|p| p.title()),
        )
    });
    match held
        .into_iter()
        .chain(remembered)
        .min_by_key(|(ago, _, _)| *ago)
    {
        Some((ago, server, app)) => Seen::Before { server, app, ago },
        None => Seen::Never,
    }
}

/// The line the account page shows.
pub fn describe(seen: &Seen) -> String {
    let through = |server: &str, app: &Option<&'static str>| match app {
        Some(app) => format!("{server} ({app})"),
        None => server.to_string(),
    };
    match seen {
        Seen::Unknown => "Last connection not known right now".to_string(),
        Seen::Never => "No connection seen since the website last started".to_string(),
        Seen::Now { server, app } => format!("Connected now, through {}", through(server, app)),
        Seen::Before { server, app, ago } => format!(
            "Last connected through {}, {}",
            through(server, app),
            how_long_ago(*ago)
        ),
    }
}

fn how_long_ago(seconds: u64) -> String {
    let (n, unit) = match seconds {
        0..60 => return "less than a minute ago".to_string(),
        60..3_600 => (seconds / 60, "minute"),
        3_600..86_400 => (seconds / 3_600, "hour"),
        _ => (seconds / 86_400, "day"),
    };
    let s = if n == 1 { "" } else { "s" };
    format!("{n} {unit}{s} ago")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{NodeReading, PeerReading};
    use crate::poller::{Health, NodeView};
    use crate::protocol::Protocol;

    const PHONE: &str = "pZQHwnLdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const LAPTOP: &str = "LApTopAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const NOW: u64 = 1_000_000;

    fn peer(key: &str, age: Option<u64>, online: bool) -> PeerReading {
        PeerReading {
            public_key: key.to_string(),
            online,
            handshake_age: age,
            rx: 0,
            tx: 0,
        }
    }

    /// A server agent read `checked` seconds before NOW, with these peers.
    fn node(
        title: &str,
        protocol: Option<Protocol>,
        checked: u64,
        peers: Option<Vec<PeerReading>>,
    ) -> NodeView {
        NodeView {
            name: title.to_lowercase(),
            title: title.to_string(),
            place: "Somewhere".to_string(),
            protocol,
            location: None,
            ip: "192.0.2.7".parse().unwrap(),
            health: if peers.is_some() {
                Health::Online
            } else {
                Health::NotResponding
            },
            checked_at: NOW - checked,
            last_good: Some(NOW - checked),
            reading: peers.map(|peers| NodeReading {
                wg_public_key: PHONE.to_string(),
                listen_port: 51820,
                online: 0,
                peers_total: peers.len() as u64,
                desired_version: Some(1),
                load1: None,
                load_steady: None,
                peers,
                logins: None,
                attention: None,
            }),
            problem: None,
            in_sync: true,
            note: None,
        }
    }

    fn board(nodes: Vec<NodeView>) -> Snapshot {
        Snapshot {
            nodes,
            list_version: Some(1),
            updated_at: Some(NOW),
            contacts: Default::default(),
        }
    }

    #[test]
    fn a_device_a_server_counts_as_online_is_connected_now_through_that_server() {
        let snapshot = board(vec![
            node(
                "Toronto",
                Some(Protocol::AmneziaWg),
                5,
                Some(vec![peer(PHONE, None, false)]),
            ),
            node(
                "Dallas",
                Some(Protocol::WireGuard),
                5,
                Some(vec![peer(PHONE, Some(30), true)]),
            ),
        ]);
        let found = seen(Some(&snapshot), PHONE, NOW);
        assert_eq!(
            found,
            Seen::Now {
                server: "Dallas".to_string(),
                app: Some("WireGuard"),
            }
        );
        assert_eq!(
            describe(&found),
            "Connected now, through Dallas (WireGuard)"
        );
    }

    #[test]
    fn otherwise_the_most_recent_handshake_on_any_server_is_the_one_shown() {
        // Toronto saw it 3 hours ago (read 10 s ago); Dallas 2 days ago.
        let snapshot = board(vec![
            node(
                "Toronto",
                Some(Protocol::AmneziaWg),
                10,
                Some(vec![peer(PHONE, Some(3 * 3600 - 10), false)]),
            ),
            node(
                "Dallas",
                Some(Protocol::WireGuard),
                10,
                Some(vec![peer(PHONE, Some(2 * 86_400), false)]),
            ),
        ]);
        let found = seen(Some(&snapshot), PHONE, NOW);
        assert_eq!(
            found,
            Seen::Before {
                server: "Toronto".to_string(),
                app: Some("AmneziaWG"),
                ago: 3 * 3600,
            }
        );
        assert_eq!(
            describe(&found),
            "Last connected through Toronto (AmneziaWG), 3 hours ago"
        );
    }

    #[test]
    fn a_device_no_server_has_seen_is_never() {
        let snapshot = board(vec![
            node(
                "Toronto",
                Some(Protocol::AmneziaWg),
                5,
                Some(vec![peer(PHONE, None, false)]),
            ),
            node(
                "Dallas",
                Some(Protocol::WireGuard),
                5,
                Some(vec![peer(LAPTOP, Some(5), true)]),
            ),
        ]);
        let found = seen(Some(&snapshot), PHONE, NOW);
        assert_eq!(found, Seen::Never);
        assert_eq!(
            describe(&found),
            "No connection seen since the website last started"
        );
    }

    #[test]
    fn without_readings_it_is_not_known() {
        assert_eq!(seen(None, PHONE, NOW), Seen::Unknown);
        let snapshot = board(vec![node("Toronto", Some(Protocol::AmneziaWg), 5, None)]);
        assert_eq!(seen(Some(&snapshot), PHONE, NOW), Seen::Unknown);
        assert_eq!(seen(Some(&board(vec![])), PHONE, NOW), Seen::Unknown);
        assert_eq!(
            describe(&Seen::Unknown),
            "Last connection not known right now"
        );
    }

    #[test]
    fn a_server_with_no_app_set_is_named_alone() {
        let found = Seen::Before {
            server: "Paris".to_string(),
            app: None,
            ago: 120,
        };
        assert_eq!(
            describe(&found),
            "Last connected through Paris, 2 minutes ago"
        );
    }

    #[test]
    fn how_long_ago_reads_naturally() {
        let line = |ago| {
            describe(&Seen::Before {
                server: "Toronto".to_string(),
                app: None,
                ago,
            })
        };
        for (ago, said) in [
            (0, "less than a minute ago"),
            (59, "less than a minute ago"),
            (60, "1 minute ago"),
            (119, "1 minute ago"),
            (3599, "59 minutes ago"),
            (3600, "1 hour ago"),
            (86_399, "23 hours ago"),
            (86_400, "1 day ago"),
            (10 * 86_400, "10 days ago"),
        ] {
            assert_eq!(
                line(ago),
                format!("Last connected through Toronto, {said}"),
                "{ago}"
            );
        }
    }

    fn contact(at: u64, server: &str, protocol: Option<Protocol>) -> crate::poller::Contact {
        crate::poller::Contact {
            at,
            server: server.to_string(),
            protocol,
        }
    }

    #[test]
    fn a_device_the_servers_have_forgotten_still_shows_when_it_was_last_seen() {
        // The servers forget a device 5 minutes after its last handshake (the agent's
        // forget_idle); the website remembers the newest contact it read, in memory only.
        let mut snapshot = board(vec![node(
            "Dallas",
            Some(Protocol::WireGuard),
            5,
            Some(vec![peer(PHONE, None, false)]),
        )]);
        snapshot.contacts.insert(
            PHONE.to_string(),
            contact(NOW - 7_200, "Dallas", Some(Protocol::WireGuard)),
        );
        let found = seen(Some(&snapshot), PHONE, NOW);
        assert_eq!(
            found,
            Seen::Before {
                server: "Dallas".to_string(),
                app: Some("WireGuard"),
                ago: 7_200,
            }
        );
        // A newer handshake that a server still holds wins over an older memory.
        let mut fresher = board(vec![node(
            "Toronto",
            Some(Protocol::AmneziaWg),
            0,
            Some(vec![peer(PHONE, Some(240), false)]),
        )]);
        fresher.contacts.insert(
            PHONE.to_string(),
            contact(NOW - 7_200, "Dallas", Some(Protocol::WireGuard)),
        );
        assert_eq!(
            seen(Some(&fresher), PHONE, NOW),
            Seen::Before {
                server: "Toronto".to_string(),
                app: Some("AmneziaWG"),
                ago: 240,
            }
        );
    }

    #[test]
    fn the_board_remembers_the_newest_contact_and_lets_go_of_devices_no_server_lists() {
        let board = crate::poller::Board::new();
        let reading = |peers| vec![node("Dallas", Some(Protocol::WireGuard), 0, Some(peers))];
        board.set_for_test(reading(vec![peer(PHONE, Some(100), true)]), NOW);
        board.set_for_test(
            reading(vec![peer(PHONE, None, false), peer(LAPTOP, None, false)]),
            NOW,
        );
        let remembered = board.snapshot(NOW).contacts;
        assert_eq!(
            remembered.get(PHONE),
            Some(&contact(NOW - 100, "Dallas", Some(Protocol::WireGuard))),
            "kept after the server forgot it"
        );
        assert!(
            !remembered.contains_key(LAPTOP),
            "never seen, nothing to keep"
        );
        assert!(
            board.snapshot_light(NOW).contacts.is_empty(),
            "the public page gets none"
        );
        // A pass with no reading at all (servers down) keeps the memory.
        board.set_for_test(
            vec![node("Dallas", Some(Protocol::WireGuard), 0, None)],
            NOW,
        );
        assert!(board.snapshot(NOW).contacts.contains_key(PHONE));
        // An agent that does not hold the current list yet (just restarted, its interface
        // empty) is no reason to forget anything.
        let mut fresh = node("Dallas", Some(Protocol::WireGuard), 0, Some(vec![]));
        fresh.in_sync = false;
        board.set_for_test(vec![fresh], NOW);
        assert!(board.snapshot(NOW).contacts.contains_key(PHONE));
        // Nor is one that holds the list but no device at all yet (a rebooted host whose
        // interface the agent has not filled).
        board.set_for_test(reading(vec![]), NOW);
        assert!(board.snapshot(NOW).contacts.contains_key(PHONE));
        // Once the servers holding the list stop listing the device (removed, or its
        // account deleted) for two polls in a row, it goes; one poll is not enough.
        board.set_for_test(reading(vec![peer(LAPTOP, None, false)]), NOW);
        assert!(board.snapshot(NOW).contacts.contains_key(PHONE), "one poll");
        board.set_for_test(reading(vec![peer(LAPTOP, None, false)]), NOW);
        assert!(board.snapshot(NOW).contacts.is_empty(), "two polls");
        // A device listed again in between is not counted as missing.
        board.set_for_test(reading(vec![peer(PHONE, Some(10), true)]), NOW);
        board.set_for_test(reading(vec![peer(LAPTOP, None, false)]), NOW);
        board.set_for_test(reading(vec![peer(PHONE, None, false)]), NOW);
        board.set_for_test(reading(vec![peer(LAPTOP, None, false)]), NOW);
        assert!(
            board.snapshot(NOW).contacts.contains_key(PHONE),
            "missing twice, but not in a row"
        );
    }
}
