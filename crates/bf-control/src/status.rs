//! What the public status page and the front page's Servers cards say about each server:
//! one word, worked out here and nowhere else, so the two never disagree
//! (`specs/status-page.md`).

use crate::closest::{Busy, Candidate};
use crate::poller::{Health, NodeView, Snapshot};
use crate::web::escape_html;

/// The one word for a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Up,
    Overloaded,
    BeingFixed,
    Down,
    Unknown,
}

/// One server as the public sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub title: String,
    pub place: String,
    pub state: State,
    /// Lines under the server about an app that is not like the rest ("AmneziaWG is not
    /// responding.").
    pub notes: Vec<String>,
    /// How close the server is to being overloaded, in percent, rounded down to the nearest
    /// 10 (100 only when it is overloaded); `None` when it is not working or has no reading.
    pub load: Option<u8>,
}

impl State {
    /// The word the public pages use.
    pub fn label(self) -> &'static str {
        match self {
            State::Up => "Up",
            State::Overloaded => "Overloaded",
            State::BeingFixed => "Being fixed",
            State::Down => "Down",
            State::Unknown => "Status unknown",
        }
    }

    /// What the word means, in one sentence, for the status page.
    pub fn meaning(self) -> &'static str {
        match self {
            State::Up => "Working.",
            State::Overloaded => {
                "Working, but it may be slower. New devices are sent to another server."
            }
            State::BeingFixed => {
                "Switched off on purpose. Devices on it will not connect until it is back."
            }
            State::Down => "Not answering. We are told after 3 minutes.",
            State::Unknown => "We have no recent reading. It does not mean the server is down.",
        }
    }

    /// The two style classes a card uses for the word: the dot's and the label's. Green for
    /// up, red for down; everything else keeps the plain amber, since the word says which.
    pub fn classes(self) -> (&'static str, &'static str) {
        match self {
            State::Up => ("dot up", "state up"),
            State::Down => ("dot down", "state down"),
            State::Overloaded | State::BeingFixed | State::Unknown => ("dot", "state"),
        }
    }
}

/// Every server on the board, in the order they first appear, with its word. A server is
/// the agents that share a title and a place.
pub fn servers(snapshot: &Snapshot, busy: &Busy) -> Vec<Server> {
    let mut groups: Vec<(&str, &str, Vec<&NodeView>)> = Vec::new();
    for node in &snapshot.nodes {
        match groups
            .iter_mut()
            .find(|(title, place, _)| *title == node.title && *place == node.place)
        {
            Some((_, _, agents)) => agents.push(node),
            None => groups.push((&node.title, &node.place, vec![node])),
        }
    }
    groups
        .into_iter()
        .map(|(title, place, agents)| {
            let (together, has_reading) = together(&agents);
            let state = state_of(&agents, &together, busy);
            let working = matches!(state, State::Up | State::Overloaded);
            Server {
                title: title.to_string(),
                place: place.to_string(),
                state,
                notes: notes_of(&agents),
                load: (working && has_reading).then(|| load_percent(&together, busy)),
            }
        })
        .collect()
}

/// A server's agents as one thing to ask "is it busy?" of, the way "Closest to you" adds
/// them up: devices online together, the highest load. The flag says whether any agent has a
/// reading at all.
fn together(agents: &[&NodeView]) -> (Candidate, bool) {
    let mut together = Candidate {
        location: None,
        online: 0,
        load: None,
    };
    let mut any = false;
    for reading in agents.iter().filter_map(|node| node.reading.as_ref()) {
        together.add_reading(reading.online, reading.load1);
        any = true;
    }
    (together, any)
}

/// How close the server is to the overloaded line, in percent, rounded down to the nearest 10:
/// the larger of its devices online over `BC_NODE_BUSY_ONLINE` and its load over
/// `BC_NODE_BUSY_LOAD`. 100 only when [`Candidate::is_busy`] says so, so 100 and Overloaded
/// are the same thing, and a server one device under the line shows 90, not 100. Rounding
/// down keeps the exact count of devices out of public view.
fn load_percent(together: &Candidate, busy: &Busy) -> u8 {
    if together.is_busy(busy) {
        return 100;
    }
    let devices = together.online as f64 / busy.online as f64;
    let load = together.load.map_or(0.0, |load| load / busy.load);
    // `f64::max` skips a NaN, and a cast of NaN or a negative number to u8 is 0.
    let tens = (devices.max(load) * 10.0).floor().clamp(0.0, 9.0);
    tens as u8 * 10
}

/// The word for one server's agents (the first rule that fits, `specs/status-page.md`).
fn state_of(agents: &[&NodeView], together: &Candidate, busy: &Busy) -> State {
    if agents.iter().any(|node| node.health == Health::Online) {
        return if together.is_busy(busy) {
            State::Overloaded
        } else {
            State::Up
        };
    }
    if agents.iter().all(|node| node.health == Health::BeingFixed) {
        State::BeingFixed
    } else if agents
        .iter()
        .all(|node| matches!(node.health, Health::NotResponding | Health::BeingFixed))
    {
        State::Down
    } else {
        State::Unknown
    }
}

/// A line for each agent of a working server that is not working: the app and what is wrong.
fn notes_of(agents: &[&NodeView]) -> Vec<String> {
    if !agents.iter().any(|node| node.health == Health::Online) {
        return Vec::new();
    }
    agents
        .iter()
        .filter_map(|node| {
            let what = match node.health {
                Health::NotResponding => "not responding",
                Health::BeingFixed => "being fixed",
                _ => return None,
            };
            let app = node.protocol.map_or("One app", |protocol| protocol.title());
            Some(format!("{app} is {what}."))
        })
        .collect()
}

/// One server's line on a card list, the same on the front page and on `/status`.
pub fn card(server: &Server, show_load: bool) -> String {
    let (dot, state) = server.state.classes();
    let load = match (show_load, server.load) {
        (true, Some(percent)) => format!("<span class=\"where\">{percent}% load</span>"),
        _ => String::new(),
    };
    format!(
        "<li><span class=\"{dot}\" aria-hidden=\"true\"></span><strong>{}</strong><span class=\"where\">{}</span>{load}<span class=\"{state}\">{}</span></li>",
        escape_html(&server.title),
        escape_html(&server.place),
        server.state.label()
    )
}

/// The HTML `/status` puts in place of its marker: the cards, a line for each note, what the
/// words in use mean, and how long ago the board was last updated. It has no device count,
/// no load figure and no node name; the words are all it says about a server.
pub fn answer(snapshot: &Snapshot, busy: &Busy, now: u64) -> String {
    let servers = servers(snapshot, busy);
    if servers.is_empty() {
        return "<p class=\"lead\">No servers are listed yet.</p>".to_string();
    }
    let mut html = String::from("<ul class=\"nodes\">\n");
    for server in &servers {
        html.push_str(&format!("    {}\n", card(server, true)));
    }
    html.push_str("  </ul>\n");
    for server in &servers {
        for note in &server.notes {
            html.push_str(&format!(
                "  <p class=\"note\">{}: {note}</p>\n",
                escape_html(&server.title)
            ));
        }
    }
    html.push_str(
        "  <h2 class=\"section-title\">What the words mean</h2>\n  <ul class=\"plain\">\n",
    );
    for state in [
        State::Up,
        State::Overloaded,
        State::BeingFixed,
        State::Down,
        State::Unknown,
    ] {
        if servers.iter().any(|server| server.state == state) {
            html.push_str(&format!(
                "    <li><strong>{}</strong>: {}</li>\n",
                state.label(),
                state.meaning()
            ));
        }
    }
    html.push_str("  </ul>\n");
    if servers.iter().any(|server| server.load.is_some()) {
        html.push_str("  <p class=\"note\">Load is how close a server is to being overloaded: 100% is overloaded. It is rounded down to the nearest 10%, because an exact count would say who is connected.</p>\n");
    }
    let checked = match snapshot.updated_at {
        Some(at) => format!("Last checked {}.", ago(now.saturating_sub(at))),
        None => "No check has finished yet.".to_string(),
    };
    html.push_str(&format!("  <p class=\"note\">{checked}</p>"));
    html
}

/// A board with nothing on it, for a site that has no poller.
pub fn empty_board() -> Snapshot {
    Snapshot {
        nodes: Vec::new(),
        list_version: None,
        updated_at: None,
        contacts: Default::default(),
    }
}

/// "4 seconds ago", "1 minute ago", "2 hours ago".
fn ago(secs: u64) -> String {
    let (n, unit) = match secs {
        0..=59 => (secs, "second"),
        60..=3599 => (secs / 60, "minute"),
        _ => (secs / 3600, "hour"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::NodeReading;
    use crate::poller::NodeView;
    use crate::protocol::Protocol;

    /// One agent of the server `title`, with the devices online and the load it reports
    /// (a reading only if it is online).
    fn agent(
        title: &str,
        protocol: Option<Protocol>,
        health: Health,
        online: u64,
        load: Option<f64>,
    ) -> NodeView {
        NodeView {
            name: format!("{}-{:?}", title.to_lowercase(), protocol),
            title: title.to_string(),
            place: "Canada".to_string(),
            protocol,
            location: None,
            ip: "192.0.2.7".parse().unwrap(),
            health,
            checked_at: 100,
            last_good: Some(100),
            reading: (health == Health::Online).then(|| NodeReading {
                wg_public_key: "WGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGA=".to_string(),
                listen_port: 51820,
                online,
                peers_total: online,
                desired_version: Some(1),
                load1: load,
                peers: Vec::new(),
                logins: None,
            }),
            problem: None,
            in_sync: true,
        }
    }

    fn board(nodes: Vec<NodeView>) -> Snapshot {
        Snapshot {
            nodes,
            list_version: Some(1),
            updated_at: Some(100),
            contacts: Default::default(),
        }
    }

    fn word(nodes: Vec<NodeView>) -> State {
        let all = servers(&board(nodes), &Busy::default());
        assert_eq!(all.len(), 1, "{all:?}");
        all[0].state
    }

    const WG: Option<Protocol> = Some(Protocol::WireGuard);
    const AWG: Option<Protocol> = Some(Protocol::AmneziaWg);

    #[test]
    fn an_online_server_that_is_not_busy_is_up() {
        assert_eq!(
            word(vec![agent("Toronto", WG, Health::Online, 3, Some(0.1))]),
            State::Up
        );
    }

    #[test]
    fn an_online_server_with_no_reading_counts_no_devices_and_is_up() {
        let mut node = agent("Toronto", WG, Health::Online, 0, None);
        node.reading = None;
        assert_eq!(word(vec![node]), State::Up);
    }

    #[test]
    fn devices_at_the_limit_make_it_overloaded_and_one_under_does_not() {
        let at = Busy::default().online;
        assert_eq!(
            word(vec![agent("Toronto", WG, Health::Online, at, None)]),
            State::Overloaded
        );
        assert_eq!(
            word(vec![agent("Toronto", WG, Health::Online, at - 1, None)]),
            State::Up
        );
    }

    #[test]
    fn load_at_the_limit_makes_it_overloaded_and_just_under_does_not() {
        let at = Busy::default().load;
        assert_eq!(
            word(vec![agent("Toronto", WG, Health::Online, 1, Some(at))]),
            State::Overloaded
        );
        assert_eq!(
            word(vec![agent(
                "Toronto",
                WG,
                Health::Online,
                1,
                Some(at - 0.01)
            )]),
            State::Up
        );
    }

    #[test]
    fn a_servers_agents_are_added_up_for_devices_and_the_highest_load_counts() {
        let half = Busy::default().online / 2;
        assert_eq!(
            word(vec![
                agent("Dallas", WG, Health::Online, half, None),
                agent("Dallas", AWG, Health::Online, half, None),
            ]),
            State::Overloaded,
            "two halves reach the limit"
        );
        assert_eq!(
            word(vec![
                agent("Dallas", WG, Health::Online, 1, Some(0.1)),
                agent("Dallas", AWG, Health::Online, 1, Some(0.95)),
            ]),
            State::Overloaded,
            "one agent's load is enough"
        );
    }

    #[test]
    fn the_settings_decide_what_busy_is_and_the_same_numbers_serve_closest_to_you() {
        let nodes = board(vec![agent("Toronto", WG, Health::Online, 50, Some(2.0))]);
        let loose = Busy {
            online: 1000,
            load: 5.0,
        };
        assert_eq!(servers(&nodes, &loose)[0].state, State::Up);
        let strict = Busy {
            online: 10,
            load: 5.0,
        };
        assert_eq!(servers(&nodes, &strict)[0].state, State::Overloaded);
    }

    #[test]
    fn a_server_whose_every_agent_is_not_responding_is_down() {
        assert_eq!(
            word(vec![
                agent("Toronto", WG, Health::NotResponding, 0, None),
                agent("Toronto", AWG, Health::NotResponding, 0, None),
            ]),
            State::Down
        );
    }

    #[test]
    fn one_agent_down_beside_an_online_one_is_still_up_with_a_line_naming_the_app() {
        let all = servers(
            &board(vec![
                agent("Dallas", WG, Health::Online, 1, None),
                agent("Dallas", AWG, Health::NotResponding, 0, None),
            ]),
            &Busy::default(),
        );
        assert_eq!(all[0].state, State::Up);
        assert_eq!(all[0].notes, vec!["AmneziaWG is not responding."]);
    }

    #[test]
    fn an_overloaded_server_with_an_agent_down_still_says_overloaded_and_names_the_app() {
        let all = servers(
            &board(vec![
                agent("Dallas", WG, Health::Online, 99, None),
                agent("Dallas", AWG, Health::NotResponding, 0, None),
            ]),
            &Busy::default(),
        );
        assert_eq!(all[0].state, State::Overloaded);
        assert_eq!(all[0].notes, vec!["AmneziaWG is not responding."]);
    }

    #[test]
    fn a_server_whose_every_agent_is_being_fixed_is_being_fixed() {
        assert_eq!(
            word(vec![
                agent("Toronto", WG, Health::BeingFixed, 0, None),
                agent("Toronto", AWG, Health::BeingFixed, 0, None),
            ]),
            State::BeingFixed
        );
    }

    #[test]
    fn one_agent_being_fixed_beside_an_online_one_is_up_with_a_line_naming_the_app() {
        let all = servers(
            &board(vec![
                agent("Toronto", WG, Health::BeingFixed, 0, None),
                agent("Toronto", AWG, Health::Online, 1, None),
            ]),
            &Busy::default(),
        );
        assert_eq!(all[0].state, State::Up);
        assert_eq!(all[0].notes, vec!["WireGuard is being fixed."]);
    }

    #[test]
    fn one_agent_being_fixed_and_the_other_not_responding_is_down() {
        assert_eq!(
            word(vec![
                agent("Toronto", WG, Health::BeingFixed, 0, None),
                agent("Toronto", AWG, Health::NotResponding, 0, None),
            ]),
            State::Down
        );
    }

    #[test]
    fn an_agent_with_no_reading_yet_keeps_the_server_unknown_unless_another_is_online() {
        assert_eq!(
            word(vec![agent("Toronto", WG, Health::Unknown, 0, None)]),
            State::Unknown
        );
        assert_eq!(
            word(vec![
                agent("Toronto", WG, Health::Unknown, 0, None),
                agent("Toronto", AWG, Health::NotResponding, 0, None),
            ]),
            State::Unknown,
            "not every agent is known to be down"
        );
        assert_eq!(
            word(vec![
                agent("Toronto", WG, Health::Unknown, 0, None),
                agent("Toronto", AWG, Health::Online, 0, None),
            ]),
            State::Up
        );
    }

    #[test]
    fn a_stale_board_reads_unknown_for_a_server_being_fixed_too() {
        let board = crate::poller::Board::new();
        board.set_for_test(vec![agent("Toronto", WG, Health::BeingFixed, 0, None)], 100);
        let late = board.snapshot_light(100 + crate::poller::STALE_AFTER_SECS + 1);
        assert_eq!(servers(&late, &Busy::default())[0].state, State::Unknown);
    }

    #[test]
    fn a_server_that_is_down_being_fixed_or_unknown_has_no_notes_its_word_says_it_all() {
        for health in [Health::NotResponding, Health::BeingFixed, Health::Unknown] {
            let all = servers(
                &board(vec![
                    agent("Dallas", WG, health, 0, None),
                    agent("Dallas", AWG, health, 0, None),
                ]),
                &Busy::default(),
            );
            assert!(all[0].notes.is_empty(), "{health:?}: {:?}", all[0].notes);
        }
        let html = page(
            vec![
                agent("Dallas", WG, Health::NotResponding, 0, None),
                agent("Dallas", AWG, Health::NotResponding, 0, None),
            ],
            105,
        );
        assert!(!html.contains("is not responding"), "{html}");
    }

    #[test]
    fn an_agent_with_no_protocol_is_called_one_app() {
        let all = servers(
            &board(vec![
                agent("Dallas", None, Health::NotResponding, 0, None),
                agent("Dallas", WG, Health::Online, 0, None),
            ]),
            &Busy::default(),
        );
        assert_eq!(all[0].notes, vec!["One app is not responding."]);
    }

    #[test]
    fn servers_are_grouped_by_title_and_place_in_the_order_they_first_appear() {
        let mut elsewhere = agent("Dallas", WG, Health::Online, 0, None);
        elsewhere.place = "United States".to_string();
        let all = servers(
            &board(vec![
                agent("Toronto", WG, Health::Online, 0, None),
                elsewhere,
                agent("Toronto", AWG, Health::NotResponding, 0, None),
                agent("Dallas", AWG, Health::Online, 0, None),
            ]),
            &Busy::default(),
        );
        let seen: Vec<_> = all
            .iter()
            .map(|s| (s.title.as_str(), s.place.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("Toronto", "Canada"),
                ("Dallas", "United States"),
                ("Dallas", "Canada")
            ],
            "the same title in another place is another server"
        );
    }

    // ---- the load percentage ----

    fn load_of(nodes: Vec<NodeView>) -> Option<u8> {
        let all = servers(&board(nodes), &Busy::default());
        assert_eq!(all.len(), 1, "{all:?}");
        all[0].load
    }

    fn on(online: u64, load: Option<f64>) -> Vec<NodeView> {
        vec![agent("Toronto", WG, Health::Online, online, load)]
    }

    #[test]
    fn the_load_is_how_close_to_overloaded_in_percent_rounded_down_to_ten() {
        // The defaults: overloaded at 40 devices or a load of 0.9.
        assert_eq!(load_of(on(0, None)), Some(0));
        assert_eq!(load_of(on(3, None)), Some(0), "7.5 percent rounds down");
        assert_eq!(load_of(on(4, None)), Some(10));
        assert_eq!(load_of(on(7, None)), Some(10), "17.5 percent");
        assert_eq!(load_of(on(20, None)), Some(50));
        assert_eq!(
            load_of(on(1, Some(0.5))),
            Some(50),
            "0.5 of 0.9 is 55 percent"
        );
        assert_eq!(
            load_of(on(1, Some(0.65))),
            Some(70),
            "0.65 of 0.9 is 72 percent"
        );
    }

    #[test]
    fn the_larger_of_the_two_ratios_counts_and_a_servers_agents_are_added_up() {
        assert_eq!(load_of(on(8, Some(0.65))), Some(70), "devices 20, load 72");
        assert_eq!(load_of(on(28, Some(0.1))), Some(70), "devices 70, load 11");
        assert_eq!(
            load_of(vec![
                agent("Toronto", WG, Health::Online, 6, None),
                agent("Toronto", AWG, Health::Online, 6, None),
            ]),
            Some(30),
            "12 of 40"
        );
        assert_eq!(
            load_of(vec![
                agent("Toronto", WG, Health::Online, 1, Some(0.1)),
                agent("Toronto", AWG, Health::Online, 1, Some(0.65)),
            ]),
            Some(70),
            "the highest load of the agents"
        );
    }

    #[test]
    fn a_hundred_percent_is_overloaded_and_never_anything_else() {
        assert_eq!(load_of(on(40, None)), Some(100));
        assert_eq!(load_of(on(987, Some(5.0))), Some(100), "capped");
        assert_eq!(load_of(on(1, Some(0.9))), Some(100));
        // One under the line is Up and shows 90, even though 39 of 40 is nearly 98.
        let nearly = servers(&board(on(39, None)), &Busy::default());
        assert_eq!((nearly[0].state, nearly[0].load), (State::Up, Some(90)));
        let nearly = servers(&board(on(1, Some(0.89))), &Busy::default());
        assert_eq!((nearly[0].state, nearly[0].load), (State::Up, Some(90)));
        for devices in 0..=300 {
            let all = servers(&board(on(devices, None)), &Busy::default());
            let load = all[0].load.expect("a reading");
            assert!(load.is_multiple_of(10), "{devices}");
            assert_eq!(
                load == 100,
                all[0].state == State::Overloaded,
                "{devices} devices"
            );
        }
    }

    #[test]
    fn the_limits_are_the_sites_settings() {
        let loose = Busy {
            online: 100,
            load: 5.0,
        };
        let all = servers(&board(on(50, Some(1.0))), &loose);
        assert_eq!((all[0].state, all[0].load), (State::Up, Some(50)));
        let strict = Busy {
            online: 50,
            load: 5.0,
        };
        let all = servers(&board(on(50, Some(1.0))), &strict);
        assert_eq!((all[0].state, all[0].load), (State::Overloaded, Some(100)));
    }

    #[test]
    fn odd_numbers_never_panic_and_stay_in_range() {
        let tiny = Busy {
            online: 1,
            load: 0.0001,
        };
        for load in [f64::NAN, -3.0, 0.0, f64::INFINITY, 1e300] {
            let all = servers(&board(on(0, Some(load))), &tiny);
            let shown = all[0].load.expect("a reading");
            assert!(shown <= 100 && shown.is_multiple_of(10), "{load}: {shown}");
        }
    }

    #[test]
    fn no_load_is_shown_for_a_server_that_is_not_working_or_has_no_reading() {
        for health in [Health::NotResponding, Health::BeingFixed, Health::Unknown] {
            assert_eq!(
                load_of(vec![agent("Toronto", WG, health, 0, None)]),
                None,
                "{health:?}"
            );
        }
        let mut no_reading = agent("Toronto", WG, Health::Online, 0, None);
        no_reading.reading = None;
        let all = servers(&board(vec![no_reading]), &Busy::default());
        assert_eq!((all[0].state, all[0].load), (State::Up, None));
    }

    #[test]
    fn a_server_that_is_not_working_shows_no_load_even_with_a_reading_left_over() {
        for health in [Health::NotResponding, Health::BeingFixed, Health::Unknown] {
            let mut node = agent("Toronto", WG, Health::Online, 20, Some(0.5));
            node.health = health;
            assert!(node.reading.is_some(), "a reading is still there");
            assert_eq!(load_of(vec![node]), None, "{health:?}");
        }
    }

    #[test]
    fn the_status_cards_show_the_load_before_the_word_and_the_front_page_cards_do_not() {
        let server = Server {
            title: "Toronto".into(),
            place: "Canada".into(),
            state: State::Up,
            notes: Vec::new(),
            load: Some(30),
        };
        assert!(
            card(&server, true).ends_with("<span class=\"where\">Canada</span><span class=\"where\">30% load</span><span class=\"state up\">Up</span></li>"),
            "{}",
            card(&server, true)
        );
        assert!(
            !card(&server, false).contains("% load"),
            "{}",
            card(&server, false)
        );
        let none = Server {
            load: None,
            ..server
        };
        assert!(
            !card(&none, true).contains("% load"),
            "no reading, no figure"
        );
    }

    #[test]
    fn the_page_explains_the_percentage_only_when_it_shows_one() {
        let with = page(on(8, None), 105);
        assert!(with.contains("20% load"), "{with}");
        assert!(
            with.contains("100% is overloaded") && with.contains("rounded down to the nearest 10%"),
            "{with}"
        );
        assert!(
            with.contains("an exact count would say who is connected"),
            "{with}"
        );
        let without = page(
            vec![agent("Toronto", WG, Health::NotResponding, 0, None)],
            105,
        );
        assert!(
            !without.contains("% load") && !without.contains("rounded down"),
            "{without}"
        );
    }

    #[test]
    fn the_page_shows_the_percentage_and_never_the_exact_count_or_load() {
        let html = page(on(17, Some(0.3333)), 105);
        assert!(html.contains("40% load"), "17 of 40 is 42 percent: {html}");
        for leaked in ["17", "0.3333", "0.33", "42%", "37%"] {
            assert!(!html.contains(leaked), "{leaked} in {html}");
        }
    }

    #[test]
    fn the_down_sentence_says_the_delay_the_alerts_really_have() {
        assert_eq!(
            crate::alerts::DOWN_AFTER,
            180,
            "the page says 3 minutes; change State::meaning with it"
        );
        assert!(State::Down.meaning().contains("3 minutes"));
    }

    #[test]
    fn an_empty_board_has_no_servers() {
        assert!(servers(&board(Vec::new()), &Busy::default()).is_empty());
    }

    // ---- the page ----

    fn page(nodes: Vec<NodeView>, now: u64) -> String {
        answer(&board(nodes), &Busy::default(), now)
    }

    #[test]
    fn each_server_is_one_card_with_its_dot_place_and_word() {
        let html = page(
            vec![
                agent("Toronto", WG, Health::Online, 1, None),
                agent("Dallas", WG, Health::NotResponding, 0, None),
            ],
            105,
        );
        assert!(html.contains("<ul class=\"nodes\">"), "{html}");
        assert!(html.contains("<li><span class=\"dot up\" aria-hidden=\"true\"></span><strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"where\">0% load</span><span class=\"state up\">Up</span></li>"), "{html}");
        assert!(html.contains("<li><span class=\"dot down\" aria-hidden=\"true\"></span><strong>Dallas</strong><span class=\"where\">Canada</span><span class=\"state down\">Down</span></li>"), "{html}");
        assert_eq!(html.matches("<li><span class=\"dot").count(), 2);
    }

    #[test]
    fn a_server_with_two_agents_is_one_card() {
        let html = page(
            vec![
                agent("Dallas", WG, Health::Online, 1, None),
                agent("Dallas", AWG, Health::Online, 1, None),
            ],
            105,
        );
        assert_eq!(html.matches("<strong>Dallas</strong>").count(), 1, "{html}");
    }

    #[test]
    fn the_word_for_each_state_and_its_colour() {
        let cases = [
            (State::Up, "Up", "state up"),
            (State::Overloaded, "Overloaded", "state"),
            (State::BeingFixed, "Being fixed", "state"),
            (State::Down, "Down", "state down"),
            (State::Unknown, "Status unknown", "state"),
        ];
        for (state, word, class) in cases {
            assert_eq!(state.label(), word);
            assert_eq!(state.classes().1, class, "{word}");
            let card = card(
                &Server {
                    title: "T".into(),
                    place: "P".into(),
                    state,
                    notes: Vec::new(),
                    load: None,
                },
                true,
            );
            assert!(
                card.ends_with(&format!("<span class=\"{class}\">{word}</span></li>")),
                "{card}"
            );
        }
    }

    #[test]
    fn a_note_is_a_line_that_names_the_server() {
        let html = page(
            vec![
                agent("Dallas", WG, Health::Online, 1, None),
                agent("Dallas", AWG, Health::NotResponding, 0, None),
            ],
            105,
        );
        assert!(
            html.contains("<p class=\"note\">Dallas: AmneziaWG is not responding.</p>"),
            "{html}"
        );
    }

    #[test]
    fn only_the_words_in_use_are_explained() {
        let html = page(
            vec![
                agent("Toronto", WG, Health::Online, 1, None),
                agent("Dallas", WG, Health::BeingFixed, 0, None),
            ],
            105,
        );
        assert!(html.contains(State::Up.meaning()), "{html}");
        assert!(html.contains(State::BeingFixed.meaning()), "{html}");
        for unused in [State::Overloaded, State::Down, State::Unknown] {
            assert!(!html.contains(unused.meaning()), "{html}");
        }
        assert!(
            html.contains("<h2 class=\"section-title\">What the words mean</h2>"),
            "the narrow pages' heading class carries the space above it: {html}"
        );
    }

    #[test]
    fn the_page_gives_no_device_count_no_raw_load_no_node_name_and_no_address() {
        let mut busy = agent("Toronto", WG, Health::Online, 987, Some(0.7654));
        busy.name = "secret-node-name".to_string();
        busy.ip = "203.0.113.77".parse().unwrap();
        let html = page(vec![busy], 105);
        for leaked in ["987", "0.7654", "0.77", "secret-node-name", "203.0.113.77"] {
            assert!(!html.contains(leaked), "{leaked} in {html}");
        }
        assert!(
            html.contains("Overloaded"),
            "it is busy, and says so: {html}"
        );
        assert!(html.contains("100% load"), "and how full: {html}");
    }

    #[test]
    fn titles_and_places_are_escaped() {
        let mut node = agent("<b>T</b> & co", WG, Health::Online, 0, None);
        node.place = "\"Q\" <i>".to_string();
        let html = page(vec![node], 105);
        assert!(html.contains("&lt;b&gt;T&lt;/b&gt; &amp; co"), "{html}");
        assert!(html.contains("&quot;Q&quot; &lt;i&gt;"), "{html}");
        assert!(!html.contains("<b>") && !html.contains("<i>"), "{html}");
    }

    #[test]
    fn notes_are_escaped_too() {
        let mut down = agent("<u>D</u>", AWG, Health::NotResponding, 0, None);
        down.place = "Canada".to_string();
        let html = page(
            vec![agent("<u>D</u>", WG, Health::Online, 0, None), down],
            105,
        );
        assert!(html.contains("&lt;u&gt;D&lt;/u&gt;: AmneziaWG"), "{html}");
        assert!(!html.contains("<u>"), "{html}");
    }

    #[test]
    fn with_no_servers_the_page_says_so() {
        let html = page(Vec::new(), 105);
        assert!(html.contains("No servers are listed yet."), "{html}");
        assert!(!html.contains("<ul class=\"nodes\">"), "{html}");
    }

    #[test]
    fn it_says_how_long_ago_the_last_check_finished() {
        for (now, said) in [
            (100, "Last checked 0 seconds ago."),
            (101, "Last checked 1 second ago."),
            (104, "Last checked 4 seconds ago."),
            (160, "Last checked 1 minute ago."),
            (100 + 5 * 60, "Last checked 5 minutes ago."),
            (100 + 3600, "Last checked 1 hour ago."),
            (100 + 7200, "Last checked 2 hours ago."),
            (99, "Last checked 0 seconds ago."),
        ] {
            let html = page(vec![agent("T", WG, Health::Online, 0, None)], now);
            assert!(html.contains(said), "{said}: {html}");
        }
    }

    #[test]
    fn before_any_check_has_finished_the_page_says_so() {
        let mut snapshot = board(vec![agent("T", WG, Health::Unknown, 0, None)]);
        snapshot.updated_at = None;
        let html = answer(&snapshot, &Busy::default(), 105);
        assert!(html.contains("No check has finished yet."), "{html}");
        assert!(html.contains("Status unknown"), "{html}");
    }
}
