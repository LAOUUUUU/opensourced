//! An email to Lao when a server stops answering, when it is back, and when someone logs in
//! to a server from somewhere new. Briefs: `research/alerts/RESEARCH.md`,
//! `specs/login-alerts.md`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;

use bf_common::logins::Login;

use crate::mail::{Email, MailFuture};
use crate::poller::{Health, Snapshot};

/// How long a server must be down before anyone is told.
pub const DOWN_AFTER: u64 = 180;
/// At most this many alert emails in one UTC day; after that they are only logged.
pub const MAX_PER_DAY: u32 = 10;
/// How often the board is looked at.
pub const EVERY_SECS: u64 = 30;
/// Where the address alerts go to is kept, unless `BC_ALERT_TO_FILE` says otherwise.
pub const ADDRESS_FILE: &str = "/etc/barely-free/alert-to";

/// The address alerts go to, from its file. It is read like the VM's other private files
/// (owner-only, small, text) and must be one plain address.
pub fn address_from(file: &std::path::Path) -> Result<String, String> {
    if !file.exists() {
        return Err(format!("there is no address file at {}", file.display()));
    }
    let text = crate::secrets::read_secret_text(file).map_err(|e| match e {
        crate::secrets::KeyError::Missing => {
            format!("there is no address file at {}", file.display())
        }
        other => format!("the address file {}: {other}", file.display()),
    })?;
    let address = text.trim();
    crate::mail::check_address(address).map_err(|_| {
        format!(
            "the address file {} does not hold one email address",
            file.display()
        )
    })?;
    Ok(address.to_string())
}

/// One change worth an email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    /// The server has not answered since `since`.
    Down { server: String, since: u64 },
    /// It answers again after `down_for` seconds.
    Back { server: String, down_for: u64 },
    /// Someone logged in to `server` with a key (or a password) from a network that key had
    /// not logged in from before.
    NewLogin { server: String, login: Login },
}

#[derive(Debug, Default)]
struct Server {
    down_since: u64,
    told: bool,
}

/// What the alerts remember between looks: which servers are down since when, and whether
/// anyone was told; and how many emails went out today.
#[derive(Debug, Default)]
pub struct Watch {
    down: BTreeMap<String, Server>,
    day: u64,
    sent_today: u32,
}

impl Watch {
    /// Looks at the board at `now` and gives the changes to tell. A server is down when
    /// every agent under its title is not responding, and up when any of them is online;
    /// anything else (unknown) changes nothing.
    pub fn step(&mut self, snapshot: &Snapshot, now: u64) -> Vec<Alert> {
        let mut servers: BTreeMap<&str, (bool, bool)> = BTreeMap::new(); // (any online, all down)
        for node in &snapshot.nodes {
            let entry = servers.entry(node.title.as_str()).or_insert((false, true));
            entry.0 |= node.health == Health::Online;
            entry.1 &= node.health == Health::NotResponding;
        }
        // A server no longer on the board is forgotten.
        self.down
            .retain(|title, _| servers.contains_key(title.as_str()));
        let mut alerts = Vec::new();
        for (title, (online, down)) in servers {
            if online {
                if let Some(server) = self.down.remove(title)
                    && server.told
                {
                    alerts.push(Alert::Back {
                        server: title.to_string(),
                        down_for: now.saturating_sub(server.down_since),
                    });
                }
            } else if down {
                let server = self.down.entry(title.to_string()).or_insert(Server {
                    down_since: now,
                    told: false,
                });
                if !server.told && now.saturating_sub(server.down_since) >= DOWN_AFTER {
                    server.told = true;
                    alerts.push(Alert::Down {
                        server: title.to_string(),
                        since: server.down_since,
                    });
                }
            }
        }
        alerts
    }

    /// Whether another email may go out at `now` (and counts it if so).
    pub fn may_send(&mut self, now: u64) -> bool {
        let day = now / 86_400;
        if day != self.day {
            self.day = day;
            self.sent_today = 0;
        }
        if self.sent_today >= MAX_PER_DAY {
            return false;
        }
        self.sent_today += 1;
        true
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn minutes(seconds: u64) -> String {
    let n = seconds.div_ceil(60);
    if n == 1 {
        "1 minute".to_string()
    } else {
        format!("{n} minutes")
    }
}

/// What a login email ends with.
const LOGIN_ADVICE: &str =
    "If this wasn't you, the key may be stolen: remove it from authorized_keys on every server.";

fn login_line(server: &str, login: &Login) -> String {
    let how = match (&login.key, &login.key_name) {
        (None, _) => "with a password".to_string(),
        (Some(fp), Some(name)) if !name.is_empty() => format!("with the key {name} ({fp})"),
        (Some(fp), _) => format!("with a key not in authorized_keys ({fp})"),
    };
    format!(
        "New login to {server}: {} from {} at {} UTC, {how}.",
        login.user,
        login.from,
        crate::app::utc_minute(login.at)
    )
}

/// The email for these changes: one line each, in plain words. New logins come first and
/// name the subject, since a stranger on a server matters more than a server being down.
pub fn email(alerts: &[Alert]) -> Email {
    let mut servers: Vec<&str> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    for alert in alerts {
        if let Alert::NewLogin { server, login } = alert {
            if !servers.contains(&server.as_str()) {
                servers.push(server);
            }
            lines.push(login_line(server, login));
        }
    }
    let logins = lines.len();
    if logins > 0 {
        lines.push(LOGIN_ADVICE.to_string());
    }
    lines.extend(alerts.iter().filter_map(|alert| match alert {
        Alert::Down { server, since } => {
            let at = crate::app::utc_minute(*since);
            let time = at.split_once(' ').map_or(at.as_str(), |(_, time)| time);
            Some(format!("{server} has not answered since {time} UTC."))
        }
        Alert::Back { server, down_for } => Some(format!(
            "{server} is answering again, after {} down.",
            minutes(*down_for)
        )),
        Alert::NewLogin { .. } => None,
    }));
    let footer = "An automatic message from the Barely-free control program on the web VM.";
    let subject: std::borrow::Cow<'static, str> = if logins > 0 {
        let s = if logins == 1 { "" } else { "s" };
        format!("New login{s} to {}", servers.join(", ")).into()
    } else if alerts.iter().any(|a| matches!(a, Alert::Down { .. })) {
        "Barely-free: a server stopped answering".into()
    } else {
        "Barely-free: a server is answering again".into()
    };
    let html_lines: String = lines
        .iter()
        .map(|line| format!("<p>{}</p>\n", escape(line)))
        .collect();
    Email {
        subject,
        html: format!(
            "<!doctype html>\n<html><body>\n{html_lines}<p style=\"color:#666\">{footer}</p>\n</body></html>\n"
        ),
        text: format!("{}\n\n{footer}\n", lines.join("\n")),
    }
}

/// Something that can send an email: Resend, or a recorder in tests.
pub trait Notify: Send + Sync {
    fn notify<'a>(&'a self, to: &'a str, email: &'a Email, key: &'a str) -> MailFuture<'a>;
}

impl Notify for crate::resend::ResendClient {
    fn notify<'a>(&'a self, to: &'a str, email: &'a Email, key: &'a str) -> MailFuture<'a> {
        Box::pin(self.send(to, email, key))
    }
}

/// What the login alerts keep between looks: the known pairs, where the VM's own logins are,
/// and which sources are failing (each is logged once, and again when it is fine).
#[derive(Debug)]
pub struct LoginWatch {
    known: crate::logins::Known,
    /// The folder `bf-logins.timer` writes the VM's own logins into.
    vm_dir: PathBuf,
    failing: BTreeSet<String>,
}

impl LoginWatch {
    pub fn new(known: crate::logins::Known, vm_dir: PathBuf) -> LoginWatch {
        LoginWatch {
            known,
            vm_dir,
            failing: BTreeSet::new(),
        }
    }

    /// The logins on the board (each server's agents, which report the same journal) and in
    /// the VM's file whose (key, network) pair is new, remembering every pair seen.
    pub fn step(
        &mut self,
        snapshot: &Snapshot,
        now: u64,
        log: &(dyn Fn(&str) + Send + Sync),
    ) -> Vec<Alert> {
        let mut seen: Vec<(String, Login)> = Vec::new();
        for node in &snapshot.nodes {
            let Some(reading) = &node.reading else {
                continue;
            };
            match &reading.logins {
                Some(logins) => {
                    self.fine(&node.name, log);
                    seen.extend(logins.iter().map(|l| (node.title.clone(), l.clone())));
                }
                None => self.failed(
                    &node.name,
                    "reports no logins (an older agent, or it cannot read its journal)",
                    log,
                ),
            }
        }
        match crate::logins::vm_logins(&self.vm_dir, now) {
            Ok(logins) => {
                self.fine(crate::logins::VM_SERVER, log);
                seen.extend(
                    logins
                        .into_iter()
                        .flatten()
                        .filter_map(crate::link::safe)
                        .map(|l| (crate::logins::VM_SERVER.to_string(), l)),
                );
            }
            Err(e) => self.failed(crate::logins::VM_SERVER, &e, log),
        }
        let mut once = HashSet::new();
        seen.retain(|(server, l)| {
            once.insert((server.clone(), l.at, l.user.clone(), l.from, l.key.clone()))
        });
        let news = self.known.news(&seen);
        match self.known.save() {
            Ok(()) => self.fine("the known-logins file", log),
            Err(e) => self.failed("the known-logins file", &e, log),
        }
        news.into_iter()
            .map(|(server, login)| Alert::NewLogin { server, login })
            .collect()
    }

    fn failed(&mut self, what: &str, why: &str, log: &(dyn Fn(&str) + Send + Sync)) {
        if self.failing.insert(what.to_string()) {
            log(&format!("alerts: logins: {what}: {why}"));
        }
    }

    fn fine(&mut self, what: &str, log: &(dyn Fn(&str) + Send + Sync)) {
        if self.failing.remove(what) {
            log(&format!("alerts: logins: {what} is fine again"));
        }
    }
}

/// One look: the changes on the board at `now`, sent as one email if the day's cap allows.
/// Every outcome is logged; nothing here stops the loop.
pub async fn look(
    watch: &mut Watch,
    snapshot: &Snapshot,
    now: u64,
    notify: &dyn Notify,
    to: &str,
    log: &(dyn Fn(&str) + Send + Sync),
) {
    look_all(watch, None, snapshot, now, notify, to, log).await;
}

/// [`look`], with new logins too when there is a [`LoginWatch`].
pub async fn look_all(
    watch: &mut Watch,
    logins: Option<&mut LoginWatch>,
    snapshot: &Snapshot,
    now: u64,
    notify: &dyn Notify,
    to: &str,
    log: &(dyn Fn(&str) + Send + Sync),
) {
    let mut alerts = watch.step(snapshot, now);
    if let Some(logins) = logins {
        alerts.extend(logins.step(snapshot, now, log));
    }
    if alerts.is_empty() {
        return;
    }
    let mail = email(&alerts);
    // Every line of news, so nothing is lost when the email cannot go.
    let summary = mail
        .text
        .lines()
        .take_while(|line| !line.is_empty())
        .filter(|line| *line != LOGIN_ADVICE)
        .collect::<Vec<_>>()
        .join(" | ");
    if !watch.may_send(now) {
        log(&format!(
            "alerts: today's {MAX_PER_DAY} emails are used up, so not sent: {summary}"
        ));
        return;
    }
    match notify.notify(to, &mail, &format!("bf-alert-{now}")).await {
        Ok(_) => log(&format!("alerts: alert sent: {summary}")),
        Err(e) => log(&format!("alerts: could not send an alert ({e}): {summary}")),
    }
}

/// Looks at the board (and, with a [`LoginWatch`], the logins) every [`EVERY_SECS`] for as
/// long as the program runs.
pub async fn run(
    board: std::sync::Arc<crate::poller::Board>,
    mut logins: Option<LoginWatch>,
    notify: std::sync::Arc<dyn Notify>,
    to: String,
    clock: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
    log: std::sync::Arc<dyn Fn(&str) + Send + Sync>,
) {
    let mut watch = Watch::default();
    loop {
        let now = clock();
        look_all(
            &mut watch,
            logins.as_mut(),
            &board.snapshot(now),
            now,
            notify.as_ref(),
            &to,
            log.as_ref(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_secs(EVERY_SECS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::{MailError, SendOutcome};
    use crate::poller::NodeView;
    use std::sync::Mutex;

    const T: u64 = 1_794_454_860; // 2026-11-12 03:41 UTC

    fn agent(name: &str, title: &str, health: Health) -> NodeView {
        NodeView {
            name: name.to_string(),
            title: title.to_string(),
            place: "Somewhere".to_string(),
            protocol: None,
            location: None,
            ip: "192.0.2.7".parse().unwrap(),
            health,
            checked_at: T,
            last_good: None,
            reading: None,
            problem: None,
            in_sync: true,
            note: None,
        }
    }

    fn board(agents: Vec<NodeView>) -> Snapshot {
        Snapshot {
            nodes: agents,
            list_version: Some(1),
            updated_at: Some(T),
            contacts: Default::default(),
        }
    }

    fn toronto(health: Health) -> Vec<NodeView> {
        vec![
            agent("toronto", "Toronto", health),
            agent("toronto-wg", "Toronto", health),
        ]
    }

    #[test]
    fn a_server_down_for_three_minutes_is_told_once() {
        let mut watch = Watch::default();
        let down = board(toronto(Health::NotResponding));
        assert!(watch.step(&down, T).is_empty());
        assert!(watch.step(&down, T + DOWN_AFTER - 1).is_empty());
        assert_eq!(
            watch.step(&down, T + DOWN_AFTER),
            [Alert::Down {
                server: "Toronto".to_string(),
                since: T
            }]
        );
        assert!(
            watch.step(&down, T + DOWN_AFTER + 30).is_empty(),
            "told once"
        );
    }

    #[test]
    fn a_blip_shorter_than_that_tells_nobody_either_way() {
        let mut watch = Watch::default();
        assert!(
            watch
                .step(&board(toronto(Health::NotResponding)), T)
                .is_empty()
        );
        assert!(
            watch
                .step(&board(toronto(Health::NotResponding)), T + 120)
                .is_empty()
        );
        assert!(
            watch
                .step(&board(toronto(Health::Online)), T + 150)
                .is_empty()
        );
        // And the clock starts again next time.
        assert!(
            watch
                .step(&board(toronto(Health::NotResponding)), T + 200)
                .is_empty()
        );
        assert!(
            watch
                .step(
                    &board(toronto(Health::NotResponding)),
                    T + 200 + DOWN_AFTER - 1
                )
                .is_empty()
        );
    }

    #[test]
    fn a_server_switched_off_for_repair_is_not_down_and_tells_nobody() {
        let mut watch = Watch::default();
        for secs in [0, DOWN_AFTER, 3_600, 7_200] {
            assert!(
                watch
                    .step(&board(toronto(Health::BeingFixed)), T + secs)
                    .is_empty(),
                "{secs}"
            );
        }
        assert!(
            watch
                .step(&board(toronto(Health::Online)), T + 7_300)
                .is_empty(),
            "and nothing when it is back: nobody was told it was down"
        );
    }

    #[test]
    fn being_fixed_does_not_start_the_down_clock_or_reset_one_that_was_told() {
        let mut watch = Watch::default();
        // Switched off for an hour, then it stops answering: the 3 minutes count from there.
        watch.step(&board(toronto(Health::BeingFixed)), T);
        assert!(
            watch
                .step(&board(toronto(Health::NotResponding)), T + 3_600)
                .is_empty()
        );
        assert_eq!(
            watch
                .step(
                    &board(toronto(Health::NotResponding)),
                    T + 3_600 + DOWN_AFTER
                )
                .len(),
            1
        );
        // Told it was down, then switched off for repair, then back: "back" still comes.
        watch.step(&board(toronto(Health::BeingFixed)), T + 4_000);
        assert_eq!(
            watch.step(&board(toronto(Health::Online)), T + 5_000),
            [Alert::Back {
                server: "Toronto".to_string(),
                down_for: 5_000 - 3_600
            }]
        );
    }

    #[test]
    fn back_is_told_only_after_down_was() {
        let mut watch = Watch::default();
        watch.step(&board(toronto(Health::NotResponding)), T);
        watch.step(&board(toronto(Health::NotResponding)), T + DOWN_AFTER);
        assert_eq!(
            watch.step(&board(toronto(Health::Online)), T + 540),
            [Alert::Back {
                server: "Toronto".to_string(),
                down_for: 540
            }]
        );
        assert!(
            watch
                .step(&board(toronto(Health::Online)), T + 600)
                .is_empty()
        );
    }

    #[test]
    fn one_agent_answering_means_the_server_is_up() {
        let mut watch = Watch::default();
        let half = board(vec![
            agent("toronto", "Toronto", Health::Online),
            agent("toronto-wg", "Toronto", Health::NotResponding),
        ]);
        watch.step(&half, T);
        assert!(watch.step(&half, T + 3_600).is_empty());
    }

    #[test]
    fn unknown_changes_nothing() {
        let mut watch = Watch::default();
        // Unknown from the start: no clock starts.
        watch.step(&board(toronto(Health::Unknown)), T);
        assert!(
            watch
                .step(&board(toronto(Health::Unknown)), T + 3_600)
                .is_empty()
        );
        // Down, then the board goes stale (unknown): still down, still told when due.
        watch.step(&board(toronto(Health::NotResponding)), T + 4_000);
        assert!(
            watch
                .step(&board(toronto(Health::Unknown)), T + 4_100)
                .is_empty()
        );
        assert_eq!(
            watch
                .step(
                    &board(toronto(Health::NotResponding)),
                    T + 4_000 + DOWN_AFTER
                )
                .len(),
            1
        );
    }

    #[test]
    fn two_servers_going_down_together_are_one_list_of_changes() {
        let mut watch = Watch::default();
        let mut both = toronto(Health::NotResponding);
        both.push(agent("dallas", "Dallas", Health::NotResponding));
        watch.step(&board(both.clone()), T);
        let told = watch.step(&board(both), T + DOWN_AFTER);
        assert_eq!(told.len(), 2, "{told:?}");
        let mail = email(&told);
        assert!(
            mail.text
                .contains("Dallas has not answered since 03:41 UTC"),
            "{}",
            mail.text
        );
        assert!(
            mail.text
                .contains("Toronto has not answered since 03:41 UTC"),
            "{}",
            mail.text
        );
    }

    #[test]
    fn the_email_says_what_happened_in_plain_words_and_escapes_titles() {
        let down = email(&[Alert::Down {
            server: "<b>Toronto</b>".to_string(),
            since: T,
        }]);
        assert_eq!(down.subject, "Barely-free: a server stopped answering");
        assert!(
            down.html.contains("&lt;b&gt;Toronto&lt;/b&gt;"),
            "{}",
            down.html
        );
        assert!(!down.html.contains("<b>Toronto"), "{}", down.html);
        let back = email(&[Alert::Back {
            server: "Toronto".to_string(),
            down_for: 540,
        }]);
        assert_eq!(back.subject, "Barely-free: a server is answering again");
        assert!(
            back.text
                .contains("Toronto is answering again, after 9 minutes down."),
            "{}",
            back.text
        );
    }

    #[test]
    fn at_most_ten_emails_a_day_and_a_new_day_starts_again() {
        let mut watch = Watch::default();
        for n in 0..MAX_PER_DAY {
            assert!(watch.may_send(T + u64::from(n)), "{n}");
        }
        assert!(!watch.may_send(T + 100));
        let tomorrow = (T / 86_400 + 1) * 86_400;
        assert!(watch.may_send(tomorrow));
    }

    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, String)>>,
        fails: bool,
    }

    impl Notify for Recorder {
        fn notify<'a>(&'a self, to: &'a str, email: &'a Email, _key: &'a str) -> MailFuture<'a> {
            Box::pin(async move {
                if self.fails {
                    return Err(MailError::Unavailable);
                }
                self.sent
                    .lock()
                    .unwrap()
                    .push((to.to_string(), email.text.clone()));
                Ok(SendOutcome::Sent {
                    id: "x".to_string(),
                })
            })
        }
    }

    const FP: &str = "SHA256:HvjXAIbzUdF23SQNP93/235ibkdyPOxPOROYgxD3Tjs";

    fn a_login(from: &str, key: Option<&str>, name: Option<&str>) -> bf_common::logins::Login {
        bf_common::logins::Login {
            at: T - 60,
            user: "root".to_string(),
            from: from.parse().unwrap(),
            key: key.map(str::to_string),
            key_name: name.map(str::to_string),
        }
    }

    fn reporting(mut node: NodeView, logins: Vec<bf_common::logins::Login>) -> NodeView {
        node.reading = Some(crate::link::NodeReading {
            wg_public_key: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=".to_string(),
            listen_port: 51820,
            online: 0,
            peers_total: 0,
            desired_version: Some(1),
            load1: None,
            peers: vec![],
            logins: Some(logins),
        });
        node
    }

    #[test]
    fn a_login_email_says_where_who_when_and_which_key_and_escapes_names() {
        let mail = email(&[
            Alert::NewLogin {
                server: "Dallas".to_string(),
                login: a_login("203.0.113.7", Some(FP), Some("lao-mac <b>")),
            },
            Alert::NewLogin {
                server: "the website server".to_string(),
                login: a_login("198.51.100.4", None, None),
            },
            Alert::NewLogin {
                server: "Toronto".to_string(),
                login: a_login("2001:db8::5", Some(FP), None),
            },
        ]);
        assert_eq!(
            mail.subject,
            "New logins to Dallas, the website server, Toronto"
        );
        for line in [
            format!("New login to Dallas: root from 203.0.113.7 at 2026-11-12 03:40 UTC, with the key lao-mac <b> ({FP})."),
            "New login to the website server: root from 198.51.100.4 at 2026-11-12 03:40 UTC, with a password.".to_string(),
            format!("New login to Toronto: root from 2001:db8::5 at 2026-11-12 03:40 UTC, with a key not in authorized_keys ({FP})."),
            "If this wasn't you, the key may be stolen: remove it from authorized_keys on every server.".to_string(),
        ] {
            assert!(mail.text.contains(&line), "missing {line:?} in\n{}", mail.text);
        }
        assert!(
            mail.html.contains("lao-mac &lt;b&gt;") && !mail.html.contains("<b>"),
            "{}",
            mail.html
        );
    }

    #[test]
    fn down_news_and_login_news_share_one_email_and_the_login_names_it() {
        let mail = email(&[
            Alert::Down {
                server: "Toronto".to_string(),
                since: T - 200,
            },
            Alert::NewLogin {
                server: "Dallas".to_string(),
                login: a_login("203.0.113.7", Some(FP), None),
            },
        ]);
        assert_eq!(
            mail.subject, "New login to Dallas",
            "a stranger on a server matters most"
        );
        assert!(
            mail.text.contains("Toronto has not answered")
                && mail.text.contains("New login to Dallas"),
            "{}",
            mail.text
        );
    }

    #[tokio::test]
    async fn a_new_login_reported_by_both_agents_of_a_server_is_one_line_in_one_email_once() {
        let recorder = Recorder::default();
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        let dir = std::env::temp_dir().join(format!("bf-alerts-logins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let known_file = dir.join("known-logins");
        std::fs::write(&known_file, format!("{FP}\t203.0.113.0/24\n")).unwrap();
        let mut logins = LoginWatch::new(
            crate::logins::Known::open(&known_file).unwrap(),
            dir.clone(),
        );
        let usual = a_login("203.0.113.7", Some(FP), None);
        let new = a_login("198.51.100.4", Some(FP), Some("lao-mac"));
        let snapshot = board(vec![
            reporting(
                agent("dallas", "Dallas", Health::Online),
                vec![usual.clone(), new.clone()],
            ),
            reporting(
                agent("dallas-awg", "Dallas", Health::Online),
                vec![usual, new],
            ),
        ]);
        let mut watch = Watch::default();
        look_all(
            &mut watch,
            Some(&mut logins),
            &snapshot,
            T,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        look_all(
            &mut watch,
            Some(&mut logins),
            &snapshot,
            T + 30,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        let sent = recorder.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "once");
        assert_eq!(
            sent[0].1.matches("New login to Dallas").count(),
            1,
            "{}",
            sent[0].1
        );
        assert_eq!(watch.sent_today, 1, "counted against the day's alerts");
    }

    fn login_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-alerts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("known-logins"), format!("{FP}\t203.0.113.0/24\n")).unwrap();
        dir
    }

    fn watching(dir: &std::path::Path) -> LoginWatch {
        LoginWatch::new(
            crate::logins::Known::open(&dir.join("known-logins")).unwrap(),
            dir.to_path_buf(),
        )
    }

    fn real_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn past_the_cap_a_new_login_on_the_vm_is_logged_in_full_and_not_sent() {
        let recorder = Recorder::default();
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        let dir = login_dir("cap");
        let now = real_now(); // the VM file is judged by its modification time
        std::fs::write(
            dir.join(bf_common::logins::LOGINS_FILE),
            format!(
                "{}.5 lao sshd-session[9]: Accepted password for root from 198.51.100.4 port 1 ssh2\n",
                now - 60
            ),
        )
        .unwrap();
        let mut logins = watching(&dir);
        let mut watch = Watch::default();
        for _ in 0..MAX_PER_DAY {
            assert!(watch.may_send(now));
        }
        look_all(
            &mut watch,
            Some(&mut logins),
            &board(vec![]),
            now,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        assert!(recorder.sent.lock().unwrap().is_empty());
        let logged = logged.lock().unwrap().clone();
        assert!(
            logged.iter().any(|l| l.contains("used up")
                && l.contains("New login to the website server: root from 198.51.100.4")
                && l.contains("with a password")),
            "{logged:?}"
        );
    }

    #[tokio::test]
    async fn a_stale_vm_file_and_an_agent_without_logins_are_each_logged_once_until_fine() {
        let recorder = Recorder::default();
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        let dir = login_dir("quiet");
        std::fs::write(dir.join(bf_common::logins::LOGINS_FILE), "").unwrap();
        let mut logins = watching(&dir);
        let mut old = reporting(agent("dallas", "Dallas", Health::Online), vec![]);
        old.reading.as_mut().unwrap().logins = None;
        let mut watch = Watch::default();
        let later = real_now() + bf_common::logins::STALE_SECS + 60;
        for at in [later, later + 30] {
            look_all(
                &mut watch,
                Some(&mut logins),
                &board(vec![old.clone()]),
                at,
                &recorder,
                "lao@example.com",
                &log,
            )
            .await;
        }
        let count = |needle: &str| {
            logged
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.contains(needle))
                .count()
        };
        assert_eq!(count("older than"), 1, "{:?}", logged.lock().unwrap());
        assert_eq!(
            count("dallas: reports no logins"),
            1,
            "{:?}",
            logged.lock().unwrap()
        );
        let now = real_now();
        std::fs::write(dir.join(bf_common::logins::LOGINS_FILE), "").unwrap();
        let new = reporting(agent("dallas", "Dallas", Health::Online), vec![]);
        look_all(
            &mut watch,
            Some(&mut logins),
            &board(vec![new]),
            now,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        assert_eq!(count("is fine again"), 2, "{:?}", logged.lock().unwrap());
        assert!(
            recorder.sent.lock().unwrap().is_empty(),
            "problems are logged, not emailed"
        );
    }

    #[tokio::test]
    async fn a_look_sends_one_email_when_something_changed_and_logs_it() {
        let recorder = Recorder::default();
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        let mut watch = Watch::default();
        let down = board(toronto(Health::NotResponding));
        look(&mut watch, &down, T, &recorder, "lao@example.com", &log).await;
        look(
            &mut watch,
            &down,
            T + DOWN_AFTER,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        let sent = recorder.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "lao@example.com");
        assert!(
            logged
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("alert sent"))
        );
    }

    #[tokio::test]
    async fn once_the_days_emails_are_used_up_a_change_is_only_logged() {
        let recorder = Recorder::default();
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        let mut watch = Watch::default();
        for _ in 0..MAX_PER_DAY {
            assert!(watch.may_send(T));
        }
        let down = board(toronto(Health::NotResponding));
        look(&mut watch, &down, T, &recorder, "lao@example.com", &log).await;
        look(
            &mut watch,
            &down,
            T + DOWN_AFTER,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        assert!(recorder.sent.lock().unwrap().is_empty());
        assert!(
            logged.lock().unwrap().iter().any(|l| l.contains("used up")),
            "{:?}",
            logged.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn a_send_that_fails_is_logged_and_the_next_change_still_goes() {
        let recorder = Recorder {
            fails: true,
            ..Recorder::default()
        };
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        let mut watch = Watch::default();
        let down = board(toronto(Health::NotResponding));
        look(&mut watch, &down, T, &recorder, "lao@example.com", &log).await;
        look(
            &mut watch,
            &down,
            T + DOWN_AFTER,
            &recorder,
            "lao@example.com",
            &log,
        )
        .await;
        assert!(
            logged
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("could not send")),
            "{:?}",
            logged.lock().unwrap()
        );
    }

    #[cfg(unix)]
    fn file(name: &str, text: &str, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bf-alerts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn the_address_file_holds_one_address_and_only_its_owner_may_read_it() {
        assert_eq!(
            address_from(&file("good", "lao@example.com\n", 0o600)),
            Ok("lao@example.com".to_string())
        );
        let missing = std::env::temp_dir().join("bf-alerts-none/alert-to");
        assert!(
            address_from(&missing)
                .unwrap_err()
                .contains("there is no address file")
        );
        for (name, text) in [
            ("list", "a@example.com, b@example.com"),
            ("empty", ""),
            ("named", "Lao <lao@example.com>"),
        ] {
            let why = address_from(&file(name, text, 0o600)).unwrap_err();
            assert!(
                why.contains("does not hold one email address"),
                "{name}: {why}"
            );
        }
        assert!(address_from(&file("open", "lao@example.com", 0o644)).is_err());
    }
}
