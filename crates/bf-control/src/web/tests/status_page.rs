//! The status page, `/status` (`specs/status-page.md`).

use super::*;
use crate::closest::Busy;
use crate::link::NodeReading;

/// A server's agent as the board holds it, with a reading when it is online.
pub(super) fn agent(
    title: &str,
    place: &str,
    health: Health,
    online: u64,
    load: Option<f64>,
) -> NodeView {
    let mut node = view(&title.to_lowercase(), title, place, health);
    node.problem = None;
    node.reading = (health == Health::Online).then(|| NodeReading {
        wg_public_key: "WGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGWGA=".to_string(),
        listen_port: 51820,
        online,
        peers_total: online,
        desired_version: Some(1),
        load1: load,
        peers: Vec::new(),
        logins: None,
    });
    node
}

fn site_with(nodes: Vec<NodeView>, busy: Busy, clock: u64) -> Site {
    let board = Board::new();
    board.set_for_test(nodes, 1_000);
    Site {
        app: None,
        live: Some(Live {
            board,
            clock: Arc::new(move || clock),
            busy,
        }),
    }
}

async fn fetch(
    site: Site,
    method: &str,
    headers: &[(&str, &str)],
) -> (u16, axum::http::HeaderMap, String) {
    let mut request = Request::builder().method(method).uri("/status");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = handle(State(site), request.body(Body::empty()).unwrap()).await;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn status_of(nodes: Vec<NodeView>) -> String {
    let (status, _, body) = fetch(site_with(nodes, Busy::default(), 1_004), "GET", &[]).await;
    assert_eq!(status, 200);
    body
}

#[tokio::test]
async fn the_status_page_draws_the_same_map_above_its_list_when_servers_have_coordinates() {
    let mut toronto = agent("Toronto", "Canada", Health::Online, 0, Some(0.1));
    toronto.location = crate::closest::Location::new(43.65, -79.38);
    let body = status_of(vec![toronto]).await;
    let map = body
        .find("<figure class=\"board\"><svg class=\"graticule\"")
        .unwrap_or_else(|| panic!("no map: {body}"));
    let list = body.find("<ul class=\"nodes\">").unwrap();
    assert!(map < list, "the map comes first");
    assert!(body.contains("class=\"pt up\""), "{body}");
    // With no coordinates there is no map, and the page is as it was.
    let plain = status_of(vec![agent(
        "Toronto",
        "Canada",
        Health::Online,
        0,
        Some(0.1),
    )])
    .await;
    assert!(!plain.contains("<svg class=\"graticule\""), "{plain}");
}

#[test]
fn the_status_page_is_never_cached_and_only_read() {
    let answer = get("/status");
    assert_eq!(
        (answer.status, answer.content_type, answer.cache_control),
        (200, HTML, "no-store")
    );
    assert_eq!(page(&Method::HEAD, "/status").status, 200);
    let posted = page(&Method::POST, "/status");
    assert_eq!((posted.status, posted.allow), (405, Some("GET, HEAD")));
}

#[tokio::test]
async fn it_shows_each_server_with_its_word_from_the_board() {
    let body = status_of(vec![
        agent("Toronto", "Canada", Health::Online, 3, Some(0.1)),
        agent("Dallas", "United States", Health::BeingFixed, 0, None),
    ])
    .await;
    assert!(body.contains("<h1>Server status</h1>"), "{body}");
    assert!(
        body.contains("<strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"where\">10% load</span><span class=\"state up\">Up</span>"),
        "{body}"
    );
    assert!(
        body.contains("<strong>Dallas</strong><span class=\"where\">United States</span><span class=\"state\">Being fixed</span>"),
        "{body}"
    );
    assert!(
        !body.contains("<!-- the answer -->"),
        "the marker is replaced"
    );
    assert!(body.contains("Last checked 4 seconds ago."), "{body}");
}

#[tokio::test]
async fn a_busy_server_reads_overloaded_by_the_sites_own_settings() {
    let nodes = vec![agent("Toronto", "Canada", Health::Online, 2, None)];
    let strict = Busy {
        online: 2,
        load: 9.0,
    };
    let (_, _, body) = fetch(site_with(nodes.clone(), strict, 1_004), "GET", &[]).await;
    assert!(
        body.contains("<span class=\"state\">Overloaded</span>"),
        "{body}"
    );
    let (_, _, body) = fetch(site_with(nodes, Busy::default(), 1_004), "GET", &[]).await;
    assert!(
        body.contains("<span class=\"state up\">Up</span>"),
        "{body}"
    );
}

#[tokio::test]
async fn a_board_that_has_gone_stale_reads_status_unknown_for_every_server() {
    let late = 1_000 + crate::poller::STALE_AFTER_SECS + 5;
    let (_, _, body) = fetch(
        site_with(
            vec![
                agent("Toronto", "Canada", Health::Online, 1, None),
                agent("Dallas", "United States", Health::BeingFixed, 0, None),
            ],
            Busy::default(),
            late,
        ),
        "GET",
        &[],
    )
    .await;
    assert_eq!(body.matches("Status unknown</span>").count(), 2, "{body}");
    assert!(!body.contains("state up"), "{body}");
}

#[tokio::test]
async fn with_no_board_or_no_servers_it_still_answers_and_says_none_are_listed() {
    let no_board = Site {
        app: None,
        live: None,
    };
    let (status, _, body) = fetch(no_board, "GET", &[]).await;
    assert_eq!(status, 200);
    assert!(body.contains("No servers are listed yet."), "{body}");
    let (status, _, body) = fetch(site_with(Vec::new(), Busy::default(), 1_004), "GET", &[]).await;
    assert_eq!(status, 200);
    assert!(body.contains("No servers are listed yet."), "{body}");
}

#[tokio::test]
async fn it_is_sent_with_no_store_noindex_and_the_site_policy() {
    let (_, headers, _) = fetch(site_with(Vec::new(), Busy::default(), 1_004), "GET", &[]).await;
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["vary"], "Cookie");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'"),
        "{headers:?}"
    );
}

#[test]
fn the_page_is_kept_out_of_search_and_runs_nothing() {
    assert!(STATUS.contains("<meta name=\"robots\" content=\"noindex\">"));
    assert!(
        !STATUS.contains("rel=\"canonical\""),
        "a noindex page names none"
    );
    assert!(!STATUS.contains("property=\"og:") && !STATUS.contains("name=\"twitter:"));
    assert_eq!(runnable_scripts(STATUS), 0);
    assert!(
        !SITEMAP.contains("/status"),
        "a live page is not in the sitemap"
    );
}

#[tokio::test]
async fn it_follows_the_chosen_theme_and_a_site_without_sign_in_has_no_account_link() {
    let (_, _, body) = fetch(
        site_with(Vec::new(), Busy::default(), 1_004),
        "GET",
        &[("cookie", "__Host-bf_theme=light")],
    )
    .await;
    assert!(
        body.contains("<html lang=\"en\" data-theme=\"light\">"),
        "{body}"
    );
    assert!(!body.contains("href=\"/account\""), "{body}");
    assert!(!body.contains("<form class=\"theme\""), "{body}");
}

#[test]
fn the_theme_buttons_on_the_page_come_back_to_it() {
    assert!(STATUS.contains("name=\"back\" value=\"/status\""));
}

#[tokio::test]
async fn a_being_fixed_server_shows_its_note_on_the_page() {
    let mut paris = agent("Paris", "France", Health::BeingFixed, 0, None);
    paris.note = Some("back at 20:00 & <soon>".to_string());
    let body = status_of(vec![
        agent("Toronto", "Canada", Health::Online, 1, None),
        paris,
    ])
    .await;
    assert!(
        body.contains("<p class=\"note\">Paris: back at 20:00 &amp; &lt;soon&gt;</p>"),
        "{body}"
    );
    assert!(!body.contains("<soon>"), "{body}");
}

#[tokio::test]
async fn the_uptime_the_poller_worked_out_is_listed_on_the_page() {
    let board = Board::new();
    board.set_for_test(
        vec![agent("Toronto", "Canada", Health::Online, 1, None)],
        1_000,
    );
    board.set_uptime(vec![crate::uptime::Uptime {
        title: "Toronto".to_string(),
        place: "Canada".to_string(),
        up: 998,
        down: 2,
        first_hour: 0,
    }]);
    let site = Site {
        app: None,
        live: Some(Live {
            board,
            clock: Arc::new(|| 1_004),
            busy: Busy::default(),
        }),
    };
    let (status, _, body) = fetch(site, "GET", &[]).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("<li><strong>Toronto</strong>: 99.8% over 1 day</li>"),
        "{body}"
    );
}
