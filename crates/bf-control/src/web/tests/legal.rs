//! The legal, help and security pages, and the header and footer every public page shares
//! (`specs/legal-and-support.md`).

use super::*;

/// The pages added for the legal and support work, by the path each is served at.
const INFO_PAGES: [&str; 6] = [
    "/terms",
    "/privacy",
    "/abuse",
    "/transparency",
    "/help",
    "/security",
];

#[test]
fn the_legal_help_and_security_pages_are_served_like_the_cookie_page() {
    for path in INFO_PAGES {
        let answer = get(path);
        assert_eq!(
            (answer.status, answer.content_type, answer.cache_control),
            (200, HTML, "private, no-cache"),
            "{path}"
        );
        assert!(
            answer
                .body
                .starts_with("<!doctype html>\n<html lang=\"en\">"),
            "{path}"
        );
        assert!(!answer.body.contains("<script"), "{path}: no scripts");
        let posted = page(&Method::POST, path);
        assert_eq!(
            (posted.status, posted.allow),
            (405, Some("GET, HEAD")),
            "{path}"
        );
    }
}

/// Days since 1970-01-01 for a `YYYY-MM-DD` date (Howard Hinnant's `days_from_civil`).
fn days(date: &str) -> i64 {
    let mut parts = date.split('-').map(|part| part.parse::<i64>().unwrap());
    let (year, month, day) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date in a page's one "Last updated" line.
fn updated(html: &str) -> &str {
    let lines: Vec<&str> = html
        .split("<p class=\"updated\">")
        .skip(1)
        .map(|rest| rest.split("</p>").next().unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "one Last updated line");
    let date = lines[0]
        .strip_prefix("Last updated <time datetime=\"")
        .expect("Last updated <time datetime=\"YYYY-MM-DD\">");
    let date = date.split('"').next().unwrap();
    assert_eq!(date.len(), 10, "YYYY-MM-DD: {date}");
    date
}

#[test]
fn the_date_arithmetic_is_right() {
    assert_eq!(days("1970-01-01"), 0);
    assert_eq!(
        days("2000-03-01") - days("2000-02-28"),
        2,
        "2000 was a leap year"
    );
    assert_eq!(days("2027-11-12") - days("2026-11-12"), 365);
    assert_eq!(days("2029-01-01") - days("2028-01-01"), 366);
}

#[test]
fn security_txt_names_a_contact_and_expires_within_a_year_of_the_security_page() {
    // RFC 9116: at /.well-known/, plain UTF-8 text, a Contact and exactly one Expires, which
    // should be less than a year away. It is dated from the security page's own date, so
    // updating that page is the moment to move the expiry on.
    let answer = get("/.well-known/security.txt");
    assert_eq!((answer.status, answer.content_type), (200, TEXT));
    assert!(answer.cache_control.contains("max-age="));
    let field = |name: &str| -> Vec<&str> {
        answer
            .body
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .collect()
    };
    // A Contact is a URI; with no email address it is the page that says how to report.
    assert_eq!(field("Contact:"), vec!["https://barely-free.com/security"]);
    let expires = field("Expires:");
    assert_eq!(expires.len(), 1, "exactly one Expires");
    let expires = expires[0];
    assert!(
        expires.len() == 20 && &expires[10..11] == "T" && expires.ends_with('Z'),
        "RFC 3339 in UTC, like 2027-11-01T00:00:00Z: {expires}"
    );
    let gap = days(&expires[..10]) - days(updated(SECURITY));
    assert!(
        (1..366).contains(&gap),
        "Expires is {gap} days after the page's date"
    );
    assert_eq!(field("Policy:"), vec!["https://barely-free.com/security"]);
    assert_eq!(field("Preferred-Languages:"), vec!["en"]);
    assert!(field("Canonical:").is_empty(), "it is not signed");
}

/// Every public page that is a file, by the path it is served at (the 404 has none).
const STATIC_PAGES: [(&str, &str); 11] = [
    ("/", INDEX),
    ("/cookies", COOKIES),
    ("/check", CHECK),
    ("/status", STATUS),
    ("/terms", TERMS),
    ("/privacy", PRIVACY),
    ("/abuse", ABUSE),
    ("/transparency", TRANSPARENCY),
    ("/help", HELP),
    ("/security", SECURITY),
    ("/404", NOT_FOUND),
];

/// The template every page of the sign-in side is drawn in.
const BASE: &str = include_str!("../../../templates/base.html");

/// The part of `html` from `start` to the end of `end`.
fn part<'a>(html: &'a str, start: &str, end: &str) -> &'a str {
    let from = html.find(start).unwrap_or_else(|| panic!("no {start}"));
    let length = html[from..].find(end).unwrap_or_else(|| panic!("no {end}")) + end.len();
    &html[from..from + length]
}

/// `html` with the template's tags taken out and the theme form's way back set to `/`, so
/// the template and every file can be held to the same markup.
fn normalised(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(start) = rest.find("{%") {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        rest = &rest[rest.find("%}").unwrap() + 2..];
    }
    out.push_str(rest);
    let marker = "name=\"back\" value=\"";
    match out.find(marker) {
        Some(at) => {
            let from = at + marker.len();
            let to = from + out[from..].find('"').unwrap();
            format!("{}/{}", &out[..from], &out[to..])
        }
        None => out,
    }
}

#[test]
fn every_public_page_has_the_same_header_and_footer() {
    // Written out in each file, like the theme buttons, so each file reads on its own; this
    // test is what keeps the copies the same. The terms page is the model.
    let header = part(TERMS, "<header class=\"top\">", "</header>");
    let footer = normalised(part(TERMS, "<footer>", "</footer>"));
    let mut pages: Vec<(&str, &str)> = STATIC_PAGES.to_vec();
    pages.push(("templates/base.html", BASE));
    for (name, html) in pages {
        assert_eq!(
            normalised(part(html, "<header class=\"top\">", "</header>")),
            header,
            "{name}: the header differs from the terms page's"
        );
        assert_eq!(
            normalised(part(html, "<footer>", "</footer>")),
            footer,
            "{name}: the footer differs from the terms page's"
        );
    }
}

#[test]
fn the_header_and_footer_lead_to_help_the_account_and_every_legal_page() {
    let header = part(TERMS, "<header class=\"top\">", "</header>");
    for target in ["/#how", "/#nodes", "/help", "/account"] {
        assert!(header.contains(&format!("href=\"{target}\"")), "{target}");
    }
    let footer = part(TERMS, "<footer>", "</footer>");
    for target in INFO_PAGES.iter().copied().chain([
        "/cookies",
        "/check",
        "/status",
        "/#how",
        "/#nodes",
        "/#funding",
    ]) {
        assert!(footer.contains(&format!("href=\"{target}\"")), "{target}");
    }
    assert!(
        footer.contains("Laoel Beqiri") && footer.contains("Ontario, Canada"),
        "who runs it, and where"
    );
}

#[test]
fn each_pages_theme_buttons_go_back_to_that_page() {
    for (path, html) in STATIC_PAGES {
        let back = if path == "/404" { "/" } else { path };
        let form = theme_form(html);
        assert!(
            form.contains(&format!("name=\"back\" value=\"{back}\"")),
            "{path}: {form}"
        );
        assert!(crate::app::THEME_BACK.contains(&back), "{back}");
    }
}

#[test]
fn the_device_page_has_no_menu_or_footer_links() {
    // The one-time page with the private key has no menu or footer links, as it has no theme
    // buttons: following one would lose the only copy of the key. (Its logo, its "Back to
    // your account" link and the app store links are older and stay.)
    for block in ["nav", "site_links", "theme_form"] {
        assert!(
            BASE.contains(&format!("{{% block {block} %}}")),
            "base.html has a {block} block"
        );
        assert!(
            include_str!("../../../templates/device.html")
                .contains(&format!("{{% block {block} %}}{{% endblock %}}")),
            "device.html empties {block}"
        );
    }
}

#[tokio::test]
async fn without_the_sign_in_side_no_page_links_the_account_or_the_sign_in_pages() {
    for (path, _) in STATIC_PAGES {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();
        let response = handle(
            State(Site {
                app: None,
                live: None,
            }),
            request,
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        for gone in ["href=\"/account\"", "href=\"/signin\"", "action=\"/theme\""] {
            assert!(!html.contains(gone), "{path}: {gone}");
        }
        assert!(
            html.contains("href=\"/help\""),
            "{path}: the rest of the menu stays"
        );
    }
}

/// The pages that make promises, and so carry a date and a list of changes.
const DATED_PAGES: [(&str, &str); 5] = [
    ("/terms", TERMS),
    ("/privacy", PRIVACY),
    ("/abuse", ABUSE),
    ("/transparency", TRANSPARENCY),
    ("/security", SECURITY),
];

/// The page's text with every tag taken out and the spaces run together, so a test can look
/// for a phrase whatever markup or line break sits inside it.
fn text(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    let out = out
        .replace("&rsquo;", "'")
        .replace("&ldquo;", "\"")
        .replace("&rdquo;", "\"");
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn each_dated_page_shows_its_date_and_its_newest_change_on_the_same_day() {
    for (path, html) in DATED_PAGES {
        let date = updated(html);
        let changes = part(html, "<ul class=\"changes\">", "</ul>");
        let newest = changes
            .split("<time datetime=\"")
            .nth(1)
            .unwrap_or_else(|| panic!("{path}: a dated change"));
        assert_eq!(
            &newest[..10],
            date,
            "{path}: the newest change is the page's date"
        );
    }
}

#[test]
fn no_page_names_an_email_address_and_every_contact_leads_to_one_place() {
    // Lao, 2026-11-12: no contact addresses ("i wont do those four email address"); a
    // community server is planned. Every "contact us" therefore leads to the help page's
    // contact section, so the way to reach us is written in one place.
    for (path, html) in STATIC_PAGES {
        assert!(!html.contains("mailto:"), "{path} names an email address");
    }
    assert!(!BASE.contains("mailto:"));
    assert!(!SECURITY_TXT.contains("mailto:"));
    assert!(HELP.contains("<h2 id=\"contact\">"), "the one place");
    for (path, html) in [
        ("/terms", TERMS),
        ("/privacy", PRIVACY),
        ("/abuse", ABUSE),
        ("/security", SECURITY),
    ] {
        assert!(
            html.contains("href=\"/help#contact\""),
            "{path} says how to reach us"
        );
    }
}

#[test]
fn the_terms_say_who_runs_it_the_age_and_the_law() {
    let terms = text(TERMS);
    for phrase in [
        "Laoel Beqiri, in Ontario, Canada",
        "You must be 13 or older",
        "under 18, a parent or guardian",
        "laws of Ontario",
        "courts of Ontario",
        "\"as is\"",
        "not refund",
    ] {
        assert!(terms.contains(phrase), "the terms say {phrase:?}");
    }
}

#[test]
fn the_privacy_policy_gives_the_numbers_the_code_uses() {
    use crate::signin::*;
    let privacy = text(PRIVACY);
    let day = 86_400;
    let backup_keep = include_str!("../../../../../deploy/bf-backup-receive")
        .split("BF_BACKUP_KEEP:-")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .unwrap()
        .to_string();
    // deploy-web.sh keeps the newest N copies made just before each update of the website.
    let deploy_keep = include_str!("../../../../../deploy/deploy-web.sh")
        .split("while [ \"$#\" -gt ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap()
        .to_string();
    assert_eq!(deploy_keep, "5", "the privacy policy says five");
    // Those copies sit next to the fingerprint key for weeks, so they are made by the new
    // program's own backup, which leaves the sign-in records out, never by a plain copy.
    let deploy = include_str!("../../../../../deploy/deploy-web.sh");
    assert!(
        deploy.contains("/usr/local/bin/bf-control.new backup \"$copy\""),
        "the pre-update copy is a backup"
    );
    assert!(!deploy.contains("cp -p \"$db\""), "and not a plain copy");
    // If that copy fails, the old program starts again under its old unit: the new unit is
    // put in place only after the copy worked.
    let copied = deploy.find("bf-control.new backup").unwrap();
    let unit_in_place = deploy
        .find(
            "mv /etc/systemd/system/bf-control.service.new /etc/systemd/system/bf-control.service",
        )
        .expect("the unit arrives as .new and is moved into place");
    assert!(unit_in_place > copied, "the unit moves only after the copy");
    assert!(!deploy.contains("\"$host:/etc/systemd/system/bf-control.service\""));
    for phrase in [
        format!("A code works for {} minutes", CODE_LIFETIME_SECS / 60),
        format!(
            "{} an hour per email address, {} an hour per network address",
            REQUESTS_PER_ADDRESS_PER_HOUR, REQUESTS_PER_NETWORK_PER_HOUR
        ),
        format!("{} days.", SESSION_LIFETIME_SECS / day),
        format!("never more than {} days", KEPT_SESSION_MAX_SECS / day),
        format!("its {MAX_SESSIONS_PER_ACCOUNT} newest sessions"),
        format!("The {backup_keep} newest nightly copies"),
        format!("until {deploy_keep} newer updates replace them"),
    ] {
        assert!(
            privacy.contains(&phrase),
            "the privacy policy says {phrase:?}"
        );
    }
    assert_eq!(
        KEEP_SECS, day,
        "the policy says sign-in records go after a day"
    );
    assert_eq!(
        privacy
            .to_lowercase()
            .matches("deleted after a day")
            .count(),
        2,
        "the code and request records"
    );
    for who in ["Cloudflare", "Resend", "vpshostingservice.co", "Ko-fi"] {
        assert!(privacy.contains(who), "names {who}");
    }
    assert!(
        PRIVACY.contains("href=\"/cookies\""),
        "links the cookie page"
    );
    assert!(privacy.contains("Laoel Beqiri"), "who is responsible");
    assert!(
        privacy.contains("Privacy Commissioner of Canada"),
        "where to complain"
    );
}

#[test]
fn the_help_page_has_every_app_link_and_the_numbers_the_code_uses() {
    // Every app the account page offers (ClashMi first since decision 019), with its links.
    for app in crate::apps::for_account() {
        for link in app.links {
            assert!(
                HELP.contains(&format!(
                    "<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>",
                    link.url, link.platform
                )),
                "{}: {}",
                app.title,
                link.platform
            );
        }
    }
    let help = text(HELP);
    let store = include_str!("../../../src/store.rs");
    let devices = store
        .split("device_limit INTEGER NOT NULL DEFAULT ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap();
    assert_eq!(devices, "3", "the help page says three devices");
    for phrase in [
        format!(
            "A code works for {} minutes",
            crate::signin::CODE_LIFETIME_SECS / 60
        ),
        format!(
            "ask for {} codes an hour",
            crate::signin::REQUESTS_PER_ADDRESS_PER_HOUR
        ),
        "room for three devices".to_string(),
        "Never send your private key".to_string(),
        "We recommend ClashMi".to_string(),
        "made by KaringX".to_string(),
    ] {
        assert!(help.contains(&phrase), "the help page says {phrase:?}");
    }
}

#[test]
fn the_front_page_says_how_it_works_now_and_who_is_behind_it() {
    for html in [INDEX.to_string(), open_wording(INDEX)] {
        assert!(!html.contains("will work"), "sign-in is live: it works now");
        assert!(!html.contains("coming soon"), "the pages exist");
        let answer = part(&html, "<summary>Who is behind it?</summary>", "</details>");
        assert!(answer.contains("Laoel Beqiri"), "{answer}");
        for target in ["/terms", "/privacy", "/abuse", "/help"] {
            assert!(answer.contains(&format!("href=\"{target}\"")), "{target}");
        }
    }
    let keep = part(INDEX, "<section id=\"privacy\">", "</section>");
    assert!(
        keep.contains("href=\"/privacy\""),
        "the summary leads to the policy"
    );
}

#[test]
fn the_unknown_note_shows_only_while_a_server_reads_unknown() {
    let note = "means we have no reading yet";
    assert!(
        INDEX.contains(note),
        "the file, with no readings at all, says it"
    );
    let online = front_page(&snapshot(vec![view(
        "toronto",
        "Toronto",
        "Canada",
        Health::Online,
    )]));
    assert!(!online.contains(note), "every card reads a state");
    let unknown = front_page(&snapshot(vec![
        view("toronto", "Toronto", "Canada", Health::Online),
        view("dallas", "Dallas", "United States", Health::Unknown),
    ]));
    assert!(unknown.contains(note), "one card reads unknown");
}

#[test]
fn the_sign_in_page_says_continuing_means_agreeing_to_the_terms_and_privacy_policy() {
    let signin = include_str!("../../../templates/signin.html");
    let line = "By continuing you agree to the <a href=\"/terms\">terms of use</a> and the \
                <a href=\"/privacy\">privacy policy</a>.";
    assert_eq!(signin.matches(line).count(), 1);
    let form = part(
        signin,
        "<form method=\"post\" action=\"/signin\">",
        "</form>",
    );
    assert!(form.contains(line), "under the button, open or closed");
    assert!(!form.contains("{% if"), "the same for everyone");
}

#[test]
fn the_privacy_policy_does_not_promise_more_than_the_servers_do() {
    // Found in review (2026-11-12). WireGuard keeps each device's last address and contact
    // time until the server restarts or the device is removed; the servers ask Cloudflare's
    // DNS for every name; the nightly copies hold the sign-in records and the fingerprint key
    // (so an IP fingerprint can be reversed by whoever holds it); an account can be found
    // from much more than its email address; the poller reads last contact back after a
    // restart; a failed email's error can name the address.
    let privacy = text(PRIVACY);
    // The privacy page names the resolver the servers really forward to (deploy/node-resolver.sh).
    let resolver = include_str!("../../../../../deploy/node-resolver.sh");
    let upstream = resolver
        .split("forward-addr: ")
        .nth(1)
        .and_then(|rest| rest.split('@').next())
        .unwrap();
    assert_eq!(upstream, "9.9.9.9", "decision 022");
    assert!(privacy.contains("Quad9 (9.9.9.9)"), "names the resolver");
    assert!(
        !privacy.contains("1.1.1.1") && !privacy.contains("answers our servers"),
        "no longer Cloudflare's DNS"
    );
    // Since 2026-11-12 the agents forget an idle device (bf_common::wg::FORGET_IDLE_AFTER_SECS).
    let forget = format!(
        "about {} minutes after",
        bf_common::wg::FORGET_IDLE_AFTER_SECS / 60
    );
    for page in [&privacy, &text(TRANSPARENCY), &text(INDEX)] {
        assert!(page.contains(&forget), "says {forget:?}");
    }
    for phrase in [
        "anyone holding our key could work out which address made one",
        "the key used to make the fingerprints",
        "Delete my account",
        // Since 2026-11-12 the nightly copy leaves the sign-in records out
        // (backup::SIGN_IN_RECORDS) and the log never holds an address
        // (resend::without_addresses).
        "without the sign-in records",
        "without email or IP addresses",
    ] {
        assert!(
            privacy.contains(phrase),
            "the privacy policy says {phrase:?}"
        );
    }
    for (path, html) in [("/privacy", PRIVACY), ("/transparency", TRANSPARENCY)] {
        let words = text(html);
        for overstated in [
            "only if we are given its email address",
            "which needs its email address",
            "gone when it restarts",
            "if the website has not restarted since",
            "or from a given address",
            "never your IP address",
            "While a device is connected, the server",
            // No longer true: say less than the code does, never more, and never stale.
            "the nightly copies below still hold it",
            "which can include the email address",
            "until the server restarts or the device is removed",
            "until a restart",
        ] {
            assert!(
                !words.contains(overstated),
                "{path} still says {overstated:?}"
            );
        }
    }
    assert_eq!(
        crate::backup::SIGN_IN_RECORDS,
        ["mail_log", "login_codes"],
        "the two tables the policy calls sign-in records"
    );
    let logged = crate::resend::without_addresses("not sent to lao@example.com.");
    assert!(!logged.contains('@'), "{logged}");
    let front = text(INDEX);
    assert!(
        !front.contains("Server logs hold"),
        "the front page agrees with the policy"
    );
    assert!(!front.contains("Each copy is deleted after 30 days"));
    assert!(
        text(HELP).contains("Delete my account"),
        "the help page points at the button"
    );
}
