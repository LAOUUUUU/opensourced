//! The public website: a few fixed pages and files built into the binary.
//!
//! One handler takes every request, so every answer, even a 404 or a 405, goes through
//! [`secured`] and carries the same security headers. The pages live in `web/` as real
//! files, and so do the font files; nothing is loaded from outside, which is why the
//! policy below can be so strict.

use std::future::Future;
use std::io;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, Response};
use tokio::net::TcpListener;

use crate::app::App;
use crate::cookie::{self, Theme};
use crate::poller::{Board, Snapshot};

const INDEX: &str = include_str!("../web/index.html");
const NOT_FOUND: &str = include_str!("../web/404.html");
const COOKIES: &str = include_str!("../web/cookies.html");
const CHECK: &str = include_str!("../web/check.html");
const STATUS: &str = include_str!("../web/status.html");
const TERMS: &str = include_str!("../web/terms.html");
const PRIVACY: &str = include_str!("../web/privacy.html");
const ABUSE: &str = include_str!("../web/abuse.html");
const TRANSPARENCY: &str = include_str!("../web/transparency.html");
const HELP: &str = include_str!("../web/help.html");
const SECURITY: &str = include_str!("../web/security.html");
/// RFC 9116's contact file. Its `Expires` must be moved on within a year (a test holds it to
/// less than a year after the security page's date).
const SECURITY_TXT: &str = include_str!("../web/security.txt");
/// Where `/check` and `/status` put their answers.
const CHECK_ANSWER: &str = "<!-- the answer -->";
const SITE_CSS: &str = include_str!("../web/site.css");
const FAVICON: &str = include_str!("../web/favicon.svg");
/// The site's fonts, served from here so that nothing loads from another site: Geist (Latin,
/// variable weight) for text and labels, and Bodoni Moda (Latin, variable weight and optical
/// size, upright and italic) for headings. Bodoni Moda's files are Fontsource's, narrowed by
/// fontTools to the weights and optical sizes the stylesheet uses (`docs/modules/bf-control.md`).
/// Their licence, the SIL Open Font License, is served beside them.
const GEIST: &[u8] = include_bytes!("../web/fonts/geist-latin-wght-normal.woff2");
const BODONI: &[u8] = include_bytes!("../web/fonts/bodoni-moda-latin-normal.woff2");
const BODONI_ITALIC: &[u8] = include_bytes!("../web/fonts/bodoni-moda-latin-italic.woff2");
const FONT_LICENSE: &str = include_str!("../web/fonts/OFL.txt");
const GEIST_PATH: &str = "/assets/fonts/geist-latin-wght-normal.woff2";
const BODONI_PATH: &str = "/assets/fonts/bodoni-moda-latin-normal.woff2";
const BODONI_ITALIC_PATH: &str = "/assets/fonts/bodoni-moda-latin-italic.woff2";
/// The picture a shared link shows in a chat app or a social site (`og:image`): 1200 by 630,
/// drawn by `tools/share-image/` from the front page's first screen. Pages name it with its
/// fingerprint, so like a font it may be kept for good.
const SHARE_PNG: &[u8] = include_bytes!("../web/share.png");
const SHARE_PATH: &str = "/assets/share.png";
const PNG: &str = "image/png";
/// A font's address carries its fingerprint (`?v=` in the stylesheet), so a changed file is
/// a new address and the old one may be kept for good.
const FONT_CACHE: &str = "public, max-age=31536000, immutable";
/// Everything may be fetched, so a `noindex` on a page is seen. No `Disallow` and no `/admin`
/// (the site answers that like any unknown path; a line here would announce it).
const ROBOTS: &str = "User-agent: *\nAllow: /\n\nSitemap: https://barely-free.com/sitemap.xml\n";
/// The public pages a search engine may list, one address each (`specs/seo.md`). Tests tie it
/// to the pages: every address is served, none is `noindex`, each is its page's canonical.
const SITEMAP: &str = include_str!("../web/sitemap.xml");

const HTML: &str = "text/html; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";
const XML: &str = "application/xml; charset=utf-8";
const WOFF2: &str = "font/woff2";

/// Nothing but this site's own stylesheet, icons and fonts may load, nothing may run, no
/// other site may frame it, and a form (the footer's theme buttons) may go to this site only.
const POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
                      base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The same, for the pages that have forms (`app.rs`): a form may be sent to this site
/// and nowhere else. Nothing else differs.
const APP_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
                          base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The public pages send a referrer only to this site, for the same reason as the pages with
/// forms below: they have a form too (the theme buttons). Nothing goes to other sites.
const PUBLIC_REFERRER_POLICY: &str = "same-origin";

/// The pages with forms send a referrer only to this site. They cannot use `no-referrer`:
/// with it a browser writes `Origin: null` on a form post, which no check can tell from a
/// sandboxed page on another site, so every sign-in would be refused. With `same-origin`
/// the browser sends the real `Origin`, and nothing at all goes to other sites.
const APP_REFERRER_POLICY: &str = "same-origin";

/// What to send for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub status: u16,
    pub content_type: &'static str,
    pub cache_control: &'static str,
    pub allow: Option<&'static str>,
    pub body: &'static str,
    /// The file itself, for an answer that is not text (a font). Then `body` is empty.
    pub bytes: Option<&'static [u8]>,
}

/// Decides the answer for a method and a path (the query string is not part of the path).
pub fn page(method: &Method, path: &str) -> Page {
    let (content_type, cache_control, body) = match path {
        // Both differ by cookie (who is signed in, which theme), so only the visitor's own
        // browser may keep a copy, and it asks again each time.
        "/" => (HTML, "private, no-cache", INDEX),
        "/cookies" => (HTML, "private, no-cache", COOKIES),
        "/terms" => (HTML, "private, no-cache", TERMS),
        "/privacy" => (HTML, "private, no-cache", PRIVACY),
        "/abuse" => (HTML, "private, no-cache", ABUSE),
        "/transparency" => (HTML, "private, no-cache", TRANSPARENCY),
        "/help" => (HTML, "private, no-cache", HELP),
        "/security" => (HTML, "private, no-cache", SECURITY),
        // The answer is about the visitor's own address: no cache may keep it at all.
        "/check" => (HTML, "no-store", CHECK),
        // Live: made from the poller's board at each request.
        "/status" => (HTML, "no-store", STATUS),
        "/assets/site.css" => ("text/css; charset=utf-8", "public, max-age=3600", SITE_CSS),
        "/favicon.svg" => ("image/svg+xml", "public, max-age=86400", FAVICON),
        GEIST_PATH | BODONI_PATH | BODONI_ITALIC_PATH => (WOFF2, FONT_CACHE, ""),
        SHARE_PATH => (PNG, FONT_CACHE, ""),
        "/assets/fonts/OFL.txt" => (TEXT, "public, max-age=86400", FONT_LICENSE),
        "/robots.txt" => (TEXT, "public, max-age=3600", ROBOTS),
        "/sitemap.xml" => (XML, "public, max-age=3600", SITEMAP),
        "/.well-known/security.txt" => (TEXT, "public, max-age=86400", SECURITY_TXT),
        "/healthz" => (TEXT, "no-store", "ok\n"),
        // Anything else is 404 whatever the method, so nothing is revealed about it.
        _ => {
            return Page {
                status: 404,
                content_type: HTML,
                cache_control: "no-store",
                allow: None,
                body: NOT_FOUND,
                bytes: None,
            };
        }
    };
    if method != Method::GET && method != Method::HEAD {
        return Page {
            status: 405,
            content_type: TEXT,
            cache_control: "no-store",
            allow: Some("GET, HEAD"),
            body: "Method not allowed\n",
            bytes: None,
        };
    }
    Page {
        status: 200,
        content_type,
        cache_control,
        allow: None,
        body,
        bytes: file_bytes(path),
    }
}

/// A file of bytes: the three fonts the stylesheet names and the share image the pages name;
/// nothing for any other address.
fn file_bytes(path: &str) -> Option<&'static [u8]> {
    match path {
        SHARE_PATH => Some(SHARE_PNG),
        GEIST_PATH => Some(GEIST),
        BODONI_PATH => Some(BODONI),
        BODONI_ITALIC_PATH => Some(BODONI_ITALIC),
        _ => None,
    }
}

/// The headers every answer carries, with the content security policy and the referrer
/// policy it is given.
fn with_security_headers(
    builder: axum::http::response::Builder,
    policy: &str,
    referrer_policy: &str,
) -> axum::http::response::Builder {
    builder
        .header("content-security-policy", policy)
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", referrer_policy)
        .header("strict-transport-security", "max-age=31536000")
        .header("cross-origin-opener-policy", "same-origin")
        .header("cross-origin-resource-policy", "same-origin")
        .header(
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), browsing-topics=()",
        )
}

/// Turns a page into a response with the security headers on it.
pub fn secured(page: &Page) -> Response<Body> {
    let body = match page.bytes {
        Some(bytes) => Body::from(bytes),
        None => Body::from(page.body),
    };
    secured_body(page, body)
}

/// Like [`secured`], with a body of its own in place of the page's.
fn secured_body(page: &Page, body: Body) -> Response<Body> {
    let mut builder = with_security_headers(
        Response::builder()
            .status(page.status)
            .header("content-type", page.content_type)
            .header("cache-control", page.cache_control),
        POLICY,
        PUBLIC_REFERRER_POLICY,
    );
    if let Some(allow) = page.allow {
        builder = builder.header("allow", allow);
    }
    // The share image is shown by chat apps and social sites from their own pages, so it may
    // be loaded from anywhere. It is the only PNG; everything else stays this site's own.
    if page.content_type == PNG
        && let Some(headers) = builder.headers_mut()
    {
        headers.insert(
            "cross-origin-resource-policy",
            axum::http::HeaderValue::from_static("cross-origin"),
        );
    }
    builder
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Turns an answer of the sign-in pages into a response: the same security headers, the
/// policy that lets a form go to this site, never cached, never indexed. `headers` are the
/// extras (`location`, `set-cookie`, `allow`).
pub(crate) fn secured_app(status: u16, headers: &[(&str, String)], body: String) -> Response<Body> {
    let mut builder = with_security_headers(
        Response::builder()
            .status(status)
            .header("content-type", HTML)
            .header("cache-control", "no-store")
            .header("x-robots-tag", "noindex"),
        APP_POLICY,
        APP_REFERRER_POLICY,
    );
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// The public site alone, with no sign-in.
pub fn router() -> Router {
    router_with(None)
}

/// The site, with the sign-in pages too when `app` is there. Without it those paths are
/// ordinary 404s, exactly as on a site that has no sign-in at all.
pub fn router_with(app: Option<Arc<App>>) -> Router {
    router_site(app, None)
}

/// The poller's readings and a clock to read them by, for the front page's server cards.
#[derive(Clone)]
pub struct Live {
    pub board: Arc<Board>,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// When a server counts as overloaded: the same numbers "Closest to you" uses.
    pub busy: crate::closest::Busy,
}

#[derive(Clone)]
struct Site {
    app: Option<Arc<App>>,
    live: Option<Live>,
}

/// The site with the sign-in pages when `app` is there and live server cards when `live`
/// is. Without `live` the front page is exactly the file.
pub fn router_site(app: Option<Arc<App>>, live: Option<Live>) -> Router {
    Router::new()
        .fallback(handle)
        .with_state(Site { app, live })
}

async fn handle(State(site): State<Site>, request: Request) -> Response<Body> {
    if let Some(app) = &site.app
        && App::handles(request.uri().path())
    {
        return app.handle(request).await;
    }
    // The admin pages are there only for a signed-in admin. For anyone else, and for any other
    // path under /admin, there is nothing: the public answer below is the one every unknown
    // path gets, byte for byte.
    if let Some(app) = &site.app
        && App::is_admin_path(request.uri().path())
        && app.admin_gate(request.headers())
    {
        return app.handle(request).await;
    }
    let answer = page(request.method(), request.uri().path());
    if answer.content_type != HTML {
        return secured(&answer);
    }
    let theme = cookie::theme_from_header(
        request
            .headers()
            .get("cookie")
            .and_then(|value| value.to_str().ok()),
    );
    if answer.status == 200 && request.uri().path() == "/check" {
        let snapshot = site
            .live
            .as_ref()
            .map(|live| live.board.snapshot_light((live.clock)()));
        let html = CHECK.replacen(
            CHECK_ANSWER,
            &check_answer(snapshot.as_ref(), request.headers()),
            1,
        );
        let html = for_visitor(html, &site, request.headers());
        return html_answer(&answer, themed(html, theme));
    }
    if answer.status == 200 && request.uri().path() == "/status" {
        let now = site.live.as_ref().map_or(0, |live| (live.clock)());
        let shown = match &site.live {
            Some(live) => crate::status::answer(
                &live.board.snapshot_counts(now),
                &live.busy,
                now,
                &live.board.uptime(),
            ),
            None => {
                crate::status::answer(&crate::status::empty_board(), &Default::default(), now, &[])
            }
        };
        let html = STATUS.replacen(CHECK_ANSWER, &shown, 1);
        let html = for_visitor(html, &site, request.headers());
        return html_answer(&answer, themed(html, theme));
    }
    if answer.status != 200 || request.uri().path() != "/" {
        // The 404 and the other fixed pages: the file as it is, in the chosen theme.
        let html = for_visitor(answer.body.to_string(), &site, request.headers());
        return html_answer(&answer, themed(html, theme));
    }
    let sign_up_open = site.app.as_ref().is_some_and(|app| app.signup_open());
    let signed_in = site
        .app
        .as_ref()
        .is_some_and(|app| app.signed_in(request.headers()));
    let mut html = match &site.live {
        Some(live) => front_page(&live.board.snapshot_counts((live.clock)()), &live.busy),
        None => INDEX.to_string(),
    };
    if site.app.is_none() {
        // No sign-in pages on this server, so no link to them, and nothing to take the theme
        // buttons (`/theme` is the sign-in side's).
        html = without_sign_in(html.replace(SIGN_IN_LINK, SIGN_IN_OFF));
    } else if signed_in {
        html = html
            .replace(SIGN_IN_LINK, ACCOUNT_LINK)
            .replacen(HEADER_CTA, "", 1);
    }
    if sign_up_open {
        html = open_wording(&html);
    }
    html_answer(&answer, themed(html, theme))
}

/// A public page's answer. It differs by cookie (who is signed in, which theme), so no
/// cache may hand one person's copy to another.
fn html_answer(answer: &Page, html: String) -> Response<Body> {
    let mut response = secured_body(answer, Body::from(html));
    response
        .headers_mut()
        .insert("vary", axum::http::HeaderValue::from_static("Cookie"));
    response
}

/// The menu's link to the account, which sends anyone not signed in to the sign-in page.
const ACCOUNT_NAV: &str = "\n    <a href=\"/account\">Account</a>";

/// The menu's button to the sign-in page. It is for someone who is not signed in, on a site
/// that has a sign-in side, so it is taken out for everyone else.
const HEADER_CTA: &str = "\n    <a class=\"button\" href=\"/signin\">Get started</a>";

/// A page for a site with no sign-in side: no menu link to the account, no theme buttons
/// (`/theme` is the sign-in side's), and any other link to the sign-in pages left as plain
/// text, since all of them would lead to a 404.
fn without_sign_in(html: String) -> String {
    let html = without_theme_form(
        html.replacen(ACCOUNT_NAV, "", 1)
            .replacen(HEADER_CTA, "", 1),
    );
    unlinked(&unlinked(&html, "/signin"), "/account")
}

/// A fixed page for this visitor: without the sign-in side's links on a site that has none,
/// and without the menu's "Get started" button for someone who is already signed in.
fn for_visitor(html: String, site: &Site, headers: &axum::http::HeaderMap) -> String {
    match &site.app {
        None => without_sign_in(html),
        Some(app) if app.signed_in(headers) => html.replacen(HEADER_CTA, "", 1),
        Some(_) => html,
    }
}

/// `html` with every link to `target` turned into its plain text.
fn unlinked(html: &str, target: &str) -> String {
    let opening = format!("<a href=\"{target}\">");
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find(&opening) {
        let after = &rest[start + opening.len()..];
        let Some(end) = after.find("</a>") else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push_str(&after[..end]);
        rest = &after[end + "</a>".len()..];
    }
    out.push_str(rest);
    out
}

/// A page without the footer's theme buttons.
fn without_theme_form(html: String) -> String {
    let Some(start) = html.find("<form class=\"theme\"") else {
        return html;
    };
    let Some(length) = html[start..].find("</form>") else {
        return html;
    };
    let end = start + length + "</form>".len();
    format!(
        "{}{}",
        html[..start].trim_end_matches([' ', '\n']),
        &html[end..]
    )
}

/// A page drawn in a chosen theme: `data-theme` on its `<html>` tag. The value is one of two
/// fixed words, never anything taken from the request.
/// The footer's buttons are written with System pressed; for a chosen theme that one is
/// pressed instead.
pub(crate) fn themed(html: String, theme: Option<Theme>) -> String {
    let Some(theme) = theme else {
        return html;
    };
    let value = theme.as_str();
    html.replacen(
        "<html lang=\"en\">",
        &format!("<html lang=\"en\" data-theme=\"{value}\">"),
        1,
    )
    .replacen(
        "value=\"system\" aria-pressed=\"true\"",
        "value=\"system\" aria-pressed=\"false\"",
        1,
    )
    .replacen(
        &format!("value=\"{value}\" aria-pressed=\"false\""),
        &format!("value=\"{value}\" aria-pressed=\"true\""),
        1,
    )
}

/// The front page's link to the sign-in pages, and what stands in its place on a server that
/// has none (they would be a 404).
const SIGN_IN_LINK: &str = "<a class=\"button\" href=\"/signin\">Sign in</a>";
const SIGN_IN_OFF: &str = "<span class=\"button\" aria-disabled=\"true\">Sign-up opens soon</span>";
/// What stands in its place for someone who is signed in.
const ACCOUNT_LINK: &str = "<a class=\"button\" href=\"/account\">Your account</a>";

/// What the front page says instead once sign-up is open: (the closed wording as it is in
/// `web/index.html`, the open wording). A test fails if a closed phrase no longer matches.
const OPEN_WORDING: [(&str, &str); 5] = [
    (
        "<meta name=\"description\" content=\"Barely-free is a free VPN built on WireGuard. Closed beta: sign-up is not open yet.\">",
        "<meta name=\"description\" content=\"Barely-free is a free VPN built on WireGuard. Sign up with just your email.\">",
    ),
    // The link preview says what the description says (a test holds them equal).
    (
        "<meta property=\"og:description\" content=\"Barely-free is a free VPN built on WireGuard. Closed beta: sign-up is not open yet.\">",
        "<meta property=\"og:description\" content=\"Barely-free is a free VPN built on WireGuard. Sign up with just your email.\">",
    ),
    (
        "<p class=\"badge\">Closed beta &middot; sign-up is not open yet</p>",
        "<p class=\"badge open\">Full release &middot; sign-up is open</p>",
    ),
    (
        SIGN_IN_LINK,
        "<a class=\"button\" href=\"/signin\">Get started</a>",
    ),
    (
        "<details name=\"faq\"><summary>Why can't I sign up yet?</summary><p>This is a closed beta while the service is rebuilt. Sign-up opens after the safeguards are in place.</p></details>",
        "<details name=\"faq\"><summary>Can anybody sign up?</summary><p>Yes. Type your email, type the six-digit code we send you, and your account is made. We take a limited number of new accounts a day, so on a busy day you may be asked to try again tomorrow.</p></details>",
    ),
];

/// The front page with the closed-beta wording swapped for the open wording.
fn open_wording(html: &str) -> String {
    OPEN_WORDING
        .iter()
        .fold(html.to_string(), |page, (closed, open)| {
            page.replace(closed, open)
        })
}

/// Said under the cards while a server reads unknown (and in the file, which has no readings).
const UNKNOWN_NOTE: &str = "<p class=\"note\">&ldquo;Unknown&rdquo; means we have no reading yet. It does not mean a server is empty or down.</p>";

const NODES_START: &str = "<!--nodes-->";
const NODES_END: &str = "<!--/nodes-->";

/// One address from a header that came exactly once; anything else is no address.
fn one_address(headers: &axum::http::HeaderMap, name: &str) -> Option<std::net::IpAddr> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.trim().parse().ok()
}

/// What `/check` says. The visitor's address is Cloudflare's `cf-connecting-ip`: one of the
/// servers' addresses means the visitor is on that server. The address shown to someone who
/// is not on is `cf-connecting-ipv6` when Cloudflare sends it (its "Pseudo IPv4" puts a
/// made-up address in the first). Without a board, a server, or one good address, the page
/// cannot tell, and says so rather than guess. Nothing is logged or kept.
pub fn check_answer(snapshot: Option<&Snapshot>, headers: &axum::http::HeaderMap) -> String {
    let cannot = "<p class=\"lead\">This page cannot tell: it did not get your address, or it does not know the servers&rsquo; addresses right now.</p>".to_string();
    let (Some(snapshot), Some(address)) = (snapshot, one_address(headers, "cf-connecting-ip"))
    else {
        return cannot;
    };
    if snapshot.nodes.is_empty() {
        return cannot;
    }
    if let Some(node) = snapshot.nodes.iter().find(|node| node.ip == address) {
        return format!(
            "<p class=\"lead\"><strong>You are on Barely-free</strong>, through the {}, {} server.</p>\n  <p>Sites see {address}, the server&rsquo;s address, not your own.</p>",
            escape_html(&node.title),
            escape_html(&node.place)
        );
    }
    let shown = one_address(headers, "cf-connecting-ipv6").unwrap_or(address);
    format!(
        "<p class=\"lead\"><strong>You are not on Barely-free.</strong> Sites see your own address: {shown}.</p>\n  <p>Turn the VPN on in the app, then load this page again.</p>"
    )
}

/// The front page, with the Servers cards made from `snapshot`, each server drawn by
/// [`crate::status`] so the cards and `/status` always say the same. With no nodes on the
/// board it is the file as it is.
pub fn front_page(snapshot: &Snapshot, busy: &crate::closest::Busy) -> String {
    if snapshot.nodes.is_empty() {
        return INDEX.to_string();
    }
    let Some((before, rest)) = INDEX.split_once(NODES_START) else {
        return INDEX.to_string();
    };
    let Some((_, after)) = rest.split_once(NODES_END) else {
        return INDEX.to_string();
    };
    let servers = crate::status::servers(snapshot, busy);
    let mut cards = String::from(
        "<p>Live status, checked every few seconds. <a href=\"/status\">Full status</a></p>\n",
    );
    if let Some(svg) = crate::status::map(&servers) {
        cards.push_str(&format!("    <figure class=\"board\">{svg}</figure>\n"));
    }
    cards.push_str("    <ul class=\"nodes\">\n");
    for server in &servers {
        cards.push_str(&format!("      {}\n", crate::status::card(server, false)));
    }
    cards.push_str("    </ul>\n");
    if servers
        .iter()
        .any(|server| server.state == crate::status::State::Unknown)
    {
        cards.push_str(&format!("    {UNKNOWN_NOTE}\n"));
    }
    format!("{before}{NODES_START}\n    {cards}    {NODES_END}{after}")
}

/// Text for the inside of an element or a quoted attribute.
pub(crate) fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Serves the site on `listener` until `shutdown` completes.
pub async fn serve(
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    serve_with(listener, None, shutdown).await
}

/// Serves the site, with the sign-in pages when `app` is given, until `shutdown` completes.
pub async fn serve_with(
    listener: TcpListener,
    app: Option<Arc<App>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    serve_site(listener, app, None, shutdown).await
}

/// Serves the site with the sign-in pages when `app` is given and live server cards when
/// `live` is, until `shutdown` completes.
pub async fn serve_site(
    listener: TcpListener,
    app: Option<Arc<App>>,
    live: Option<Live>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    axum::serve(listener, router_site(app, live))
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use tokio::sync::oneshot;

    use super::*;
    use crate::poller::{Health, NodeView};

    mod front;
    mod legal;
    mod seo;
    mod status_page;

    /// The front page at the default busy numbers; the tests that need others call
    /// `super::front_page`.
    fn front_page(snapshot: &Snapshot) -> String {
        super::front_page(snapshot, &Default::default())
    }

    fn get(path: &str) -> Page {
        page(&Method::GET, path)
    }

    /// How many scripts in `html` would run. The front page carries one block of data for
    /// search engines (`type="application/ld+json"`); no browser runs that, and the policy
    /// (`default-src 'none'`) lets it be, checked in a real browser (`specs/seo.md`). Any other
    /// `<script` counts.
    fn runnable_scripts(html: &str) -> usize {
        html.matches("<script").count()
            - html
                .matches("<script type=\"application/ld+json\">")
                .count()
    }

    /// The `href` and `src` values in `html` that stay on this site.
    fn local_targets(html: &str) -> Vec<String> {
        let mut found = Vec::new();
        for attribute in ["href=\"", "src=\""] {
            for piece in html.split(attribute).skip(1) {
                let value = piece.split('"').next().unwrap_or("");
                if value.starts_with('/') || value.starts_with('#') {
                    found.push(value.to_string());
                }
            }
        }
        found
    }

    #[test]
    fn the_front_page_is_self_contained_html_that_says_it_is_a_closed_beta() {
        let front = get("/");

        assert_eq!(front.status, 200);
        assert_eq!(front.content_type, HTML);
        assert!(front.body.contains("<html lang=\"en\">"));
        assert!(
            front.body.contains("Closed beta"),
            "say what state the service is in"
        );
        assert!(
            front
                .body
                .contains("<a class=\"button\" href=\"/signin\">Sign in</a>")
        );
        assert!(!front.body.contains("http://"), "no plain-http address");
        assert_eq!(runnable_scripts(front.body), 0, "no scripts");
    }

    #[test]
    fn the_front_page_says_closest_server_is_built_and_that_the_location_is_not_kept() {
        let front = get("/").body;
        // The feature cards became the rows of a specification sheet (decision 028); the
        // closest server is told in the Servers row.
        let card = front
            .split("<dt>Servers</dt>")
            .nth(1)
            .and_then(|rest| rest.split("</dd>").next())
            .expect("the Servers row");
        assert!(card.contains("closest server"), "{card}");
        assert!(!card.contains("Planned"), "{card}");
        let keep = front
            .split("<h2>What we keep</h2>")
            .nth(1)
            .and_then(|rest| rest.split("</section>").next())
            .expect("What we keep");
        assert!(keep.contains("approximate location"), "{keep}");
        assert!(keep.contains("not kept"), "{keep}");
        assert!(keep.contains("already on the VPN"), "{keep}");
    }

    #[test]
    fn the_front_page_says_where_the_backups_go_that_they_are_encrypted_and_for_how_long() {
        let keep = INDEX
            .split("<h2>What we keep</h2>")
            .nth(1)
            .and_then(|rest| rest.split("</section>").next())
            .expect("What we keep");
        let line = keep
            .split("<li>")
            .find(|item| item.contains("backup"))
            .unwrap_or_else(|| panic!("no line about backups: {keep}"));
        for part in ["every night", "encrypted", "our two servers", "30 days"] {
            assert!(line.contains(part), "{part:?} missing: {line}");
        }
    }

    #[test]
    fn tracker_blocking_is_no_longer_planned_and_the_questions_say_how_to_switch_it_off() {
        // The feature card became a row of the specification sheet (decision 028).
        let card = INDEX
            .split("<dt>Trackers</dt>")
            .nth(1)
            .and_then(|rest| rest.split("</dd>").next())
            .unwrap();
        assert!(!card.contains("Planned"), "{card}");
        assert!(card.contains("It does not block ads."), "{card}");

        let faq = INDEX.split("<section id=\"faq\">").nth(1).unwrap();
        let answer = faq
            .split("<summary>How do I let trackers through on one device?</summary>")
            .nth(1)
            .and_then(|rest| rest.split("</details>").next())
            .unwrap_or_else(|| panic!("no such question:\n{faq}"));
        for part in ["your account page", "Allow trackers", "added again"] {
            assert!(answer.contains(part), "{part:?} missing: {answer}");
        }

        let kept = INDEX.split("<section id=\"privacy\">").nth(1).unwrap();
        assert!(
            kept.contains("The servers&rsquo; DNS keeps no record of the names it looks up."),
            "{kept}"
        );
    }

    /// This site's own absolute address: the canonical link and the sitemap name pages that way
    /// (`specs/seo.md`). Only the exact host counts, never a longer name that starts with it.
    fn is_this_site(value: &str) -> bool {
        value == "https://barely-free.com" || value.starts_with("https://barely-free.com/")
    }

    /// The `href` and `src` values in `html` that point to another site.
    fn outside_targets(html: &str) -> Vec<String> {
        let mut found = Vec::new();
        for attribute in ["href=\"", "src=\""] {
            for piece in html.split(attribute).skip(1) {
                let value = piece.split('"').next().unwrap_or("");
                if (value.starts_with("http") || value.starts_with("//")) && !is_this_site(value) {
                    found.push(value.to_string());
                }
            }
        }
        found
    }

    /// The `#funding` section of the front page.
    fn funding_section() -> &'static str {
        let from = INDEX
            .split("<section id=\"funding\">")
            .nth(1)
            .expect("the front page has a funding section");
        from.split("</section>").next().unwrap()
    }

    /// The public source repository (a scrubbed snapshot of the code), linked from every
    /// page's menu and footer.
    const SOURCE: &str = "https://github.com/LAOUUUUU/opensourced";

    #[test]
    fn the_only_addresses_outside_this_site_are_ko_fi_and_the_public_source_repository() {
        // The front page: Ko-fi twice (the button in the funding section and the floating
        // one), and the source repository twice (the menu and the footer).
        let outside = outside_targets(INDEX);
        assert_eq!(outside.len(), 4, "{outside:?}");
        assert!(
            outside
                .iter()
                .all(|target| target == "https://ko-fi.com/laouuu" || target == SOURCE),
            "the only addresses out are the Ko-fi page and the source repository: {outside:?}"
        );
        assert_eq!(outside.iter().filter(|t| *t == SOURCE).count(), 2);
        // Every other page: just the source repository, in the menu and the footer.
        assert_eq!(outside_targets(NOT_FOUND), vec![SOURCE, SOURCE]);
        assert_eq!(outside_targets(COOKIES), vec![SOURCE, SOURCE]);

        for html in [INDEX, NOT_FOUND, COOKIES] {
            assert_eq!(
                html.matches(&format!(
                    "<a href=\"{SOURCE}\" rel=\"noopener noreferrer\">"
                ))
                .count(),
                2,
                "each link to another site says noopener noreferrer"
            );
            assert_eq!(runnable_scripts(html), 0, "no script that runs");
            for forbidden in ["<iframe", "<embed", "<object", "@import"] {
                assert!(!html.contains(forbidden), "{forbidden}");
            }
            assert_eq!(
                forms(html),
                vec![THEME_FORM_TAG],
                "the theme buttons are the only form"
            );
        }
    }

    #[test]
    fn the_funding_section_is_in_the_menu_and_links_out_safely() {
        // Since the shared footer (specs/legal-and-support.md) the link is in every page's
        // footer, under Service, rather than in the front page's own menu.
        let footer = INDEX.split("<footer>").nth(1).unwrap();
        assert!(
            footer.contains("<a href=\"/#funding\">Costs and funding</a>"),
            "a footer link to the section"
        );
        let section = funding_section();
        let link = section
            .split("<a ")
            .find(|piece| piece.contains("ko-fi.com"))
            .expect("the donate link is in the section");
        let tag = link.split('>').next().unwrap();
        assert!(tag.contains("rel=\"noopener noreferrer\""), "{tag}");
        assert!(
            section.to_lowercase().contains("opens another site"),
            "say the link leaves the site"
        );
    }

    /// The `<a ...>` tag of the floating button, and the text inside it.
    fn floating_button() -> (&'static str, &'static str) {
        let from = INDEX
            .split("<a class=\"support-float\"")
            .nth(1)
            .expect("the front page has a floating support button");
        let (tag, rest) = from.split_once('>').unwrap();
        let text = rest.split("</a>").next().unwrap();
        (tag, text)
    }

    #[test]
    fn the_floating_support_button_is_a_plain_link_to_ko_fi_with_no_script() {
        let (tag, text) = floating_button();

        assert!(tag.contains("href=\"https://ko-fi.com/laouuu\""), "{tag}");
        assert!(tag.contains("rel=\"noopener noreferrer\""), "{tag}");
        assert_eq!(text.trim(), "Support me");
        // A screen reader hears where it goes; the name starts with the visible words.
        let label = tag
            .split("aria-label=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("an accessible name");
        assert!(label.starts_with("Support me"), "{label}");
        assert!(
            label.to_lowercase().contains("opens another site"),
            "{label}"
        );
        assert!(
            !tag.contains("style="),
            "no inline style: the policy forbids it"
        );
        assert!(!tag.contains("onclick") && !tag.contains("javascript:"));
    }

    #[test]
    fn the_floating_button_is_last_in_the_page_so_it_comes_last_for_keyboards_and_readers() {
        let button = INDEX.find("support-float").unwrap();
        assert!(button > INDEX.find("</footer>").unwrap());
        assert_eq!(
            INDEX.matches("support-float").count(),
            1,
            "one button, only on this page"
        );
        assert!(!NOT_FOUND.contains("support-float"));
        assert!(
            INDEX.contains("<body class=\"has-float\">"),
            "the page leaves room under the footer so the button never hides text"
        );
    }

    /// WCAG relative luminance of an sRGB colour.
    fn luminance(rgb: [u8; 3]) -> f64 {
        let channel = |c: u8| {
            let c = f64::from(c) / 255.0;
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2])
    }

    /// The colour tokens of each theme in the stylesheet: the dark ones in the first `:root`
    /// block and the light ones in the `prefers-color-scheme: light` block.
    fn token_blocks(css: &str) -> Vec<(&'static str, &str)> {
        let block_after = |marker: &str| {
            let from = css.split(marker).nth(1).expect(marker);
            from.split('}').next().unwrap()
        };
        vec![
            ("dark", block_after(":root {")),
            ("light", block_after("@media (prefers-color-scheme: light)")),
        ]
    }

    /// A `#rrggbb` token's colour out of a block of custom properties.
    fn token(block: &str, name: &str) -> [u8; 3] {
        let value = block
            .split(&format!("{name}:"))
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .map(str::trim)
            .unwrap_or_else(|| panic!("{name} in {block}"));
        let hex = value.strip_prefix('#').unwrap_or_else(|| panic!("{value}"));
        let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
        [byte(0), byte(2), byte(4)]
    }

    /// `css` with its `/* ... */` comments taken out.
    fn without_comments(css: &str) -> String {
        let mut out = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(start) = rest.find("/*") {
            out.push_str(&rest[..start]);
            rest = match rest[start..].find("*/") {
                Some(end) => &rest[start + end + 2..],
                None => "",
            };
        }
        out.push_str(rest);
        out
    }

    /// The addresses inside `url(...)` in `css`, with their quotes taken off.
    fn css_urls(css: &str) -> Vec<String> {
        css.split("url(")
            .skip(1)
            .map(|rest| {
                rest.split(')')
                    .next()
                    .unwrap()
                    .trim()
                    .trim_matches(['"', '\''])
                    .to_string()
            })
            .collect()
    }

    /// The at-rule preludes (`@media ...`, `@supports ...`) around byte `at` of `css`.
    fn enclosing_at_rules(css: &str, at: usize) -> Vec<String> {
        let mut stack: Vec<String> = Vec::new();
        let mut start = 0;
        for (i, c) in css[..at].char_indices() {
            match c {
                '{' => {
                    stack.push(css[start..i].trim().to_string());
                    start = i + 1;
                }
                '}' => {
                    stack.pop();
                    start = i + 1;
                }
                ';' => start = i + 1,
                _ => {}
            }
        }
        stack.into_iter().filter(|p| p.starts_with('@')).collect()
    }

    /// Every page file and the base template, by name: the pages whose head the tests hold to
    /// the same stylesheet, icon and font links.
    fn head_pages() -> [(&'static str, &'static str); 12] {
        [
            ("web/index.html", INDEX),
            ("web/404.html", NOT_FOUND),
            ("web/cookies.html", COOKIES),
            ("web/check.html", CHECK),
            ("web/status.html", STATUS),
            ("web/terms.html", TERMS),
            ("web/privacy.html", PRIVACY),
            ("web/abuse.html", ABUSE),
            ("web/transparency.html", TRANSPARENCY),
            ("web/help.html", HELP),
            ("web/security.html", SECURITY),
            (
                "templates/base.html",
                include_str!("../templates/base.html"),
            ),
        ]
    }

    /// The stylesheet's last block: everything that moves lives in it, so one rule decides
    /// who sees motion, and nobody who has asked for less does.
    const MOTION_BLOCK: &str = "@media (prefers-reduced-motion: no-preference) {";

    #[test]
    fn the_stylesheet_names_only_this_sites_three_font_files_by_their_fingerprints() {
        for (path, bytes) in [
            (GEIST_PATH, GEIST),
            (BODONI_PATH, BODONI),
            (BODONI_ITALIC_PATH, BODONI_ITALIC),
        ] {
            let expected = format!("url(\"{path}?v={:016x}\")", fingerprint_bytes(bytes));
            assert!(
                SITE_CSS.contains(&expected),
                "a font changed or is missing: set its url in site.css to {expected}"
            );
        }
        let urls = css_urls(&without_comments(SITE_CSS));
        assert_eq!(urls.len(), 3, "only the three fonts are named: {urls:?}");
        for url in urls {
            let path = url.split('?').next().unwrap();
            assert_eq!(get(path).status, 200, "{url}");
        }
        assert!(!SITE_CSS.contains("data:"), "no data address");
    }

    /// The preload line for a font file, by its address and fingerprint.
    fn preload(path: &str, bytes: &[u8]) -> String {
        format!(
            "<link rel=\"preload\" href=\"{path}?v={:016x}\" as=\"font\" type=\"font/woff2\" crossorigin>",
            fingerprint_bytes(bytes)
        )
    }

    #[test]
    fn every_page_preloads_the_fonts_its_first_screen_uses_by_their_fingerprints() {
        // Without it the text is drawn in a stand-in font first and then swapped, which moves
        // the page. The address is the stylesheet's, so the browser fetches the file once.
        // Every page's first screen has text (Geist) and a heading and the name (Bodoni Moda).
        for (name, html) in head_pages() {
            for tag in [preload(GEIST_PATH, GEIST), preload(BODONI_PATH, BODONI)] {
                assert!(html.contains(&tag), "{name} lacks {tag}");
            }
        }
        // Only the front page's first screen has an italic word, so only it fetches the italic
        // early; elsewhere it comes when a page uses it, if ever.
        let italic = preload(BODONI_ITALIC_PATH, BODONI_ITALIC);
        for (name, html) in head_pages() {
            let want = name == "web/index.html";
            assert_eq!(html.contains(&italic), want, "{name}: the italic preload");
        }
    }

    #[test]
    fn everything_that_moves_sits_in_one_last_block_behind_no_motion_preference() {
        let css = without_comments(SITE_CSS);
        assert_eq!(
            css.matches(MOTION_BLOCK).count(),
            1,
            "one block, not several"
        );
        let at = css.find(MOTION_BLOCK).unwrap();
        let (calm, moving) = css.split_at(at);
        // It runs to the end of the file: its braces close exactly at the last one.
        let mut depth = 0i32;
        for (i, c) in moving.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        assert_eq!(moving[i + 1..].trim(), "", "nothing follows the block");
                    }
                }
                _ => {}
            }
        }
        assert_eq!(depth, 0, "the block's braces balance");
        for word in [
            "animation",
            "transition",
            "@keyframes",
            "scroll-behavior",
            "view-transition",
            "will-change",
        ] {
            assert!(!calm.contains(word), "{word} outside the motion block");
        }
        assert!(moving.contains("@keyframes"), "the block holds the motion");
    }

    #[test]
    fn scroll_driven_rules_sit_behind_a_support_check_so_other_browsers_get_a_still_page() {
        let css = without_comments(SITE_CSS);
        let mut found = 0;
        for (at, _) in css.match_indices("animation-timeline") {
            // The support check names the property in its condition; that is not a use.
            if css[..at].trim_end().ends_with('(') {
                continue;
            }
            found += 1;
            let around = enclosing_at_rules(&css, at);
            assert!(
                around
                    .iter()
                    .any(|p| p.starts_with("@supports") && p.contains("animation-timeline")),
                "animation-timeline at byte {at} is not inside @supports (animation-timeline: ...): {around:?}"
            );
        }
        assert!(found > 0, "the redesign uses scroll-driven animation");
    }

    /// The top-level items of a comma-separated CSS value (commas inside brackets stay).
    fn css_list(value: &str) -> Vec<String> {
        let mut items = vec![String::new()];
        let mut depth = 0i32;
        for c in value.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(String::new());
                    continue;
                }
                _ => {}
            }
            items.last_mut().unwrap().push(c);
        }
        items
            .into_iter()
            .map(|item| item.trim().to_string())
            .collect()
    }

    /// The declarations (`name: value`) inside the block that opens at `css[open]`.
    fn block_body(css: &str, open: usize) -> &str {
        let mut depth = 0i32;
        for (i, c) in css[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &css[open + 1..open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("an unclosed block at byte {open}");
    }

    /// The properties that may move: the compositor draws them without laying out or
    /// repainting the page (decision 028).
    const MAY_MOVE: [&str; 5] = ["transform", "opacity", "translate", "scale", "rotate"];

    #[test]
    fn everything_that_moves_animates_only_transform_and_opacity() {
        let css = without_comments(SITE_CSS);
        let moving = &css[css.find(MOTION_BLOCK).unwrap()..];
        // Every keyframe sets only those.
        let mut frames = 0;
        for (at, _) in moving.match_indices("@keyframes") {
            frames += 1;
            let open = at + moving[at..].find('{').unwrap();
            for step in block_body(moving, open).split('}') {
                let Some((_, body)) = step.split_once('{') else {
                    continue;
                };
                for declaration in body.split(';').filter(|d| !d.trim().is_empty()) {
                    let name = declaration.split(':').next().unwrap().trim();
                    assert!(
                        MAY_MOVE.contains(&name),
                        "a keyframe animates {name}: {}",
                        &moving[at..open]
                    );
                }
            }
        }
        assert!(frames > 0, "the page has its motion");
        // Every transition names only those (and, for the menu's popover, the two discrete
        // steps that let it fade out before it leaves the top layer).
        for (at, _) in moving.match_indices("transition") {
            // A declaration, not `@view-transition` or `view-transition-name`.
            let before = moving[..at].trim_end();
            if !(before.ends_with('{') || before.ends_with(';')) {
                continue;
            }
            let rest = &moving[at..];
            let Some((name, value)) = rest.split(';').next().unwrap().split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name.starts_with("transition-") && name != "transition-property" {
                continue; // a delay, a duration or a timing function
            }
            for item in css_list(value) {
                let property = item.split_whitespace().next().unwrap_or("");
                assert!(
                    MAY_MOVE.contains(&property)
                        || property == "none"
                        || (["display", "overlay"].contains(&property)
                            && item.contains("allow-discrete")),
                    "a transition of {property}: {item}"
                );
            }
        }
        // Nothing moves forever, so nothing needs a control to stop it (WCAG 2.2.2).
        assert!(!css.contains("infinite"), "an endless animation");
    }

    #[test]
    fn the_header_hides_on_the_way_down_only_where_the_browser_can_tell_and_motion_is_welcome() {
        let css = without_comments(SITE_CSS);
        let at = css
            .find("@container scroll-state(scrolled: bottom)")
            .expect("the header steps aside while the page scrolls down");
        assert!(
            at > css.find(MOTION_BLOCK).unwrap(),
            "inside the motion block: nobody who asked for less sees the header move"
        );
        let around = enclosing_at_rules(&css, at);
        assert!(
            around
                .iter()
                .any(|p| p.starts_with("@supports") && p.contains("scroll-state")),
            "where the browser cannot tell the direction, the header simply stays: {around:?}"
        );
        // It never hides while its menu is open or a key has moved into it.
        let rule = block_body(&css, at + css[at..].find('{').unwrap());
        assert!(rule.contains(":popover-open"), "{rule}");
        assert!(rule.contains(":focus-within"), "{rule}");
    }

    #[test]
    fn every_text_colour_reads_on_every_surface_it_sits_on_in_both_themes() {
        let ratio = |a: [u8; 3], b: [u8; 3]| {
            let (hi, lo) = if luminance(a) > luminance(b) {
                (a, b)
            } else {
                (b, a)
            };
            (luminance(hi) + 0.05) / (luminance(lo) + 0.05)
        };
        for (scheme, block) in token_blocks(SITE_CSS) {
            // WCAG 1.4.3: 4.5 to 1 for text.
            for (ink, ground) in [
                ("--text", "--bg"),
                ("--text", "--surface"),
                ("--muted", "--bg"),
                ("--muted", "--surface"),
                ("--accent-ink", "--bg"),
                ("--accent-ink", "--surface"),
                ("--on-accent", "--accent"),
                ("--unknown", "--bg"),
                ("--unknown", "--surface"),
                ("--ok", "--bg"),
                ("--bad", "--bg"),
                ("--bad", "--surface"),
            ] {
                let r = ratio(token(block, ink), token(block, ground));
                assert!(
                    r >= 4.5,
                    "{scheme}: {ink} on {ground} is {r:.2}:1, under 4.5:1"
                );
            }
            // WCAG 1.4.11: 3 to 1 for the edge of a control.
            for ground in ["--bg", "--surface"] {
                let r = ratio(token(block, "--field"), token(block, ground));
                assert!(r >= 3.0, "{scheme}: --field on {ground} is {r:.2}:1");
            }
        }
    }

    #[test]
    fn the_edge_of_every_form_field_stands_out_from_its_background() {
        // WCAG 1.4.11: a control's boundary needs 3 to 1 against what is next to it.
        for (scheme, block) in token_blocks(SITE_CSS) {
            let field = token(block, "--field");
            for next_to in ["--surface", "--bg"] {
                let other = token(block, next_to);
                let (hi, lo) = if luminance(field) > luminance(other) {
                    (field, other)
                } else {
                    (other, field)
                };
                let ratio = (luminance(hi) + 0.05) / (luminance(lo) + 0.05);
                assert!(ratio >= 3.0, "{scheme}: --field on {next_to} is {ratio:.2}");
            }
        }
    }

    #[test]
    fn the_floating_button_is_fixed_in_the_corner_readable_and_hidden_in_print() {
        let css = SITE_CSS;
        let rule = css
            .split(".support-float {")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .expect("a .support-float rule");

        assert!(rule.contains("position: fixed"), "{rule}");
        assert!(
            rule.contains("right:") && rule.contains("bottom:"),
            "{rule}"
        );
        // In the page's own colours (Lao, 2026-11-10): ink on paper, turned over.
        assert!(rule.contains("background: var(--text)"), "{rule}");
        assert!(rule.contains("color: var(--bg)"), "{rule}");
        assert!(
            rule.contains("safe-area-inset-bottom"),
            "clear of a phone's home bar: {rule}"
        );
        assert!(css.contains(".support-float:hover"));
        assert!(
            css.contains(".support-float:focus-visible"),
            "visible for keyboards"
        );
        let print = css.split("@media print").nth(1).expect("a print rule");
        assert!(print.contains(".support-float") && print.contains("display: none"));
        assert!(css.contains("body.has-float"));

        // Both ways round, in every theme, it must read at WCAG AA for normal text (4.5 to 1).
        for (scheme, block) in token_blocks(css) {
            let text = token(block, "--text");
            let bg = token(block, "--bg");
            let (hi, lo) = if luminance(text) > luminance(bg) {
                (text, bg)
            } else {
                (bg, text)
            };
            let ratio = (luminance(hi) + 0.05) / (luminance(lo) + 0.05);
            assert!(ratio >= 4.5, "{scheme}: contrast {ratio:.2}");
        }
    }

    #[test]
    fn the_sign_in_code_is_one_centered_field_that_respects_reduced_motion() {
        let css = SITE_CSS;
        let rule = css
            .split("input.code-input {")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .expect("an input.code-input rule");

        assert!(
            rule.contains("text-align: center"),
            "digits stay aligned: {rule}"
        );
        assert!(
            rule.contains("letter-spacing"),
            "digits stay distinct: {rule}"
        );
        assert!(
            rule.contains("width: min(100%, 25rem)"),
            "fits its container: {rule}"
        );
        assert!(
            rule.contains("ui-monospace"),
            "digits that are all the same width: {rule}"
        );
        assert!(rule.contains("caret-color"), "{rule}");
        assert!(
            css.contains("input.code-input:focus"),
            "the field lights up while typing"
        );
        // Nothing about it is animated outside the stylesheet's motion block, which is behind
        // "no motion preference". (Hairline faded its border there; the editorial direction
        // animates only transform and opacity, so the border now simply changes.)
        let plain = without_comments(css);
        let (calm, moving) = plain.split_at(plain.find(MOTION_BLOCK).expect("a motion block"));
        assert!(
            !calm.contains("transition"),
            "no transition outside the block"
        );
        assert!(
            !moving.contains("input.code-input"),
            "the field's border is not animated"
        );

        // It is still one input, so pasting, an SMS autofill and a screen reader all work,
        // and there is no script to move between boxes.
        let template = include_str!("../templates/code.html");
        assert_eq!(
            template.matches("name=\"code\"").count(),
            1,
            "one field, not six"
        );
        for needed in [
            "maxlength=\"6\"",
            "inputmode=\"numeric\"",
            "autocomplete=\"one-time-code\"",
            "pattern=\"[0-9]{6}\"",
            "class=\"code-input\"",
            "required",
            "<label for=\"code\">",
        ] {
            assert!(template.contains(needed), "{needed}");
        }
        assert!(!template.contains("<script"));
    }

    /// FNV-1a, 64 bits: a short fingerprint of a file's bytes.
    fn fingerprint_bytes(bytes: &[u8]) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// The same, of the stylesheet's or the icon's text.
    fn fingerprint(text: &str) -> u64 {
        fingerprint_bytes(text.as_bytes())
    }

    #[test]
    fn every_page_links_the_icon_by_a_version_that_changes_whenever_the_icon_does() {
        // The icon is cached for a day, by browsers and by Cloudflare in front of the site. A
        // page that links a plain address keeps showing the old icon after it changes (it
        // did, 2026-11-10), so the address carries the icon's own fingerprint, like the
        // stylesheet's: edit the icon and this test fails until every page links the new one.
        let expected = format!("/favicon.svg?v={:016x}", fingerprint(FAVICON));
        let pages = [
            ("web/index.html", INDEX),
            ("web/404.html", NOT_FOUND),
            ("web/cookies.html", COOKIES),
            ("web/check.html", CHECK),
            ("web/status.html", STATUS),
            ("web/terms.html", TERMS),
            ("web/privacy.html", PRIVACY),
            ("web/abuse.html", ABUSE),
            ("web/transparency.html", TRANSPARENCY),
            ("web/help.html", HELP),
            ("web/security.html", SECURITY),
            (
                "templates/base.html",
                include_str!("../templates/base.html"),
            ),
        ];
        for (name, html) in pages {
            assert!(
                html.contains(&format!(
                    "<link rel=\"icon\" href=\"{expected}\" type=\"image/svg+xml\">"
                )),
                "favicon.svg changed: set the icon link in {name} to {expected}"
            );
            // The header's mark is the same drawing, written into the page so it takes the
            // theme's colours and can move; the tab icon is still the file.
            assert!(
                html.contains("<svg class=\"mark\""),
                "{name}: the header carries the mark"
            );
            assert!(
                !html.contains("\"/favicon.svg\""),
                "{name} links the icon without a version"
            );
        }
        // The address still serves the icon, whatever the version says.
        let icon = get("/favicon.svg");
        assert_eq!((icon.status, icon.body), (200, FAVICON));
    }

    #[test]
    fn every_page_links_the_stylesheet_by_a_version_that_changes_whenever_the_stylesheet_does() {
        // The stylesheet is cached for an hour. A page that links a plain address would show
        // new markup with old styling to anyone who visited in the last hour, so the address
        // carries a version, and the version is the stylesheet's own fingerprint: edit the
        // CSS and this test fails until every page links the new address.
        let version = format!("{:016x}", fingerprint(SITE_CSS));
        let expected = format!("/assets/site.css?v={version}");
        let pages = [
            ("web/index.html", INDEX),
            ("web/404.html", NOT_FOUND),
            ("web/cookies.html", COOKIES),
            ("web/check.html", CHECK),
            ("web/status.html", STATUS),
            ("web/terms.html", TERMS),
            ("web/privacy.html", PRIVACY),
            ("web/abuse.html", ABUSE),
            ("web/transparency.html", TRANSPARENCY),
            ("web/help.html", HELP),
            ("web/security.html", SECURITY),
            (
                "templates/base.html",
                include_str!("../templates/base.html"),
            ),
        ];
        for (name, html) in pages {
            assert!(
                html.contains(&expected),
                "site.css changed: set the stylesheet link in {name} to {expected}"
            );
            assert!(
                !html.contains("\"/assets/site.css\""),
                "{name} links the stylesheet without a version"
            );
        }
        // And the address still serves the stylesheet, whatever the version says.
        let css = get("/assets/site.css");
        assert_eq!(css.status, 200);
        assert!(css.cache_control.contains("max-age="));
    }

    #[test]
    fn the_funding_section_says_a_donation_is_a_gift_and_what_happens_if_the_money_runs_out() {
        let text = funding_section().to_lowercase();

        assert!(text.contains("not a purchase"), "{text}");
        assert!(text.contains("no guarantee"), "{text}");
        assert!(text.contains("refund"), "{text}");
        assert!(
            text.contains("free whether or not"),
            "still free for those who give nothing"
        );
        assert!(text.contains("runs out"), "{text}");
        assert!(text.contains("sign-ups stop first"), "{text}");
        assert!(text.contains("nothing donated yet"), "no made-up numbers");
    }

    #[test]
    fn the_funding_section_gives_the_yearly_cost_in_both_currencies_and_nothing_is_planned() {
        // Lao, 2026-11-12: about US$60 a year for the two servers. At the Bank of Canada's
        // rate of 10 November 2026 (1.4181) that is about C$85.
        let section = funding_section();
        assert!(section.contains("US$60 a year"), "{section}");
        assert!(section.contains("C$85"), "{section}");
        assert!(
            section.to_lowercase().contains("the two servers"),
            "{section}"
        );
        assert!(!section.contains("Planned"), "{section}");
    }

    #[test]
    fn the_email_fingerprint_is_built_so_it_is_not_marked_planned() {
        let line = INDEX
            .split("<li>")
            .find(|item| item.contains("keyed fingerprint"))
            .unwrap();
        let line = line.split("</li>").next().unwrap();
        assert!(!line.contains("Planned"), "{line}");
    }

    #[test]
    fn every_link_on_the_pages_leads_somewhere() {
        let pages = [
            INDEX,
            NOT_FOUND,
            COOKIES,
            CHECK,
            TERMS,
            PRIVACY,
            ABUSE,
            TRANSPARENCY,
            HELP,
            SECURITY,
            include_str!("../templates/base.html"),
            include_str!("../templates/signin.html"),
        ];
        for html in pages {
            for target in local_targets(html) {
                // The server looks only at the path; a query such as `?v=...` is not part of
                // it, and a `#section` must be an id on the page it points to.
                let (path, section) = match target.split_once('#') {
                    Some((path, section)) => (path, Some(section)),
                    None => (target.as_str(), None),
                };
                let path = path.split('?').next().unwrap();
                let body = match path {
                    "" => html,
                    "/signin" | "/account" => {
                        assert!(App::handles(path), "{target}");
                        continue;
                    }
                    _ => {
                        let answer = get(path);
                        assert_eq!(answer.status, 200, "{target}");
                        answer.body
                    }
                };
                if let Some(id) = section {
                    assert!(
                        body.contains(&format!("id=\"{id}\"")),
                        "no section {target}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_stylesheet_and_icon_are_served_cacheable_and_pull_in_nothing_from_outside() {
        let css = get("/assets/site.css");
        assert_eq!(
            (css.status, css.content_type),
            (200, "text/css; charset=utf-8")
        );
        assert!(css.cache_control.contains("max-age="));
        assert!(!css.body.contains("@import") && !css.body.contains("http"));

        let icon = get("/favicon.svg");
        assert_eq!((icon.status, icon.content_type), (200, "image/svg+xml"));
        assert!(icon.body.starts_with("<svg"));
    }

    /// The three font files and where they live: Geist (Latin, variable weight) for text and
    /// labels, and Bodoni Moda (Latin, variable weight and optical size) upright and italic
    /// for the headings (`research/redesign-editorial/RESEARCH.md`).
    const FONT_PATHS: [&str; 3] = [
        "/assets/fonts/geist-latin-wght-normal.woff2",
        "/assets/fonts/bodoni-moda-latin-normal.woff2",
        "/assets/fonts/bodoni-moda-latin-italic.woff2",
    ];

    #[test]
    fn the_three_font_files_are_served_as_woff2_and_cached_for_a_year() {
        for path in FONT_PATHS {
            let font = get(path);
            assert_eq!(font.status, 200, "{path}");
            assert_eq!(font.content_type, "font/woff2", "{path}");
            // The stylesheet names each file with its fingerprint (`?v=`), so a changed font is
            // a new address and the old one may be kept for good.
            assert_eq!(
                font.cache_control, "public, max-age=31536000, immutable",
                "{path}"
            );
            let bytes = font.bytes.unwrap_or_else(|| panic!("{path} has no bytes"));
            // Each address serves its own file: the sans, the serif and the serif's italic.
            let own = match path {
                p if p == FONT_PATHS[0] => GEIST,
                p if p == FONT_PATHS[1] => BODONI,
                _ => BODONI_ITALIC,
            };
            assert_eq!(bytes, own, "{path} serves the wrong file");
            assert!(bytes.starts_with(b"wOF2"), "{path} is not a WOFF2 file");
            assert!(
                (10_000..60_000).contains(&bytes.len()),
                "{path} is {} bytes: a Latin subset is a few tens of KB",
                bytes.len()
            );
            assert_eq!(font.body, "", "{path}: a file of bytes has no text body");
        }
    }

    #[test]
    fn the_share_image_is_a_1200_by_630_png_kept_a_year_that_other_sites_may_show() {
        let image = get(SHARE_PATH);
        assert_eq!((image.status, image.content_type), (200, PNG));
        assert_eq!(image.cache_control, FONT_CACHE, "named by its fingerprint");
        let bytes = image.bytes.expect("a file of bytes");
        assert_eq!(bytes, SHARE_PNG);
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "a PNG");
        // The first chunk is IHDR: width and height, big-endian, after the 16 bytes before it.
        let size = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!(&bytes[12..16], b"IHDR");
        assert_eq!(
            (size(16), size(20)),
            (1200, 630),
            "the size previews expect"
        );
        assert!(
            bytes.len() < 300_000,
            "{} bytes: small enough to fetch at once",
            bytes.len()
        );
        assert_eq!(page(&Method::HEAD, SHARE_PATH).status, 200);
        assert_eq!(page(&Method::POST, SHARE_PATH).status, 405);
        assert_eq!(get("/share.png").status, 404, "one address");
    }

    #[tokio::test]
    async fn only_the_share_image_may_be_loaded_by_other_sites() {
        // A chat app or a social site shows the picture from its own pages, so this one file
        // says other sites may load it. Pages, fonts and the icon stay this site's own.
        let header = |path: &'static str| async move {
            let request = Request::builder().uri(path).body(Body::empty()).unwrap();
            let response = handle(
                State(Site {
                    app: None,
                    live: None,
                }),
                request,
            )
            .await;
            response.headers()["cross-origin-resource-policy"]
                .to_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(header(SHARE_PATH).await, "cross-origin");
        for path in [
            "/",
            "/terms",
            BODONI_PATH,
            "/favicon.svg",
            "/assets/site.css",
            "/nope",
        ] {
            assert_eq!(header(path).await, "same-origin", "{path}");
        }
    }

    #[test]
    fn the_fonts_licence_is_served_beside_them() {
        let licence = get("/assets/fonts/OFL.txt");
        assert_eq!((licence.status, licence.content_type), (200, TEXT));
        assert!(licence.body.contains("SIL OPEN FONT LICENSE Version 1.1"));
        assert!(licence.body.contains("The Geist Project Authors"));
        assert!(
            licence.body.contains("The Bodoni Moda Project Authors"),
            "every font served is named in its licence"
        );
        assert!(licence.bytes.is_none(), "the licence is text");
    }

    #[test]
    fn a_font_answers_head_and_refuses_other_methods_and_no_other_font_path_exists() {
        for path in FONT_PATHS {
            assert_eq!(page(&Method::HEAD, path).status, 200, "{path}");
            let refused = page(&Method::POST, path);
            assert_eq!(
                (refused.status, refused.allow),
                (405, Some("GET, HEAD")),
                "{path}"
            );
            assert!(refused.bytes.is_none(), "{path}: a refusal carries no font");
        }
        for path in [
            "/assets/fonts",
            "/assets/fonts/",
            "/assets/fonts/other.woff2",
            "/assets/fonts/geist-latin-wght-normal.woff2/",
            // Geist Mono was served by the first redesign; the labels are Geist now.
            "/assets/fonts/geist-mono-latin-wght-normal.woff2",
            "/assets/fonts/GEIST-LATIN-WGHT-NORMAL.WOFF2",
            "/assets/fonts/../site.css",
            "/assets/fonts/%2e%2e/site.css",
        ] {
            assert_eq!(get(path).status, 404, "{path:?}");
        }
    }

    #[tokio::test]
    async fn a_font_goes_out_with_its_own_bytes_and_every_security_header() {
        for path in FONT_PATHS {
            let request = Request::builder().uri(path).body(Body::empty()).unwrap();
            let response = handle(
                State(Site {
                    app: None,
                    live: None,
                }),
                request,
            )
            .await;
            let headers = response.headers().clone();
            assert_eq!(headers["content-type"], "font/woff2", "{path}");
            assert_eq!(headers["x-content-type-options"], "nosniff");
            assert_eq!(headers["cross-origin-resource-policy"], "same-origin");
            let policy = headers["content-security-policy"].to_str().unwrap();
            assert!(policy.contains("font-src 'self'"), "{policy}");
            let sent = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            assert_eq!(sent.as_ref(), get(path).bytes.unwrap(), "{path}");
        }
    }

    #[test]
    fn health_and_robots_are_plain_text() {
        let health = get("/healthz");
        assert_eq!(
            (health.status, health.content_type, health.body),
            (200, TEXT, "ok\n")
        );
        assert_eq!(health.cache_control, "no-store");

        let robots = get("/robots.txt");
        assert_eq!((robots.status, robots.content_type), (200, TEXT));
        assert!(robots.body.starts_with("User-agent: *"));
    }

    #[test]
    fn unknown_paths_get_a_404_page_that_search_engines_skip() {
        let missing = get("/nothing-here");

        assert_eq!((missing.status, missing.content_type), (404, HTML));
        assert!(missing.body.contains("Page not found") && missing.body.contains("noindex"));
    }

    #[test]
    fn a_wrong_method_is_refused_but_only_on_paths_that_exist() {
        let refused = page(&Method::POST, "/");
        assert_eq!(refused.status, 405);
        assert_eq!(refused.allow, Some("GET, HEAD"));

        // Nothing is revealed about paths that do not exist, whatever the method.
        assert_eq!(page(&Method::POST, "/nope").status, 404);
        assert_eq!(page(&Method::HEAD, "/").status, 200);
    }

    #[test]
    fn paths_that_try_to_escape_are_simply_unknown() {
        for path in [
            "/assets/../Cargo.toml",
            "/assets/",
            "//",
            "/index.html",
            "/%2e%2e/etc/passwd",
            "/assets/site.css/",
            "/assets/SITE.CSS",
            "",
        ] {
            assert_eq!(get(path).status, 404, "{path:?}");
        }
    }

    #[test]
    fn every_response_carries_the_security_headers() {
        for path in [
            "/",
            "/assets/site.css",
            "/favicon.svg",
            FONT_PATHS[0],
            "/healthz",
            "/nope",
        ] {
            let response = secured(&get(path));
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .map(|value| value.to_str().unwrap().to_string())
            };

            let policy = header("content-security-policy").unwrap();
            assert!(policy.contains("default-src 'none'"), "{path}: {policy}");
            assert!(
                policy.contains("frame-ancestors 'none'"),
                "{path}: {policy}"
            );
            assert!(!policy.contains("unsafe"), "{path}: {policy}");
            assert_eq!(header("x-content-type-options").as_deref(), Some("nosniff"));
            // Not `no-referrer`: the theme buttons post from these pages, and with that policy
            // a browser writes `Origin: null`, which the same-origin check must refuse.
            // `same-origin` still sends nothing to any other site.
            assert_eq!(header("referrer-policy").as_deref(), Some("same-origin"));
            assert!(
                header("strict-transport-security")
                    .unwrap()
                    .contains("max-age=")
            );
            assert_eq!(
                header("cross-origin-opener-policy").as_deref(),
                Some("same-origin")
            );
            assert!(header("permissions-policy").is_some(), "{path}");
        }
    }

    // ---- /check: am I on the VPN? ----

    /// A site whose board has Toronto at 192.0.2.176, or no board at all.
    fn check_site(with_board: bool, title: &str) -> Site {
        let live = with_board.then(|| {
            let board = Board::new();
            let mut toronto = view("toronto", title, "Canada", Health::Online);
            toronto.ip = "192.0.2.176".parse().unwrap();
            let mut dallas = view("dallas", "Dallas", "United States", Health::NotResponding);
            dallas.ip = "198.51.100.185".parse().unwrap();
            board.set_for_test(vec![toronto, dallas], 1_000);
            Live {
                board,
                clock: Arc::new(|| 1_000),
                busy: Default::default(),
            }
        });
        Site { app: None, live }
    }

    async fn check_with(
        site: Site,
        method: &str,
        headers: &[(&str, &str)],
    ) -> (u16, axum::http::HeaderMap, String) {
        let mut request = Request::builder().method(method).uri("/check");
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

    async fn check(headers: &[(&str, &str)]) -> String {
        let (status, _, body) = check_with(check_site(true, "Toronto"), "GET", headers).await;
        assert_eq!(status, 200);
        body
    }

    #[tokio::test]
    async fn a_visitor_at_a_servers_address_is_told_they_are_on_it() {
        let body = check(&[("cf-connecting-ip", "192.0.2.176")]).await;
        assert!(body.contains("You are on Barely-free"), "{body}");
        assert!(body.contains("Toronto, Canada"), "{body}");
        assert!(body.contains("192.0.2.176"), "{body}");
        assert!(!body.contains("not on Barely-free"), "{body}");

        // Whatever the poller last heard from that server.
        let body = check(&[("cf-connecting-ip", "198.51.100.185")]).await;
        assert!(body.contains("Dallas, United States"), "{body}");
    }

    #[tokio::test]
    async fn a_visitor_on_a_server_that_is_being_fixed_is_still_told_which_one() {
        let board = Board::new();
        let mut toronto = view("toronto", "Toronto", "Canada", Health::BeingFixed);
        toronto.ip = "192.0.2.176".parse().unwrap();
        toronto.problem = None;
        board.set_for_test(vec![toronto], 1_000);
        let site = Site {
            app: None,
            live: Some(Live {
                board,
                clock: Arc::new(|| 1_000),
                busy: Default::default(),
            }),
        };
        let (status, _, body) =
            check_with(site, "GET", &[("cf-connecting-ip", "192.0.2.176")]).await;
        assert_eq!(status, 200);
        assert!(body.contains("You are on Barely-free"), "{body}");
        assert!(body.contains("Toronto, Canada"), "{body}");
    }

    #[tokio::test]
    async fn any_other_address_is_told_it_is_not_on_and_shown_its_own_address() {
        let body = check(&[("cf-connecting-ip", "203.0.113.9")]).await;
        assert!(body.contains("You are not on Barely-free"), "{body}");
        assert!(body.contains("203.0.113.9"), "{body}");
        assert!(!body.contains("You are on Barely-free"), "{body}");
    }

    #[tokio::test]
    async fn without_one_good_address_the_page_cannot_tell() {
        for headers in [
            vec![],
            vec![("cf-connecting-ip", "not an address")],
            vec![("cf-connecting-ip", "192.0.2.176, 203.0.113.9")],
            vec![
                ("cf-connecting-ip", "192.0.2.176"),
                ("cf-connecting-ip", "192.0.2.176"),
            ],
        ] {
            let body = check(&headers).await;
            assert!(body.contains("cannot tell"), "{headers:?}: {body}");
            assert!(!body.contains("You are on"), "{headers:?}");
            assert!(!body.contains("You are not on"), "{headers:?}");
        }
    }

    #[tokio::test]
    async fn an_ipv6_visitor_behind_a_pseudo_ipv4_is_shown_their_real_address() {
        let body = check(&[
            ("cf-connecting-ip", "240.16.0.1"),
            ("cf-connecting-ipv6", "2001:db8::1"),
        ])
        .await;
        assert!(body.contains("You are not on Barely-free"), "{body}");
        assert!(body.contains("2001:db8::1"), "{body}");
        assert!(!body.contains("240.16.0.1"), "{body}");
    }

    #[tokio::test]
    async fn with_no_board_the_page_cannot_tell_rather_than_say_not_on() {
        let (status, _, body) = check_with(
            check_site(false, "Toronto"),
            "GET",
            &[("cf-connecting-ip", "192.0.2.176")],
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("cannot tell"), "{body}");
        assert!(!body.contains("You are not on"), "{body}");
    }

    #[tokio::test]
    async fn a_board_with_no_servers_cannot_tell_either() {
        let board = Board::new();
        board.set_for_test(vec![], 1_000);
        let site = Site {
            app: None,
            live: Some(Live {
                board,
                clock: Arc::new(|| 1_000),
                busy: Default::default(),
            }),
        };
        let (_, _, body) = check_with(site, "GET", &[("cf-connecting-ip", "203.0.113.9")]).await;
        assert!(body.contains("cannot tell"), "{body}");
    }

    #[tokio::test]
    async fn the_check_is_never_kept_by_any_cache_and_has_every_pages_headers() {
        let (status, headers, _) = check_with(
            check_site(true, "Toronto"),
            "GET",
            &[("cf-connecting-ip", "192.0.2.176")],
        )
        .await;
        assert_eq!(status, 200);
        let header = |name: &str| headers.get(name).map(|v| v.to_str().unwrap().to_string());
        assert_eq!(header("cache-control").as_deref(), Some("no-store"));
        assert_eq!(header("vary").as_deref(), Some("Cookie"));
        assert!(
            header("content-security-policy")
                .unwrap()
                .contains("default-src 'none'")
        );
        assert_eq!(header("x-content-type-options").as_deref(), Some("nosniff"));

        let (status, _, _) = check_with(check_site(true, "Toronto"), "HEAD", &[]).await;
        assert_eq!(status, 200);
        let (status, headers, _) = check_with(check_site(true, "Toronto"), "POST", &[]).await;
        assert_eq!(status, 405);
        assert_eq!(headers.get("allow").unwrap(), "GET, HEAD");
    }

    #[tokio::test]
    async fn a_server_title_is_escaped() {
        let (_, _, body) = check_with(
            check_site(true, "<b>Toronto</b>"),
            "GET",
            &[("cf-connecting-ip", "192.0.2.176")],
        )
        .await;
        assert!(body.contains("&lt;b&gt;Toronto&lt;/b&gt;"), "{body}");
        assert!(!body.contains("<b>Toronto</b>"), "{body}");
    }

    #[test]
    fn the_front_page_asks_and_answers_how_to_check_and_links_the_page() {
        let faq = INDEX.split("<section id=\"faq\">").nth(1).unwrap();
        let answer = faq
            .split("<summary>How do I know the VPN is on?</summary>")
            .nth(1)
            .and_then(|rest| rest.split("</details>").next())
            .unwrap_or_else(|| panic!("no such question:\n{faq}"));
        assert!(answer.contains("href=\"/check\""), "{answer}");
        assert!(CHECK.contains("<h1>Am I on Barely-free?</h1>"));
        assert!(
            CHECK.contains("value=\"/check\""),
            "the theme buttons come back here"
        );
    }

    fn view(name: &str, title: &str, place: &str, health: Health) -> NodeView {
        NodeView {
            name: name.to_string(),
            title: title.to_string(),
            place: place.to_string(),
            protocol: None,
            location: None,
            ip: "192.0.2.7".parse().unwrap(),
            health,
            checked_at: 100,
            last_good: Some(100),
            reading: None,
            problem: Some(crate::poller::Problem::Internal),
            in_sync: false,
            note: None,
        }
    }

    fn snapshot(nodes: Vec<NodeView>) -> Snapshot {
        Snapshot {
            nodes,
            list_version: Some(3),
            updated_at: Some(100),
            contacts: Default::default(),
        }
    }

    /// The cards between the markers of a rendered front page.
    fn cards(html: &str) -> &str {
        html.split(NODES_START)
            .nth(1)
            .and_then(|rest| rest.split(NODES_END).next())
            .expect("the markers are in the page")
    }

    #[test]
    fn with_nothing_on_the_board_the_front_page_is_the_file_as_it_is() {
        assert_eq!(front_page(&snapshot(Vec::new())), INDEX);
        assert!(INDEX.contains(NODES_START) && INDEX.contains(NODES_END));
        assert!(
            INDEX.contains("Status unknown"),
            "the fallback says it does not know"
        );
    }

    #[test]
    fn each_node_is_a_card_with_its_title_place_and_state_in_words() {
        let page = front_page(&snapshot(vec![
            view("toronto", "Toronto", "Canada", Health::Online),
            view("dallas", "Dallas", "United States", Health::NotResponding),
            view("paris", "Paris", "France", Health::Unknown),
            view("lyon", "Lyon", "France", Health::BeingFixed),
        ]));
        let cards = cards(&page);

        assert_eq!(cards.matches("<li>").count(), 4, "{cards}");
        assert!(
            cards.contains(
                "<li><span class=\"dot up\" aria-hidden=\"true\"></span><strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"state up\">Up</span></li>"
            ),
            "{cards}"
        );
        assert!(
            cards.contains("<span class=\"dot down\" aria-hidden=\"true\"></span><strong>Dallas</strong><span class=\"where\">United States</span><span class=\"state down\">Down</span>"),
            "{cards}"
        );
        assert!(
            cards.contains("<span class=\"dot\" aria-hidden=\"true\"></span><strong>Paris</strong><span class=\"where\">France</span><span class=\"state\">Status unknown</span>"),
            "{cards}"
        );
        assert!(
            cards.contains("<span class=\"dot\" aria-hidden=\"true\"></span><strong>Lyon</strong><span class=\"where\">France</span><span class=\"state\">Being fixed</span>"),
            "a disabled server is on the front page too: {cards}"
        );
        assert!(
            !cards.contains("Online") && !cards.contains("Not responding"),
            "the old words are gone: {cards}"
        );
        assert!(
            !page.contains("Two servers to start with"),
            "the old line is gone"
        );
        assert!(page.contains("checked every few seconds"), "{cards}");
    }

    #[test]
    fn the_servers_section_draws_a_map_above_the_list_when_the_servers_have_coordinates() {
        let mut toronto = view("toronto", "Toronto", "Canada", Health::Online);
        toronto.location = crate::closest::Location::new(43.65, -79.38);
        let mut dallas = view("dallas", "Dallas", "United States", Health::NotResponding);
        dallas.location = crate::closest::Location::new(32.78, -96.80);
        let page = front_page(&snapshot(vec![toronto, dallas]));
        let section = cards(&page);

        let map = section
            .find("<figure class=\"board\"><svg class=\"graticule\"")
            .unwrap_or_else(|| panic!("no map: {section}"));
        let list = section.find("<ul class=\"nodes\">").unwrap();
        assert!(map < list, "the map comes first: {section}");
        assert!(section.contains("class=\"pt up\""), "{section}");
        assert!(section.contains("class=\"pt down\""), "{section}");
        // The list is as it was: one card a server, in words.
        assert_eq!(section.matches("<li>").count(), 2, "{section}");
        assert!(section.contains("<span class=\"state up\">Up</span>"));
        // The page outside the section is the file as it is.
        assert!(page.starts_with(INDEX.split(NODES_START).next().unwrap()));
    }

    #[test]
    fn without_coordinates_the_servers_section_is_the_list_alone() {
        let page = front_page(&snapshot(vec![view(
            "toronto",
            "Toronto",
            "Canada",
            Health::Online,
        )]));
        assert!(!cards(&page).contains("<svg"), "{}", cards(&page));
        assert!(cards(&page).contains("<ul class=\"nodes\">"));
    }

    #[test]
    fn a_busy_server_reads_overloaded_on_the_front_page_by_the_same_numbers_as_the_status_page() {
        let busy_node = status_page::agent("Toronto", "Canada", Health::Online, 5, None);
        let nodes = || snapshot(vec![busy_node.clone()]);
        let strict = crate::closest::Busy {
            online: 5,
            load: 9.0,
        };
        let page = super::front_page(&nodes(), &strict);
        assert!(
            cards(&page).contains("<span class=\"state\">Overloaded</span>"),
            "{page}"
        );
        assert!(
            !cards(&page).contains("% load"),
            "the front page's cards give the word only: {page}"
        );
        let page = super::front_page(&nodes(), &crate::closest::Busy::default());
        assert!(
            cards(&page).contains("<span class=\"state up\">Up</span>"),
            "{page}"
        );
    }

    #[test]
    fn the_live_cards_link_to_the_status_page_and_the_help_page_does_too() {
        let page = front_page(&snapshot(vec![view(
            "toronto",
            "Toronto",
            "Canada",
            Health::Online,
        )]));
        assert!(
            cards(&page).contains("<a href=\"/status\">Full status</a>"),
            "{page}"
        );
        assert!(
            HELP.contains("href=\"/status\""),
            "the help page's \"Is a server down?\" points at it"
        );
    }

    #[test]
    fn the_two_agents_of_a_server_are_one_card_up_if_either_is_online() {
        let page = front_page(&snapshot(vec![
            view("toronto", "Toronto", "Canada", Health::Online),
            view("dallas", "Dallas", "United States", Health::Unknown),
            view("toronto-wg", "Toronto", "Canada", Health::NotResponding),
            view(
                "dallas-awg",
                "Dallas",
                "United States",
                Health::NotResponding,
            ),
            view("paris", "Paris", "France", Health::Unknown),
            view("paris-wg", "Paris", "France", Health::Unknown),
            view("lyon", "Lyon", "France", Health::NotResponding),
            view("lyon-wg", "Lyon", "France", Health::NotResponding),
        ]));
        let cards = cards(&page);

        assert_eq!(cards.matches("<li>").count(), 4, "one per server: {cards}");
        assert_eq!(cards.matches("<strong>Toronto</strong>").count(), 1);
        assert!(
            cards.contains("<strong>Toronto</strong><span class=\"where\">Canada</span><span class=\"state up\">Up</span>"),
            "one agent online is enough: {cards}"
        );
        assert!(
            cards.contains("<strong>Dallas</strong><span class=\"where\">United States</span><span class=\"state\">Status unknown</span>"),
            "one agent unknown and the other not responding: not known to be down: {cards}"
        );
        assert!(
            cards.contains("<strong>Lyon</strong><span class=\"where\">France</span><span class=\"state down\">Down</span>"),
            "every agent not responding: {cards}"
        );
        assert!(
            cards.contains("<strong>Paris</strong><span class=\"where\">France</span><span class=\"state\">Status unknown</span>"),
            "{cards}"
        );
        let order: Vec<usize> = ["Toronto", "Dallas", "Paris", "Lyon"]
            .iter()
            .map(|title| cards.find(&format!("<strong>{title}</strong>")).unwrap())
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "in the order servers first appear"
        );
    }

    /// The front page as a visitor gets it from a site whose sign-in pages are open or closed.
    async fn front_page_of_a_site_with_sign_in(open: bool) -> String {
        use crate::mail::RecordingMailer;
        use crate::secrets::ControlKeys;

        let mut store = crate::store::Store::open_in_memory().unwrap();
        if open {
            store = store.with_open_signup(crate::signin::OpenLimits::default());
        }
        let app = App::new(
            store,
            ControlKeys::from_parts([1; 32], [2; 32]),
            Arc::new(RecordingMailer::new()),
            vec!["https://barely-free.com".to_string()],
            Arc::new(|| 1_000),
        );
        let request = Request::builder().uri("/").body(Body::empty()).unwrap();
        let response = handle(
            State(Site {
                app: Some(app),
                live: None,
            }),
            request,
        )
        .await;
        assert_eq!(response.status(), 200);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn when_sign_up_is_open_the_front_page_says_so_and_when_closed_it_still_says_closed_beta()
    {
        let closed = front_page_of_a_site_with_sign_in(false).await;
        let open = front_page_of_a_site_with_sign_in(true).await;

        assert_eq!(closed, INDEX, "a closed site serves the file as it is");
        for gone in [
            "Closed beta",
            "closed beta",
            "not open yet",
            "sign-up is not open",
            "Why can't I sign up yet?",
            "before sign-up opens",
            "Sign-up opens",
        ] {
            assert!(!open.contains(gone), "{gone:?} on an open site");
        }
        // The menu, the hero and the closing line each lead in: three buttons, so a change to the
        // hero's wording cannot hide behind the menu's own "Get started".
        assert_eq!(
            open.matches("<a class=\"button\" href=\"/signin\">Get started</a>")
                .count(),
            3,
            "the menu, the hero and the closing line lead in"
        );
        assert_eq!(
            INDEX
                .matches("<a class=\"button\" href=\"/signin\">Sign in</a>")
                .count(),
            2,
            "until sign-up opens the hero and the closing line say Sign in"
        );
        assert!(open.contains("sign-up is open"), "the badge says so");
        assert!(
            open.contains("<p class=\"badge open\">Full release &middot; sign-up is open</p>"),
            "the badge says it is a full release"
        );
        assert!(
            !open.to_lowercase().contains("beta"),
            "an open site is not a beta anywhere on the page"
        );
        assert!(open.contains("Can anybody sign up?"));
        assert!(
            open.contains("new sign-ups stop first"),
            "the funding promise stays, it is what the daily cap does"
        );
        assert_eq!(runnable_scripts(&open), 0, "no script that runs");
        for forbidden in ["<iframe", "<embed", "<object", "@import"] {
            assert!(!open.contains(forbidden), "{forbidden}");
        }
        assert_eq!(forms(&open), vec![THEME_FORM_TAG]);
        assert_eq!(
            outside_targets(&open),
            outside_targets(INDEX),
            "no new address leaves the site"
        );
    }

    /// The answer (headers and body) for `path` on a site with sign-in, for a browser that
    /// sends `cookie` (the session cookie's value), where `session` is a live one at time 1000.
    async fn page_with_cookie(
        path: &str,
        open: bool,
        cookie: impl Fn(&str) -> Option<String>,
    ) -> (axum::http::HeaderMap, String) {
        use crate::mail::RecordingMailer;
        use crate::secrets::ControlKeys;

        let mut store = crate::store::Store::open_in_memory().unwrap();
        if open {
            store = store.with_open_signup(crate::signin::OpenLimits::default());
        }
        let account = store.add_account("lao", 900).unwrap();
        let session = store.create_session(account.id, 900).unwrap();
        let app = App::new(
            store,
            ControlKeys::from_parts([1; 32], [2; 32]),
            Arc::new(RecordingMailer::new()),
            vec!["https://barely-free.com".to_string()],
            Arc::new(|| 1_000),
        );
        let mut request = Request::builder().uri(path);
        if let Some(value) = cookie(&session.cookie) {
            request = request.header("cookie", format!("a=b; __Host-bf_session={value}"));
        }
        let response = handle(
            State(Site {
                app: Some(app),
                live: None,
            }),
            request.body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), 200);
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (headers, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_signed_in_visitor_sees_your_account_where_the_sign_in_button_was() {
        let your_account = "<a class=\"button\" href=\"/account\">Your account</a>";
        for open in [false, true] {
            let (headers, html) = page_with_cookie("/", open, |live| Some(live.to_string())).await;

            assert!(html.contains(your_account), "open {open}: {html}");
            assert!(!html.contains("href=\"/signin\""), "open {open}");
            assert_eq!(headers.get("vary").unwrap(), "Cookie");
            // `private`: a shared cache (Cloudflare ignores `Vary: Cookie`) must never keep
            // one person's copy for another, even if a cache-everything rule is added later.
            assert_eq!(headers.get("cache-control").unwrap(), "private, no-cache");
        }

        // Signed out, a made-up cookie, a right id with a wrong secret: the page as before.
        let made_up = |_: &str| Some(format!("{}.{}", "1".repeat(32), "2".repeat(64)));
        let wrong_secret = |live: &str| {
            let (id, _) = live.split_once('.').unwrap();
            Some(format!("{id}.{}", "0".repeat(64)))
        };
        let none = |_: &str| None;
        let junk = |_: &str| Some("<script>".to_string());
        for (name, cookie) in [
            ("none", &none as &dyn Fn(&str) -> Option<String>),
            ("made up", &made_up),
            ("wrong secret", &wrong_secret),
            ("junk", &junk),
        ] {
            let (headers, html) = page_with_cookie("/", false, cookie).await;
            assert_eq!(html, INDEX, "{name}");
            assert_eq!(headers.get("vary").unwrap(), "Cookie", "{name}");
        }
    }

    #[tokio::test]
    async fn the_get_started_button_in_the_menu_is_for_visitors_who_are_not_signed_in() {
        let button = "<a class=\"button\" href=\"/signin\">Get started</a>";
        let account = "<a href=\"/account\">Account</a>";
        let paths = [
            "/",
            "/terms",
            "/privacy",
            "/abuse",
            "/transparency",
            "/security",
            "/help",
            "/cookies",
            "/check",
            "/status",
        ];
        for path in paths {
            // Signed out: the way in is there, and so is the account link (it leads to sign-in).
            let (_, html) = page_with_cookie(path, true, |_| None).await;
            assert!(html.contains(button), "{path}: signed out");
            assert!(html.contains(account), "{path}: signed out");
            // Signed in: nothing to get started on, and the account link stays.
            let (headers, html) = page_with_cookie(path, true, |live| Some(live.to_string())).await;
            assert!(
                !html.contains(button),
                "{path}: signed in still has the button"
            );
            assert!(html.contains(account), "{path}: signed in");
            assert_eq!(headers.get("vary").unwrap(), "Cookie", "{path}");
        }
    }

    #[tokio::test]
    async fn an_expired_session_is_not_signed_in_on_the_front_page() {
        use crate::mail::RecordingMailer;
        use crate::secrets::ControlKeys;

        let mut store = crate::store::Store::open_in_memory().unwrap();
        let account = store.add_account("lao", 0).unwrap();
        let session = store.create_session(account.id, 0).unwrap();
        let after = crate::signin::SESSION_LIFETIME_SECS;
        let app = App::new(
            store,
            ControlKeys::from_parts([1; 32], [2; 32]),
            Arc::new(RecordingMailer::new()),
            vec!["https://barely-free.com".to_string()],
            Arc::new(move || after),
        );
        let request = Request::builder()
            .uri("/")
            .header("cookie", format!("__Host-bf_session={}", session.cookie))
            .body(Body::empty())
            .unwrap();
        let response = handle(
            State(Site {
                app: Some(app),
                live: None,
            }),
            request,
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), INDEX);
    }

    /// The answer to `GET path` from a site with sign-in, for a browser sending `cookie`.
    async fn answer_with_cookie(path: &str, cookie: &str) -> (axum::http::HeaderMap, String) {
        use crate::mail::RecordingMailer;
        use crate::secrets::ControlKeys;

        let app = App::new(
            crate::store::Store::open_in_memory().unwrap(),
            ControlKeys::from_parts([1; 32], [2; 32]),
            Arc::new(RecordingMailer::new()),
            vec!["https://barely-free.com".to_string()],
            Arc::new(|| 1_000),
        );
        let request = Request::builder()
            .uri(path)
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let response = handle(
            State(Site {
                app: Some(app),
                live: None,
            }),
            request,
        )
        .await;
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (headers, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn the_front_page_and_the_404_are_drawn_in_the_chosen_theme_and_vary_by_cookie() {
        for (path, file) in [("/", INDEX), ("/nothing-here", NOT_FOUND)] {
            for (cookie, theme) in [
                ("__Host-bf_theme=dark", "dark"),
                ("a=b; __Host-bf_theme=light", "light"),
            ] {
                let (headers, html) = answer_with_cookie(path, cookie).await;
                assert_eq!(
                    html,
                    // The tag, and which footer button is pressed; nothing else.
                    file.replacen(
                        "<html lang=\"en\">",
                        &format!("<html lang=\"en\" data-theme=\"{theme}\">"),
                        1
                    )
                    .replacen(
                        "value=\"system\" aria-pressed=\"true\"",
                        "value=\"system\" aria-pressed=\"false\"",
                        1
                    )
                    .replacen(
                        &format!("value=\"{theme}\" aria-pressed=\"false\""),
                        &format!("value=\"{theme}\" aria-pressed=\"true\""),
                        1
                    ),
                    "{path} {cookie}"
                );
                assert_eq!(headers.get("vary").unwrap(), "Cookie", "{path}");
            }
            for cookie in [
                "",
                "__Host-bf_theme=system",
                "__Host-bf_theme=dark\"><script>",
                "__Host-bf_theme=light dark",
                "bf_theme=dark",
            ] {
                let (headers, html) = answer_with_cookie(path, cookie).await;
                assert_eq!(html, file, "{path} {cookie:?}");
                assert_eq!(headers.get("vary").unwrap(), "Cookie", "{path}");
            }
        }
        // Not the stylesheet or the icon: they are the same for everyone and cached.
        let (headers, _) = answer_with_cookie("/assets/site.css", "__Host-bf_theme=dark").await;
        assert!(headers.get("vary").is_none());
    }

    /// The opening tags of the forms in `html`.
    fn forms(html: &str) -> Vec<&str> {
        html.split("<form")
            .skip(1)
            .map(|rest| rest.split('>').next().unwrap())
            .collect()
    }

    /// What follows `<form` in the theme form's tag.
    const THEME_FORM_TAG: &str = " class=\"theme\" method=\"post\" action=\"/theme\"";

    /// The theme form in `html`, from its tag to `</form>`.
    fn theme_form(html: &str) -> &str {
        let from = html
            .split("<form class=\"theme\"")
            .nth(1)
            .expect("a theme form");
        from.split("</form>").next().unwrap()
    }

    #[test]
    fn every_page_has_the_theme_buttons_in_its_footer_and_says_they_use_a_cookie() {
        let pages = [
            ("web/index.html", INDEX, "/"),
            ("web/404.html", NOT_FOUND, "/"),
            ("web/cookies.html", COOKIES, "/cookies"),
            ("web/check.html", CHECK, "/check"),
            ("web/status.html", STATUS, "/status"),
            (
                "templates/base.html",
                include_str!("../templates/base.html"),
                "{% block back %}/{% endblock %}",
            ),
        ];
        for (name, html, back) in pages {
            let footer = html.split("<footer>").nth(1).expect(name);
            assert_eq!(forms(footer), vec![THEME_FORM_TAG], "{name}");
            let form = theme_form(footer);
            assert!(
                form.contains(&format!(
                    "<input type=\"hidden\" name=\"back\" value=\"{back}\">"
                )),
                "{name}: {form}"
            );
            for value in ["system", "light", "dark"] {
                assert_eq!(
                    form.matches(&format!("name=\"theme\" value=\"{value}\""))
                        .count(),
                    1,
                    "{name}: {value}"
                );
            }
            assert!(form.contains("cookie"), "{name}: say it uses a cookie");
            assert!(
                !form.contains("csrf"),
                "{name}: no session token, it changes nothing"
            );
        }
    }

    #[test]
    fn the_public_policy_lets_a_form_go_to_this_site_only_and_still_runs_nothing() {
        assert!(POLICY.contains("form-action 'self'"), "{POLICY}");
        for kept in [
            "default-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
        ] {
            assert!(POLICY.contains(kept), "{kept}");
        }
        // The redesign adds one thing: fonts from this site's own files. Pinned whole, so an
        // allowance added by accident fails here.
        assert_eq!(
            POLICY,
            "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
             base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        );
        for never in [
            "script-src",
            "connect-src",
            "object-src",
            "frame-src",
            "worker-src",
            "unsafe",
            "data:",
            "http",
        ] {
            assert!(!POLICY.contains(never), "{never}: {POLICY}");
        }
        assert_eq!(
            POLICY, APP_POLICY,
            "the public and app pages now differ in nothing"
        );
    }

    #[tokio::test]
    async fn without_the_sign_in_side_there_are_no_theme_buttons_to_press() {
        for path in ["/", "/nothing-here", "/cookies"] {
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
            assert!(forms(&html).is_empty(), "{path}: /theme would be a 404");
            assert!(html.contains("</footer>"), "{path}");
        }
    }

    #[test]
    fn a_chosen_theme_overrides_the_devices_setting_in_the_stylesheet() {
        let css = SITE_CSS;
        assert!(
            css.contains(":root[data-theme=\"light\"] {"),
            "light chosen"
        );
        assert!(css.contains(":root[data-theme=\"dark\"] {"), "dark chosen");
        let light_block = css
            .split(":root[data-theme=\"light\"] {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        assert!(light_block.contains("color-scheme: light"), "{light_block}");
        let dark_block = css
            .split(":root[data-theme=\"dark\"] {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        assert!(dark_block.contains("color-scheme: dark"), "{dark_block}");
        // The device's light setting counts only when nobody chose.
        let media = css
            .split("@media (prefers-color-scheme: light)")
            .nth(1)
            .unwrap();
        assert!(
            media
                .trim_start()
                .starts_with("{\n  :root:not([data-theme]) {"),
            "{}",
            &media[..80]
        );
        // The same light colours either way.
        assert_eq!(
            light_block
                .replace("color-scheme: light;", "")
                .split_whitespace()
                .collect::<Vec<_>>(),
            media
                .split('}')
                .next()
                .unwrap()
                .split(":root:not([data-theme]) {")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>(),
        );
    }

    /// The cookie names `cookie.rs` defines (`pub const ..._COOKIE: &str = "...";`).
    fn cookie_names() -> Vec<&'static str> {
        include_str!("cookie.rs")
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("pub const ")?;
                let (name, rest) = rest.split_once(": &str = \"")?;
                name.ends_with("_COOKIE")
                    .then(|| rest.split('"').next().unwrap())
            })
            .collect()
    }

    #[test]
    fn the_cookie_page_lists_every_cookie_the_server_can_set_with_what_it_does_and_how_long() {
        let names = cookie_names();
        assert_eq!(
            names,
            ["__Host-bf_session", "__Host-bf_pending", "__Host-bf_theme"],
            "the names this test found in cookie.rs"
        );
        let page = get("/cookies");
        assert_eq!((page.status, page.content_type), (200, HTML));
        assert_eq!(page.cache_control, "private, no-cache");
        for name in &names {
            let entry = COOKIES
                .split(&format!("<dt><code>{name}</code></dt>"))
                .nth(1)
                .unwrap_or_else(|| panic!("{name} has no line on the cookie page"));
            let entry = entry.split("</dd>").next().unwrap();
            for part in ["What it does:", "Set:", "Lasts:"] {
                assert!(entry.contains(part), "{name}: {part}");
            }
        }
        assert_eq!(
            COOKIES.matches("<dt>").count(),
            names.len(),
            "no line for a cookie that does not exist"
        );
        assert!(COOKIES.contains("Cloudflare"), "say who else sees them");
        for forbidden in ["<script", "<iframe", "@import", "style="] {
            assert!(!COOKIES.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn the_lifetimes_on_the_cookie_page_are_the_ones_the_code_uses() {
        use crate::signin::{CODE_LIFETIME_SECS, KEPT_SESSION_MAX_SECS, SESSION_LIFETIME_SECS};
        const DAY: u64 = 86_400;
        let entry = |name: &str| {
            COOKIES
                .split(&format!("<dt><code>{name}</code></dt>"))
                .nth(1)
                .unwrap()
                .split("</dd>")
                .next()
                .unwrap()
        };
        let session = entry("__Host-bf_session");
        assert_eq!(SESSION_LIFETIME_SECS, 60 * DAY, "the page says 60 days");
        assert!(
            session.contains("<strong>Lasts:</strong> 60 days."),
            "{session}"
        );
        assert_eq!(KEPT_SESSION_MAX_SECS, 365 * DAY, "the page says a year");
        assert!(session.contains("never more than a year"), "{session}");
        assert_eq!(CODE_LIFETIME_SECS, 600, "the page says 10 minutes");
        assert!(entry("__Host-bf_pending").contains("<strong>Lasts:</strong> 10 minutes"));
        assert_eq!(
            cookie::THEME_MAX_AGE_SECS,
            365 * DAY,
            "the page says one year"
        );
        assert!(entry("__Host-bf_theme").contains("<strong>Lasts:</strong> one year."));
    }

    #[test]
    fn every_footer_links_to_the_cookie_page() {
        for (name, html) in [
            ("web/index.html", INDEX),
            ("web/404.html", NOT_FOUND),
            ("web/cookies.html", COOKIES),
            ("web/check.html", CHECK),
            ("web/status.html", STATUS),
            (
                "templates/base.html",
                include_str!("../templates/base.html"),
            ),
        ] {
            let footer = html.split("<footer>").nth(1).expect(name);
            assert!(footer.contains("href=\"/cookies\""), "{name}");
        }
        let code = include_str!("../templates/code.html");
        let tick = code.split("name=\"keep\"").nth(1).unwrap();
        assert!(
            tick.split("</p>")
                .next()
                .unwrap()
                .contains("href=\"/cookies\""),
            "the tick box links to the cookie page"
        );
    }

    #[tokio::test]
    async fn the_cookie_page_is_drawn_in_the_chosen_theme_too() {
        let (headers, html) = answer_with_cookie("/cookies", "__Host-bf_theme=light").await;
        assert!(html.starts_with("<!doctype html>\n<html lang=\"en\" data-theme=\"light\">"));
        assert_eq!(headers.get("vary").unwrap(), "Cookie");
        let (_, html) = answer_with_cookie("/cookies", "").await;
        assert_eq!(html, COOKIES);
    }

    #[test]
    fn every_page_sends_its_theme_buttons_back_to_a_page_the_theme_form_accepts() {
        let mut found = 0;
        for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates")).unwrap() {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            for back in text.split("{% block back %}").skip(1) {
                let back = back.split("{% endblock %}").next().unwrap();
                assert!(crate::app::THEME_BACK.contains(&back), "{back}");
                found += 1;
            }
        }
        assert!(found >= 10, "the base default and the pages' own: {found}");
        for html in [INDEX, NOT_FOUND, COOKIES] {
            let form = theme_form(html);
            let back = form.split("name=\"back\" value=\"").nth(1).unwrap();
            let back = back.split('"').next().unwrap();
            assert!(crate::app::THEME_BACK.contains(&back), "{back}");
        }
    }

    #[tokio::test]
    async fn the_theme_buttons_say_which_theme_is_in_use() {
        let pressed = |html: &str| -> Vec<(String, String)> {
            theme_form(html)
                .split("name=\"theme\" value=\"")
                .skip(1)
                .map(|rest| {
                    let value = rest.split('"').next().unwrap().to_string();
                    let state = rest
                        .split('>')
                        .next()
                        .unwrap()
                        .split("aria-pressed=\"")
                        .nth(1)
                        .map(|s| s.split('"').next().unwrap().to_string())
                        .unwrap_or_default();
                    (value, state)
                })
                .collect()
        };
        let expect = |on: &str| -> Vec<(String, String)> {
            ["system", "light", "dark"]
                .iter()
                .map(|v| (v.to_string(), (*v == on).to_string()))
                .collect()
        };
        for path in ["/", "/nothing-here", "/cookies"] {
            for (cookie, on) in [
                ("", "system"),
                ("__Host-bf_theme=light", "light"),
                ("__Host-bf_theme=dark", "dark"),
                ("__Host-bf_theme=junk", "system"),
            ] {
                let (_, html) = answer_with_cookie(path, cookie).await;
                assert_eq!(pressed(&html), expect(on), "{path} {cookie}");
            }
        }
        assert!(SITE_CSS.contains("form.theme button[aria-pressed=\"true\"]"));
    }

    #[test]
    fn every_open_wording_swap_still_matches_the_front_page_file() {
        for (closed, open) in OPEN_WORDING {
            assert!(
                INDEX.contains(closed),
                "index.html no longer holds {closed:?}; update OPEN_WORDING with it"
            );
            assert_ne!(closed, open);
        }
    }

    #[tokio::test]
    async fn without_the_sign_in_pages_the_front_page_does_not_link_to_them() {
        let board = Board::new();
        board.set_for_test(
            vec![view("toronto", "Toronto", "Canada", Health::Online)],
            1_000,
        );
        let live = Live {
            board,
            clock: Arc::new(|| 1_000),
            busy: Default::default(),
        };
        for live in [None, Some(live)] {
            let request = Request::builder().uri("/").body(Body::empty()).unwrap();
            let response = handle(State(Site { app: None, live }), request).await;
            assert_eq!(response.status(), 200);
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let html = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(
                !html.contains("/signin"),
                "no link to pages that are not there"
            );
            assert!(
                html.contains(SIGN_IN_OFF),
                "the button says sign-up is not open"
            );
        }
    }

    #[test]
    fn the_cards_replace_the_fixed_ones_and_the_rest_of_the_page_is_untouched() {
        let page = front_page(&snapshot(vec![view(
            "paris",
            "Paris",
            "France",
            Health::Online,
        )]));

        assert!(!page.contains("Dallas") && !page.contains("Toronto"));
        let (before, after) = INDEX.split_once(NODES_START).unwrap();
        let (_, tail) = after.split_once(NODES_END).unwrap();
        assert!(page.starts_with(before));
        assert!(page.ends_with(tail));
        // Every card reads a state, so the note about "unknown" is left out
        // (specs/legal-and-support.md); it shows while one reads unknown.
        assert!(!page.contains("&ldquo;Unknown&rdquo; means we have no reading yet"));
    }

    #[test]
    fn a_title_or_place_is_text_never_markup() {
        let page = front_page(&snapshot(vec![view(
            "x",
            "<script>alert(1)</script>",
            "A & B \"quoted\" 'single'",
            Health::Online,
        )]));
        let cards = cards(&page);

        assert!(!cards.contains("<script"), "{cards}");
        assert!(
            cards.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{cards}"
        );
        assert!(
            cards.contains("A &amp; B &quot;quoted&quot; &#39;single&#39;"),
            "{cards}"
        );
        assert_eq!(runnable_scripts(&page), 0, "no scripts anywhere");
    }

    #[test]
    fn the_public_cards_say_nothing_about_counts_load_keys_or_what_is_wrong() {
        let mut node = view("toronto", "Toronto", "Canada", Health::Online);
        node.reading = Some(crate::link::NodeReading {
            wg_public_key: "SERVERKEYSERVERKEYSERVERKEYSERVERKEYSERVER=".to_string(),
            listen_port: 51820,
            online: 7,
            peers_total: 9,
            desired_version: Some(3),
            load1: Some(0.42),
            load_steady: Some(0.42),
            peers: Vec::new(),
            logins: None,
            attention: None,
        });
        node.problem = Some(crate::poller::Problem::Ahead {
            node: 8,
            database: 3,
        });

        let page = front_page(&snapshot(vec![node]));
        let cards = cards(&page);

        for secret in ["SERVERKEY", "51820", "0.42", "ahead", "7 online", "9"] {
            assert!(!cards.contains(secret), "{secret}: {cards}");
        }
    }

    #[test]
    fn a_live_front_page_is_served_with_the_same_headers_and_a_stale_board_reads_as_unknown() {
        let board = Board::new();
        board.set_for_test(
            vec![view("toronto", "Toronto", "Canada", Health::Online)],
            1_000,
        );
        let now = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let clock = now.clone();
        let live = Live {
            board,
            clock: Arc::new(move || clock.load(std::sync::atomic::Ordering::SeqCst)),
            busy: Default::default(),
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                axum::serve(listener, router_site(None, Some(live)))
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
        });
        let ask = |request: &str| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            answer
        };
        let get = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";

        let fresh = ask(get);
        let head = ask("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let post =
            ask("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        now.store(1_000 + 61, std::sync::atomic::Ordering::SeqCst);
        let stale = ask(get);
        let css = ask("GET /assets/site.css HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let _ = stop.send(());
        server.join().unwrap();

        assert!(fresh.starts_with("HTTP/1.1 200"), "{fresh}");
        assert!(
            fresh.contains("<span class=\"state up\">Up</span>"),
            "{fresh}"
        );
        let lower = fresh.to_lowercase();
        assert!(
            lower.contains("cache-control: private, no-cache"),
            "{fresh}"
        );
        assert!(
            lower.contains("content-security-policy: default-src 'none'"),
            "{fresh}"
        );
        assert!(lower.contains("form-action 'self'"), "{fresh}");
        assert!(lower.contains("referrer-policy: same-origin"), "{fresh}");
        assert!(
            head.starts_with("HTTP/1.1 200") && head.ends_with("\r\n\r\n"),
            "{head}"
        );
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        assert!(
            post.contains("Method not allowed") && !post.contains("state up"),
            "a refused method gets the refusal, not the page: {post}"
        );
        assert!(
            stale.contains("<span class=\"state\">Status unknown</span>"),
            "{stale}"
        );
        assert!(!stale.contains("state up"), "{stale}");
        assert!(
            css.starts_with("HTTP/1.1 200") && css.contains("text/css"),
            "{css}"
        );
    }

    /// Runs the real server on a free port, asks it three things over a socket, stops it.
    /// What the whole site says to one raw request: everything but the date.
    fn raw_answer(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        answer
            .lines()
            .filter(|line| !line.to_lowercase().starts_with("date:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn nobody_but_a_signed_in_admin_can_tell_that_the_admin_pages_exist() {
        use crate::app::App;
        use crate::mail::RecordingMailer;
        use crate::secrets::ControlKeys;

        // A site with the sign-in pages, one ordinary account that is signed in (sam), and an
        // admin (lao) who is signed in too. The clock can be moved, to let sessions run out.
        let mut store = crate::store::Store::open_in_memory().unwrap();
        store.add_account("sam", 1).unwrap();
        store.add_account("lao", 1).unwrap();
        store.set_admin(2, true).unwrap();
        let session = store.create_session(1, 1_000).unwrap();
        let admin_session = store.create_session(2, 1_000).unwrap();
        let now = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let clock = {
            let now = now.clone();
            Arc::new(move || now.load(std::sync::atomic::Ordering::SeqCst))
        };
        let app = App::new(
            store,
            ControlKeys::from_parts([1; 32], [2; 32]),
            Arc::new(RecordingMailer::new()),
            vec!["https://barely-free.com".to_string()],
            clock,
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                axum::serve(listener, router_site(Some(app), None))
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
        });
        let cookie = format!("__Host-bf_session={}", session.cookie);
        let asks = |method: &str, path: &str, cookie: Option<&str>| {
            let cookie_line = cookie.map_or(String::new(), |c| format!("Cookie: {c}\r\n"));
            let body = if method == "POST" {
                "Content-Length: 0\r\n"
            } else {
                ""
            };
            raw_answer(
                addr,
                &format!(
                    "{method} {path} HTTP/1.1\r\nHost: x\r\n{cookie_line}{body}Connection: close\r\n\r\n"
                ),
            )
        };

        for method in ["GET", "POST", "HEAD"] {
            for who in [None, Some("__Host-bf_session=junk"), Some(cookie.as_str())] {
                // What this visitor gets for a path that does not exist. A signed-in visitor is
                // not offered "Get started" in the menu, so the comparison is with the same
                // visitor's own 404: an admin path must look like any other unknown path to
                // whoever asks.
                let nothing = asks(method, "/nothing-here", who);
                assert!(nothing.starts_with("HTTP/1.1 404"), "{nothing}");
                for path in [
                    "/admin",
                    "/admin/unlock",
                    "/admin/lock",
                    "/admin/accounts",
                    "/admin/devices",
                    "/admin/devices/remove",
                    "/admin/kicks",
                    "/admin/kicks/lift",
                    "/admin/",
                    "/admin/anything",
                ] {
                    assert_eq!(
                        asks(method, path, who),
                        nothing,
                        "{method} {path} as {who:?}: not an admin, so the same as any unknown path"
                    );
                }
            }
        }
        // The ordinary pages next to them still work for the same visitor.
        assert!(asks("GET", "/account", Some(&cookie)).starts_with("HTTP/1.1 200"));

        // The admin, signed in: the admin pages are there, and only those. Every other path,
        // `/` and the unknown ones under `/admin` included, is exactly what everyone gets.
        let admin_cookie = format!("__Host-bf_session={}", admin_session.cookie);
        let admin = Some(admin_cookie.as_str());
        let front = asks("GET", "/", None);
        assert!(front.starts_with("HTTP/1.1 200"), "{front}");
        // Signed in, the front page's button says "Your account" and the menu has no "Get
        // started"; nothing else differs.
        let without_length = |answer: &str| {
            answer
                .lines()
                .filter(|line| !line.starts_with("content-length:"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let admin_front = asks("GET", "/", admin);
        assert!(admin_front.contains(ACCOUNT_LINK), "{admin_front}");
        assert_eq!(
            without_length(&admin_front.replace(ACCOUNT_LINK, SIGN_IN_LINK)),
            without_length(&front.replacen(HEADER_CTA, "", 1)),
            "the front page, not an admin page"
        );
        for method in ["GET", "POST", "HEAD"] {
            let nothing = asks(method, "/nothing-here", admin);
            for path in [
                "/admin/",
                "/admin/anything",
                "/admin/accounts/",
                "/Admin",
                "/nothing-here",
            ] {
                assert_eq!(
                    asks(method, path, admin),
                    nothing,
                    "{method} {path} as the admin: not an admin page"
                );
            }
        }
        let password_page = asks("GET", "/admin", admin);
        assert!(
            password_page.starts_with("HTTP/1.1 200")
                && password_page.contains("type=\"password\""),
            "a signed-in admin who has not given the password: {password_page}"
        );
        let locked_out = asks("GET", "/admin/accounts", admin);
        assert!(
            locked_out.starts_with("HTTP/1.1 303") && locked_out.contains("location: /admin"),
            "{locked_out}"
        );

        // Sixty days on every session has run out, the admin's too: back to nothing.
        now.store(1_000 + 61 * 86_400, std::sync::atomic::Ordering::SeqCst);
        for method in ["GET", "POST", "HEAD"] {
            let nothing = asks(method, "/nothing-here", None);
            for path in [
                "/admin",
                "/admin/accounts",
                "/admin/devices",
                "/admin/kicks",
            ] {
                assert_eq!(
                    asks(method, path, admin),
                    nothing,
                    "{method} {path} as an admin whose session has run out"
                );
            }
        }

        let _ = stop.send(());
        server.join().unwrap();
    }

    #[test]
    fn a_font_crosses_a_real_socket_byte_for_byte_with_its_length_and_headers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                serve(listener, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            });
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(
                format!("GET {GEIST_PATH}?v=x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        let _ = stop.send(());
        server.join().unwrap();

        let split = answer
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("the end of the headers");
        let head = String::from_utf8_lossy(&answer[..split]).to_lowercase();
        let body = &answer[split + 4..];
        assert!(head.starts_with("http/1.1 200"), "{head}");
        assert!(head.contains("content-type: font/woff2"), "{head}");
        assert!(
            head.contains("cache-control: public, max-age=31536000, immutable"),
            "{head}"
        );
        assert!(
            head.contains(&format!("content-length: {}", GEIST.len())),
            "{head}"
        );
        assert!(head.contains("font-src 'self'"), "{head}");
        assert_eq!(body, GEIST, "the bytes are the file's, untouched");
    }

    #[test]
    fn the_server_answers_over_a_socket_and_every_answer_is_secured() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                serve(listener, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            });
        });
        let ask = |request: &str| {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            answer.to_lowercase()
        };

        let front = ask("GET / HTTP/1.1\r\nHost: barely-free.com\r\nConnection: close\r\n\r\n");
        let post =
            ask("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let head = ask("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let _ = stop.send(());
        server.join().unwrap();

        assert!(front.starts_with("http/1.1 200"), "{front}");
        assert!(
            front.contains("content-security-policy: default-src 'none'"),
            "{front}"
        );
        assert!(front.contains("<title>barely-free"), "{front}");
        assert!(post.starts_with("http/1.1 405"), "{post}");
        assert!(
            post.contains("allow: get, head") && post.contains("content-security-policy"),
            "{post}"
        );
        assert!(
            head.starts_with("http/1.1 200") && head.ends_with("\r\n\r\n"),
            "{head}"
        );
    }
}
