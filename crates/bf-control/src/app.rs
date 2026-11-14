//! The pages that need the database: sign in with an emailed code, sign out, and the
//! account page. Everything else on the site is a fixed page in `web.rs`.
//!
//! The rules, in short (spec: `specs/accounts-and-admin.md`):
//! - Asking for a code gets the same answer, at the same moment, whether or not an
//!   account has the address. The email is sent afterwards, in a task of its own.
//! - A request that changes something is accepted only if the browser says it came from
//!   this site (`guard.rs`), and a signed-in one also needs the session's form token.
//! - The session is a `__Host-` cookie that scripts cannot read (`cookie.rs`).
//! - Every page here has `form-action 'self'` and `no-store`. The public pages have
//!   `form-action 'self'` too, since the footer's theme buttons (`/theme`) are on them.
//! - What a person typed is never echoed back unless it is a clean address, and every
//!   value goes through the templates' escaping.

use std::io::Write;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, Response};
use bf_common::sign::{hex, unhex};

use crate::cookie::{self, Theme};
use crate::form::{self, Form};
use crate::guard;
use crate::keys::KeyPair;
use crate::mail::{MailError, Mailer, check_address};
use crate::poller::{Board, Health};
use crate::protocol::Protocol;
use crate::resend::{ApiKey, ResendClient};
use crate::secrets::{ControlKeys, KeyError, constant_time_eq, read_secret_text};
use crate::signin::{
    CODE_LIFETIME_SECS, CodeCheck, CodeRequest, MailResult, OpenLimits, SESSION_LIFETIME_SECS,
};
use crate::store::{Store, StoreError};
use crate::wgconf::{self, AmneziaParams, ClientConfig};

/// The biggest form body read. Ours are a few dozen bytes.
const MAX_BODY_BYTES: usize = 4096;

mod admin;

/// The pages a theme button may send someone back to. Anything else goes to the front page,
/// so the form cannot be used to bounce a browser to another site.
pub(crate) const THEME_BACK: [&str; 17] = [
    "/",
    "/signin",
    "/verify",
    "/account",
    "/cookies",
    "/check",
    "/status",
    "/terms",
    "/privacy",
    "/abuse",
    "/transparency",
    "/help",
    "/security",
    "/admin",
    "/admin/accounts",
    "/admin/devices",
    "/admin/kicks",
];

/// What a failed sign-in code looks like to the person, whatever the reason.
const BAD_CODE: &str = "That code did not work. Check it and try again, or ask for a new one.";

/// The sign-in side of the site: the database, the keys and the mailer.
pub struct App {
    store: Mutex<Store>,
    keys: ControlKeys,
    mailer: Arc<dyn Mailer>,
    origins: Vec<String>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Whether sign-up is open, read once from the store. Kept here because pages are built
    /// while the store is locked.
    open_signup: bool,
    /// What adding a device needs from the poller; set once the poller is running.
    devices: OnceLock<DeviceHooks>,
    /// Add-a-device forms already used, so a reload or a double click makes one device.
    used_attempts: Mutex<std::collections::VecDeque<String>>,
    /// When a server is too busy for "Closest to you"; the defaults until [`App::set_busy`].
    busy: OnceLock<crate::closest::Busy>,
    /// The nightly backup's status file (`BC_BACKUP_STATUS`), shown on the admin overview.
    backup_status: OnceLock<std::path::PathBuf>,
}

/// The poller's side of adding a device: which node is up (and its key), and a way to ask for
/// a pass now so the node has the new key before the person has scanned the code.
struct DeviceHooks {
    board: Arc<Board>,
    poke: Arc<dyn Fn() + Send + Sync>,
}

/// How many used add-a-device forms are remembered.
const ATTEMPTS_KEPT: usize = 256;

/// Must match the AmneziaWG settings on Toronto's active interface.
const AMNEZIA_PARAMS: AmneziaParams = AmneziaParams {
    jc: 4,
    jmin: 40,
    jmax: 70,
    s1: 15,
    s2: 20,
    h1: 1_000_000_001,
    h2: 1_000_000_002,
    h3: 1_000_000_003,
    h4: 1_000_000_004,
};

/// One answer, before the security headers are put on it.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

impl Reply {
    fn page(status: u16, body: String) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body,
        }
    }

    fn redirect(to: &str) -> Reply {
        Reply {
            status: 303,
            headers: vec![("location", to.to_string())],
            body: String::new(),
        }
    }

    fn with(mut self, name: &'static str, value: String) -> Reply {
        self.headers.push((name, value));
        self
    }
}

/// Why a form could not be read.
enum FormError {
    /// It did not come from this site.
    Refused,
    /// Not sent as a form.
    WrongType,
    /// Too big.
    TooBig,
    /// A form, but not a clean one (a field twice, bad escapes, not UTF-8, too many).
    Malformed,
}

#[derive(Template)]
#[template(path = "signin.html")]
struct SignInPage<'a> {
    error: Option<&'a str>,
    /// Open sign-up: anyone may make an account, so the page does not say it is closed.
    open: bool,
}

#[derive(Template)]
#[template(path = "code.html")]
struct CodePage<'a> {
    email: &'a str,
    error: Option<&'a str>,
    open: bool,
    /// The tick box was ticked when a wrong code was sent: keep it ticked.
    keep: bool,
}

#[derive(Template)]
#[template(path = "notice.html")]
struct NoticePage<'a> {
    heading: &'a str,
    message: &'a str,
    back_href: &'a str,
    back_text: &'a str,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage<'a> {
    label: &'a str,
    csrf: &'a str,
    attempt: &'a str,
    devices: Vec<DeviceRow>,
    /// The servers a new device can be made on now, in the order of the board.
    servers: Vec<ServerOption>,
    /// Whether WireGuard is the app checked on the form: only when some server can make a
    /// WireGuard device now; otherwise AmneziaWG.
    wireguard_first: bool,
    /// Both apps, for the "Get the app" links.
    apps: Vec<crate::apps::AppGroup>,
    can_add: bool,
    limit: u32,
    is_admin: bool,
}

struct DeviceRow {
    id: i64,
    name: String,
    address: String,
    added: String,
    /// Whether the server's resolver blocks trackers for it (`specs/trackers.md`).
    trackers: bool,
    /// When it last connected, and through which server ([`crate::seen`]).
    seen: String,
}

#[derive(Template)]
#[template(path = "device.html")]
struct DevicePage<'a> {
    name: &'a str,
    server: &'a str,
    /// The app it needs ("WireGuard", "AmneziaWG"), and its download links.
    app: crate::apps::AppGroup,
    /// AmneziaWG: Amnezia documents importing the file, so it comes before the QR code.
    file_first: bool,
    /// Whether the server was picked for the person ("Closest to you").
    picked: bool,
    /// The other ports the server takes this app on ("53 or 123").
    ports: &'static str,
    qr: &'a str,
    data: &'a str,
    stem: &'a str,
    config: &'a str,
    /// The ClashMi profile as link text; empty when no server could go in it.
    clashmi: &'a str,
}

fn render<T: Template>(status: u16, template: &T) -> Reply {
    match template.render() {
        Ok(body) => Reply::page(status, body),
        Err(_) => Reply::page(
            500,
            "<!doctype html><title>Barely-free</title><p>Something went wrong. Please try again.</p>\n"
                .to_string(),
        ),
    }
}

fn notice(status: u16, heading: &str, message: &str, back_href: &str, back_text: &str) -> Reply {
    render(
        status,
        &NoticePage {
            heading,
            message,
            back_href,
            back_text,
        },
    )
}

fn server_error() -> Reply {
    notice(
        500,
        "Something went wrong",
        "Please try again in a moment.",
        "/",
        "Back to the front page",
    )
}

/// Log lines carry no address, no code and no key.
fn log(message: &str) {
    let _ = writeln!(std::io::stderr(), "bf-control: {message}");
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// What the browser remembers between the page where an address is typed and the page where
/// the code is typed: the address, as hex, in a cookie that goes nowhere but back here. The
/// web address stays plain `/verify`, the address is never in a URL (history, logs, a link
/// someone could craft) and the server stores nothing.
fn pending_value(email: &str) -> String {
    hex(email.as_bytes())
}

/// The address a code was asked for, from the pending cookie, if there is a clean one.
fn pending_email(headers: &HeaderMap) -> Option<String> {
    let value = cookie::pending_from_header(header(headers, "cookie"))?;
    let email = String::from_utf8(unhex(value)?).ok()?;
    let email = email.trim().to_string();
    check_address(&email).ok().map(|()| email)
}

/// The answer to a code request that was taken: on to `/verify`, remembering the address.
/// What a new address is told when open sign-up has used up the day's room.
fn sign_ups_full() -> Reply {
    notice(
        503,
        "Sign-ups are full for today",
        "We take a limited number of new accounts a day, and today's are used up. Please try again tomorrow. People who already have an account are not affected.",
        "/",
        "Back to the front page",
    )
}

fn to_verify_page(email: &str) -> Reply {
    Reply::redirect("/verify").with(
        "set-cookie",
        cookie::set_pending(&pending_value(email), CODE_LIFETIME_SECS),
    )
}

impl App {
    /// `origins` are the addresses this site is reached at (`https://barely-free.com`):
    /// a form is accepted only from one of them. `clock` gives Unix seconds.
    pub fn new(
        store: Store,
        keys: ControlKeys,
        mailer: Arc<dyn Mailer>,
        origins: Vec<String>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Arc<App> {
        Arc::new(App {
            open_signup: store.open_limits().is_some(),
            store: Mutex::new(store),
            keys,
            mailer,
            origins,
            clock,
            devices: OnceLock::new(),
            used_attempts: Mutex::default(),
            busy: OnceLock::new(),
            backup_status: OnceLock::new(),
        })
    }

    /// Sets when a server counts as busy (`BC_NODE_BUSY_ONLINE`, `BC_NODE_BUSY_LOAD`). Only
    /// the first call counts.
    pub fn set_busy(&self, busy: crate::closest::Busy) {
        let _ = self.busy.set(busy);
    }

    /// Sets where the nightly backup writes its status (`BC_BACKUP_STATUS`). Only the first
    /// call counts.
    pub fn set_backup_status(&self, path: std::path::PathBuf) {
        let _ = self.backup_status.set(path);
    }

    fn busy(&self) -> crate::closest::Busy {
        self.busy.get().copied().unwrap_or_default()
    }

    /// Connects the poller: from now on a person can add a device, and it is put on the nodes
    /// without waiting for the next pass. Only the first call counts.
    pub fn connect_poller(&self, board: Arc<Board>, poke: Arc<dyn Fn() + Send + Sync>) {
        let _ = self.devices.set(DeviceHooks { board, poke });
    }

    /// Whether this app answers `path` (any method; a wrong method gets a 405).
    pub fn handles(path: &str) -> bool {
        matches!(
            path,
            "/signin"
                | "/verify"
                | "/signout"
                | "/account"
                | "/account/devices"
                | "/account/devices/remove"
                | "/account/devices/trackers"
                | "/account/delete"
                | "/theme"
        )
    }

    /// Answers one request.
    pub async fn handle(self: &Arc<App>, request: Request) -> Response<Body> {
        let theme = cookie::theme_from_header(header(request.headers(), "cookie"));
        let mut reply = self.route(request).await;
        // Pages differ by cookie: who is signed in, and the theme they are drawn in.
        reply.headers.push(("vary", "Cookie".to_string()));
        let body = crate::web::themed(reply.body, theme);
        crate::web::secured_app(reply.status, &reply.headers, body)
    }

    /// Whether anyone may make an account by typing a sign-in code (the `BC_OPEN_SIGNUP`
    /// setting), as opposed to the closed beta where an admin makes every account.
    pub fn signup_open(&self) -> bool {
        self.open_signup
    }

    /// Whether these request headers carry the cookie of a live session (for the front page's
    /// "Your account" link). A database failure counts as not signed in.
    pub fn signed_in(&self, headers: &HeaderMap) -> bool {
        let Some(cookie_value) = cookie::session_from_header(header(headers, "cookie")) else {
            return false;
        };
        matches!(self.store().session(cookie_value, self.now()), Ok(Some(_)))
    }

    fn sign_in_page(&self, status: u16, error: Option<&str>) -> Reply {
        let open = self.signup_open();
        render(status, &SignInPage { error, open })
    }

    fn code_page(&self, status: u16, email: &str, error: Option<&str>) -> Reply {
        self.code_page_ticked(status, email, error, false)
    }

    fn code_page_ticked(&self, status: u16, email: &str, error: Option<&str>, keep: bool) -> Reply {
        let open = self.signup_open();
        render(
            status,
            &CodePage {
                email,
                error,
                open,
                keep,
            },
        )
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        // A panic while the lock was held leaves the data fine: the database is SQLite's.
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Answers one request, then renews a kept session the request carried (see
    /// [`Store::renew_session`]): the answer then sends the cookie again for the time left.
    async fn route(self: &Arc<App>, request: Request) -> Reply {
        let session_cookie =
            cookie::session_from_header(header(request.headers(), "cookie")).map(str::to_string);
        let uses_session = App::uses_session(request.uri().path());
        let reply = self.route_only(request).await;
        // Only a signed-in page that answered counts as using the session: not the sign-in
        // pages, the theme buttons, a wrong method or a refused form.
        let Some(session_cookie) = session_cookie.filter(|_| uses_session && reply.status < 400)
        else {
            return reply;
        };
        // After the answer: a sign-out has ended the session by now, and a sign-in has
        // ended the old one, so neither is renewed.
        let now = self.now();
        match self.store().renew_session(&session_cookie, now) {
            Ok(Some(until)) => with_renewed_session(
                reply,
                &cookie::set_session(&session_cookie, until.saturating_sub(now)),
            ),
            Ok(None) => reply,
            Err(e) => {
                log(&format!("session: could not renew: {e}"));
                reply
            }
        }
    }

    /// The pages that only a signed-in person can use: the account pages and the admin pages.
    fn uses_session(path: &str) -> bool {
        path == "/account" || path.starts_with("/account/") || App::is_admin_path(path)
    }

    async fn route_only(self: &Arc<App>, request: Request) -> Reply {
        let method = request.method().as_str().to_string();
        let path = request.uri().path().to_string();
        match (path.as_str(), method.as_str()) {
            ("/signin", "GET" | "HEAD") => self.sign_in_page(200, None),
            ("/signin", "POST") => self.post_sign_in(request).await,
            ("/verify", "GET" | "HEAD") => match pending_email(request.headers()) {
                Some(email) => self.code_page(200, &email, None),
                None => Reply::redirect("/signin"),
            },
            ("/verify", "POST") => self.post_code(request).await,
            ("/signout", "POST") => self.post_sign_out(request).await,
            ("/account", "GET" | "HEAD") => self.get_account(request.headers()),
            ("/account/devices", "POST") => self.post_add_device(request).await,
            ("/account/devices/remove", "POST") => self.post_remove_device(request).await,
            ("/account/devices/trackers", "POST") => self.post_device_trackers(request).await,
            ("/account/delete", "POST") => self.post_delete_account(request).await,
            (
                "/account/devices"
                | "/account/devices/remove"
                | "/account/devices/trackers"
                | "/account/delete",
                _,
            ) => method_not_allowed("POST"),
            ("/theme", "POST") => self.post_theme(request).await,
            ("/theme", _) => method_not_allowed("POST"),
            ("/admin", "GET" | "HEAD") => self.get_admin(request.headers()),
            ("/admin/accounts", "GET" | "HEAD") => self.get_admin_accounts(request.headers()),
            ("/admin/account", "GET" | "HEAD") => {
                self.get_admin_account(request.headers(), request.uri().query())
            }
            ("/admin/accounts/delete", "POST") => self.post_admin_account_delete(request).await,
            ("/admin/devices", "GET" | "HEAD") => self.get_admin_devices(request.headers()),
            ("/admin/kicks", "GET" | "HEAD") => {
                self.get_admin_kicks(request.headers(), request.uri().query())
            }
            ("/admin/unlock", "POST") => self.post_admin_unlock(request).await,
            ("/admin/lock", "POST") => self.post_admin_lock(request).await,
            ("/admin/accounts", "POST") => self.post_admin_accounts(request).await,
            ("/admin/devices/remove", "POST") => self.post_admin_device_remove(request).await,
            ("/admin/kicks", "POST") => self.post_admin_kick(request).await,
            ("/admin/kicks/lift", "POST") => self.post_admin_kick_lift(request).await,
            (
                "/admin/unlock"
                | "/admin/lock"
                | "/admin/devices/remove"
                | "/admin/kicks/lift"
                | "/admin/accounts/delete",
                _,
            ) => method_not_allowed("POST"),
            ("/admin" | "/admin/devices" | "/admin/account", _) => method_not_allowed("GET, HEAD"),
            ("/admin/accounts" | "/admin/kicks", _) => method_not_allowed("GET, HEAD, POST"),
            ("/signin" | "/verify", _) => method_not_allowed("GET, HEAD, POST"),
            ("/signout", _) => method_not_allowed("POST"),
            _ => method_not_allowed("GET, HEAD"),
        }
    }

    /// Checks that a form came from this site and reads it.
    async fn read_form(&self, request: Request) -> Result<Form, FormError> {
        let (parts, body) = request.into_parts();
        let came_from_here = guard::same_origin(
            header(&parts.headers, "sec-fetch-site"),
            header(&parts.headers, "origin"),
            &self.origins,
        );
        if !came_from_here {
            return Err(FormError::Refused);
        }
        let is_form = header(&parts.headers, "content-type")
            .and_then(|value| value.split(';').next())
            .is_some_and(|kind| {
                kind.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
        if !is_form {
            return Err(FormError::WrongType);
        }
        let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| FormError::TooBig)?;
        form::parse(&bytes).ok_or(FormError::Malformed)
    }

    /// The answer for a form that could not be read, when the page has no better one.
    fn form_problem(error: &FormError) -> Option<Reply> {
        match error {
            FormError::Refused => Some(notice(
                403,
                "Request refused",
                "That request did not come from this site, so nothing was done.",
                "/",
                "Back to the front page",
            )),
            FormError::WrongType => Some(notice(
                415,
                "Request not understood",
                "Forms on this site are sent as ordinary web forms.",
                "/",
                "Back to the front page",
            )),
            FormError::TooBig => Some(notice(
                413,
                "Request too large",
                "That was far more than a form needs.",
                "/",
                "Back to the front page",
            )),
            FormError::Malformed => None,
        }
    }

    async fn post_sign_in(self: &Arc<App>, request: Request) -> Reply {
        let ip_text = header(request.headers(), "cf-connecting-ip")
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_string());
        let form = match self.read_form(request).await {
            Ok(form) => form,
            Err(error) => {
                return App::form_problem(&error).unwrap_or_else(|| {
                    self.sign_in_page(400, Some("Please type your email address."))
                });
            }
        };
        let email = form.get("email").unwrap_or("").trim().to_string();
        if check_address(&email).is_err() {
            return self.sign_in_page(400, Some("That does not look like an email address."));
        }
        let email_fp = self.keys.email_fingerprint(&email);
        let ip_fp = ip_text.map(|ip| self.keys.ip_fingerprint(&ip));

        let outcome = self
            .store()
            .request_code(&self.keys, &email_fp, ip_fp.as_ref(), self.now());
        match outcome {
            Ok(CodeRequest::Send { code_id, code }) => {
                self.send_in_background(email.clone(), email_fp, code_id, code);
                to_verify_page(&email)
            }
            // The page for an address nobody has is the same page.
            Ok(CodeRequest::Nothing) => to_verify_page(&email),
            Ok(CodeRequest::Limited) => notice(
                429,
                "Too many requests",
                "Too many sign-in codes have been asked for just now. Please wait an hour and try again.",
                "/signin",
                "Back to sign in",
            ),
            Ok(CodeRequest::Paused) => notice(
                503,
                "Sign-in emails are paused",
                "Sign-in emails are paused for today, because the day's mail is used up. Please try again tomorrow. People who are already signed in are not affected.",
                "/",
                "Back to the front page",
            ),
            Ok(CodeRequest::Full) => {
                log("sign-up: today's room for new accounts is used up");
                sign_ups_full()
            }
            Err(e) => {
                log(&format!("sign-in: the database failed: {e}"));
                server_error()
            }
        }
    }

    /// Mails the code after the answer has gone, so the answer's timing says nothing about
    /// whether there was a mail to send, and writes down how it went.
    fn send_in_background(
        self: &Arc<App>,
        to: String,
        email_fp: [u8; 32],
        code_id: i64,
        code: String,
    ) {
        let app = Arc::clone(self);
        tokio::spawn(async move {
            let key = format!("signin/{code_id}");
            let result = match app.mailer.send_code(&to, &code, &key).await {
                Ok(_) => MailResult::Sent,
                Err(MailError::QuotaExhausted) => {
                    log(
                        "mail: Resend says its sending quota is used up; sign-in mail is paused until midnight UTC",
                    );
                    MailResult::QuotaExhausted
                }
                Err(e) => {
                    log(&format!("mail: a sign-in email could not be sent: {e}"));
                    MailResult::Failed
                }
            };
            let now = app.now();
            if let Err(e) = app.store().record_mail_result(&email_fp, result, now) {
                log(&format!("mail: could not write down the result: {e}"));
            }
        });
    }

    async fn post_code(self: &Arc<App>, request: Request) -> Reply {
        let old_cookie =
            cookie::session_from_header(header(request.headers(), "cookie")).map(str::to_string);
        let pending = pending_email(request.headers());
        let form = match self.read_form(request).await {
            Ok(form) => form,
            Err(error) => {
                return App::form_problem(&error).unwrap_or_else(|| match &pending {
                    Some(email) => self.code_page(400, email, Some(BAD_CODE)),
                    None => Reply::redirect("/signin"),
                });
            }
        };
        // Which address is the cookie's business, never the form's.
        let Some(email) = pending else {
            return Reply::redirect("/signin");
        };
        let code = form.get("code").unwrap_or("").trim().to_string();
        // The tick box sends exactly `1`; anything else, or nothing, is not a tick.
        let keep = form.get("keep") == Some("1");
        let email_fp = self.keys.email_fingerprint(&email);

        let mut store = self.store();
        let checked = store.verify_code(&self.keys, &email_fp, &code, self.now());
        let account_id = match checked {
            Ok(CodeCheck::Verified { account_id }) => account_id,
            Ok(CodeCheck::Created { account_id }) => {
                log("sign-up: a new account was made");
                account_id
            }
            Ok(CodeCheck::Bad) => {
                return self.code_page_ticked(400, &email, Some(BAD_CODE), keep);
            }
            Ok(CodeCheck::Full) => {
                log("sign-up: today's room for new accounts is used up");
                return sign_ups_full();
            }
            Err(e) => {
                log(&format!("sign-in: the database failed: {e}"));
                return server_error();
            }
        };
        // A browser that already held a session gets a new one: the old id is ended.
        if let Some(old) = old_cookie
            && let Err(e) = store.end_session(&old)
        {
            log(&format!("sign-in: could not end the old session: {e}"));
        }
        match store.create_session_keeping(account_id, keep, self.now()) {
            Ok(session) => Reply::redirect("/account")
                .with(
                    "set-cookie",
                    cookie::set_session(&session.cookie, SESSION_LIFETIME_SECS),
                )
                // The address was only needed to check the code.
                .with("set-cookie", cookie::clear_pending()),
            Err(e) => {
                log(&format!("sign-in: could not start a session: {e}"));
                server_error()
            }
        }
    }

    /// The footer's theme buttons: keep the choice in a cookie (or forget it, for "System")
    /// and go back to the page they were pressed on. No session token: it changes nothing
    /// but how pages look, and the same-origin check keeps other sites from pressing them.
    async fn post_theme(&self, request: Request) -> Reply {
        let form = match self.read_form(request).await {
            Ok(form) => form,
            Err(FormError::Malformed) => return Reply::redirect("/"),
            Err(error) => return App::form_problem(&error).unwrap_or_else(server_error),
        };
        let back = form
            .get("back")
            .filter(|back| THEME_BACK.contains(back))
            .unwrap_or("/");
        let reply = Reply::redirect(back);
        match form.get("theme") {
            Some("light") => reply.with("set-cookie", cookie::set_theme(Theme::Light)),
            Some("dark") => reply.with("set-cookie", cookie::set_theme(Theme::Dark)),
            Some("system") => reply.with("set-cookie", cookie::clear_theme()),
            _ => reply,
        }
    }

    async fn post_sign_out(self: &Arc<App>, request: Request) -> Reply {
        let cookie_value =
            cookie::session_from_header(header(request.headers(), "cookie")).map(str::to_string);
        let form = match self.read_form(request).await {
            Ok(form) => form,
            Err(FormError::Malformed) => {
                return App::form_problem(&FormError::Refused).unwrap_or_else(server_error);
            }
            Err(error) => return App::form_problem(&error).unwrap_or_else(server_error),
        };
        let Some(cookie_value) = cookie_value else {
            return Reply::redirect("/signin");
        };
        let mut store = self.store();
        let session = match store.session(&cookie_value, self.now()) {
            Ok(Some(session)) => session,
            Ok(None) => return Reply::redirect("/signin"),
            Err(e) => {
                log(&format!("sign-out: the database failed: {e}"));
                return server_error();
            }
        };
        let sent = form.get("csrf").unwrap_or("");
        if !constant_time_eq(sent.as_bytes(), session.csrf.as_bytes()) {
            return App::form_problem(&FormError::Refused).unwrap_or_else(server_error);
        }
        // Say so if the session could not be ended: clearing the cookie alone would leave it
        // valid for anyone who has a copy.
        if let Err(e) = store.end_session(&cookie_value) {
            log(&format!("sign-out: could not end the session: {e}"));
            return server_error();
        }
        Reply::redirect("/").with("set-cookie", cookie::clear_session())
    }

    fn get_account(&self, headers: &HeaderMap) -> Reply {
        let Some(cookie_value) = cookie::session_from_header(header(headers, "cookie")) else {
            return Reply::redirect("/signin");
        };
        let store = self.store();
        let session = match store.session(cookie_value, self.now()) {
            Ok(Some(session)) => session,
            Ok(None) => return Reply::redirect("/signin"),
            Err(e) => {
                log(&format!("account: the database failed: {e}"));
                return server_error();
            }
        };
        let account = match store.account(session.account_id) {
            Ok(Some(account)) => account,
            Ok(None) => return Reply::redirect("/signin"),
            Err(e) => {
                log(&format!("account: the database failed: {e}"));
                return server_error();
            }
        };
        let devices = match store.devices_of(account.id) {
            Ok(devices) => devices,
            Err(e) => {
                log(&format!("account: the database failed: {e}"));
                return server_error();
            }
        };
        let can_add = u32::try_from(devices.len()).unwrap_or(u32::MAX) < account.device_limit;
        let now = self.now();
        let readings = self.devices.get().map(|hooks| hooks.board.snapshot(now));
        let attempt = random_attempt();
        let servers = self.server_options();
        let wireguard_first = servers
            .iter()
            .any(|server| server.protocols.contains(&Protocol::WireGuard));
        render(
            200,
            &AccountPage {
                label: &account.label,
                csrf: &session.csrf,
                attempt: &attempt,
                devices: devices
                    .iter()
                    .map(|d| DeviceRow {
                        id: d.id,
                        name: d.name.clone(),
                        address: d.address.to_string(),
                        added: ymd(d.created_at),
                        trackers: d.tracker_filter,
                        seen: crate::seen::describe(&crate::seen::seen(
                            readings.as_ref(),
                            &d.public_key,
                            now,
                        )),
                    })
                    .collect(),
                servers,
                wireguard_first,
                apps: crate::apps::for_account(),
                can_add,
                limit: account.device_limit,
                is_admin: store.is_admin(account.id).unwrap_or(false),
            },
        )
    }

    /// The servers with at least one agent that is online, has a reading and has a protocol,
    /// in the order they first appear. A server is its title (the form sends only that):
    /// agents with one title are one server, shown with the first one's place.
    fn server_options(&self) -> Vec<ServerOption> {
        let Some(hooks) = self.devices.get() else {
            return Vec::new();
        };
        let mut options: Vec<ServerOption> = Vec::new();
        for node in hooks.board.snapshot(self.now()).nodes {
            let Some(protocol) = node.protocol else {
                continue;
            };
            if node.health != Health::Online || node.reading.is_none() {
                continue;
            }
            match options.iter_mut().find(|option| option.title == node.title) {
                Some(option) if !option.protocols.contains(&protocol) => {
                    option.protocols.push(protocol);
                }
                Some(_) => {}
                None => options.push(ServerOption {
                    title: node.title,
                    place: node.place,
                    protocols: vec![protocol],
                }),
            }
        }
        options
    }

    /// The agent a new device of `protocol` on the server called `title` would use: online,
    /// with a reading, and that protocol.
    fn server_for_new_device(&self, title: &str, protocol: Protocol) -> Option<ServerChoice> {
        let hooks = self.devices.get()?;
        let snapshot = hooks.board.snapshot(self.now());
        snapshot
            .nodes
            .iter()
            .filter(|node| node.title == title)
            .find_map(|node| choice_of(node, protocol))
    }

    /// "Closest to you": the server [`crate::closest::pick`] chooses among those with an
    /// agent of `protocol` that could take the device now, from where the person is (`from`,
    /// used for this choice only). A server's devices online and load count all its agents.
    fn closest_server(
        &self,
        protocol: Protocol,
        from: Option<crate::closest::Location>,
    ) -> Option<ServerChoice> {
        let hooks = self.devices.get()?;
        let nodes = hooks.board.snapshot(self.now()).nodes;
        let mut servers: Vec<(&str, Option<ServerChoice>, crate::closest::Candidate)> = Vec::new();
        for node in &nodes {
            let at = match servers.iter().position(|(title, ..)| *title == node.title) {
                Some(at) => at,
                None => {
                    servers.push((
                        node.title.as_str(),
                        None,
                        crate::closest::Candidate {
                            location: None,
                            online: 0,
                            load: None,
                        },
                    ));
                    servers.len() - 1
                }
            };
            let (_, choice, server) = &mut servers[at];
            if let Some(reading) = &node.reading {
                server.add_reading(reading.online, reading.load1);
            }
            server.location = server.location.or(node.location);
            if choice.is_none() {
                *choice = choice_of(node, protocol);
            }
        }
        servers.retain(|(_, choice, _)| choice.is_some());
        let candidates: Vec<_> = servers.iter().map(|(.., server)| server.clone()).collect();
        let chosen = crate::closest::pick(&candidates, from, &self.busy())?;
        let mut choice = servers.swap_remove(chosen).1?;
        choice.picked = true;
        Some(choice)
    }

    /// Reads a signed-in form: the session, and the form's own token checked against it.
    async fn signed_in_form(
        self: &Arc<App>,
        request: Request,
        what: &str,
    ) -> Result<(crate::signin::SessionInfo, Form, String), Reply> {
        let cookie_value =
            cookie::session_from_header(header(request.headers(), "cookie")).map(str::to_string);
        let form = match self.read_form(request).await {
            Ok(form) => form,
            Err(FormError::Malformed) => {
                return Err(App::form_problem(&FormError::Refused).unwrap_or_else(server_error));
            }
            Err(error) => return Err(App::form_problem(&error).unwrap_or_else(server_error)),
        };
        let Some(cookie_value) = cookie_value else {
            return Err(Reply::redirect("/signin"));
        };
        let session = match self.store().session(&cookie_value, self.now()) {
            Ok(Some(session)) => session,
            Ok(None) => return Err(Reply::redirect("/signin")),
            Err(e) => {
                log(&format!("{what}: the database failed: {e}"));
                return Err(server_error());
            }
        };
        let sent = form.get("csrf").unwrap_or("");
        if !constant_time_eq(sent.as_bytes(), session.csrf.as_bytes()) {
            return Err(App::form_problem(&FormError::Refused).unwrap_or_else(server_error));
        }
        Ok((session, form, cookie_value))
    }

    async fn post_add_device(self: &Arc<App>, request: Request) -> Reply {
        // Where the person is, for "Closest to you": used for this one choice, in memory,
        // and never stored or written to the log.
        let from = crate::closest::from_headers(request.headers());
        let (session, form, _) = match self.signed_in_form(request, "add device").await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let back = |status, heading: &str, message: &str| {
            notice(status, heading, message, "/account", "Back to your account")
        };
        let Some(hooks) = self.devices.get() else {
            return back(
                503,
                "Not available yet",
                "Adding devices is not switched on yet. Please try again later.",
            );
        };
        let attempt = form.get("attempt").unwrap_or("");
        if attempt.len() != 32 || !attempt.bytes().all(|b| b.is_ascii_hexdigit()) {
            return App::form_problem(&FormError::Refused).unwrap_or_else(server_error);
        }
        let protocol = form.get("protocol").and_then(Protocol::parse);
        let title = form.get("server").map(str::trim).unwrap_or("");
        let Some(protocol) = protocol.filter(|_| !title.is_empty()) else {
            return back(
                400,
                "Choose a server and an app",
                "Pick a server and WireGuard or AmneziaWG, then try again. Nothing was made.",
            );
        };
        let server = if title == CLOSEST {
            self.closest_server(protocol, from)
        } else {
            self.server_for_new_device(title, protocol)
        };
        let Some(server) = server else {
            return back(
                503,
                "That server cannot take a device right now",
                "A device made now could not connect, so none was made. Try the other app or server, or again in a minute.",
            );
        };
        if !self.use_attempt(attempt) {
            return back(
                409,
                "That device was already made",
                "The setup is shown only once, when the device is made, so it cannot be shown again. If you did not save it, remove the device and add it again.",
            );
        }
        let name = form.get("name").unwrap_or("");
        let pair = match KeyPair::generate() {
            Ok(pair) => pair,
            Err(e) => {
                log(&format!("add device: no random key: {e}"));
                return server_error();
            }
        };
        let mut config = None;
        let mut address = None;
        let added = self.store().add_device_with(
            session.account_id,
            name,
            &pair.public_key,
            self.now(),
            |device| {
                let private_key = pair.private_key();
                address = Some(device.address);
                let setup = |address| ClientConfig {
                    private_key: &private_key,
                    address,
                    server_public_key: &server.public_key,
                    endpoint_ip: server.ip,
                    endpoint_port: server.port,
                };
                config = Some(match protocol {
                    Protocol::WireGuard => {
                        setup(crate::protocol::wireguard_address(device.address)).render()
                    }
                    Protocol::AmneziaWg => setup(device.address)
                        .render_amnezia(AMNEZIA_PARAMS)
                        .expect("the built-in AmneziaWG parameters are valid"),
                });
                Ok(())
            },
        );
        match added {
            Ok(_) => {}
            Err(StoreError::BadName) => {
                return back(
                    400,
                    "That name does not work",
                    "A device name is 1 to 64 characters with no control characters.",
                );
            }
            Err(StoreError::DeviceLimit(limit)) => {
                return back(
                    409,
                    "Device limit reached",
                    &format!(
                        "An account holds at most {limit} devices. Remove one to add another."
                    ),
                );
            }
            Err(StoreError::Kicked) => {
                return back(
                    403,
                    "A device is switched off",
                    "One of your devices has been switched off by the admin, so no device can be added until it is switched back on.",
                );
            }
            Err(StoreError::PoolFull) => {
                return back(
                    503,
                    "No addresses left",
                    "Every address on the servers is taken. Please try again later.",
                );
            }
            Err(e) => {
                log(&format!("add device: {e}"));
                return server_error();
            }
        }
        let Some(config) = config else {
            return server_error();
        };
        (hooks.poke)();
        let Ok(qr) = wgconf::qr_svg(&config) else {
            return server_error();
        };
        // The ClashMi profile, the recommended setup (decision 019): made now from the same
        // key and the board, carried in the page like the file, never kept.
        let clashmi = match address {
            Some(address) => {
                let private_key = pair.private_key();
                let snapshot = hooks.board.snapshot(self.now());
                crate::clashmi::profile(
                    &crate::clashmi::Device {
                        name,
                        private_key: &private_key,
                        address,
                    },
                    &crate::clashmi::entries(&snapshot, &server.title),
                    AMNEZIA_PARAMS,
                    false,
                )
                .map(|yaml| wgconf::data_url_text(&yaml))
                .unwrap_or_default()
            }
            _ => String::new(),
        };
        render(
            200,
            &DevicePage {
                name,
                server: &server.title,
                app: crate::apps::app_for(protocol),
                file_first: protocol == Protocol::AmneziaWg,
                picked: server.picked,
                ports: protocol.backup_ports(),
                qr: &qr,
                data: &wgconf::data_url_text(&config),
                stem: &wgconf::file_stem(name),
                config: &config,
                clashmi: &clashmi,
            },
        )
    }

    /// Deletes the signed-in person's own account when they type "delete" (`confirm`). An
    /// admin cannot, here. Its devices leave the servers on the next pass, asked for now, and
    /// the session cookie is cleared (the session itself went with the account).
    async fn post_delete_account(self: &Arc<App>, request: Request) -> Reply {
        let (session, form, _) = match self.signed_in_form(request, "delete account").await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let back = |status, heading: &str, message: &str| {
            notice(status, heading, message, "/account", "Back to your account")
        };
        match self.store().is_admin(session.account_id) {
            Ok(false) => {}
            Ok(true) => {
                return back(
                    403,
                    "An admin account stays",
                    "An admin account cannot be deleted from the account page. Nothing was deleted.",
                );
            }
            Err(e) => {
                log(&format!("delete account: the database failed: {e}"));
                return server_error();
            }
        }
        let typed = form.get("confirm").unwrap_or("").trim().to_lowercase();
        if typed != "delete" {
            return back(
                400,
                "Type delete to confirm",
                "To delete your account, type the word delete in the box. Nothing was deleted.",
            );
        }
        match self.store().delete_account(session.account_id) {
            Ok(gone) => log(&format!(
                "account {} deleted itself and its {} devices",
                session.account_id, gone.devices
            )),
            Err(e) => {
                log(&format!("delete account: {e}"));
                return server_error();
            }
        }
        if let Some(hooks) = self.devices.get() {
            (hooks.poke)();
        }
        notice(
            200,
            "Your account is deleted",
            "Your account, its sign-in address and its devices are gone, and the devices are taken off the servers within seconds. The nightly encrypted backups still hold it for up to 30 days, then it is gone from them too.",
            "/",
            "Back to the front page",
        )
        .with("set-cookie", cookie::clear_session())
    }

    async fn post_remove_device(self: &Arc<App>, request: Request) -> Reply {
        let (session, form, _) = match self.signed_in_form(request, "remove device").await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let id = form.get("device").and_then(|text| text.parse::<i64>().ok());
        let removed = match id {
            Some(id) => self
                .store()
                .remove_own_device(session.account_id, id, self.now()),
            None => Err(StoreError::NoSuchDevice),
        };
        match removed {
            Ok(_) => {}
            Err(StoreError::NoSuchDevice) => {
                return notice(
                    404,
                    "No such device",
                    "That device is not on your account.",
                    "/account",
                    "Back to your account",
                );
            }
            Err(StoreError::Kicked) => {
                return notice(
                    403,
                    "This device is switched off",
                    "This device has been switched off by the admin, so it cannot be removed until it is switched back on.",
                    "/account",
                    "Back to your account",
                );
            }
            Err(e) => {
                log(&format!("remove device: {e}"));
                return server_error();
            }
        }
        if let Some(hooks) = self.devices.get() {
            (hooks.poke)();
        }
        Reply::redirect("/account")
    }

    /// Turns tracker blocking on (`on=1`) or off (`on=0`) for one of the account's own
    /// devices. It does not poke the poller: its next pass (every 10 s by default) carries
    /// the change. A poke per press would let anyone signed in drive a pass a second, and
    /// every pass moves each node's signing time ahead of the clock (`Link::next_time`).
    async fn post_device_trackers(self: &Arc<App>, request: Request) -> Reply {
        let (session, form, _) = match self.signed_in_form(request, "device trackers").await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let on = match form.get("on") {
            Some("1") => true,
            Some("0") => false,
            _ => return App::form_problem(&FormError::Refused).unwrap_or_else(server_error),
        };
        let switched = match form.get("device").and_then(|text| text.parse::<i64>().ok()) {
            Some(id) => self.store().set_tracker_filter(session.account_id, id, on),
            None => Err(StoreError::NoSuchDevice),
        };
        match switched {
            Ok(_) => {}
            Err(StoreError::NoSuchDevice) => {
                return notice(
                    404,
                    "No such device",
                    "That device is not on your account.",
                    "/account",
                    "Back to your account",
                );
            }
            Err(e) => {
                log(&format!("device trackers: {e}"));
                return server_error();
            }
        }
        Reply::redirect("/account")
    }

    /// Marks an add-a-device form as used. False if it was already.
    fn use_attempt(&self, attempt: &str) -> bool {
        let mut used = self.used_attempts.lock().unwrap_or_else(|e| e.into_inner());
        if used.iter().any(|seen| seen == attempt) {
            return false;
        }
        used.push_back(attempt.to_string());
        while used.len() > ATTEMPTS_KEPT {
            used.pop_front();
        }
        true
    }
}

/// The add form's value for "Closest to you". A server titled exactly this could only be
/// reached through it, not by name.
const CLOSEST: &str = "auto";

/// A server on the add form.
struct ServerOption {
    title: String,
    place: String,
    /// What its agents that can take a device now speak.
    protocols: Vec<Protocol>,
}

impl ServerOption {
    /// Said beside it when only one of its apps can take a device ("WireGuard only right
    /// now"), or empty.
    fn note(&self) -> String {
        match self.protocols.as_slice() {
            [only] => format!("{} only right now", only.title()),
            _ => String::new(),
        }
    }
}

/// What a new device's file needs from a node.
struct ServerChoice {
    /// "Toronto, Canada".
    title: String,
    ip: std::net::IpAddr,
    port: u16,
    public_key: String,
    /// Chosen by "Closest to you", not by name.
    picked: bool,
}

/// What a device of `protocol` made on `node` would use, if that agent can take one now:
/// it speaks `protocol`, is online and has a reading.
fn choice_of(node: &crate::poller::NodeView, protocol: Protocol) -> Option<ServerChoice> {
    if node.protocol != Some(protocol) || node.health != Health::Online {
        return None;
    }
    let reading = node.reading.as_ref()?;
    Some(ServerChoice {
        title: format!("{}, {}", node.title, node.place),
        ip: node.ip,
        port: reading.listen_port,
        public_key: reading.wg_public_key.clone(),
        picked: false,
    })
}

/// A fresh form id: 128 random bits as hex.
fn random_attempt() -> String {
    crate::secrets::random_bytes::<16>()
        .map(|bytes| bf_common::sign::hex(&bytes))
        .unwrap_or_else(|_| "0".repeat(32))
}

/// A date and time for a page: `2026-11-12 03:41`, in UTC.
pub(crate) fn utc_minute(secs: u64) -> String {
    let minutes = secs / 60;
    format!(
        "{} {:02}:{:02}",
        ymd(secs),
        (minutes / 60) % 24,
        minutes % 60
    )
}

/// A date for a page: `2026-11-10`, in UTC.
fn ymd(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Adds the renewed session cookie to an answer, unless the answer already sets the session
/// cookie itself (signing in sets a new one, signing out clears it): that one wins.
fn with_renewed_session(reply: Reply, renewed: &str) -> Reply {
    let sets_session = reply.headers.iter().any(|(name, value)| {
        *name == "set-cookie" && value.starts_with(&format!("{}=", cookie::SESSION_COOKIE))
    });
    if sets_session {
        reply
    } else {
        reply.with("set-cookie", renewed.to_string())
    }
}

fn method_not_allowed(allow: &str) -> Reply {
    Reply::page(405, "Method not allowed\n".to_string()).with("allow", allow.to_string())
}

/// What the sign-in side needs to start. Every field is checked by [`build`].
#[derive(Debug, Clone)]
pub struct AppSettings {
    /// The database.
    pub db: std::path::PathBuf,
    /// The control key file (read, never created).
    pub key_file: std::path::PathBuf,
    /// The file holding the Resend key.
    pub resend_key_file: std::path::PathBuf,
    /// Where Resend is (HTTPS, or plain HTTP on this computer only).
    pub resend_url: String,
    /// Who mail comes from.
    pub mail_from: String,
    /// The addresses this site is reached at, as a browser writes them in `Origin`.
    pub origins: Vec<String>,
    /// Whether anyone may make an account by typing a sign-in code (`BC_OPEN_SIGNUP=1`).
    pub open_signup: bool,
    /// When a server is too busy for "Closest to you" (`BC_NODE_BUSY_ONLINE`,
    /// `BC_NODE_BUSY_LOAD`; [`crate::closest::busy_online`], [`crate::closest::busy_load`]).
    pub busy: crate::closest::Busy,
    /// Where the nightly backup writes its status (`BC_BACKUP_STATUS`).
    pub backup_status: std::path::PathBuf,
}

/// Reads `BC_OPEN_SIGNUP`: unset or `0` is the closed beta, `1` is open sign-up. Anything else
/// is refused, never guessed, because a typo must not open or close the doors by accident.
pub fn check_open_signup(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!(
            "BC_OPEN_SIGNUP must be 0 or 1 (or not set), not {other:?}"
        )),
    }
}

/// An address as a browser writes it in an `Origin` header, or why it is not one.
///
/// A browser writes `https://barely-free.com`, never with a trailing slash, a path, a
/// default port, capital letters or a user name, so an entry that is not exactly that
/// could never match and is refused at start instead of failing quietly later. Plain
/// HTTP is for this computer only.
pub fn check_origin(origin: &str) -> Result<String, String> {
    let typed = origin.trim();
    let not_an_origin = || {
        format!(
            "{typed:?} is not an address a browser sends as an origin (write it like https://barely-free.com, with no slash, path, default port, capitals or user name)"
        )
    };
    let url = reqwest::Url::parse(typed).map_err(|_| not_an_origin())?;
    if url.origin().ascii_serialization() != typed {
        return Err(not_an_origin());
    }
    match url.scheme() {
        "https" => Ok(typed.to_string()),
        "http" if crate::resend::url_is_on_this_computer(&url) => Ok(typed.to_string()),
        "http" => Err(format!(
            "{typed:?} is plain http, which is allowed only for this computer; use https"
        )),
        _ => Err(not_an_origin()),
    }
}

/// Starts the sign-in side, or says why it cannot. Nothing is created: no key file, and
/// no database unless every other setting is already good.
pub fn build(settings: &AppSettings) -> Result<Arc<App>, String> {
    if settings.origins.is_empty() {
        return Err("BC_ORIGINS must name at least one address".to_string());
    }
    let origins = settings
        .origins
        .iter()
        .map(|origin| check_origin(origin))
        .collect::<Result<Vec<String>, String>>()?;

    let keys = ControlKeys::load(&settings.key_file).map_err(|e| match e {
        KeyError::Missing => format!(
            "the control key file {} does not exist",
            settings.key_file.display()
        ),
        other => format!("{other} ({})", settings.key_file.display()),
    })?;
    let text = read_secret_text(&settings.resend_key_file).map_err(|e| match e {
        KeyError::Missing => format!(
            "the Resend key file {} does not exist",
            settings.resend_key_file.display()
        ),
        other => format!(
            "the Resend key file: {other} ({})",
            settings.resend_key_file.display()
        ),
    })?;
    let key = ApiKey::new(&text).map_err(|e| e.to_string())?;
    let mailer = ResendClient::new(&settings.resend_url, key, &settings.mail_from)
        .map_err(|e| e.to_string())?;

    // The database last: nothing is created unless every other setting is already good.
    let mut store = Store::open(&settings.db)
        .map_err(|e| format!("the database {}: {e}", settings.db.display()))?;
    if settings.open_signup {
        store = store.with_open_signup(OpenLimits::default());
    }
    let clock = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0)
    });
    let app = App::new(store, keys, Arc::new(mailer), origins, clock);
    app.set_busy(settings.busy);
    app.set_backup_status(settings.backup_status.clone());
    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bf_common::sign::hex;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use crate::cookie;
    use crate::mail::{MailError, RecordingMailer};
    use crate::signin::{MailResult, SESSION_LIFETIME_SECS};

    const T0: u64 = 20_000 * 86_400 + 1_000;
    const ORIGIN: &str = "https://barely-free.com";
    const APP_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; \
                              base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    fn keys() -> ControlKeys {
        ControlKeys::from_parts([1; 32], [2; 32])
    }

    struct Harness {
        app: Arc<App>,
        mailer: Arc<RecordingMailer>,
        now: Arc<AtomicU64>,
    }

    /// An app with these accounts: (label, email or none).
    fn harness_with(mailer: RecordingMailer, accounts: &[(&str, Option<&str>)]) -> Harness {
        harness_build(mailer, accounts, None)
    }

    /// The same, with open sign-up and these caps.
    fn harness_open(accounts: &[(&str, Option<&str>)], limits: OpenLimits) -> Harness {
        harness_build(RecordingMailer::new(), accounts, Some(limits))
    }

    fn harness_build(
        mailer: RecordingMailer,
        accounts: &[(&str, Option<&str>)],
        open: Option<OpenLimits>,
    ) -> Harness {
        let mut store = Store::open_in_memory().unwrap();
        if let Some(limits) = open {
            store = store.with_open_signup(limits);
        }
        for (label, email) in accounts {
            let account = store.add_account(label, 1_000).unwrap();
            if let Some(email) = email {
                store
                    .set_email_fp(account.id, &keys().email_fingerprint(email))
                    .unwrap();
            }
        }
        let mailer = Arc::new(mailer);
        let now = Arc::new(AtomicU64::new(T0));
        let clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst)) as Arc<dyn Fn() -> u64 + Send + Sync>
        };
        let app = App::new(
            store,
            keys(),
            mailer.clone(),
            vec![
                ORIGIN.to_string(),
                "https://www.barely-free.com".to_string(),
            ],
            clock,
        );
        Harness { app, mailer, now }
    }

    fn harness(accounts: &[(&str, Option<&str>)]) -> Harness {
        harness_with(RecordingMailer::new(), accounts)
    }

    /// An app where "lao" can sign in with lao@example.com.
    fn lao() -> Harness {
        harness(&[("lao", Some("lao@example.com"))])
    }

    /// An app that has no account with that address.
    fn nobody() -> Harness {
        harness(&[("sam", Some("sam@example.com"))])
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Resp {
        status: u16,
        headers: BTreeMap<String, Vec<String>>,
        body: String,
    }

    impl Resp {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .get(name)
                .and_then(|v| v.first())
                .map(String::as_str)
        }
    }

    fn make_request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
        let mut builder = axum::http::Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::from(body.to_vec())).unwrap()
    }

    async fn call_raw(
        h: &Harness,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        let response = h
            .app
            .handle(make_request(method, path, headers, body))
            .await;
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in &parts.headers {
            map.entry(name.as_str().to_string())
                .or_default()
                .push(value.to_str().unwrap().to_string());
        }
        let resp = Resp {
            status: parts.status.as_u16(),
            headers: map,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        };
        assert_secure(&resp);
        resp
    }

    /// Every answer of this app carries these, whatever it is.
    fn assert_secure(r: &Resp) {
        assert_eq!(
            r.header("content-security-policy"),
            Some(APP_POLICY),
            "{r:?}"
        );
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(r.header("x-robots-tag"), Some("noindex"));
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        // Not `no-referrer`: with that policy a browser writes `Origin: null` on a form post,
        // which no check can tell from a sandboxed page on another site. `same-origin`
        // sends nothing to other sites and lets the browser send the real `Origin` here.
        assert_eq!(r.header("referrer-policy"), Some("same-origin"));
        assert!(r.header("strict-transport-security").is_some());
        assert_eq!(r.header("cross-origin-opener-policy"), Some("same-origin"));
        assert_eq!(
            r.header("cross-origin-resource-policy"),
            Some("same-origin")
        );
        assert!(r.header("permissions-policy").is_some());
    }

    const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");

    async fn get(h: &Harness, path: &str, cookie: Option<&str>) -> Resp {
        let value = cookie.map(|c| format!("{}={c}", cookie::SESSION_COOKIE));
        let mut headers = Vec::new();
        if let Some(v) = &value {
            headers.push(("cookie", v.as_str()));
        }
        call_raw(h, "GET", path, &headers, b"").await
    }

    /// A form post the way a browser on this site sends it.
    async fn post(h: &Harness, path: &str, body: &str, extra: &[(&str, &str)]) -> Resp {
        let mut headers = vec![FORM, ("sec-fetch-site", "same-origin"), ("origin", ORIGIN)];
        headers.extend_from_slice(extra);
        call_raw(h, "POST", path, &headers, body.as_bytes()).await
    }

    fn email_body(email: &str) -> String {
        format!("email={}", email.replace('@', "%40"))
    }

    fn count(h: &Harness, sql: &str) -> i64 {
        h.app
            .store
            .lock()
            .unwrap()
            .conn
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    }

    async fn wait_for_mails(h: &Harness, n: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while h.mailer.sent().len() < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {n} emails, got {:?}", h.mailer.sent()));
    }

    /// Waits until the background task has written down its result.
    async fn wait_for_log(h: &Harness, kind: &str, n: i64) {
        let sql = format!("SELECT COUNT(*) FROM mail_log WHERE kind = '{kind}'");
        tokio::time::timeout(Duration::from_secs(3), async {
            while count(h, &sql) < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {n} {kind} rows"));
    }

    /// Signs in as lao and returns the cookie value.
    /// The `Cookie` header a browser sends to /verify after a code was asked for `email`.
    fn pending_header(email: &str) -> String {
        format!("{}={}", cookie::PENDING_COOKIE, hex(email.as_bytes()))
    }

    /// The pending cookie (`name=value`) a response set, ready to send back.
    fn pending_set_by(r: &Resp) -> String {
        r.headers
            .get("set-cookie")
            .expect("cookies were set")
            .iter()
            .find(|header| header.starts_with("__Host-bf_pending="))
            .map(|header| header.split(';').next().unwrap().to_string())
            .expect("a pending cookie was set")
    }

    /// Types a code on /verify the way a browser does after asking for one for `cookies`.
    async fn verify(h: &Harness, cookies: &str, code: &str) -> Resp {
        post(
            h,
            "/verify",
            &format!("code={code}"),
            &[("cookie", cookies)],
        )
        .await
    }

    /// Signs in as lao and returns the session cookie value.
    async fn sign_in(h: &Harness) -> String {
        sign_in_with(h, "").await
    }

    /// Signs in as lao from a browser that already sends `extra_cookies`.
    async fn sign_in_with(h: &Harness, extra_cookies: &str) -> String {
        let before = h.mailer.sent().len();
        let asked = post(h, "/signin", &email_body("lao@example.com"), &[]).await;
        assert_eq!(asked.status, 303, "{asked:?}");
        wait_for_mails(h, before + 1).await;
        let code = h.mailer.sent().last().unwrap().code.clone();
        let mut cookies = pending_set_by(&asked);
        if !extra_cookies.is_empty() {
            cookies = format!("{cookies}; {extra_cookies}");
        }
        let r = verify(h, &cookies, &code).await;
        assert_eq!(r.status, 303, "{r:?}");
        cookie_value(&r)
    }

    fn cookie_value(r: &Resp) -> String {
        let headers = r.headers.get("set-cookie").expect("a cookie was set");
        let session: Vec<&String> = headers
            .iter()
            .filter(|header| header.starts_with("__Host-bf_session="))
            .collect();
        assert_eq!(session.len(), 1, "exactly one session cookie: {headers:?}");
        session[0]
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("__Host-bf_session=")
            .unwrap()
            .to_string()
    }

    fn csrf_in(html: &str) -> String {
        let at = html.find("name=\"csrf\" value=\"").expect("a csrf field");
        let rest = &html[at + "name=\"csrf\" value=\"".len()..];
        rest.split('"').next().unwrap().to_string()
    }

    // ---- routing ----

    #[test]
    fn the_app_answers_exactly_the_sign_in_sign_out_and_account_paths() {
        for yes in [
            "/signin",
            "/verify",
            "/signout",
            "/account",
            "/account/devices",
            "/account/devices/remove",
            "/account/devices/trackers",
            "/theme",
        ] {
            assert!(App::handles(yes), "{yes}");
        }
        for no in [
            "/",
            "/signin/",
            "/verify/",
            "/accounts",
            "/account/",
            "/account/devices/",
            "/account/devices/remove/",
            "/account/devices/trackers/",
            "/account/devices/1",
            "/admin",
            "/SIGNIN",
            "/signin/x",
            "",
        ] {
            assert!(!App::handles(no), "{no}");
        }
    }

    #[tokio::test]
    async fn only_the_right_methods_are_allowed_and_a_wrong_one_says_which() {
        let h = lao();
        let cases = [
            ("GET", "/signout", "POST"),
            ("PUT", "/signin", "GET, HEAD, POST"),
            ("DELETE", "/verify", "GET, HEAD, POST"),
            ("POST", "/account", "GET, HEAD"),
            ("PATCH", "/account", "GET, HEAD"),
            ("HEAD", "/signout", "POST"),
        ];
        for (method, path, allow) in cases {
            let r = call_raw(&h, method, path, &[], b"").await;
            assert_eq!(r.status, 405, "{method} {path}");
            assert_eq!(r.header("allow"), Some(allow), "{method} {path}");
        }
        assert_eq!(call_raw(&h, "HEAD", "/signin", &[], b"").await.status, 200);
    }

    // ---- the pages ----

    #[tokio::test]
    async fn the_sign_in_form_is_a_plain_page_with_nothing_loaded_from_outside() {
        let h = lao();

        let r = get(&h, "/signin", None).await;

        assert_eq!(r.status, 200);
        assert!(r.header("content-type").unwrap().starts_with("text/html"));
        assert!(
            r.body.contains("<form method=\"post\" action=\"/signin\""),
            "{}",
            r.body
        );
        assert!(r.body.contains("type=\"email\"") && r.body.contains("name=\"email\""));
        assert!(
            r.body
                .contains("<meta name=\"robots\" content=\"noindex\">")
        );
        assert!(r.body.contains("/assets/site.css"));
        // The one address out is a plain link to the public source (in the menu and the
        // footer); it loads nothing.
        let link = "href=\"https://github.com/LAOUUUUU/opensourced\" rel=\"noopener noreferrer\"";
        assert_eq!(r.body.matches(link).count(), 2, "the source link, twice");
        let body = r.body.replace(link, "");
        for forbidden in [
            "<script",
            "<iframe",
            "<embed",
            "<object",
            "http://",
            "https://",
            "style=",
            "onclick",
            "javascript:",
        ] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
    }

    #[tokio::test]
    async fn the_verify_page_is_just_the_code_box_and_names_the_address_it_was_asked_for() {
        let h = lao();
        let pending = pending_header("lao@example.com");

        let r = call_raw(&h, "GET", "/verify", &[("cookie", pending.as_str())], b"").await;

        assert_eq!(r.status, 200);
        assert!(r.body.contains("action=\"/verify\""), "{}", r.body);
        assert!(
            r.body.contains("name=\"code\"") && r.body.contains("autocomplete=\"one-time-code\"")
        );
        assert!(r.body.contains("inputmode=\"numeric\"") && r.body.contains("maxlength=\"6\""));
        assert!(
            r.body.contains("lao@example.com"),
            "the address is named: {}",
            r.body
        );
        assert!(
            !r.body.contains("name=\"email\""),
            "no address field, not even a hidden one: the address is not in the page's form"
        );
        assert!(
            r.body.contains("If that address has an account"),
            "{}",
            r.body
        );
        assert!(!r.body.contains("<script"));
    }

    #[tokio::test]
    async fn opening_verify_without_a_pending_sign_in_goes_back_to_the_sign_in_page() {
        let h = lao();
        let session_only = format!("{}=abc", cookie::SESSION_COOKIE);
        let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
            ("/verify", vec![]),
            (
                "/verify",
                vec![("cookie", format!("{}=", cookie::PENDING_COOKIE))],
            ),
            (
                "/verify",
                vec![("cookie", format!("{}=zz", cookie::PENDING_COOKIE))],
            ),
            (
                "/verify",
                vec![("cookie", format!("{}=fffe", cookie::PENDING_COOKIE))],
            ),
            ("/verify", vec![("cookie", pending_header("not-an-email"))]),
            (
                "/verify",
                vec![("cookie", pending_header("a@b.com, c@d.com"))],
            ),
            ("/verify", vec![("cookie", session_only)]),
            // The address is not read from the web address any more.
            ("/verify?email=lao%40example.com", vec![]),
        ];
        for (path, headers) in cases {
            let headers: Vec<(&str, &str)> =
                headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
            let r = call_raw(&h, "GET", path, &headers, b"").await;
            assert_eq!(r.status, 303, "{path} {headers:?}");
            assert_eq!(r.header("location"), Some("/signin"), "{path} {headers:?}");
        }
    }

    #[tokio::test]
    async fn the_address_is_never_in_the_web_address_and_a_plus_address_works_all_the_way() {
        let h = harness(&[("anna", Some("anna+news@example.com"))]);

        let asked = post(
            &h,
            "/signin",
            &email_body("anna+news@example.com").replace('+', "%2B"),
            &[],
        )
        .await;

        assert_eq!(asked.status, 303, "{asked:?}");
        assert_eq!(
            asked.header("location"),
            Some("/verify"),
            "a clean address, no query"
        );
        let pending = pending_set_by(&asked);
        let page = call_raw(&h, "GET", "/verify", &[("cookie", pending.as_str())], b"").await;
        assert_eq!(page.status, 200);
        assert!(page.body.contains("anna+news@example.com"), "{}", page.body);
        wait_for_mails(&h, 1).await;
        assert_eq!(h.mailer.sent()[0].to, "anna+news@example.com");
        let code = h.mailer.sent()[0].code.clone();
        let done = verify(&h, &pending, &code).await;
        assert_eq!(done.status, 303, "{done:?}");
        assert_eq!(done.header("location"), Some("/account"));
    }

    // ---- asking for a code ----

    #[tokio::test]
    async fn a_known_address_is_sent_to_the_verify_page_and_the_code_is_mailed_in_the_background() {
        let h = lao();

        let r = post(&h, "/signin", &email_body("  Lao@Example.com "), &[]).await;

        assert_eq!(r.status, 303, "{r:?}");
        assert_eq!(r.header("location"), Some("/verify"));
        assert_eq!(
            r.headers["set-cookie"],
            [cookie::set_pending(&hex(b"Lao@Example.com"), 600)],
            "the address is remembered, by this browser only, for as long as the code works"
        );
        wait_for_mails(&h, 1).await;
        let mail = &h.mailer.sent()[0];
        assert_eq!(mail.to, "Lao@Example.com");
        assert_eq!(mail.code.len(), 6);
        assert!(mail.code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(mail.idempotency_key, "signin/1");
        assert!(
            !r.body.contains(&mail.code),
            "the code is only in the email"
        );
        wait_for_log(&h, "sent", 1).await;
    }

    #[tokio::test]
    async fn the_answer_is_the_same_for_an_address_with_an_account_and_one_without() {
        let known = lao();
        let unknown = nobody();

        let a = post(&known, "/signin", &email_body("lao@example.com"), &[]).await;
        let b = post(&unknown, "/signin", &email_body("lao@example.com"), &[]).await;

        assert_eq!(a, b, "every header and every byte");
        wait_for_mails(&known, 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(unknown.mailer.sent().is_empty(), "no account, no email");
        assert_eq!(count(&unknown, "SELECT COUNT(*) FROM login_codes"), 0);
    }

    #[tokio::test]
    async fn the_answer_comes_before_the_email_is_sent_so_its_timing_tells_nothing() {
        let known = harness_with(
            RecordingMailer::slow(Duration::from_millis(400)),
            &[("lao", Some("lao@example.com"))],
        );
        let unknown = harness_with(
            RecordingMailer::slow(Duration::from_millis(400)),
            &[("sam", Some("sam@example.com"))],
        );

        let started = Instant::now();
        post(&known, "/signin", &email_body("lao@example.com"), &[]).await;
        let known_took = started.elapsed();
        let started = Instant::now();
        post(&unknown, "/signin", &email_body("lao@example.com"), &[]).await;
        let unknown_took = started.elapsed();

        assert!(known_took < Duration::from_millis(200), "{known_took:?}");
        assert!(
            unknown_took < Duration::from_millis(200),
            "{unknown_took:?}"
        );
    }

    #[tokio::test]
    async fn too_many_requests_get_the_same_429_for_everyone() {
        let known = lao();
        let unknown = nobody();
        for h in [&known, &unknown] {
            for _ in 0..3 {
                assert_eq!(
                    post(h, "/signin", &email_body("lao@example.com"), &[])
                        .await
                        .status,
                    303
                );
            }
        }

        let a = post(&known, "/signin", &email_body("lao@example.com"), &[]).await;
        let b = post(&unknown, "/signin", &email_body("lao@example.com"), &[]).await;

        assert_eq!(a.status, 429);
        assert_eq!(a, b);
        assert!(a.body.contains("Too many"), "{}", a.body);
        assert!(
            !a.body.contains("<form method=\"post\" action=\"/verify\""),
            "no code form on a notice"
        );
    }

    #[tokio::test]
    async fn when_mail_is_paused_everyone_is_told_so_with_the_same_503() {
        let known = lao();
        let unknown = nobody();
        for h in [&known, &unknown] {
            h.app
                .store
                .lock()
                .unwrap()
                .record_mail_result(&[9; 32], MailResult::QuotaExhausted, T0)
                .unwrap();
        }

        let a = post(&known, "/signin", &email_body("lao@example.com"), &[]).await;
        let b = post(&unknown, "/signin", &email_body("lao@example.com"), &[]).await;

        assert_eq!(a.status, 503);
        assert_eq!(a, b);
        assert!(a.body.contains("paused"), "{}", a.body);
        assert!(known.mailer.sent().is_empty());
    }

    #[tokio::test]
    async fn a_network_address_is_held_to_ten_requests_an_hour_and_a_missing_or_bad_address_is_not_held_at_all()
     {
        let h = nobody();
        let ip = [("cf-connecting-ip", "203.0.113.7")];
        for i in 0..10 {
            let r = post(
                &h,
                "/signin",
                &email_body(&format!("user{i}@example.com")),
                &ip,
            )
            .await;
            assert_eq!(r.status, 303, "request {i}");
        }

        assert_eq!(
            post(&h, "/signin", &email_body("user10@example.com"), &ip)
                .await
                .status,
            429
        );
        assert_eq!(
            post(
                &h,
                "/signin",
                &email_body("user11@example.com"),
                &[("cf-connecting-ip", "203.0.113.8")]
            )
            .await
            .status,
            303,
            "another network"
        );
        assert_eq!(
            post(&h, "/signin", &email_body("user12@example.com"), &[])
                .await
                .status,
            303,
            "no address to hold to"
        );
        assert_eq!(
            post(
                &h,
                "/signin",
                &email_body("user13@example.com"),
                &[("cf-connecting-ip", "not an address")]
            )
            .await
            .status,
            303,
            "a header that is not an address counts as none"
        );
        assert_eq!(
            post(
                &h,
                "/signin",
                &email_body("user14@example.com"),
                &[("cf-connecting-ip", "203.0.113.7, 198.51.100.1")]
            )
            .await
            .status,
            303,
            "a list is not an address either"
        );
    }

    #[tokio::test]
    async fn a_request_that_is_not_an_address_is_sent_back_to_the_form_and_not_counted() {
        let h = lao();
        for body in [
            "email=not-an-address",
            "email=",
            "other=1",
            "",
            "email=Lao+%3Clao%40example.com%3E",
            "email=a%40b.com%2C+c%40d.com",
        ] {
            let r = post(&h, "/signin", body, &[]).await;
            assert_eq!(r.status, 400, "{body:?}");
            assert!(
                r.body.contains("<form method=\"post\" action=\"/signin\""),
                "{body:?}"
            );
            assert!(r.body.to_lowercase().contains("address"), "{body:?}");
        }
        assert_eq!(count(&h, "SELECT COUNT(*) FROM mail_log"), 0);
        assert!(h.mailer.sent().is_empty());
    }

    #[tokio::test]
    async fn what_was_typed_is_never_echoed_unless_it_is_a_clean_address_and_then_it_is_escaped() {
        let h = lao();
        let payload = "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E";

        let r = post(&h, "/signin", &format!("email={payload}"), &[]).await;

        assert_eq!(r.status, 400);
        assert!(!r.body.contains("<script"), "{}", r.body);
        assert!(
            !r.body.contains("alert(1)"),
            "not echoed at all: {}",
            r.body
        );
    }

    #[tokio::test]
    async fn nothing_typed_or_stored_in_the_cookie_is_echoed_unless_it_is_a_clean_address() {
        let h = lao();
        let payload = "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        let raw = "\"><script>alert(1)</script>@example.com";

        // A cookie made by hand with something nasty in it shows nothing at all.
        let r = call_raw(
            &h,
            "GET",
            "/verify",
            &[("cookie", pending_header(raw).as_str())],
            b"",
        )
        .await;
        assert_eq!(r.status, 303);
        assert!(!r.body.contains("alert(1)"));

        // A nasty code is just a wrong code, and is not shown either.
        let pending = pending_header("lao@example.com");
        for body in [format!("code={payload}"), "code=%3Cb%3E".to_string()] {
            let r = post(&h, "/verify", &body, &[("cookie", pending.as_str())]).await;
            assert_eq!(r.status, 400, "{body}");
            assert!(!r.body.contains("<script"), "{body}: {}", r.body);
            assert!(!r.body.contains("alert(1)"), "{body}: {}", r.body);
            assert!(!r.body.contains("<b>"), "{body}");
        }
        // And an address in the form is ignored: the cookie says which address.
        let r = post(
            &h,
            "/verify",
            &format!("email={payload}&code=123456"),
            &[("cookie", pending.as_str())],
        )
        .await;
        assert_eq!(r.status, 400);
        assert!(!r.body.contains("alert(1)"), "{}", r.body);
    }

    // ---- typing the code ----

    #[tokio::test]
    async fn a_right_code_signs_in_sets_the_protected_cookie_forgets_the_pending_address_and_goes_to_the_account_page()
     {
        let h = lao();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&h, 1).await;
        let code = h.mailer.sent()[0].code.clone();
        let pending = pending_set_by(&asked);

        let r = verify(&h, &pending, &code).await;

        assert_eq!(r.status, 303, "{r:?}");
        assert_eq!(r.header("location"), Some("/account"));
        let value = cookie_value(&r);
        assert!(
            r.headers["set-cookie"].contains(&cookie::set_session(&value, SESSION_LIFETIME_SECS))
        );
        assert!(
            r.headers["set-cookie"].contains(&cookie::clear_pending()),
            "the remembered address is let go: {:?}",
            r.headers["set-cookie"]
        );
        assert_eq!(r.headers["set-cookie"].len(), 2);
        let page = get(&h, "/account", Some(&value)).await;
        assert_eq!(page.status, 200, "{page:?}");
        assert!(page.body.contains("lao"));
        // The same code does not work twice.
        let again = verify(&h, &pending, &code).await;
        assert_eq!(again.status, 400);
        assert!(!again.headers.contains_key("set-cookie"));
    }

    // ---- keep me signed in (specs/cookies.md, piece 1) ----

    const DAY: u64 = 86_400;

    /// Signs in as lao typing the code with `form_tail` after it (`&keep=1`, or nothing), and
    /// returns the session cookie value.
    async fn sign_in_typing(h: &Harness, form_tail: &str) -> String {
        let before = h.mailer.sent().len();
        let asked = post(h, "/signin", &email_body("lao@example.com"), &[]).await;
        assert_eq!(asked.status, 303, "{asked:?}");
        wait_for_mails(h, before + 1).await;
        let code = h.mailer.sent().last().unwrap().code.clone();
        let pending = pending_set_by(&asked);
        let r = post(
            h,
            "/verify",
            &format!("code={code}{form_tail}"),
            &[("cookie", &pending)],
        )
        .await;
        assert_eq!(r.status, 303, "{r:?}");
        cookie_value(&r)
    }

    /// The `Set-Cookie` headers that start a session cookie, in an answer.
    fn session_cookies_set(r: &Resp) -> Vec<String> {
        r.headers
            .get("set-cookie")
            .map(|all| {
                all.iter()
                    .filter(|header| header.starts_with("__Host-bf_session="))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn the_code_page_offers_to_keep_me_signed_in_unticked_and_says_it_uses_a_cookie() {
        let h = lao();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        let pending = pending_set_by(&asked);

        let page = call_raw(&h, "GET", "/verify", &[("cookie", &pending)], b"").await;

        assert_eq!(page.status, 200, "{page:?}");
        assert!(
            page.body
                .contains("Keep me signed in on this device (uses a cookie)"),
            "{}",
            page.body
        );
        let at = page.body.find("name=\"keep\"").expect("the tick box");
        let input = &page.body[page.body[..at].rfind("<input").unwrap()..][..120];
        assert!(input.contains("type=\"checkbox\""), "{input}");
        assert!(input.contains("value=\"1\""), "{input}");
        assert!(!input.contains("checked"), "unticked by default: {input}");
    }

    #[tokio::test]
    async fn only_a_ticked_box_makes_a_kept_session_and_nothing_else_about_signing_in_changes() {
        let h = lao();
        let before = count(&h, "SELECT COUNT(*) FROM sessions WHERE keep = 1");
        assert_eq!(before, 0);

        // An hour between sign-ins, so the three-codes-an-hour limit stays out of the way.
        let next_hour = || h.now.fetch_add(3_600, Ordering::SeqCst);

        // Ticked: the browser sends keep=1.
        let ticked = sign_in_typing(&h, "&keep=1").await;
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sessions WHERE keep = 1"), 1);
        // Not ticked: no field. Anything but exactly 1 is not a tick either.
        for tail in ["", "&keep=yes", "&keep=0"] {
            next_hour();
            sign_in_typing(&h, tail).await;
        }
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM sessions WHERE keep = 1"),
            1,
            "only the ticked one"
        );
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sessions WHERE keep = 0"), 3);

        // The answer to a ticked sign-in is the same as to any other: the account page, the
        // same cookie lifetime, the pending address let go, two cookies.
        next_hour();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&h, 5).await;
        let code = h.mailer.sent().last().unwrap().code.clone();
        let r = post(
            &h,
            "/verify",
            &format!("code={code}&keep=1"),
            &[("cookie", &pending_set_by(&asked))],
        )
        .await;
        let value = cookie_value(&r);
        assert_eq!(r.header("location"), Some("/account"));
        assert!(
            r.headers["set-cookie"].contains(&cookie::set_session(&value, SESSION_LIFETIME_SECS))
        );
        assert!(r.headers["set-cookie"].contains(&cookie::clear_pending()));
        assert_eq!(r.headers["set-cookie"].len(), 2);
        let page = get(&h, "/account", Some(&ticked)).await;
        assert_eq!(page.status, 200, "{page:?}");
    }

    #[tokio::test]
    async fn a_kept_session_that_is_used_on_a_later_day_gets_its_cookie_again_once() {
        let h = lao();
        let kept = sign_in_typing(&h, "&keep=1").await;

        // The same day: nothing to renew, so nothing is sent.
        let same_day = get(&h, "/account", Some(&kept)).await;
        assert_eq!(same_day.status, 200);
        assert_eq!(session_cookies_set(&same_day), Vec::<String>::new());

        // A later day: the cookie again, for the sixty days that start now.
        h.now.store(T0 + 2 * DAY, Ordering::SeqCst);
        let later = get(&h, "/account", Some(&kept)).await;
        assert_eq!(later.status, 200);
        assert_eq!(
            session_cookies_set(&later),
            vec![cookie::set_session(&kept, 60 * DAY)]
        );

        // And not again the same day.
        let again = get(&h, "/account", Some(&kept)).await;
        assert_eq!(session_cookies_set(&again), Vec::<String>::new());
        // The session now really runs past its first sixty days.
        h.now.store(T0 + 61 * DAY, Ordering::SeqCst);
        assert_eq!(get(&h, "/account", Some(&kept)).await.status, 200);
    }

    #[tokio::test]
    async fn the_cookie_of_a_kept_session_never_outlives_the_year_it_may_run() {
        let h = lao();
        let kept = sign_in_typing(&h, "&keep=1").await;
        // Used every fifty days: each time it gets sixty more.
        for day in (50..=300).step_by(50) {
            h.now.store(T0 + day * DAY, Ordering::SeqCst);
            let r = get(&h, "/account", Some(&kept)).await;
            assert_eq!(r.status, 200, "day {day}");
            assert_eq!(
                session_cookies_set(&r),
                vec![cookie::set_session(&kept, 60 * DAY)],
                "day {day}"
            );
        }

        // On day 340 sixty more would pass the year, so the cookie gets the 25 days left.
        h.now.store(T0 + 340 * DAY, Ordering::SeqCst);
        let r = get(&h, "/account", Some(&kept)).await;
        assert_eq!(r.status, 200);
        assert_eq!(
            session_cookies_set(&r),
            vec![cookie::set_session(&kept, 25 * DAY)],
            "only the time to the year, not sixty days"
        );

        // At the cap there is nothing to renew, and at the year it runs out.
        h.now.store(T0 + 364 * DAY, Ordering::SeqCst);
        let r = get(&h, "/account", Some(&kept)).await;
        assert_eq!(r.status, 200);
        assert_eq!(session_cookies_set(&r), Vec::<String>::new());
        h.now.store(T0 + 365 * DAY, Ordering::SeqCst);
        assert_eq!(
            get(&h, "/account", Some(&kept)).await.status,
            303,
            "it ran out"
        );
    }

    #[tokio::test]
    async fn a_kept_session_that_signs_in_again_on_a_renewal_day_is_replaced_not_renewed() {
        let h = lao();
        let old = sign_in_typing(&h, "&keep=1").await;
        h.now.store(T0 + 2 * DAY, Ordering::SeqCst);

        let before = h.mailer.sent().len();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&h, before + 1).await;
        let code = h.mailer.sent().last().unwrap().code.clone();
        let cookies = format!(
            "{}; {}={old}",
            pending_set_by(&asked),
            cookie::SESSION_COOKIE
        );
        let r = post(
            &h,
            "/verify",
            &format!("code={code}&keep=1"),
            &[("cookie", &cookies)],
        )
        .await;

        assert_eq!(r.status, 303, "{r:?}");
        let new = cookie_value(&r);
        assert_ne!(new, old);
        assert_eq!(
            session_cookies_set(&r),
            vec![cookie::set_session(&new, SESSION_LIFETIME_SECS)],
            "one session cookie, the new one"
        );
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM sessions"),
            1,
            "the old row is gone"
        );
        assert_eq!(get(&h, "/account", Some(&old)).await.status, 303);
    }

    #[tokio::test]
    async fn only_the_signed_in_pages_renew_a_kept_session() {
        let h = lao();
        let kept = sign_in_typing(&h, "&keep=1").await;
        h.now.store(T0 + 2 * DAY, Ordering::SeqCst);
        let held = format!("{}={kept}", cookie::SESSION_COOKIE);

        // Pages that do not use the session, and an answer that refuses: nothing renewed.
        for (method, path) in [("GET", "/signin"), ("GET", "/verify"), ("PUT", "/account")] {
            let r = call_raw(&h, method, path, &[("cookie", held.as_str())], b"").await;
            assert_eq!(
                session_cookies_set(&r),
                Vec::<String>::new(),
                "{method} {path}"
            );
        }
        let r = post(&h, "/theme", "theme=dark&back=%2F", &[("cookie", &held)]).await;
        assert_eq!(
            session_cookies_set(&r),
            Vec::<String>::new(),
            "the theme buttons"
        );
        let r = post(
            &h,
            "/account/devices/remove",
            "csrf=wrong&device=1",
            &[("cookie", &held)],
        )
        .await;
        assert_eq!(r.status, 403);
        assert_eq!(
            session_cookies_set(&r),
            Vec::<String>::new(),
            "a refused form"
        );

        // The account page does.
        let r = get(&h, "/account", Some(&kept)).await;
        assert_eq!(
            session_cookies_set(&r),
            vec![cookie::set_session(&kept, 60 * DAY)]
        );
    }

    /// The `<input ...>` tag of the tick box in a page.
    fn keep_input(html: &str) -> &str {
        let at = html.find("name=\"keep\"").expect("the tick box");
        let start = html[..at].rfind("<input").unwrap();
        let end = start + html[start..].find('>').unwrap();
        &html[start..=end]
    }

    #[tokio::test]
    async fn a_wrong_code_keeps_the_tick_so_the_right_one_still_makes_a_kept_session() {
        let h = lao();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&h, 1).await;
        let code: u32 = h.mailer.sent().last().unwrap().code.parse().unwrap();
        let wrong = format!("{:06}", (code + 1) % 1_000_000);
        let pending = pending_set_by(&asked);

        let ticked = post(
            &h,
            "/verify",
            &format!("code={wrong}&keep=1"),
            &[("cookie", &pending)],
        )
        .await;
        assert_eq!(ticked.status, 400);
        assert!(
            keep_input(&ticked.body).contains(" checked"),
            "{}",
            keep_input(&ticked.body)
        );

        let unticked = post(
            &h,
            "/verify",
            &format!("code={wrong}"),
            &[("cookie", &pending)],
        )
        .await;
        assert_eq!(unticked.status, 400);
        assert!(!keep_input(&unticked.body).contains("checked"));
    }

    #[tokio::test]
    async fn a_session_made_without_the_tick_never_has_its_cookie_sent_again() {
        let h = lao();
        let plain = sign_in_typing(&h, "").await;

        for day in [2, 10, 59] {
            h.now.store(T0 + day * DAY, Ordering::SeqCst);
            let r = get(&h, "/account", Some(&plain)).await;
            assert_eq!(r.status, 200, "day {day}");
            assert_eq!(session_cookies_set(&r), Vec::<String>::new(), "day {day}");
        }
        h.now.store(T0 + 60 * DAY, Ordering::SeqCst);
        assert_eq!(
            get(&h, "/account", Some(&plain)).await.status,
            303,
            "exactly sixty days, as before"
        );
    }

    #[tokio::test]
    async fn signing_out_of_a_kept_session_only_clears_the_cookie() {
        let h = lao();
        let kept = sign_in_typing(&h, "&keep=1").await;
        h.now.store(T0 + 2 * DAY, Ordering::SeqCst);
        let csrf = {
            let store = h.app.store.lock().unwrap();
            store.session(&kept, T0 + 2 * DAY).unwrap().unwrap().csrf
        };
        let cookie_header = format!("{}={kept}", cookie::SESSION_COOKIE);

        let r = post(
            &h,
            "/signout",
            &format!("csrf={csrf}"),
            &[("cookie", &cookie_header)],
        )
        .await;

        assert_eq!(r.status, 303, "{r:?}");
        assert_eq!(session_cookies_set(&r), vec![cookie::clear_session()]);
    }

    #[test]
    fn a_renewed_cookie_is_never_added_to_an_answer_that_sets_the_session_cookie_itself() {
        let renewed = cookie::set_session("old.secret", 60 * DAY);
        let signing_in = Reply::redirect("/account")
            .with("set-cookie", cookie::set_session("new.secret", 60 * DAY));
        let signing_out = Reply::redirect("/").with("set-cookie", cookie::clear_session());
        let plain = Reply::redirect("/account");

        let after_sign_in = with_renewed_session(signing_in, &renewed);
        let after_sign_out = with_renewed_session(signing_out, &renewed);
        let after_plain = with_renewed_session(plain, &renewed);

        let cookies = |reply: &Reply| -> Vec<String> {
            reply
                .headers
                .iter()
                .filter(|(name, _)| *name == "set-cookie")
                .map(|(_, value)| value.clone())
                .collect()
        };
        assert_eq!(
            cookies(&after_sign_in),
            vec![cookie::set_session("new.secret", 60 * DAY)]
        );
        assert_eq!(cookies(&after_sign_out), vec![cookie::clear_session()]);
        assert_eq!(cookies(&after_plain), vec![renewed]);
    }

    // ---- the theme (specs/cookies.md, piece 2) ----

    /// The `Set-Cookie` headers of an answer.
    fn cookies_set(r: &Resp) -> Vec<String> {
        r.headers.get("set-cookie").cloned().unwrap_or_default()
    }

    #[tokio::test]
    async fn choosing_a_theme_keeps_it_in_a_cookie_and_goes_back_to_the_page() {
        let h = nobody();
        for (body, cookie_header, back) in [
            (
                "theme=dark&back=%2Faccount",
                cookie::set_theme(Theme::Dark),
                "/account",
            ),
            ("theme=light&back=%2F", cookie::set_theme(Theme::Light), "/"),
            (
                "back=%2Fsignin&theme=system",
                cookie::clear_theme(),
                "/signin",
            ),
            (
                "theme=dark&back=%2Fadmin%2Fkicks",
                cookie::set_theme(Theme::Dark),
                "/admin/kicks",
            ),
            (
                "theme=dark&back=%2Fcookies",
                cookie::set_theme(Theme::Dark),
                "/cookies",
            ),
            (
                "theme=dark&back=%2Fcheck",
                cookie::set_theme(Theme::Dark),
                "/check",
            ),
            (
                "theme=dark&back=%2Fstatus",
                cookie::set_theme(Theme::Dark),
                "/status",
            ),
        ] {
            let r = post(&h, "/theme", body, &[]).await;
            assert_eq!(r.status, 303, "{body}: {r:?}");
            assert_eq!(r.header("location"), Some(back), "{body}");
            assert_eq!(cookies_set(&r), vec![cookie_header], "{body}");
        }
    }

    #[tokio::test]
    async fn a_theme_that_is_not_one_of_the_three_changes_nothing() {
        let h = nobody();
        for body in [
            "theme=blue&back=%2F",
            "theme=&back=%2F",
            "theme=Dark&back=%2F",
            "back=%2F",
            "theme=dark%22%3E&back=%2F",
        ] {
            let r = post(&h, "/theme", body, &[]).await;
            assert_eq!(r.status, 303, "{body}: {r:?}");
            assert_eq!(r.header("location"), Some("/"), "{body}");
            assert_eq!(cookies_set(&r), Vec::<String>::new(), "{body}");
        }
    }

    #[tokio::test]
    async fn the_way_back_is_one_of_the_sites_own_pages_or_the_front_page() {
        let h = nobody();
        for back in [
            "https%3A%2F%2Fevil.example%2F",
            "%2F%2Fevil.example",
            "%2F%5Cevil.example",
            "%2Fadmin%2F..%2Faccount",
            "%2Fsignin%3Fx%3D1",
            "%2Fnothing-here",
            "account",
            "",
        ] {
            let r = post(&h, "/theme", &format!("theme=dark&back={back}"), &[]).await;
            assert_eq!(r.status, 303, "{back}");
            assert_eq!(r.header("location"), Some("/"), "{back}");
        }
        let r = post(&h, "/theme", "theme=dark", &[]).await;
        assert_eq!(r.header("location"), Some("/"), "no back at all");
    }

    #[tokio::test]
    async fn a_theme_form_from_another_site_is_refused_and_sets_nothing() {
        let h = nobody();
        let r = call_raw(
            &h,
            "POST",
            "/theme",
            &[
                FORM,
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.example"),
            ],
            b"theme=dark&back=%2F",
        )
        .await;
        assert_eq!(r.status, 403, "{r:?}");
        assert_eq!(cookies_set(&r), Vec::<String>::new());

        let r = call_raw(&h, "GET", "/theme", &[], b"").await;
        assert_eq!(r.status, 405);
        assert_eq!(r.header("allow"), Some("POST"));
    }

    #[tokio::test]
    async fn every_page_of_the_app_is_drawn_in_the_chosen_theme_and_varies_by_cookie() {
        let h = lao();
        let session = sign_in(&h).await;
        let pages: [(&str, &str, Option<&str>); 3] = [
            ("GET", "/signin", None),
            ("GET", "/account", Some(session.as_str())),
            ("POST", "/signout", None),
        ];
        for (theme, cookie_value, attribute) in [
            (
                Some("dark"),
                "__Host-bf_theme=dark",
                Some(" data-theme=\"dark\""),
            ),
            (
                Some("light"),
                "__Host-bf_theme=light",
                Some(" data-theme=\"light\""),
            ),
            (None, "", None),
            (None, "__Host-bf_theme=dark\"><b>", None),
            (None, "__Host-bf_theme=light dark", None),
            (None, "__Host-bf_theme=system", None),
        ] {
            for (method, path, session) in pages {
                let mut cookie_header = cookie_value.to_string();
                if let Some(session) = session {
                    cookie_header.push_str(&format!("; {}={session}", cookie::SESSION_COOKIE));
                }
                let mut headers = vec![("cookie", cookie_header.as_str())];
                if method == "POST" {
                    // An answer that is a page, not a redirect: a sign-out from another site.
                    headers.extend([FORM, ("sec-fetch-site", "cross-site")]);
                }
                let r = call_raw(&h, method, path, &headers, b"csrf=x").await;
                assert!(r.body.starts_with("<!doctype html>"), "{path}: {r:?}");
                let tag = r.body.lines().find(|l| l.starts_with("<html")).unwrap();
                match attribute {
                    Some(attribute) => {
                        assert_eq!(
                            tag,
                            format!("<html lang=\"en\"{attribute}>"),
                            "{path} {theme:?}"
                        )
                    }
                    None => assert_eq!(tag, "<html lang=\"en\">", "{path} {cookie_value}"),
                }
                assert!(
                    !r.body.contains("<b>"),
                    "the cookie's value is never copied"
                );
                assert_eq!(r.header("vary"), Some("Cookie"), "{path}");
            }
        }
    }

    // ---- open sign-up (specs/open-signup.md) ----

    #[tokio::test]
    async fn open_a_new_address_signs_up_with_a_code_and_lands_on_its_own_account_page() {
        let h = harness_open(&[], OpenLimits::default());

        let asked = post(&h, "/signin", &email_body("new@example.com"), &[]).await;
        assert_eq!(asked.status, 303, "{asked:?}");
        wait_for_mails(&h, 1).await;
        let mail = &h.mailer.sent()[0];
        assert_eq!(mail.to, "new@example.com");
        let code = mail.code.clone();
        assert_eq!(count(&h, "SELECT COUNT(*) FROM accounts"), 0, "not yet");

        let r = verify(&h, &pending_set_by(&asked), &code).await;

        assert_eq!(r.status, 303, "{r:?}");
        assert_eq!(r.header("location"), Some("/account"));
        let page = get(&h, "/account", Some(&cookie_value(&r))).await;
        assert_eq!(page.status, 200, "{page:?}");
        assert!(page.body.contains("member-1"), "{}", page.body);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM accounts"), 1);
        assert_eq!(
            count(
                &h,
                "SELECT COUNT(*) FROM accounts WHERE label LIKE '%new@example.com%'"
            ),
            0,
            "the address is not kept"
        );
    }

    #[tokio::test]
    async fn open_the_answer_is_the_same_for_a_new_address_and_a_known_one() {
        let known = harness_open(&[("lao", Some("lao@example.com"))], OpenLimits::default());
        let unknown = harness_open(&[("sam", Some("sam@example.com"))], OpenLimits::default());

        let a = post(&known, "/signin", &email_body("lao@example.com"), &[]).await;
        let b = post(&unknown, "/signin", &email_body("lao@example.com"), &[]).await;

        assert_eq!(a, b, "every header and every byte");
        wait_for_mails(&known, 1).await;
        wait_for_mails(&unknown, 1).await;
    }

    #[tokio::test]
    async fn open_when_the_days_room_is_used_up_a_new_address_is_told_so_and_a_member_is_not() {
        let h = harness_open(
            &[("lao", Some("lao@example.com"))],
            OpenLimits {
                new_mail_per_day: 0,
                new_accounts_per_day: 20,
            },
        );

        let full = post(&h, "/signin", &email_body("new@example.com"), &[]).await;
        let member = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;

        assert_eq!(full.status, 503, "{full:?}");
        assert!(full.body.contains("full for today"), "{}", full.body);
        assert!(
            !full
                .body
                .contains("<form method=\"post\" action=\"/verify\""),
            "no code form on a notice"
        );
        assert!(!full.headers.contains_key("set-cookie"));
        assert_eq!(member.status, 303, "members are not held by it");
        wait_for_mails(&h, 1).await;
        assert_eq!(h.mailer.sent()[0].to, "lao@example.com");
    }

    #[tokio::test]
    async fn open_a_right_code_typed_after_the_last_place_of_the_day_went_says_full_and_signs_nobody_in()
     {
        let h = harness_open(
            &[],
            OpenLimits {
                new_mail_per_day: 60,
                new_accounts_per_day: 1,
            },
        );
        let asked = post(&h, "/signin", &email_body("new@example.com"), &[]).await;
        wait_for_mails(&h, 1).await;
        let code = h.mailer.sent()[0].code.clone();
        h.app
            .store
            .lock()
            .unwrap()
            .add_account("someone-else", T0)
            .unwrap();

        let r = verify(&h, &pending_set_by(&asked), &code).await;

        assert_eq!(r.status, 503, "{r:?}");
        assert!(r.body.contains("full for today"), "{}", r.body);
        assert!(!r.headers.contains_key("set-cookie"));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM accounts"), 1);
    }

    #[tokio::test]
    async fn the_sign_in_and_code_pages_say_what_is_true_for_a_closed_and_an_open_site() {
        let closed = lao();
        let open = harness_open(&[], OpenLimits::default());

        let closed_in = get(&closed, "/signin", None).await;
        let open_in = get(&open, "/signin", None).await;
        let closed_code = code_for(&closed, "lao@example.com").await;
        let open_code = code_for(&open, "new@example.com").await;

        assert!(closed_in.body.contains("only accounts we have made"));
        assert!(closed_code.body.contains("If that address has an account"));
        for page in [&open_in, &open_code] {
            assert!(
                !page.body.contains("only accounts we have made"),
                "{}",
                page.body
            );
            assert!(!page.body.contains("not open yet"), "{}", page.body);
            assert!(
                !page.body.contains("If that address has an account"),
                "{}",
                page.body
            );
            assert!(
                !page.body.to_lowercase().contains("closed beta"),
                "{}",
                page.body
            );
        }
        assert!(
            open_in.body.contains("create an account"),
            "{}",
            open_in.body
        );
    }

    /// The `/verify` page a browser reaches after asking for a code for `email`.
    async fn code_for(h: &Harness, email: &str) -> Resp {
        let asked = post(h, "/signin", &email_body(email), &[]).await;
        let pending = pending_set_by(&asked);
        call_raw(h, "GET", "/verify", &[("cookie", pending.as_str())], b"").await
    }

    #[tokio::test]
    async fn the_address_comes_from_the_cookie_never_from_the_form() {
        let h = lao();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&h, 1).await;
        let code = h.mailer.sent()[0].code.clone();
        let pending = pending_set_by(&asked);

        // A form that names another address changes nothing about whose code this is.
        let r = post(
            &h,
            "/verify",
            &format!("email=sam%40example.com&code={code}"),
            &[("cookie", pending.as_str())],
        )
        .await;
        assert_eq!(r.status, 303, "{r:?}");
        let value = cookie_value(&r);
        let account = get(&h, "/account", Some(&value)).await;
        assert!(account.body.contains("lao"), "{}", account.body);
    }

    #[tokio::test]
    async fn typing_a_code_with_no_pending_sign_in_goes_back_to_the_sign_in_page_and_changes_nothing()
     {
        let h = lao();
        for headers in [vec![], vec![("cookie", "__Host-bf_pending=zz")]] {
            let r = post(&h, "/verify", "code=123456", &headers).await;
            assert_eq!(r.status, 303, "{headers:?}");
            assert_eq!(r.header("location"), Some("/signin"));
            assert!(!r.headers.contains_key("set-cookie"));
        }
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sessions"), 0);
    }

    #[tokio::test]
    async fn a_wrong_code_gets_one_plain_answer_and_five_of_them_end_the_code() {
        let h = lao();
        let asked = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&h, 1).await;
        let code = h.mailer.sent()[0].code.clone();
        let pending = pending_set_by(&asked);
        let wrong = if code == "000000" { "000001" } else { "000000" };

        for _ in 0..5 {
            let r = verify(&h, &pending, wrong).await;
            assert_eq!(r.status, 400);
            assert!(r.body.contains("did not work"), "{}", r.body);
            assert!(
                r.body.contains("lao@example.com"),
                "the address is still named"
            );
            assert!(!r.headers.contains_key("set-cookie"));
        }

        let late = verify(&h, &pending, &code).await;
        assert_eq!(late.status, 400, "the fifth wrong try ended the code");
    }

    #[tokio::test]
    async fn a_wrong_code_looks_the_same_for_an_address_with_an_account_and_one_without() {
        let known = lao();
        let unknown = nobody();
        post(&known, "/signin", &email_body("lao@example.com"), &[]).await;
        wait_for_mails(&known, 1).await;
        let pending = pending_header("lao@example.com");

        let a = verify(&known, &pending, "000000").await;
        let b = verify(&unknown, &pending, "000000").await;

        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn junk_where_the_code_goes_is_just_a_wrong_code() {
        let h = lao();
        let pending = pending_header("lao@example.com");
        for body in [
            "code=12345",
            "code=1234567",
            "code=abcdef",
            "code=",
            "",
            "other=1",
        ] {
            let r = post(&h, "/verify", body, &[("cookie", pending.as_str())]).await;
            assert_eq!(r.status, 400, "{body:?}");
            assert!(!r.headers.contains_key("set-cookie"), "{body:?}");
        }
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sessions"), 0);
    }

    #[tokio::test]
    async fn signing_in_ends_any_session_the_browser_already_held() {
        let h = lao();
        let old = sign_in(&h).await;

        let new = sign_in_with_cookie(&h, &old).await;

        assert_ne!(old, new, "a new id every time");
        assert_eq!(
            get(&h, "/account", Some(&old)).await.status,
            303,
            "the old one is gone"
        );
        assert_eq!(get(&h, "/account", Some(&new)).await.status, 200);
    }

    async fn sign_in_with_cookie(h: &Harness, cookie_value: &str) -> String {
        // A second code is allowed: three requests an hour.
        let held = format!("{}={cookie_value}", cookie::SESSION_COOKIE);
        sign_in_with(h, &held).await
    }

    // ---- other sites ----

    #[tokio::test]
    async fn a_form_that_does_not_come_from_this_site_changes_nothing() {
        let h = lao();
        let value = sign_in(&h).await;
        let account = get(&h, "/account", Some(&value)).await;
        let csrf = csrf_in(&account.body);
        let cookie_header = format!("{}={value}", cookie::SESSION_COOKIE);
        let sent_before = h.mailer.sent().len();
        let logs_before = count(&h, "SELECT COUNT(*) FROM mail_log");
        let sessions_before = count(&h, "SELECT COUNT(*) FROM sessions");

        let foreign: [&[(&str, &str)]; 6] = [
            &[("sec-fetch-site", "cross-site")],
            &[("sec-fetch-site", "same-site")],
            &[("sec-fetch-site", "none")],
            &[("origin", "https://evil.example")],
            &[("origin", "null")],
            &[],
        ];
        for path in ["/signin", "/verify", "/signout"] {
            for headers in foreign {
                let mut all = vec![FORM, ("cookie", cookie_header.as_str())];
                all.extend_from_slice(headers);
                let body = match path {
                    "/signout" => format!("csrf={csrf}"),
                    "/signin" => email_body("lao@example.com"),
                    _ => "code=123456".to_string(),
                };
                let r = call_raw(&h, "POST", path, &all, body.as_bytes()).await;
                assert_eq!(r.status, 403, "{path} {headers:?}");
                assert!(!r.headers.contains_key("set-cookie"), "{path} {headers:?}");
            }
        }

        assert_eq!(h.mailer.sent().len(), sent_before, "no email");
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM mail_log"),
            logs_before,
            "nothing counted"
        );
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sessions"), sessions_before);
        assert_eq!(
            get(&h, "/account", Some(&value)).await.status,
            200,
            "still signed in"
        );
    }

    #[tokio::test]
    async fn the_origin_header_alone_is_enough_when_it_is_this_site_and_the_www_name_counts() {
        let h = nobody();
        for origin in [ORIGIN, "https://www.barely-free.com"] {
            let r = call_raw(
                &h,
                "POST",
                "/signin",
                &[FORM, ("origin", origin)],
                email_body("a@example.com").as_bytes(),
            )
            .await;
            assert_eq!(r.status, 303, "{origin}");
        }
        let r = call_raw(
            &h,
            "POST",
            "/signin",
            &[FORM, ("sec-fetch-site", "same-origin")],
            email_body("b@example.com").as_bytes(),
        )
        .await;
        assert_eq!(r.status, 303, "Sec-Fetch-Site alone");
    }

    // ---- signing out ----

    #[tokio::test]
    async fn signing_out_needs_the_forms_own_token_and_ends_that_session() {
        let h = lao();
        let value = sign_in(&h).await;
        let other = sign_in_with_cookie(&h, &value).await; // a second session; the first is replaced
        let csrf = csrf_in(&get(&h, "/account", Some(&other)).await.body);
        let cookie_header = format!("{}={other}", cookie::SESSION_COOKIE);
        let with_cookie = [("cookie", cookie_header.as_str())];

        for body in [
            "",
            "csrf=",
            "csrf=wrong",
            &format!("csrf={}", "0".repeat(32)),
            &format!("csrf={csrf}&csrf={csrf}"),
            "other=1",
        ] {
            let r = post(&h, "/signout", body, &with_cookie).await;
            assert_eq!(r.status, 403, "{body:?}");
        }
        assert_eq!(
            get(&h, "/account", Some(&other)).await.status,
            200,
            "still signed in"
        );

        let r = post(&h, "/signout", &format!("csrf={csrf}"), &with_cookie).await;

        assert_eq!(r.status, 303, "{r:?}");
        assert_eq!(r.header("location"), Some("/"));
        assert_eq!(r.headers["set-cookie"], [cookie::clear_session()]);
        assert_eq!(get(&h, "/account", Some(&other)).await.status, 303);
    }

    #[tokio::test]
    async fn if_the_session_cannot_be_ended_signing_out_says_so_and_keeps_the_cookie() {
        let h = lao();
        let value = sign_in(&h).await;
        let csrf = csrf_in(&get(&h, "/account", Some(&value)).await.body);
        let cookie_header = format!("{}={value}", cookie::SESSION_COOKIE);
        let with_cookie = [("cookie", cookie_header.as_str())];
        h.app
            .store
            .lock()
            .unwrap()
            .conn
            .execute_batch(
                "CREATE TRIGGER no_delete BEFORE DELETE ON sessions
                 BEGIN SELECT RAISE(ABORT, 'locked'); END;",
            )
            .unwrap();

        let r = post(&h, "/signout", &format!("csrf={csrf}"), &with_cookie).await;

        assert_eq!(r.status, 500, "{r:?}");
        assert!(!r.headers.contains_key("set-cookie"), "{r:?}");
        assert_eq!(
            get(&h, "/account", Some(&value)).await.status,
            200,
            "the session is still there, and the person was told it failed"
        );
    }

    #[tokio::test]
    async fn one_sessions_token_does_not_sign_another_session_out() {
        let h = lao();
        let first = sign_in(&h).await;
        let csrf_first = csrf_in(&get(&h, "/account", Some(&first)).await.body);
        // A different account's session.
        h.app
            .store
            .lock()
            .unwrap()
            .add_account("sam", 1_000)
            .unwrap();
        let sam = h.app.store.lock().unwrap().create_session(2, T0).unwrap();
        let sam_header = format!("{}={}", cookie::SESSION_COOKIE, sam.cookie);

        let r = post(
            &h,
            "/signout",
            &format!("csrf={csrf_first}"),
            &[("cookie", sam_header.as_str())],
        )
        .await;

        assert_eq!(r.status, 403);
        assert_ne!(csrf_first, sam.csrf);
        assert_eq!(get(&h, "/account", Some(&sam.cookie)).await.status, 200);
    }

    #[tokio::test]
    async fn signing_out_when_not_signed_in_just_goes_home_and_clears_the_cookie() {
        let h = lao();

        let r = post(&h, "/signout", "csrf=x", &[]).await;

        assert_eq!(r.status, 303);
        assert_eq!(r.header("location"), Some("/signin"));
    }

    // ---- the account page ----

    #[tokio::test]
    async fn the_account_page_needs_a_live_session() {
        let h = lao();
        let value = sign_in(&h).await;

        for cookie in [None, Some("junk"), Some(""), Some(&"0".repeat(97)[..])] {
            let r = get(&h, "/account", cookie).await;
            assert_eq!(r.status, 303, "{cookie:?}");
            assert_eq!(r.header("location"), Some("/signin"));
        }
        assert_eq!(get(&h, "/account", Some(&value)).await.status, 200);

        h.now.store(T0 + SESSION_LIFETIME_SECS, Ordering::SeqCst);
        assert_eq!(
            get(&h, "/account", Some(&value)).await.status,
            303,
            "sixty days later"
        );
    }

    #[tokio::test]
    async fn the_account_page_shows_the_label_escaped_and_a_sign_out_form_with_its_token() {
        let label = "<script>alert(1)</script> & \"q\" 'p'";
        let h = harness(&[(label, Some("lao@example.com"))]);
        let value = sign_in(&h).await;

        let r = get(&h, "/account", Some(&value)).await;

        assert_eq!(r.status, 200);
        assert!(!r.body.contains("<script"), "{}", r.body);
        let shown = r
            .body
            .split("<strong>")
            .nth(1)
            .and_then(|rest| rest.split("</strong>").next())
            .expect("the label is shown");
        for raw in ['<', '>', '"', '\''] {
            assert!(!shown.contains(raw), "{raw} is raw in {shown}");
        }
        assert_eq!(
            unescape(shown),
            label,
            "the entities decode back to what was stored"
        );
        assert!(r.body.contains("<form method=\"post\" action=\"/signout\""));
        assert_eq!(csrf_in(&r.body).len(), 32);
        // Links out are only the official app pages (pinned in
        // `the_account_page_and_the_device_page_link_to_the_official_apps`).
        for forbidden in ["http://", "style="] {
            assert!(!r.body.contains(forbidden), "{forbidden}");
        }
    }

    /// Undoes the HTML entities askama writes (named, decimal and hex).
    fn unescape(text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find('&') {
            out.push_str(&rest[..at]);
            let tail = &rest[at..];
            let end = tail.find(';').expect("an entity ends with a semicolon");
            let entity = &tail[1..end];
            out.push(match entity {
                "lt" => '<',
                "gt" => '>',
                "amp" => '&',
                "quot" => '"',
                "apos" => '\'',
                number if number.starts_with("#x") => {
                    char::from_u32(u32::from_str_radix(&number[2..], 16).unwrap()).unwrap()
                }
                number if number.starts_with('#') => {
                    char::from_u32(number[1..].parse().unwrap()).unwrap()
                }
                other => panic!("unknown entity &{other};"),
            });
            rest = &tail[end + 1..];
        }
        out.push_str(rest);
        out
    }

    // ---- what a form post must look like ----

    #[tokio::test]
    async fn a_post_must_be_a_form_of_a_sane_size_and_shape() {
        let h = nobody();
        let good = email_body("a@example.com");
        let big = format!("email=a%40example.com&pad={}", "x".repeat(5_000));
        /// Headers, body, and the status that should come back.
        type Case<'a> = (Vec<(&'a str, &'a str)>, Vec<u8>, u16);
        let cases: Vec<Case> = vec![
            (
                vec![
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "application/json"),
                ],
                good.clone().into_bytes(),
                415,
            ),
            (
                vec![
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "text/plain"),
                ],
                good.clone().into_bytes(),
                415,
            ),
            (
                vec![
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "multipart/form-data; boundary=x"),
                ],
                good.clone().into_bytes(),
                415,
            ),
            (
                vec![("sec-fetch-site", "same-origin")],
                good.clone().into_bytes(),
                415,
            ),
            (
                vec![FORM, ("sec-fetch-site", "same-origin")],
                big.into_bytes(),
                413,
            ),
            (
                vec![FORM, ("sec-fetch-site", "same-origin")],
                b"email=a%40example.com&email=b%40example.com".to_vec(),
                400,
            ),
            (
                vec![FORM, ("sec-fetch-site", "same-origin")],
                vec![b'e', b'=', 0xff, 0xfe],
                400,
            ),
            (
                vec![
                    (
                        "content-type",
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    ),
                    ("sec-fetch-site", "same-origin"),
                ],
                good.clone().into_bytes(),
                303,
            ),
            (
                vec![
                    ("content-type", "Application/X-WWW-Form-Urlencoded"),
                    ("sec-fetch-site", "same-origin"),
                ],
                good.into_bytes(),
                303,
            ),
        ];
        for (headers, body, expect) in cases {
            let r = call_raw(&h, "POST", "/signin", &headers, &body).await;
            assert_eq!(r.status, expect, "{headers:?}");
        }
    }

    // ---- when the email does not go ----

    #[tokio::test]
    async fn if_resend_says_its_quota_is_used_up_the_next_person_is_told_mail_is_paused() {
        let h = lao();
        h.mailer.answer_with(Err(MailError::QuotaExhausted));
        let first = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;
        assert_eq!(first.status, 303, "the person is not told");
        wait_for_log(&h, "quota", 1).await;

        let next = post(&h, "/signin", &email_body("other@example.com"), &[]).await;

        assert_eq!(next.status, 503);
    }

    #[tokio::test]
    async fn any_other_mail_failure_is_written_down_without_using_the_budget_or_telling_anyone() {
        let h = lao();
        h.mailer
            .answer_with(Err(MailError::Network("down".to_string())));

        let r = post(&h, "/signin", &email_body("lao@example.com"), &[]).await;

        assert_eq!(r.status, 303);
        wait_for_log(&h, "failed", 1).await;
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM mail_log WHERE kind = 'sent'"),
            0
        );
        assert_eq!(
            post(&h, "/signin", &email_body("other@example.com"), &[])
                .await
                .status,
            303
        );
    }

    // ---- starting up ----

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-app-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write_private(path: &std::path::Path, text: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Settings that work, in a directory of their own.
    fn good_settings(name: &str) -> AppSettings {
        let dir = temp_dir(name);
        let key_file = dir.join("control.key");
        ControlKeys::load_or_create(&key_file).unwrap();
        let resend_key_file = dir.join("resend.key");
        write_private(&resend_key_file, "re_SECRETKEY_999\n", 0o600);
        AppSettings {
            db: dir.join("control.db"),
            key_file,
            resend_key_file,
            resend_url: "https://api.resend.com".to_string(),
            mail_from: "Barely-Free VPN <noreply@barely-free.com>".to_string(),
            origins: vec!["https://barely-free.com".to_string()],
            open_signup: false,
            busy: crate::closest::Busy::default(),
            backup_status: dir.join("backup-status"),
        }
    }

    #[test]
    fn building_the_app_gives_it_the_busy_settings() {
        assert_eq!(
            build(&good_settings("busy-default")).unwrap().busy(),
            crate::closest::Busy {
                online: 40,
                load: 0.9
            }
        );
        let mut settings = good_settings("busy-set");
        settings.busy = crate::closest::Busy {
            online: 7,
            load: 2.5,
        };
        assert_eq!(build(&settings).unwrap().busy(), settings.busy);
    }

    #[test]
    fn open_sign_up_is_off_unless_the_setting_is_exactly_one() {
        assert_eq!(check_open_signup(None), Ok(false));
        assert_eq!(check_open_signup(Some("0")), Ok(false));
        assert_eq!(check_open_signup(Some("1")), Ok(true));
        for bad in ["", " 1", "1 ", "yes", "true", "on", "2", "01", "-1"] {
            let why = check_open_signup(Some(bad)).expect_err(bad);
            assert!(why.contains("BC_OPEN_SIGNUP"), "{bad:?}: {why}");
        }
    }

    #[test]
    fn building_the_app_opens_sign_up_only_when_the_setting_says_so() {
        let closed = build(&good_settings("closed-signup")).unwrap();
        let mut settings = good_settings("open-signup");
        settings.open_signup = true;
        let open = build(&settings).unwrap();

        assert!(!closed.signup_open());
        assert!(open.signup_open());
    }

    #[test]
    fn an_origin_is_exactly_what_a_browser_writes() {
        for (typed, kept) in [
            ("https://barely-free.com", "https://barely-free.com"),
            (
                "  https://www.barely-free.com  ",
                "https://www.barely-free.com",
            ),
            ("http://localhost:18500", "http://localhost:18500"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://[::1]:9000", "http://[::1]:9000"),
            (
                "https://barely-free.com:8443",
                "https://barely-free.com:8443",
            ),
        ] {
            assert_eq!(check_origin(typed).as_deref(), Ok(kept), "{typed}");
        }
        for bad in [
            "",
            "barely-free.com",
            "ftp://barely-free.com",
            "http://barely-free.com",
            "http://example.com:18500",
            "https://barely-free.com/",
            "https://barely-free.com/path",
            "https://barely-free.com:443",
            "https://user@barely-free.com",
            "https://barely-free.com?x=1",
            "https://barely-free.com#top",
            "https://BARELY-FREE.COM",
            "file:///etc/passwd",
            "null",
            "*",
            "https://",
        ] {
            assert!(check_origin(bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_app_starts_when_everything_is_in_place() {
        let settings = good_settings("build-ok");

        let app = build(&settings);

        assert!(app.is_ok(), "{:?}", app.err());
        assert!(settings.db.exists(), "the database was opened");
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_key_or_resend_key_stops_it_before_a_database_is_made_and_makes_no_key_file() {
        let mut settings = good_settings("build-missing");
        std::fs::remove_file(&settings.key_file).unwrap();
        let why = build(&settings).err().expect("no key file");
        assert!(why.contains("key file"), "{why}");
        assert!(!settings.key_file.exists(), "a key file is never made here");
        assert!(!settings.db.exists(), "no database either");

        settings = good_settings("build-missing-resend");
        std::fs::remove_file(&settings.resend_key_file).unwrap();
        let why = build(&settings).err().expect("no Resend key");
        assert!(why.contains("Resend"), "{why}");
        assert!(!settings.db.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_resend_key_others_can_read_or_a_bad_setting_is_refused_without_ever_showing_the_key() {
        let settings = good_settings("build-bad");
        write_private(&settings.resend_key_file, "re_SECRETKEY_999\n", 0o644);
        let why = build(&settings).err().expect("an open key file");
        assert!(why.contains("chmod 600"), "{why}");
        assert!(!why.contains("SECRETKEY"), "{why}");
        assert!(!settings.db.exists());

        let mut settings = good_settings("build-bad-url");
        settings.resend_url = "http://example.com".to_string();
        let why = build(&settings).err().expect("a plain-http Resend");
        assert!(why.contains("https"), "{why}");
        assert!(!why.contains("SECRETKEY"), "{why}");

        let mut settings = good_settings("build-bad-origin");
        settings.origins = vec![
            "https://barely-free.com".to_string(),
            "barely-free.com/".to_string(),
        ];
        let why = build(&settings).err().expect("a bad origin");
        assert!(why.contains("barely-free.com/"), "{why}");
        assert!(
            !settings.db.exists(),
            "settings are checked before the database is touched"
        );

        let mut settings = good_settings("build-no-origin");
        settings.origins = Vec::new();
        assert!(build(&settings).is_err(), "at least one origin is needed");

        let mut settings = good_settings("build-no-dir");
        settings.db = settings.db.with_file_name("nowhere").join("control.db");
        assert!(
            build(&settings).is_err(),
            "a database that cannot be opened"
        );

        let mut settings = good_settings("build-from");
        settings.mail_from = String::new();
        assert!(build(&settings).is_err(), "no sender");
    }

    mod admin_pages;

    // ---- devices ----

    /// A harness with two accounts: lao (1) can sign in, sam (2) holds a device.
    #[tokio::test]
    async fn the_account_page_links_the_check_page() {
        let h = lao();
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await;
        assert_eq!(page.status, 200);
        assert!(page.body.contains("<a href=\"/check\">"), "{}", page.body);
    }

    #[tokio::test]
    async fn the_account_page_says_when_each_device_last_connected_and_through_which_server() {
        let h = lao();
        let phone = crate::keys::KeyPair::from_private([7; 32]).public_key;
        let laptop = crate::keys::KeyPair::from_private([8; 32]).public_key;
        {
            let mut store = h.app.store.lock().unwrap();
            store.add_device(1, "phone", &phone, T0).unwrap();
            store.add_device(1, "laptop", &laptop, T0).unwrap();
        }
        let cookie = sign_in(&h).await;

        // No poller: not known.
        let page = get(&h, "/account", Some(&cookie)).await.body;
        assert_eq!(
            page.matches("Last connection not known right now").count(),
            2,
            "{page}"
        );

        let mut toronto = server_node_named("toronto", "Toronto", "Canada", Health::Online, true);
        toronto.reading.as_mut().unwrap().peers = vec![crate::link::PeerReading {
            public_key: phone.clone(),
            online: true,
            handshake_age: Some(20),
            rx: 1,
            tx: 1,
        }];
        board_of(&h, vec![toronto]);
        let page = get(&h, "/account", Some(&cookie)).await.body;
        assert!(
            page.contains("Connected now, through Toronto (AmneziaWG)"),
            "{page}"
        );
        assert!(
            page.contains("No connection seen since the website last started"),
            "the laptop: {page}"
        );
    }

    #[tokio::test]
    async fn someone_can_delete_their_own_account_after_typing_delete() {
        let h = two_accounts();
        two_servers(&h);
        let who = lao_ready(&h).await;
        assert_eq!(add_device(&h, &who, "phone").await.status, 200);
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        assert!(page.contains("action=\"/account/delete\""), "{page}");
        assert!(page.contains("Delete my account"), "{page}");

        let cookie = sign_in(&h).await;
        let account = get(&h, "/account", Some(&cookie)).await.body;
        let csrf = csrf_in(&account);
        let header = session_header(&cookie);
        for wrong in ["", "yes", "delete it"] {
            let r = post(
                &h,
                "/account/delete",
                &format!("csrf={csrf}&confirm={}", wrong.replace(' ', "+")),
                &[("cookie", header.as_str())],
            )
            .await;
            assert_eq!(r.status, 400, "{wrong:?}: {}", r.body);
            assert_eq!(
                count(&h, "SELECT COUNT(*) FROM accounts WHERE id = 1"),
                1,
                "{wrong:?}"
            );
        }

        let r = post(
            &h,
            "/account/delete",
            &format!("csrf={csrf}&confirm=+Delete+"),
            &[("cookie", header.as_str())],
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("Your account is deleted"), "{}", r.body);
        assert!(
            r.header("set-cookie")
                .is_some_and(|c| c.contains("Max-Age=0")),
            "{r:?}"
        );
        assert_eq!(count(&h, "SELECT COUNT(*) FROM accounts WHERE id = 1"), 0);
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM devices WHERE account_id = 1"),
            0
        );
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM sessions WHERE account_id = 1"),
            0
        );
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM accounts WHERE id = 2"),
            1,
            "sam stays"
        );
        let after = get(&h, "/account", Some(&cookie)).await;
        assert_eq!(after.header("location"), Some("/signin"));
    }

    #[tokio::test]
    async fn deleting_your_account_asks_the_poller_for_a_pass_so_its_devices_leave_at_once() {
        let h = lao();
        let pokes = with_server(&h);
        let cookie = sign_in(&h).await;
        let account = get(&h, "/account", Some(&cookie)).await.body;
        let r = post(
            &h,
            "/account/delete",
            &format!("csrf={}&confirm=delete", csrf_in(&account)),
            &[("cookie", session_header(&cookie).as_str())],
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(pokes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_admin_cannot_delete_their_own_account_from_the_account_page() {
        let h = two_accounts();
        h.app.store.lock().unwrap().set_admin(1, true).unwrap();
        let cookie = sign_in(&h).await;
        let account = get(&h, "/account", Some(&cookie)).await.body;
        assert!(!account.contains("action=\"/account/delete\""), "{account}");
        let r = post(
            &h,
            "/account/delete",
            &format!("csrf={}&confirm=delete", csrf_in(&account)),
            &[("cookie", session_header(&cookie).as_str())],
        )
        .await;
        assert_eq!(r.status, 403, "{}", r.body);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM accounts WHERE id = 1"), 1);
    }

    fn two_accounts() -> Harness {
        harness(&[
            ("lao", Some("lao@example.com")),
            ("sam", Some("sam@example.com")),
        ])
    }

    const SERVER_PUBLIC: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";

    fn server_node(health: Health, up: bool) -> crate::poller::NodeView {
        server_node_named("toronto", "Toronto", "Canada", health, up)
    }

    fn server_node_named(
        name: &str,
        title: &str,
        place: &str,
        health: Health,
        up: bool,
    ) -> crate::poller::NodeView {
        crate::poller::NodeView {
            name: name.to_string(),
            title: title.to_string(),
            place: place.to_string(),
            protocol: Some(crate::protocol::Protocol::AmneziaWg),
            location: None,
            ip: "192.0.2.7".parse().unwrap(),
            health,
            checked_at: T0,
            last_good: Some(T0),
            reading: up.then(|| crate::link::NodeReading {
                wg_public_key: SERVER_PUBLIC.to_string(),
                listen_port: 51820,
                online: 0,
                peers_total: 0,
                desired_version: Some(1),
                load1: None,
                peers: Vec::new(),
                logins: None,
            }),
            problem: None,
            in_sync: true,
            note: None,
        }
    }

    /// Connects a poller whose one node is up; returns how many times it was poked.
    fn with_server(h: &Harness) -> Arc<std::sync::atomic::AtomicUsize> {
        let board = Board::new();
        board.set_for_test(vec![server_node(Health::Online, true)], T0);
        let pokes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = pokes.clone();
        h.app.connect_poller(
            board,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        pokes
    }

    fn field_in(html: &str, name: &str) -> String {
        let needle = format!("name=\"{name}\" value=\"");
        let at = html
            .find(&needle)
            .unwrap_or_else(|| panic!("a {name} field in {html}"));
        html[at + needle.len()..]
            .split('"')
            .next()
            .unwrap()
            .to_string()
    }

    fn base64_decode(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut count = 0;
        let mut out = Vec::new();
        for c in text.bytes().filter(|c| *c != b'=') {
            bits = (bits << 6) | ALPHABET.iter().position(|a| *a == c).unwrap() as u32;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        out
    }

    fn session_header(value: &str) -> String {
        format!("{}={value}", cookie::SESSION_COOKIE)
    }

    /// Signs in as lao and returns (cookie header, csrf token, a fresh add-a-device form id).
    async fn lao_ready(h: &Harness) -> (String, String, String) {
        let value = sign_in(h).await;
        let page = get(h, "/account", Some(&value)).await.body;
        (
            session_header(&value),
            csrf_in(&page),
            field_in(&page, "attempt"),
        )
    }

    async fn add_device(h: &Harness, who: &(String, String, String), name: &str) -> Resp {
        add_device_on(h, who, name, "Toronto", "amneziawg").await
    }

    async fn add_device_on(
        h: &Harness,
        who: &(String, String, String),
        name: &str,
        server: &str,
        protocol: &str,
    ) -> Resp {
        let body = format!(
            "csrf={}&attempt={}&name={}&server={}&protocol={}",
            who.1,
            who.2,
            name,
            server.replace(' ', "+"),
            protocol
        );
        post(h, "/account/devices", &body, &[("cookie", who.0.as_str())]).await
    }

    // ---- both protocols on every server (specs/dual-protocol.md) ----

    const WG_TORONTO: &str = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=";
    const WG_DALLAS: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

    /// One agent on the board. `server` is (title, place, IP address).
    fn agent_view(
        name: &str,
        server: (&str, &str, &str),
        protocol: Option<crate::protocol::Protocol>,
        health: Health,
        key: &str,
        port: u16,
    ) -> crate::poller::NodeView {
        let (title, place, ip) = server;
        let mut view = server_node_named(name, title, place, health, health == Health::Online);
        view.protocol = protocol;
        view.ip = ip.parse().unwrap();
        if let Some(reading) = &mut view.reading {
            reading.wg_public_key = key.to_string();
            reading.listen_port = port;
        }
        view
    }

    /// Toronto with both agents up, Dallas with only WireGuard up, Paris with an agent whose
    /// protocol is not set.
    fn two_servers(h: &Harness) {
        use crate::protocol::Protocol::{AmneziaWg, WireGuard};
        let board = Board::new();
        board.set_for_test(
            vec![
                agent_view(
                    "toronto",
                    ("Toronto", "Canada", "192.0.2.7"),
                    Some(AmneziaWg),
                    Health::Online,
                    SERVER_PUBLIC,
                    443,
                ),
                agent_view(
                    "toronto-wg",
                    ("Toronto", "Canada", "192.0.2.7"),
                    Some(WireGuard),
                    Health::Online,
                    WG_TORONTO,
                    51820,
                ),
                agent_view(
                    "dallas",
                    ("Dallas", "United States", "198.51.100.9"),
                    Some(WireGuard),
                    Health::Online,
                    WG_DALLAS,
                    51820,
                ),
                agent_view(
                    "dallas-awg",
                    ("Dallas", "United States", "198.51.100.9"),
                    Some(AmneziaWg),
                    Health::NotResponding,
                    SERVER_PUBLIC,
                    443,
                ),
                agent_view(
                    "paris",
                    ("Paris", "France", "203.0.113.5"),
                    None,
                    Health::Online,
                    SERVER_PUBLIC,
                    443,
                ),
            ],
            T0,
        );
        h.app.connect_poller(board, Arc::new(|| {}));
    }

    #[tokio::test]
    async fn the_account_page_recommends_clashmi_first_then_the_official_apps() {
        let h = lao();
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        let clashmi = page.find("<h3>ClashMi").unwrap_or_else(|| panic!("{page}"));
        let wireguard = page.find("<h3>WireGuard</h3>").unwrap();
        let amnezia = page.find("<h3>AmneziaWG</h3>").unwrap();
        assert!(clashmi < wireguard && wireguard < amnezia, "{page}");
        assert!(
            page.contains("https://apps.apple.com/app/clash-mi/id6744321968"),
            "{page}"
        );
        assert!(page.contains("https://clashmi.app/download"), "{page}");
    }

    #[tokio::test]
    async fn the_add_form_offers_the_servers_that_can_take_a_device_and_both_apps() {
        let h = two_accounts();
        two_servers(&h);
        let value = sign_in(&h).await;
        let page = get(&h, "/account", Some(&value)).await.body;

        let radios = |name: &str| -> Vec<String> {
            page.split(&format!("name=\"{name}\" value=\""))
                .skip(1)
                .map(|rest| rest.split('"').next().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            radios("server"),
            ["auto", "Toronto", "Dallas"],
            "not Paris: no protocol set"
        );
        assert_eq!(radios("protocol"), ["wireguard", "amneziawg"]);
        let checked = |value: &str| {
            let at = page.find(&format!("value=\"{value}\"")).unwrap();
            page[at..].split('>').next().unwrap().contains("checked")
        };
        assert!(
            checked("auto") && !checked("Toronto") && !checked("Dallas"),
            "Closest to you is chosen"
        );
        assert!(
            checked("wireguard") && !checked("amneziawg"),
            "WireGuard is the default"
        );
        assert!(
            page.contains("WireGuard only right now"),
            "Dallas says what it has: {page}"
        );
        assert!(page.contains("for networks that block VPNs"), "{page}");
    }

    #[tokio::test]
    async fn an_agent_that_is_not_online_is_not_offered_even_with_a_reading_left_over() {
        use crate::protocol::Protocol::AmneziaWg;
        for health in [Health::Unknown, Health::NotResponding, Health::BeingFixed] {
            let h = two_accounts();
            let mut agent = agent_view(
                "toronto",
                ("Toronto", "Canada", "192.0.2.7"),
                Some(AmneziaWg),
                Health::Online,
                SERVER_PUBLIC,
                443,
            );
            agent.health = health;
            assert!(agent.reading.is_some(), "a reading is still there");
            let board = Board::new();
            board.set_for_test(vec![agent], T0);
            h.app.connect_poller(board, Arc::new(|| {}));
            let value = sign_in(&h).await;
            let page = get(&h, "/account", Some(&value)).await.body;
            assert!(
                page.contains("no server can be reached"),
                "{health:?}: {page}"
            );
            assert!(!page.contains("name=\"server\""), "{health:?}");
            // A form sent anyway (an old page, or by hand) makes nothing either. The page has
            // no add form, so the form id is made up.
            let who = (
                session_header(&value),
                csrf_in(&page),
                "0123456789abcdef0123456789abcdef".to_string(),
            );
            let named = add_device_on(&h, &who, "x", "Toronto", "amneziawg").await;
            let closest = add_closest(&h, &who, "amneziawg", None).await;
            assert_eq!((named.status, closest.status), (503, 503), "{health:?}");
            assert_eq!(device_count(&h, 1), 0, "{health:?}");
        }
    }

    #[tokio::test]
    async fn everyone_gets_the_clashmi_profile_first_and_the_official_app_behind_a_button() {
        let h = two_accounts();
        two_servers(&h);
        let r = add_device_on(&h, &lao_ready(&h).await, "phone", "Toronto", "amneziawg").await;
        assert_eq!(r.status, 200, "{}", r.body);
        let body = &r.body;
        assert!(body.contains("Recommended: ClashMi"), "{body}");
        assert!(
            body.contains("download=\"bf-phone-clashmi.yaml\""),
            "{body}"
        );
        // The profile is in the link itself, with every connection and no trial entry.
        let link = body
            .split("download=\"bf-phone-clashmi.yaml\"")
            .next()
            .unwrap();
        let link = link.rsplit("href=\"").next().unwrap();
        assert!(link.contains("type%3A%20fallback"), "{link}");
        assert!(link.contains("Toronto%20AmneziaWG%20443"), "{link}");
        assert!(!link.contains("Trial"), "{link}");
        // The official app comes after, inside a toggle that reads plainly.
        let clashmi_at = body.find("Recommended: ClashMi").unwrap();
        let official = body
            .find("<summary>Or use the official AmneziaWG app, made by the people who made AmneziaWG</summary>")
            .unwrap_or_else(|| panic!("{body}"));
        assert!(clashmi_at < official, "{body}");
        let inside = &body[official..];
        assert!(inside.contains("download=\"bf-phone.conf\""), "{body}");
        assert!(inside.contains("class=\"qr\""), "{body}");
        assert!(inside.contains("</details>"), "{body}");
    }

    #[tokio::test]
    async fn a_wireguard_device_gets_a_plain_setup_in_its_own_range_from_that_servers_wireguard_agent()
     {
        let h = two_accounts();
        two_servers(&h);
        let who = lao_ready(&h).await;

        let r = add_device_on(&h, &who, "laptop", "Toronto", "wireguard").await;

        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("Address = 10.78.0.2/32"), "{}", r.body);
        assert!(
            r.body.contains(&format!("PublicKey = {WG_TORONTO}")),
            "{}",
            r.body
        );
        assert!(r.body.contains("Endpoint = 192.0.2.7:51820"), "{}", r.body);
        for amnezia in ["Jc =", "Jmin =", "S1 =", "H1 ="] {
            assert!(!r.body.contains(amnezia), "plain WireGuard: {amnezia}");
        }
        assert!(r.body.contains("Toronto, Canada"), "{}", r.body);
        assert!(r.body.contains("WireGuard app"), "{}", r.body);
        assert!(!r.body.contains("AmneziaWG app"), "{}", r.body);
        let stored: i64 = count(&h, "SELECT address FROM devices WHERE name = 'laptop'");
        assert_eq!(
            std::net::Ipv4Addr::from(stored as u32),
            std::net::Ipv4Addr::new(10, 77, 0, 2),
            "one address is kept; WireGuard's is the same two numbers in 10.78"
        );

        let r = add_device_on(&h, &lao_ready(&h).await, "desk", "Dallas", "wireguard").await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("Address = 10.78.0.3/32"), "{}", r.body);
        assert!(
            r.body.contains(&format!("PublicKey = {WG_DALLAS}")),
            "{}",
            r.body
        );
        assert!(
            r.body.contains("Endpoint = 198.51.100.9:51820"),
            "{}",
            r.body
        );
    }

    #[tokio::test]
    async fn an_amneziawg_device_gets_the_parameters_and_the_amneziawg_agents_key_and_port() {
        let h = two_accounts();
        two_servers(&h);
        let who = lao_ready(&h).await;

        let r = add_device_on(&h, &who, "phone", "Toronto", "amneziawg").await;

        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("Address = 10.77.0.2/32"), "{}", r.body);
        assert!(
            r.body.contains(&format!("PublicKey = {SERVER_PUBLIC}")),
            "{}",
            r.body
        );
        assert!(r.body.contains("Endpoint = 192.0.2.7:443"), "{}", r.body);
        assert!(r.body.contains("Jc = 4"), "{}", r.body);
        assert!(r.body.contains("AmneziaWG app"), "{}", r.body);
        // Amnezia documents importing the file: it comes before the QR code.
        let file = r.body.find("download=\"bf-phone.conf\"").unwrap();
        let qr = r.body.find("<div class=\"qr\"").unwrap();
        assert!(file < qr, "the file first for AmneziaWG");
    }

    #[tokio::test]
    async fn a_server_or_app_that_cannot_take_a_device_makes_nothing() {
        let h = two_accounts();
        two_servers(&h);
        // One sign-in: a refused choice does not use the form up.
        let who = lao_ready(&h).await;
        for (server, protocol, status) in [
            ("Dallas", "amneziawg", 503),
            ("Paris", "amneziawg", 503),
            ("Paris", "wireguard", 503),
            ("Atlantis", "wireguard", 503),
            ("Toronto", "openvpn", 400),
            ("Toronto", "", 400),
            ("", "wireguard", 400),
        ] {
            let r = add_device_on(&h, &who, "x", server, protocol).await;
            assert_eq!(r.status, status, "{server} {protocol}: {}", r.body);
            assert!(!r.body.contains("PrivateKey"), "{server} {protocol}");
        }
        assert_eq!(device_count(&h, 1), 0, "nothing was made");
    }

    /// Puts these agents on the board and connects it.
    fn board_of(h: &Harness, views: Vec<crate::poller::NodeView>) {
        let board = Board::new();
        board.set_for_test(views, T0);
        h.app.connect_poller(board, Arc::new(|| {}));
    }

    /// Whether the radio button with this value is checked.
    fn is_checked(page: &str, value: &str) -> bool {
        let at = page
            .find(&format!("value=\"{value}\""))
            .unwrap_or_else(|| panic!("a {value} button in {page}"));
        page[at..].split('>').next().unwrap().contains("checked")
    }

    #[tokio::test]
    async fn agents_with_one_title_are_one_server_on_the_form_even_if_their_places_differ() {
        // The form sends the title alone, so a server is its title everywhere: two places
        // under one title would be two buttons that mean the same thing.
        use crate::protocol::Protocol::{AmneziaWg, WireGuard};
        let h = two_accounts();
        board_of(
            &h,
            vec![
                agent_view(
                    "toronto",
                    ("Toronto", "Canada", "192.0.2.7"),
                    Some(AmneziaWg),
                    Health::Online,
                    SERVER_PUBLIC,
                    443,
                ),
                agent_view(
                    "toronto-wg",
                    ("Toronto", "Ontario", "192.0.2.7"),
                    Some(WireGuard),
                    Health::Online,
                    WG_TORONTO,
                    51820,
                ),
            ],
        );
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;

        assert_eq!(
            page.matches("name=\"server\" value=\"Toronto\"").count(),
            1,
            "{page}"
        );
        assert!(!page.contains("only right now"), "it has both apps: {page}");

        // Two WireGuard agents under one title are still one server with one app.
        let h = two_accounts();
        board_of(
            &h,
            vec![
                agent_view(
                    "toronto-wg",
                    ("Toronto", "Canada", "192.0.2.7"),
                    Some(WireGuard),
                    Health::Online,
                    WG_TORONTO,
                    51820,
                ),
                agent_view(
                    "toronto-wg2",
                    ("Toronto", "Canada", "192.0.2.8"),
                    Some(WireGuard),
                    Health::Online,
                    WG_DALLAS,
                    51820,
                ),
            ],
        );
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        assert_eq!(
            page.matches("name=\"server\" value=\"Toronto\"").count(),
            1,
            "{page}"
        );
        assert!(page.contains("WireGuard only right now"), "{page}");
    }

    #[tokio::test]
    async fn the_form_checks_wireguard_only_when_some_server_can_make_a_wireguard_device() {
        use crate::protocol::Protocol::{AmneziaWg, WireGuard};
        let h = two_accounts();
        board_of(
            &h,
            vec![
                agent_view(
                    "toronto",
                    ("Toronto", "Canada", "192.0.2.7"),
                    Some(AmneziaWg),
                    Health::Online,
                    SERVER_PUBLIC,
                    443,
                ),
                agent_view(
                    "toronto-wg",
                    ("Toronto", "Canada", "192.0.2.7"),
                    Some(WireGuard),
                    Health::NotResponding,
                    WG_TORONTO,
                    51820,
                ),
            ],
        );
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        assert!(
            is_checked(&page, "amneziawg") && !is_checked(&page, "wireguard"),
            "only AmneziaWG can take a device: {page}"
        );

        let h = two_accounts();
        two_servers(&h);
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        assert!(
            is_checked(&page, "wireguard") && !is_checked(&page, "amneziawg"),
            "{page}"
        );
    }

    // ---- closest to you (decision 014) ----

    const AWG_DALLAS: &str = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=";
    const MONTREAL: (&str, &str) = ("45.50", "-73.57");
    const HOUSTON: (&str, &str) = ("29.76", "-95.37");

    /// Toronto and Dallas with both agents online and their locations set. `online` is the
    /// devices online on toronto, toronto-wg, dallas and dallas-awg.
    fn located_views(online: [u64; 4]) -> Vec<crate::poller::NodeView> {
        use crate::protocol::Protocol::{AmneziaWg, WireGuard};
        let toronto = ("Toronto", "Canada", "192.0.2.7");
        let dallas = ("Dallas", "United States", "198.51.100.9");
        let mut views = vec![
            agent_view(
                "toronto",
                toronto,
                Some(AmneziaWg),
                Health::Online,
                SERVER_PUBLIC,
                443,
            ),
            agent_view(
                "toronto-wg",
                toronto,
                Some(WireGuard),
                Health::Online,
                WG_TORONTO,
                51820,
            ),
            agent_view(
                "dallas",
                dallas,
                Some(WireGuard),
                Health::Online,
                WG_DALLAS,
                51820,
            ),
            agent_view(
                "dallas-awg",
                dallas,
                Some(AmneziaWg),
                Health::Online,
                AWG_DALLAS,
                443,
            ),
        ];
        for (view, online) in views.iter_mut().zip(online) {
            view.location = Some(if view.title == "Toronto" {
                crate::closest::Location {
                    lat: 43.65,
                    lon: -79.38,
                }
            } else {
                crate::closest::Location {
                    lat: 32.78,
                    lon: -96.80,
                }
            });
            view.reading.as_mut().unwrap().online = online;
            view.reading.as_mut().unwrap().load1 = Some(0.1);
        }
        views
    }

    /// Adds a device on "Closest to you", from this location (latitude, longitude) if any.
    async fn add_closest(
        h: &Harness,
        who: &(String, String, String),
        protocol: &str,
        from: Option<(&str, &str)>,
    ) -> Resp {
        let body = format!(
            "csrf={}&attempt={}&name=phone&server=auto&protocol={protocol}",
            who.1, who.2
        );
        let mut headers = vec![("cookie", who.0.as_str())];
        if let Some((lat, lon)) = from {
            headers.push(("cf-iplatitude", lat));
            headers.push(("cf-iplongitude", lon));
        }
        post(h, "/account/devices", &body, &headers).await
    }

    #[tokio::test]
    async fn the_form_offers_closest_to_you_first_and_checked() {
        let h = two_accounts();
        board_of(&h, located_views([0; 4]));
        let page = get(&h, "/account", Some(&sign_in(&h).await)).await.body;

        let servers: Vec<&str> = page
            .split("name=\"server\" value=\"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap())
            .collect();
        assert_eq!(servers, ["auto", "Toronto", "Dallas"]);
        assert!(is_checked(&page, "auto"), "{page}");
        assert!(!is_checked(&page, "Toronto") && !is_checked(&page, "Dallas"));
        assert!(page.contains("Closest to you"), "{page}");
    }

    #[tokio::test]
    async fn closest_to_you_sends_a_person_to_the_server_nearest_them_with_the_app_they_chose() {
        let h = two_accounts();
        board_of(&h, located_views([0; 4]));

        let r = add_closest(&h, &lao_ready(&h).await, "wireguard", Some(HOUSTON)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(
            r.body.contains(&format!("PublicKey = {WG_DALLAS}")),
            "{}",
            r.body
        );
        assert!(
            r.body.contains("Endpoint = 198.51.100.9:51820"),
            "{}",
            r.body
        );
        assert!(r.body.contains("Address = 10.78."), "{}", r.body);
        assert!(r.body.contains("Dallas, United States"), "{}", r.body);
        assert!(r.body.contains("picked for you"), "{}", r.body);
        assert!(
            !r.body.contains("29.76") && !r.body.contains("95.37"),
            "the location is not shown back"
        );

        let r = add_closest(&h, &lao_ready(&h).await, "amneziawg", Some(MONTREAL)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(
            r.body.contains(&format!("PublicKey = {SERVER_PUBLIC}")),
            "{}",
            r.body
        );
        assert!(r.body.contains("Endpoint = 192.0.2.7:443"), "{}", r.body);
        assert!(r.body.contains("Jc = 4"), "{}", r.body);
        assert!(r.body.contains("Toronto, Canada"), "{}", r.body);

        // A server chosen by name says nothing about picking.
        let r = add_device_on(&h, &lao_ready(&h).await, "desk", "Dallas", "wireguard").await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(!r.body.contains("picked for you"), "{}", r.body);
    }

    #[tokio::test]
    async fn closest_to_you_skips_a_busy_server_counting_both_its_agents() {
        // 25 + 15 = 40 online on Toronto: the default cap.
        let h = two_accounts();
        board_of(&h, located_views([25, 15, 0, 0]));
        let r = add_closest(&h, &lao_ready(&h).await, "wireguard", Some(MONTREAL)).await;
        assert!(
            r.body.contains("Endpoint = 198.51.100.9:51820"),
            "{}",
            r.body
        );

        // The highest load of the two counts.
        let h = two_accounts();
        let mut views = located_views([0; 4]);
        views[1].reading.as_mut().unwrap().load1 = Some(0.95);
        board_of(&h, views);
        let r = add_closest(&h, &lao_ready(&h).await, "amneziawg", Some(MONTREAL)).await;
        assert!(r.body.contains("Endpoint = 198.51.100.9:443"), "{}", r.body);
        assert!(
            r.body.contains(&format!("PublicKey = {AWG_DALLAS}")),
            "{}",
            r.body
        );

        // The cap is a setting.
        let h = two_accounts();
        h.app.set_busy(crate::closest::Busy {
            online: 100,
            load: 0.9,
        });
        board_of(&h, located_views([25, 15, 0, 0]));
        let r = add_closest(&h, &lao_ready(&h).await, "wireguard", Some(MONTREAL)).await;
        assert!(r.body.contains("Endpoint = 192.0.2.7:51820"), "{}", r.body);
    }

    #[tokio::test]
    async fn a_server_takes_its_location_from_whichever_of_its_agents_has_one() {
        // `node set-location` run on one agent of each server only.
        let h = two_accounts();
        let mut views = located_views([0; 4]);
        views[1].location = None;
        views[2].location = None;
        board_of(&h, views);

        let r = add_closest(&h, &lao_ready(&h).await, "wireguard", Some(MONTREAL)).await;
        assert!(r.body.contains("Endpoint = 192.0.2.7:51820"), "{}", r.body);
        let r = add_closest(&h, &lao_ready(&h).await, "amneziawg", Some(HOUSTON)).await;
        assert!(r.body.contains("Endpoint = 198.51.100.9:443"), "{}", r.body);
    }

    #[tokio::test]
    async fn without_a_location_closest_to_you_takes_the_least_loaded_server() {
        let h = two_accounts();
        board_of(&h, located_views([3, 2, 1, 1]));
        let r = add_closest(&h, &lao_ready(&h).await, "wireguard", None).await;
        assert!(
            r.body.contains("Endpoint = 198.51.100.9:51820"),
            "{}",
            r.body
        );

        // A location that cannot be read is no location.
        let r = add_closest(&h, &lao_ready(&h).await, "wireguard", Some(("NaN", "1"))).await;
        assert!(
            r.body.contains("Endpoint = 198.51.100.9:51820"),
            "{}",
            r.body
        );
    }

    #[tokio::test]
    async fn closest_to_you_only_picks_a_server_that_can_make_the_app_chosen_now() {
        let h = two_accounts();
        let mut views = located_views([0; 4]);
        views[3].health = Health::NotResponding;
        views[3].reading = None;
        board_of(&h, views);
        let r = add_closest(&h, &lao_ready(&h).await, "amneziawg", Some(HOUSTON)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(
            r.body.contains("Endpoint = 192.0.2.7:443"),
            "Dallas has no AmneziaWG agent online: {}",
            r.body
        );

        let h = two_accounts();
        board_of(&h, located_views([0; 4])[..1].to_vec());
        let who = lao_ready(&h).await;
        let r = add_closest(&h, &who, "wireguard", Some(HOUSTON)).await;
        assert_eq!(r.status, 503, "{}", r.body);
        assert!(!r.body.contains("PrivateKey"));
        assert_eq!(device_count(&h, 1), 0, "nothing was made");
    }

    #[tokio::test]
    async fn the_account_and_device_pages_say_which_other_ports_to_try() {
        let h = two_accounts();
        two_servers(&h);
        let who = lao_ready(&h).await;
        let account = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        let wireguard = add_device_on(&h, &who, "laptop", "Toronto", "wireguard")
            .await
            .body;
        let amnezia = add_device_on(&h, &lao_ready(&h).await, "phone", "Toronto", "amneziawg")
            .await
            .body;

        for text in ["Endpoint", "53 or 123", "4500"] {
            assert!(account.contains(text), "account: {text}: {account}");
        }
        assert!(wireguard.contains("to 53 or 123."), "{wireguard}");
        assert!(!wireguard.contains("to 4500"), "only its own: {wireguard}");
        assert!(amnezia.contains("to 4500."), "{amnezia}");
        assert!(!amnezia.contains("53 or 123"), "only its own: {amnezia}");
        assert!(
            wireguard.contains("Endpoint = 192.0.2.7:51820")
                && amnezia.contains("Endpoint = 192.0.2.7:443"),
            "the files keep the main ports"
        );
    }

    #[tokio::test]
    async fn the_account_page_and_the_device_page_link_to_the_official_apps() {
        let h = two_accounts();
        two_servers(&h);
        let who = lao_ready(&h).await;
        let account = get(&h, "/account", Some(&sign_in(&h).await)).await.body;
        let device = add_device_on(&h, &who, "phone", "Dallas", "wireguard")
            .await
            .body;

        let wireguard = [
            "https://apps.apple.com/app/wireguard/id1441195209",
            "https://apps.apple.com/app/wireguard/id1451685025",
            "https://play.google.com/store/apps/details?id=com.wireguard.android",
            "https://download.wireguard.com/windows-client/wireguard-installer.exe",
            "https://www.wireguard.com/install/",
        ];
        let amnezia = [
            "https://apps.apple.com/app/amneziawg/id6478942365",
            "https://play.google.com/store/apps/details?id=org.amnezia.awg",
            "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest",
        ];
        for url in wireguard.iter().chain(&amnezia) {
            assert!(
                account.contains(&format!("href=\"{url}\"")),
                "account: {url}"
            );
        }
        for url in wireguard {
            assert!(device.contains(&format!("href=\"{url}\"")), "device: {url}");
        }
        for page in [&account, &device] {
            for link in page.split("<a ").skip(1) {
                let tag = link.split('>').next().unwrap();
                if tag.contains("href=\"https://") {
                    assert!(tag.contains("rel=\"noopener noreferrer\""), "{tag}");
                }
            }
        }
        assert!(account.contains("no Linux app"), "say it plainly");
    }

    fn device_count(h: &Harness, account: i64) -> i64 {
        count(
            h,
            &format!(
                "SELECT COUNT(*) FROM devices WHERE account_id = {account} AND removed_at IS NULL"
            ),
        )
    }

    #[tokio::test]
    async fn adding_a_device_shows_its_file_and_qr_code_once_and_keeps_only_the_public_key() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let who = lao_ready(&h).await;

        let r = add_device(&h, &who, "My+phone").await;

        assert_eq!(r.status, 200, "{}", r.body);
        assert_secure(&r);
        let body = &r.body;
        assert!(
            body.contains("[Interface]") && body.contains("[Peer]"),
            "{body}"
        );
        assert!(body.contains("Address = 10.77.0.2/32"), "{body}");
        assert!(
            body.contains("Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 20\n"),
            "{body}"
        );
        assert!(
            body.contains("H1 = 1000000001\nH2 = 1000000002\nH3 = 1000000003\nH4 = 1000000004\n"),
            "{body}"
        );
        assert!(
            body.contains(&format!("PublicKey = {SERVER_PUBLIC}")),
            "{body}"
        );
        assert!(body.contains("Endpoint = 192.0.2.7:51820"), "{body}");
        assert!(body.contains("AllowedIPs = 0.0.0.0/0, ::/0"), "{body}");
        assert!(body.contains("Toronto, Canada"), "{body}");
        assert!(body.contains("AmneziaWG app"), "{body}");
        // (The header's mark is a drawing too, so the code is counted by its own box.)
        assert_eq!(body.matches("<div class=\"qr\"").count(), 1, "one QR code");
        assert!(
            !body.contains("style="),
            "nothing the page's policy would block"
        );
        assert!(!body.contains("<script"), "no scripts");
        assert!(
            body.contains("download=\"bf-my-phone.conf\""),
            "a file name from the device name: {body}"
        );
        assert!(
            body.contains("href=\"data:text/plain;charset=utf-8,%5BInterface%5D"),
            "{body}"
        );
        assert!(
            body.contains("only time the private key is shown"),
            "{body}"
        );
        // Nothing on the page leaves it by a form: the key could not be shown again. The
        // footer's theme buttons, there on every other page, are left out here.
        assert!(!body.contains("<form"), "{body}");
        assert!(!body.contains("action=\"/theme\""), "{body}");

        // The key in the file is the private half of the key the database holds.
        let private = body
            .lines()
            .find_map(|line| line.strip_prefix("PrivateKey = "))
            .unwrap()
            .to_string();
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&base64_decode(&private));
        let stored: String = h
            .app
            .store
            .lock()
            .unwrap()
            .conn
            .query_row("SELECT public_key FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(KeyPair::from_private(raw).public_key, stored);
        assert_ne!(private, stored);
        assert_eq!(device_count(&h, 1), 1);
        assert_eq!(
            pokes.load(Ordering::SeqCst),
            1,
            "the poller was asked to pass now"
        );

        // And the key is nowhere else: the account page lists the device without it.
        let again = get(
            &h,
            "/account",
            Some(who.0.strip_prefix("__Host-bf_session=").unwrap()),
        )
        .await;
        assert!(
            again.body.contains("My phone") && again.body.contains("10.77.0.2"),
            "{}",
            again.body
        );
        assert!(!again.body.contains(&private) && !again.body.contains("[Interface]"));
    }

    #[tokio::test]
    async fn the_account_page_lists_devices_offers_a_form_with_a_new_id_each_time_and_escapes_names()
     {
        let h = two_accounts();
        with_server(&h);
        let value = sign_in(&h).await;
        {
            let mut store = h.app.store.lock().unwrap();
            let key = |n: u8| KeyPair::from_private([n; 32]).public_key;
            store
                .add_device(1, "<script>x</script>", &key(1), T0)
                .unwrap();
            store.add_device(2, "sams-device", &key(2), T0).unwrap();
        }

        let first = get(&h, "/account", Some(&value)).await;
        let second = get(&h, "/account", Some(&value)).await;

        assert!(
            first.body.contains("&#60;script&#62;x&#60;/script&#62;"),
            "{}",
            first.body
        );
        assert!(!first.body.contains("<script>x"), "escaped");
        assert!(!first.body.contains("sams-device"), "only its own devices");
        assert!(
            first.body.contains("10.77.0.2") && first.body.contains(&ymd(T0)),
            "{}",
            first.body
        );
        assert!(first.body.contains("action=\"/account/devices\""));
        assert!(first.body.contains("action=\"/account/devices/remove\""));
        assert_eq!(field_in(&first.body, "attempt").len(), 32);
        assert_ne!(
            field_in(&first.body, "attempt"),
            field_in(&second.body, "attempt")
        );
        assert_eq!(csrf_in(&first.body), csrf_in(&second.body));
    }

    #[tokio::test]
    async fn without_a_reachable_server_no_device_is_made_and_the_page_says_so() {
        let mut dallas =
            server_node_named("dallas", "Dallas", "United States", Health::Online, true);
        dallas.protocol = None;
        for (what, board_nodes) in [
            (
                "not responding",
                vec![server_node(Health::NotResponding, false)],
            ),
            ("unknown", vec![server_node(Health::Unknown, false)]),
            ("no nodes at all", Vec::new()),
            (
                "up but without a reading",
                vec![server_node(Health::Online, false)],
            ),
            (
                "an agent with no protocol set online, Toronto unavailable",
                vec![dallas, server_node(Health::NotResponding, false)],
            ),
        ] {
            let h = two_accounts();
            let board = Board::new();
            board.set_for_test(board_nodes, T0);
            let pokes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = pokes.clone();
            h.app.connect_poller(
                board,
                Arc::new(move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                }),
            );
            let value = sign_in(&h).await;
            let page = get(&h, "/account", Some(&value)).await.body;
            assert!(page.contains("no server can be reached"), "{what}: {page}");
            assert!(
                !page.contains("action=\"/account/devices\""),
                "{what}: no form"
            );

            let who = (session_header(&value), csrf_in(&page), "0".repeat(32));
            let r = add_device(&h, &who, "phone").await;

            assert_eq!(r.status, 503, "{what}");
            assert!(
                r.body.contains("None was made") || r.body.contains("none was made"),
                "{what}: {}",
                r.body
            );
            assert_eq!(device_count(&h, 1), 0, "{what}");
            assert_eq!(pokes.load(Ordering::SeqCst), 0, "{what}");
        }
    }

    #[tokio::test]
    async fn a_board_that_has_gone_stale_means_no_server_either() {
        let h = two_accounts();
        with_server(&h);
        let who = lao_ready(&h).await;
        h.now.store(T0 + 10_000, Ordering::SeqCst);
        let value = who
            .0
            .strip_prefix("__Host-bf_session=")
            .unwrap()
            .to_string();
        // The session itself is still good (60 days), the poller's reading is not.
        let r = add_device(&h, &who, "phone").await;

        assert_eq!(r.status, 503, "{}", r.body);
        assert_eq!(device_count(&h, 1), 0);
        let _ = value;
    }

    #[tokio::test]
    async fn until_the_poller_is_connected_adding_a_device_is_not_offered() {
        let h = two_accounts();
        let value = sign_in(&h).await;
        let page = get(&h, "/account", Some(&value)).await.body;
        assert!(page.contains("no server can be reached"), "{page}");

        let who = (session_header(&value), csrf_in(&page), "1".repeat(32));
        let r = add_device(&h, &who, "phone").await;

        assert_eq!(r.status, 503);
        assert_eq!(device_count(&h, 1), 0);
    }

    #[tokio::test]
    async fn the_add_device_form_needs_a_session_its_own_token_and_this_site() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let who = lao_ready(&h).await;
        let good = format!(
            "csrf={}&attempt={}&name=phone&server=Toronto&protocol=amneziawg",
            who.1, who.2
        );
        let with_cookie = [("cookie", who.0.as_str())];

        for body in [
            "".to_string(),
            "csrf=&attempt=00000000000000000000000000000000&name=phone".to_string(),
            format!("csrf=wrong&attempt={}&name=phone", who.2),
            format!("csrf={}&csrf={}&attempt={}&name=phone", who.1, who.1, who.2),
            format!("attempt={}&name=phone", who.2),
        ] {
            let r = post(&h, "/account/devices", &body, &with_cookie).await;
            assert_eq!(r.status, 403, "{body:?}");
        }
        // Not signed in.
        let r = post(&h, "/account/devices", &good, &[]).await;
        assert_eq!((r.status, r.header("location")), (303, Some("/signin")));
        // From another site.
        let r = call_raw(
            &h,
            "POST",
            "/account/devices",
            &[
                FORM,
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.example"),
                with_cookie[0],
            ],
            good.as_bytes(),
        )
        .await;
        assert_eq!(r.status, 403);
        // A form id that is not 32 hex characters.
        let r = post(
            &h,
            "/account/devices",
            &format!("csrf={}&attempt=short&name=phone", who.1),
            &with_cookie,
        )
        .await;
        assert_eq!(r.status, 403);

        assert_eq!(device_count(&h, 1), 0, "nothing was made");
        assert_eq!(pokes.load(Ordering::SeqCst), 0);
        assert_eq!(
            post(&h, "/account/devices", &good, &with_cookie)
                .await
                .status,
            200
        );
    }

    #[tokio::test]
    async fn the_same_form_makes_one_device_however_often_it_is_sent() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let who = lao_ready(&h).await;

        let first = add_device(&h, &who, "phone").await;
        let reload = add_device(&h, &who, "phone").await;
        let again = add_device(&h, &who, "other").await;

        assert_eq!(first.status, 200);
        assert_eq!(reload.status, 409);
        assert_eq!(again.status, 409);
        assert!(reload.body.contains("already made"), "{}", reload.body);
        assert!(
            !reload.body.contains("PrivateKey"),
            "the key is not shown again"
        );
        assert_eq!(device_count(&h, 1), 1);
        assert_eq!(pokes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bad_names_and_the_device_limit_are_refused_with_a_reason_and_nothing_is_made() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let mut who = lao_ready(&h).await;

        for (n, name) in ["", "+++", &"x".repeat(65), "a%0Ab", "a%00b", "a%E2%80%AEb"]
            .into_iter()
            .enumerate()
        {
            who.2 = format!("{n:032x}");
            let r = add_device(&h, &who, name).await;
            assert_eq!(r.status, 400, "{name:?}: {}", r.body);
            assert!(r.body.contains("1 to 64 characters"), "{name:?}");
        }
        assert_eq!(device_count(&h, 1), 0);
        assert_eq!(pokes.load(Ordering::SeqCst), 0);

        for n in 0..3u32 {
            who.2 = format!("{:032x}", 100 + n);
            assert_eq!(
                add_device(&h, &who, &format!("d{n}")).await.status,
                200,
                "{n}"
            );
        }
        who.2 = format!("{:032x}", 200);
        let r = add_device(&h, &who, "fourth").await;

        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body.contains("at most 3 devices"), "{}", r.body);
        assert_eq!(device_count(&h, 1), 3);
        let page = get(
            &h,
            "/account",
            Some(who.0.strip_prefix("__Host-bf_session=").unwrap()),
        )
        .await
        .body;
        assert!(
            page.contains("limit of 3 devices") && !page.contains("action=\"/account/devices\"")
        );
    }

    #[tokio::test]
    async fn a_device_name_with_markup_is_text_on_every_page() {
        let h = two_accounts();
        with_server(&h);
        let who = lao_ready(&h).await;

        let r = add_device(&h, &who, "%3Cscript%3Ealert(1)%3C%2Fscript%3E").await;

        assert_eq!(r.status, 200);
        assert!(
            r.body.contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
            "{}",
            r.body
        );
        assert!(!r.body.contains("<script"));
        assert!(
            r.body.contains("download=\"bf-script-ale.conf\""),
            "{}",
            r.body
        );
    }

    #[tokio::test]
    async fn only_the_owner_can_remove_a_device_and_it_needs_the_token() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let who = lao_ready(&h).await;
        {
            let mut store = h.app.store.lock().unwrap();
            let key = |n: u8| KeyPair::from_private([n; 32]).public_key;
            store.add_device(1, "mine", &key(1), T0).unwrap();
            store.add_device(2, "sams", &key(2), T0).unwrap();
        }
        let with_cookie = [("cookie", who.0.as_str())];

        for body in ["device=1", "csrf=wrong&device=1"] {
            assert_eq!(
                post(&h, "/account/devices/remove", body, &with_cookie)
                    .await
                    .status,
                403,
                "{body}"
            );
        }
        for body in [
            format!("csrf={}&device=2", who.1),
            format!("csrf={}&device=99", who.1),
            format!("csrf={}&device=abc", who.1),
            format!("csrf={}", who.1),
        ] {
            let r = post(&h, "/account/devices/remove", &body, &with_cookie).await;
            assert_eq!(r.status, 404, "{body}: {}", r.body);
        }
        assert_eq!(device_count(&h, 1), 1);
        assert_eq!(device_count(&h, 2), 1, "sam's device is untouched");
        assert_eq!(pokes.load(Ordering::SeqCst), 0);

        let r = post(
            &h,
            "/account/devices/remove",
            &format!("csrf={}&device=1", who.1),
            &with_cookie,
        )
        .await;

        assert_eq!((r.status, r.header("location")), (303, Some("/account")));
        assert_eq!(device_count(&h, 1), 0);
        assert_eq!(device_count(&h, 2), 1);
        assert_eq!(pokes.load(Ordering::SeqCst), 1, "the node is told soon");
        let unsigned = post(&h, "/account/devices/remove", "csrf=x&device=2", &[]).await;
        assert_eq!(
            (unsigned.status, unsigned.header("location")),
            (303, Some("/signin"))
        );
    }

    #[tokio::test]
    async fn a_kicked_account_can_neither_add_a_device_nor_remove_the_kicked_one() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let who = lao_ready(&h).await;
        let (phone, laptop) = {
            let mut store = h.app.store.lock().unwrap();
            let key = |n: u8| KeyPair::from_private([n; 32]).public_key;
            let phone = store.add_device(1, "phone", &key(1), T0).unwrap();
            let laptop = store.add_device(1, "laptop", &key(2), T0).unwrap();
            store
                .kick(
                    phone.id,
                    crate::store::KickEnd::UntilLifted,
                    "admin",
                    "",
                    T0,
                )
                .unwrap();
            (phone.id, laptop.id)
        };
        let with_cookie = [("cookie", who.0.as_str())];

        let added = add_device(&h, &who, "new+phone").await;
        assert_eq!(added.status, 403, "{}", added.body);
        assert!(added.body.contains("switched off"), "{}", added.body);
        assert!(!added.body.contains("[Interface]"), "{}", added.body);
        let kept = post(
            &h,
            "/account/devices/remove",
            &format!("csrf={}&device={phone}", who.1),
            &with_cookie,
        )
        .await;
        assert_eq!(kept.status, 403, "{}", kept.body);
        assert!(kept.body.contains("switched off"), "{}", kept.body);
        assert_eq!(device_count(&h, 1), 2);
        assert_eq!(
            pokes.load(Ordering::SeqCst),
            0,
            "the node list is unchanged"
        );

        let r = post(
            &h,
            "/account/devices/remove",
            &format!("csrf={}&device={laptop}", who.1),
            &with_cookie,
        )
        .await;
        assert_eq!(
            (r.status, r.header("location")),
            (303, Some("/account")),
            "a device that is not kicked can still go"
        );
        assert_eq!(device_count(&h, 1), 1);
        assert_eq!(pokes.load(Ordering::SeqCst), 1, "and the node is told");
    }

    fn tracker_filter(h: &Harness, device: i64) -> i64 {
        count(
            h,
            &format!("SELECT tracker_filter FROM devices WHERE id = {device}"),
        )
    }

    #[tokio::test]
    async fn only_the_owner_can_switch_trackers_and_it_needs_the_token() {
        let h = two_accounts();
        let pokes = with_server(&h);
        let who = lao_ready(&h).await;
        {
            let mut store = h.app.store.lock().unwrap();
            let key = |n: u8| KeyPair::from_private([n; 32]).public_key;
            store.add_device(1, "mine", &key(1), T0).unwrap();
            store.add_device(2, "sams", &key(2), T0).unwrap();
        }
        let with_cookie = [("cookie", who.0.as_str())];
        let path = "/account/devices/trackers";

        for body in ["device=1&on=0", "csrf=wrong&device=1&on=0"] {
            assert_eq!(
                post(&h, path, body, &with_cookie).await.status,
                403,
                "{body}"
            );
        }
        for body in [
            format!("csrf={}&device=1", who.1),
            format!("csrf={}&device=1&on=yes", who.1),
            format!("csrf={}&device=1&on=2", who.1),
        ] {
            assert_eq!(
                post(&h, path, &body, &with_cookie).await.status,
                403,
                "{body}"
            );
        }
        for body in [
            format!("csrf={}&device=2&on=0", who.1),
            format!("csrf={}&device=99&on=0", who.1),
            format!("csrf={}&device=abc&on=0", who.1),
            format!("csrf={}&on=0", who.1),
        ] {
            let r = post(&h, path, &body, &with_cookie).await;
            assert_eq!(r.status, 404, "{body}: {}", r.body);
        }
        assert_eq!((tracker_filter(&h, 1), tracker_filter(&h, 2)), (1, 1));
        assert_eq!(pokes.load(Ordering::SeqCst), 0);

        let r = post(
            &h,
            path,
            &format!("csrf={}&device=1&on=0", who.1),
            &with_cookie,
        )
        .await;

        assert_eq!((r.status, r.header("location")), (303, Some("/account")));
        assert_eq!((tracker_filter(&h, 1), tracker_filter(&h, 2)), (0, 1));
        // No poke: the poller's own pass (every 10 s) publishes it. A poke per press would let
        // anyone signed in run the poller once a second, and each pass moves the signing time
        // of every node ahead of the clock (`Link::next_time`) until the agents refuse it.
        assert_eq!(pokes.load(Ordering::SeqCst), 0);
        assert!(
            !h.app.store.lock().unwrap().publish(T0).unwrap().peers[0].trackers,
            "the next pass carries it"
        );

        let r = post(
            &h,
            path,
            &format!("csrf={}&device=1&on=1", who.1),
            &with_cookie,
        )
        .await;
        assert_eq!(r.status, 303);
        assert_eq!(tracker_filter(&h, 1), 1);
        assert_eq!(pokes.load(Ordering::SeqCst), 0);

        let unsigned = post(&h, path, "csrf=x&device=2&on=0", &[]).await;
        assert_eq!(
            (unsigned.status, unsigned.header("location")),
            (303, Some("/signin"))
        );

        // From another site, with a good token and the session: refused, nothing changes.
        let r = call_raw(
            &h,
            "POST",
            path,
            &[
                FORM,
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.example"),
                with_cookie[0],
            ],
            format!("csrf={}&device=1&on=0", who.1).as_bytes(),
        )
        .await;
        assert_eq!(r.status, 403);
        assert_eq!(tracker_filter(&h, 1), 1);
    }

    #[tokio::test]
    async fn the_account_page_shows_each_devices_tracker_state_and_the_button_that_flips_it() {
        let h = two_accounts();
        let _pokes = with_server(&h);
        let who = lao_ready(&h).await;
        {
            let mut store = h.app.store.lock().unwrap();
            let key = |n: u8| KeyPair::from_private([n; 32]).public_key;
            store.add_device(1, "blocked-one", &key(1), T0).unwrap();
            let off = store.add_device(1, "allowed-one", &key(2), T0).unwrap();
            store.set_tracker_filter(1, off.id, false).unwrap();
        }

        let page = call_raw(&h, "GET", "/account", &[("cookie", &who.0)], b"")
            .await
            .body;

        let row = |name: &str| {
            let start = page.find(name).unwrap_or_else(|| panic!("{name}: {page}"));
            let end = page[start..].find("</li>").unwrap() + start;
            page[start..end].to_string()
        };
        let blocked = row("blocked-one");
        assert!(blocked.contains("Trackers&nbsp;blocked"), "{blocked}");
        assert!(
            blocked.contains("action=\"/account/devices/trackers\""),
            "{blocked}"
        );
        assert!(blocked.contains("name=\"on\" value=\"0\""), "{blocked}");
        assert!(blocked.contains(">Allow trackers</button>"), "{blocked}");
        let allowed = row("allowed-one");
        assert!(allowed.contains("Trackers&nbsp;allowed"), "{allowed}");
        assert!(allowed.contains("name=\"on\" value=\"1\""), "{allowed}");
        assert!(allowed.contains(">Block trackers</button>"), "{allowed}");
        assert_eq!(
            page.matches(&format!("value=\"{}\"", who.1)).count(),
            page.matches("name=\"csrf\"").count()
        );
        // Files made before blocking started name 1.1.1.1, which the switch cannot reach.
        assert!(
            page.contains("Blocking works through the DNS in a device&rsquo;s setup."),
            "{page}"
        );
        assert!(page.contains("remove it and add it again"), "{page}");
    }

    #[tokio::test]
    async fn the_device_routes_take_post_only() {
        let h = two_accounts();
        for path in [
            "/account/devices",
            "/account/devices/remove",
            "/account/devices/trackers",
        ] {
            for method in ["GET", "HEAD", "PUT", "DELETE"] {
                let r = call_raw(&h, method, path, &[], b"").await;
                assert_eq!(r.status, 405, "{method} {path}");
                assert_eq!(r.header("allow"), Some("POST"), "{method} {path}");
            }
        }
    }

    #[test]
    fn a_date_is_written_year_month_day_in_utc() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(86_399), "1970-01-01");
        assert_eq!(ymd(86_400), "1970-01-02");
        assert_eq!(ymd(365 * 86_400), "1971-01-01");
        assert_eq!(ymd(T0), "2024-10-04");
        assert_eq!(ymd(1_709_164_800), "2024-02-29", "a leap day");
        assert_eq!(ymd(1_709_251_200), "2024-03-01");
        assert_eq!(ymd(4_102_444_800), "2100-01-01");
    }
}
