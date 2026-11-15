//! The admin pages (`specs/accounts-and-admin.md`, slice 5).
//!
//! Every one of them is for a signed-in admin who has also given the admin password in the
//! last half hour. Everybody else, and every path that is not one of these, gets the site's
//! ordinary 404: `web.rs` asks [`App::admin_gate`] first and only lets an admin session
//! through. A form here needs the session's token and the same-origin check like any other, and
//! what an admin does is recorded under their account label.

use askama::Template;

use std::sync::Arc;

use super::{App, Form, Reply, header, log, notice, render, server_error, ymd};
use crate::adminauth::AdminUnlock;
use crate::cli::parse_length;
use crate::cookie;
use crate::mail::check_address;
use crate::poller::Health;
use crate::store::StoreError;

#[derive(Template)]
#[template(path = "admin_unlock.html")]
struct UnlockPage<'a> {
    csrf: &'a str,
    failed: bool,
}

struct NodeRow {
    title: String,
    place: String,
    state: &'static str,
    counts: String,
    note: String,
}

#[derive(Template)]
#[template(path = "admin_overview.html")]
struct OverviewPage<'a> {
    csrf: &'a str,
    accounts: u32,
    devices: u32,
    active_kicks: u32,
    nodes: Vec<NodeRow>,
    list_line: String,
    backup_line: String,
    backup_warn: bool,
}

struct AccountDeviceRow {
    id: i64,
    name: String,
    address: String,
    added: String,
    kicked: bool,
    trackers: bool,
    seen: String,
}

#[derive(Template)]
#[template(path = "admin_account.html")]
struct AccountPage<'a> {
    csrf: &'a str,
    id: i64,
    label: String,
    made: String,
    limit: u32,
    email: bool,
    admin: bool,
    own: bool,
    devices: Vec<AccountDeviceRow>,
    kicks: Vec<KickRow>,
}

struct AccountRow {
    id: i64,
    label: String,
    devices: u32,
    limit: u32,
    admin: bool,
    email: bool,
    made: String,
}

#[derive(Template)]
#[template(path = "admin_accounts.html")]
struct AccountsPage<'a> {
    csrf: &'a str,
    rows: Vec<AccountRow>,
}

struct DeviceRow {
    id: i64,
    account: String,
    name: String,
    address: String,
    added: String,
    kicked: bool,
    trackers: bool,
}

#[derive(Template)]
#[template(path = "admin_devices.html")]
struct DevicesPage<'a> {
    csrf: &'a str,
    rows: Vec<DeviceRow>,
}

struct KickRow {
    device_id: i64,
    device_name: String,
    removed: bool,
    by: String,
    reason: String,
    started: String,
    ends: String,
    lifted: String,
}

#[derive(Template)]
#[template(path = "admin_kicks.html")]
struct KicksPage<'a> {
    csrf: &'a str,
    active: Vec<KickRow>,
    history: Vec<KickRow>,
    /// The device id from a Devices page "Kick" link, put in the form's first field.
    prefill: Option<&'a str>,
}

/// The device id in `?device=<id>` (the whole query, 1 to 12 digits), or nothing.
/// What needs attention on a server, in words for the overview (decision 031): "Needs a
/// reboot (asked by …)." and "Updates waiting: name version, …." Empty when nothing does.
fn attention_note(news: &bf_common::attention::Attention) -> String {
    let mut parts = Vec::new();
    if news.reboot {
        parts.push(if news.reboot_by.is_empty() {
            "Needs a reboot.".to_string()
        } else {
            format!("Needs a reboot (asked by {}).", news.reboot_by.join(", "))
        });
    }
    if !news.waiting.is_empty() {
        let waiting: Vec<String> = news
            .waiting
            .iter()
            .map(|w| format!("{} {}", w.name, w.version))
            .collect();
        parts.push(format!("Updates waiting: {}.", waiting.join(", ")));
    }
    parts.join(" ")
}

fn kick_prefill(query: Option<&str>) -> Option<&str> {
    let id = query?.strip_prefix("device=")?;
    (!id.is_empty() && id.len() <= 12 && id.bytes().all(|b| b.is_ascii_digit())).then_some(id)
}

/// A time for the admin pages: `2026-11-10 14:05 UTC`.
pub(super) fn stamp(secs: u64) -> String {
    format!(
        "{} {:02}:{:02} UTC",
        ymd(secs),
        secs % 86_400 / 3_600,
        secs % 3_600 / 60
    )
}

/// The admin who is asking.
struct Admin {
    /// For the log: which account did something (an id, never a label or an address).
    account_id: i64,
    csrf: String,
    label: String,
    unlocked: bool,
}

fn not_found() -> Reply {
    notice(
        404,
        "Not found",
        "There is nothing at this address.",
        "/",
        "Back to the front page",
    )
}

fn back(status: u16, heading: &str, message: &str, to: &str) -> Reply {
    notice(status, heading, message, to, "Back")
}

impl App {
    /// The paths of the admin pages. Anything else under `/admin` is an ordinary 404.
    pub fn is_admin_path(path: &str) -> bool {
        matches!(
            path,
            "/admin"
                | "/admin/unlock"
                | "/admin/lock"
                | "/admin/accounts"
                | "/admin/account"
                | "/admin/accounts/delete"
                | "/admin/devices"
                | "/admin/devices/remove"
                | "/admin/kicks"
                | "/admin/kicks/lift"
        )
    }

    /// Whether this request is from a signed-in admin, unlocked or not. `web.rs` lets a request
    /// reach an admin page only if so; everyone else gets the same 404 as for any unknown path.
    pub fn admin_gate(&self, headers: &axum::http::HeaderMap) -> bool {
        let Some(cookie) = cookie::session_from_header(header(headers, "cookie")) else {
            return false;
        };
        self.store()
            .session_is_admin(cookie, self.now())
            .unwrap_or(false)
    }

    fn admin_from_cookie(&self, cookie_value: &str) -> Result<Admin, Reply> {
        let now = self.now();
        let store = self.store();
        let session = match store.session(cookie_value, now) {
            Ok(Some(session)) => session,
            Ok(None) => return Err(not_found()),
            Err(e) => {
                log(&format!("admin: the database failed: {e}"));
                return Err(server_error());
            }
        };
        match store.is_admin(session.account_id) {
            Ok(true) => {}
            Ok(false) => return Err(not_found()),
            Err(e) => {
                log(&format!("admin: the database failed: {e}"));
                return Err(server_error());
            }
        }
        let label = match store.account(session.account_id) {
            Ok(Some(account)) => account.label,
            _ => return Err(not_found()),
        };
        let unlocked = store.admin_unlocked(cookie_value, now).unwrap_or(false);
        Ok(Admin {
            account_id: session.account_id,
            csrf: session.csrf,
            label,
            unlocked,
        })
    }

    fn admin_from_headers(&self, headers: &axum::http::HeaderMap) -> Result<Admin, Reply> {
        match cookie::session_from_header(header(headers, "cookie")) {
            Some(cookie_value) => self.admin_from_cookie(cookie_value),
            None => Err(not_found()),
        }
    }

    /// A page for an unlocked admin; a locked one is sent to the password page.
    fn admin_page(
        &self,
        headers: &axum::http::HeaderMap,
        page: impl FnOnce(&Admin) -> Reply,
    ) -> Reply {
        match self.admin_from_headers(headers) {
            Ok(admin) if admin.unlocked => page(&admin),
            Ok(_) => Reply::redirect("/admin"),
            Err(reply) => reply,
        }
    }

    /// A form from an admin: the same-origin check and the session's own token come first.
    /// With `needs_unlock` the admin password must have been given in the last half hour; a
    /// locked admin is sent to the password page and nothing is done.
    async fn admin_form(
        self: &Arc<App>,
        request: axum::extract::Request,
        what: &str,
        needs_unlock: bool,
    ) -> Result<(Admin, Form, String), Reply> {
        let (_, form, cookie_value) = self.signed_in_form(request, what).await?;
        let admin = self.admin_from_cookie(&cookie_value)?;
        if needs_unlock && !admin.unlocked {
            return Err(Reply::redirect("/admin"));
        }
        Ok((admin, form, cookie_value))
    }

    /// Asks the poller for a pass now, so a change reaches the servers in a moment.
    fn poke_poller(&self) {
        if let Some(hooks) = self.devices.get() {
            (hooks.poke)();
        }
    }

    // ---- GET pages ----

    pub(super) fn get_admin(&self, headers: &axum::http::HeaderMap) -> Reply {
        let admin = match self.admin_from_headers(headers) {
            Ok(admin) => admin,
            Err(reply) => return reply,
        };
        if !admin.unlocked {
            return render(
                200,
                &UnlockPage {
                    csrf: &admin.csrf,
                    failed: false,
                },
            );
        }
        let now = self.now();
        let overview = match self.store().admin_overview(now) {
            Ok(overview) => overview,
            Err(e) => {
                log(&format!("admin: the database failed: {e}"));
                return server_error();
            }
        };
        let (nodes, list_line) = match self.devices.get() {
            None => (
                Vec::new(),
                "The poller is not running, so the state of the servers is unknown.".to_string(),
            ),
            Some(hooks) => {
                let snapshot = hooks.board.snapshot(now);
                let rows = snapshot
                    .nodes
                    .iter()
                    .map(|node| NodeRow {
                        title: node.title.clone(),
                        place: node.place.clone(),
                        state: node.health.label(),
                        counts: match (&node.reading, node.health) {
                            (Some(reading), Health::Online) => {
                                format!("{} of {}", reading.online, reading.peers_total)
                            }
                            // No reading is "unknown", never a count of 0.
                            _ => "unknown".to_string(),
                        },
                        note: {
                            let state = match (&node.problem, node.health, node.in_sync) {
                                (Some(problem), _, _) => problem.to_string(),
                                (None, Health::Online, false) => {
                                    "does not hold the current list yet".to_string()
                                }
                                _ => String::new(),
                            };
                            let attention = node
                                .reading
                                .as_ref()
                                .and_then(|reading| reading.attention.as_ref())
                                .map(attention_note)
                                .unwrap_or_default();
                            [state, attention]
                                .into_iter()
                                .filter(|part| !part.is_empty())
                                .collect::<Vec<_>>()
                                .join(" ")
                        },
                    })
                    .collect();
                let line = match snapshot.list_version {
                    Some(version) => {
                        format!("The list the servers are given is at version {version}.")
                    }
                    None => "No list has been published to the servers yet.".to_string(),
                };
                (rows, line)
            }
        };
        let backup = match self.backup_status.get() {
            Some(path) => crate::backup::status_line(std::fs::read_to_string(path), now),
            None => crate::backup::Line {
                text: "This program was not told where the backup status is (BC_BACKUP_STATUS)."
                    .to_string(),
                warn: true,
            },
        };
        render(
            200,
            &OverviewPage {
                csrf: &admin.csrf,
                accounts: overview.accounts,
                devices: overview.devices,
                active_kicks: overview.active_kicks,
                nodes,
                list_line,
                backup_line: backup.text,
                backup_warn: backup.warn,
            },
        )
    }

    pub(super) fn get_admin_accounts(&self, headers: &axum::http::HeaderMap) -> Reply {
        self.admin_page(headers, |admin| match self.store().admin_accounts() {
            Ok(accounts) => render(
                200,
                &AccountsPage {
                    csrf: &admin.csrf,
                    rows: accounts
                        .into_iter()
                        .map(|a| AccountRow {
                            id: a.id,
                            label: a.label,
                            devices: a.devices,
                            limit: a.device_limit,
                            admin: a.is_admin,
                            email: a.has_email,
                            made: ymd(a.created_at),
                        })
                        .collect(),
                },
            ),
            Err(e) => {
                log(&format!("admin: the database failed: {e}"));
                server_error()
            }
        })
    }

    /// One account: what it is, its devices and kicks, and (unless it is your own) the form
    /// that deletes it. `?id=` names it; anything else is a 404.
    pub(super) fn get_admin_account(
        &self,
        headers: &axum::http::HeaderMap,
        query: Option<&str>,
    ) -> Reply {
        self.admin_page(headers, |admin| {
            let Some(id) = query
                .and_then(|q| q.strip_prefix("id="))
                .and_then(|id| id.parse::<i64>().ok())
            else {
                return not_found();
            };
            let now = self.now();
            let store = self.store();
            let account = match store.admin_accounts() {
                Ok(accounts) => accounts.into_iter().find(|a| a.id == id),
                Err(e) => {
                    log(&format!("admin: the database failed: {e}"));
                    return server_error();
                }
            };
            let Some(account) = account else {
                return not_found();
            };
            let (devices, kicks) = match (store.admin_devices(now), store.kicks_of_account(id)) {
                (Ok(devices), Ok(kicks)) => (devices, kicks),
                (Err(e), _) | (_, Err(e)) => {
                    log(&format!("admin: the database failed: {e}"));
                    return server_error();
                }
            };
            drop(store);
            let readings = self.devices.get().map(|hooks| hooks.board.snapshot(now));
            let keys: std::collections::HashMap<i64, String> = self
                .store()
                .devices_of(id)
                .map(|ds| ds.into_iter().map(|d| (d.id, d.public_key)).collect())
                .unwrap_or_default();
            let devices = devices
                .into_iter()
                .filter(|d| d.account_id == id)
                .map(|d| AccountDeviceRow {
                    seen: keys.get(&d.id).map_or_else(String::new, |key| {
                        crate::seen::describe(&crate::seen::seen(readings.as_ref(), key, now))
                    }),
                    id: d.id,
                    name: d.name,
                    address: d.address.to_string(),
                    added: ymd(d.created_at),
                    kicked: d.kicked,
                    trackers: d.trackers,
                })
                .collect();
            let kicks = kicks
                .into_iter()
                .rev()
                .map(|(kick, device_name, removed)| KickRow {
                    device_id: kick.device_id,
                    device_name,
                    removed,
                    by: kick.by,
                    reason: kick.reason,
                    started: stamp(kick.started_at),
                    ends: kick.until.map_or_else(|| "until lifted".to_string(), stamp),
                    lifted: match (kick.lifted_at, kick.lifted_by) {
                        (Some(at), Some(by)) => format!("{} by {by}", stamp(at)),
                        _ => String::new(),
                    },
                })
                .collect();
            render(
                200,
                &AccountPage {
                    csrf: &admin.csrf,
                    id,
                    label: account.label,
                    made: ymd(account.created_at),
                    limit: account.device_limit,
                    email: account.has_email,
                    admin: account.is_admin,
                    own: id == admin.account_id,
                    devices,
                    kicks,
                },
            )
        })
    }

    pub(super) fn get_admin_devices(&self, headers: &axum::http::HeaderMap) -> Reply {
        self.admin_page(headers, |admin| {
            match self.store().admin_devices(self.now()) {
                Ok(devices) => render(
                    200,
                    &DevicesPage {
                        csrf: &admin.csrf,
                        rows: devices
                            .into_iter()
                            .map(|d| DeviceRow {
                                id: d.id,
                                account: d.account_label,
                                name: d.name,
                                address: d.address.to_string(),
                                added: ymd(d.created_at),
                                kicked: d.kicked,
                                trackers: d.trackers,
                            })
                            .collect(),
                    },
                ),
                Err(e) => {
                    log(&format!("admin: the database failed: {e}"));
                    server_error()
                }
            }
        })
    }

    pub(super) fn get_admin_kicks(
        &self,
        headers: &axum::http::HeaderMap,
        query: Option<&str>,
    ) -> Reply {
        self.admin_page(headers, |admin| {
            let now = self.now();
            let history = match self.store().kick_history(None) {
                Ok(history) => history,
                Err(e) => {
                    log(&format!("admin: the database failed: {e}"));
                    return server_error();
                }
            };
            let mut active = Vec::new();
            let mut recent = Vec::new();
            // Newest first; the history keeps the last 100.
            for (kick, device_name, removed) in history.into_iter().rev() {
                // A removed device's kick stays in force: it still holds its account
                // (decision 012), so it is shown, marked removed, with a Lift button.
                let in_force = kick.lifted_at.is_none()
                    && kick.started_at <= now
                    && kick.until.is_none_or(|until| until > now);
                let row = KickRow {
                    device_id: kick.device_id,
                    device_name,
                    removed,
                    by: kick.by,
                    reason: kick.reason,
                    started: stamp(kick.started_at),
                    ends: kick.until.map_or_else(|| "until lifted".to_string(), stamp),
                    lifted: match (kick.lifted_at, kick.lifted_by) {
                        (Some(at), Some(by)) => format!("{} by {by}", stamp(at)),
                        _ => String::new(),
                    },
                };
                if in_force {
                    active.push(row);
                } else if recent.len() < 100 {
                    recent.push(row);
                }
            }
            render(
                200,
                &KicksPage {
                    csrf: &admin.csrf,
                    active,
                    history: recent,
                    prefill: kick_prefill(query),
                },
            )
        })
    }

    // ---- forms ----

    pub(super) async fn post_admin_unlock(
        self: &Arc<App>,
        request: axum::extract::Request,
    ) -> Reply {
        let (admin, form, cookie_value) =
            match self.admin_form(request, "admin unlock", false).await {
                Ok(ok) => ok,
                Err(reply) => return reply,
            };
        let password = form.get("password").unwrap_or("");
        let result = self
            .store()
            .admin_unlock(&cookie_value, password, self.now());
        // The log says what happened; the person is told the same thing whatever went wrong.
        let id = admin.account_id;
        match &result {
            Ok(AdminUnlock::Unlocked { .. }) => log(&format!("admin: account {id} unlocked")),
            Ok(AdminUnlock::WrongPassword) => {
                log(&format!("admin: wrong admin password for account {id}"));
            }
            Ok(AdminUnlock::Locked { .. }) => {
                log(&format!(
                    "admin: account {id} tried to unlock while locked out"
                ));
            }
            Ok(AdminUnlock::NoPassword) => {
                log(&format!("admin: account {id} has no admin password set"));
            }
            Ok(_) | Err(_) => {}
        }
        match result {
            Ok(AdminUnlock::Unlocked { .. }) => Reply::redirect("/admin"),
            // Wrong, locked, no password set: the person is told the same thing.
            Ok(_) => render(
                403,
                &UnlockPage {
                    csrf: &admin.csrf,
                    failed: true,
                },
            ),
            Err(e) => {
                log(&format!("admin unlock: the database failed: {e}"));
                server_error()
            }
        }
    }

    pub(super) async fn post_admin_lock(self: &Arc<App>, request: axum::extract::Request) -> Reply {
        let (admin, _, cookie_value) = match self.admin_form(request, "admin lock", false).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        if let Err(e) = self.store().admin_lock(&cookie_value) {
            log(&format!("admin lock: the database failed: {e}"));
            return server_error();
        }
        log(&format!("admin: account {} locked", admin.account_id));
        Reply::redirect("/admin")
    }

    pub(super) async fn post_admin_accounts(
        self: &Arc<App>,
        request: axum::extract::Request,
    ) -> Reply {
        let (admin, form, _) = match self.admin_form(request, "admin account", true).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let to = "/admin/accounts";
        let label = form.get("label").unwrap_or("");
        let email = form.get("email").map(str::trim).filter(|e| !e.is_empty());
        let mut store = self.store();
        let fingerprint = match email {
            Some(address) => {
                if check_address(address).is_err() {
                    return back(
                        400,
                        "That address does not look right",
                        "A sign-in address looks like name@example.com. Nothing was made.",
                        to,
                    );
                }
                let fingerprint = self.keys.email_fingerprint(address);
                match store.account_for_email_fp(&fingerprint) {
                    Ok(None) => Some(fingerprint),
                    Ok(Some(_)) => {
                        return back(
                            409,
                            "That address is already used",
                            "Another account already signs in with that address. Nothing was made.",
                            to,
                        );
                    }
                    Err(e) => {
                        log(&format!("admin account: the database failed: {e}"));
                        return server_error();
                    }
                }
            }
            None => None,
        };
        // One transaction: never an account without the address it was given.
        match store.add_account_with_email(label, fingerprint.as_ref(), self.now()) {
            Ok(account) => {
                log(&format!(
                    "admin: account {} made account {}",
                    admin.account_id, account.id
                ));
                Reply::redirect(to)
            }
            Err(StoreError::EmailInUse) => back(
                409,
                "That address is already used",
                "Another account already signs in with that address. Nothing was made.",
                to,
            ),
            Err(StoreError::BadName) => back(
                400,
                "That label does not work",
                "A label is 1 to 64 characters with no control characters. Nothing was made.",
                to,
            ),
            Err(e) => {
                log(&format!("admin account: {e}"));
                server_error()
            }
        }
    }

    /// Deletes an account (`account`) when its label is typed exactly (`confirm`). Never the
    /// admin's own account. Its devices leave the servers on the next pass, asked for now.
    pub(super) async fn post_admin_account_delete(
        self: &Arc<App>,
        request: axum::extract::Request,
    ) -> Reply {
        let (admin, form, _) = match self.admin_form(request, "admin delete account", true).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let to = "/admin/accounts";
        let Some(id) = form.get("account").and_then(|t| t.parse::<i64>().ok()) else {
            return back(404, "No such account", "That is not an account id.", to);
        };
        if id == admin.account_id {
            return back(
                403,
                "Not your own account",
                "You cannot delete the account you are signed in with from here. Nothing was deleted.",
                to,
            );
        }
        let label = match self.store().account(id) {
            Ok(Some(account)) => account.label,
            Ok(None) => {
                return back(
                    404,
                    "No such account",
                    "There is no account with that id.",
                    to,
                );
            }
            Err(e) => {
                log(&format!("admin delete account: {e}"));
                return server_error();
            }
        };
        if form.get("confirm") != Some(label.as_str()) {
            return back(
                400,
                "The label did not match",
                "To delete an account, type its label exactly. Nothing was deleted.",
                &format!("/admin/account?id={id}"),
            );
        }
        match self.store().delete_account(id) {
            Ok(gone) => log(&format!(
                "admin: account {} deleted account {id} and its {} devices",
                admin.account_id, gone.devices
            )),
            Err(StoreError::NoSuchAccount) => {
                return back(
                    404,
                    "No such account",
                    "There is no account with that id.",
                    to,
                );
            }
            Err(e) => {
                log(&format!("admin delete account: {e}"));
                return server_error();
            }
        }
        self.poke_poller();
        Reply::redirect(to)
    }

    pub(super) async fn post_admin_device_remove(
        self: &Arc<App>,
        request: axum::extract::Request,
    ) -> Reply {
        let (admin, form, _) = match self.admin_form(request, "admin remove device", true).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let to = "/admin/devices";
        let Some(device) = form.get("device").and_then(|t| t.parse::<i64>().ok()) else {
            return back(404, "No such device", "That is not a device id.", to);
        };
        match self.store().remove_device(device, self.now()) {
            Ok(_) => log(&format!(
                "admin: account {} removed device {device}",
                admin.account_id
            )),
            Err(StoreError::NoSuchDevice) => {
                return back(
                    404,
                    "No such device",
                    "There is no live device with that id.",
                    to,
                );
            }
            Err(e) => {
                log(&format!("admin remove device: {e}"));
                return server_error();
            }
        }
        self.poke_poller();
        Reply::redirect(to)
    }

    pub(super) async fn post_admin_kick(self: &Arc<App>, request: axum::extract::Request) -> Reply {
        let (admin, form, _) = match self.admin_form(request, "admin kick", true).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let to = "/admin/kicks";
        let Some(device) = form
            .get("device")
            .and_then(|t| t.trim().parse::<i64>().ok())
        else {
            return back(404, "No such device", "That is not a device id.", to);
        };
        let now = self.now();
        // The length is required every time: no default, so no kick lasts longer than meant.
        let Some(end) = parse_length(form.get("length").unwrap_or("").trim(), now) else {
            return back(
                400,
                "Say how long",
                "A kick needs a length: a number and a unit (90s, 30m, 2h, 7d) or forever. Nothing was done.",
                to,
            );
        };
        let reason = form.get("reason").unwrap_or("").trim();
        match self.store().kick(device, end, &admin.label, reason, now) {
            Ok(_) => {}
            Err(StoreError::NoSuchDevice) => {
                return back(
                    404,
                    "No such device",
                    "There is no live device with that id.",
                    to,
                );
            }
            Err(StoreError::BadReason) => {
                return back(
                    400,
                    "That reason does not work",
                    "A reason is at most 200 characters with no control characters. Nothing was done.",
                    to,
                );
            }
            Err(e) => {
                log(&format!("admin kick: {e}"));
                return server_error();
            }
        }
        self.poke_poller();
        Reply::redirect(to)
    }

    pub(super) async fn post_admin_kick_lift(
        self: &Arc<App>,
        request: axum::extract::Request,
    ) -> Reply {
        let (admin, form, _) = match self.admin_form(request, "admin lift", true).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
        let to = "/admin/kicks";
        let Some(device) = form.get("device").and_then(|t| t.parse::<i64>().ok()) else {
            return back(404, "No such device", "That is not a device id.", to);
        };
        match self.store().lift(device, &admin.label, self.now()) {
            Ok(_) => {}
            Err(StoreError::NoSuchDevice) => {
                return back(
                    404,
                    "No such device",
                    "There is no live device with that id.",
                    to,
                );
            }
            Err(e) => {
                log(&format!("admin lift: {e}"));
                return server_error();
            }
        }
        self.poke_poller();
        Reply::redirect(to)
    }
}
