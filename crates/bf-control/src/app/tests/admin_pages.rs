//! Tests of the admin pages, included from `app.rs`'s tests so they can use its harness.

use super::super::admin::stamp;
use super::*;

const ADMIN_PASSWORD: &str = "an admin password!";

/// lao (account 1) is an admin with a password; sam (account 2) is an ordinary account.
fn admin_harness() -> Harness {
    let h = two_accounts();
    {
        let mut store = h.app.store.lock().unwrap();
        store.set_admin(1, true).unwrap();
        store.set_admin_password(1, ADMIN_PASSWORD).unwrap();
    }
    h
}

struct Ready {
    cookie: String,
    header: String,
    csrf: String,
}

/// Signs in as lao (not yet unlocked).
async fn signed_in_admin(h: &Harness) -> Ready {
    let value = sign_in(h).await;
    let page = get(h, "/admin", Some(&value)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    Ready {
        header: session_header(&value),
        csrf: csrf_in(&page.body),
        cookie: value,
    }
}

async fn admin_post(h: &Harness, who: &Ready, path: &str, fields: &str) -> Resp {
    let body = format!("csrf={}&{fields}", who.csrf);
    post(h, path, &body, &[("cookie", who.header.as_str())]).await
}

/// Signs in and gives the admin password.
async fn unlocked_admin(h: &Harness) -> Ready {
    let who = signed_in_admin(h).await;
    let r = admin_post(
        h,
        &who,
        "/admin/unlock",
        &format!("password={}", ADMIN_PASSWORD.replace(' ', "+")),
    )
    .await;
    assert_eq!(
        (r.status, r.header("location")),
        (303, Some("/admin")),
        "{}",
        r.body
    );
    who
}

fn password_field(password: &str) -> String {
    format!("password={}", password.replace(' ', "+"))
}

async fn page(h: &Harness, who: &Ready, path: &str) -> Resp {
    get(h, path, Some(&who.cookie)).await
}

fn count_rows(h: &Harness, sql: &str) -> i64 {
    count(h, sql)
}

// ---- the password page ----

#[tokio::test]
async fn a_signed_in_admin_who_has_not_given_the_password_sees_only_the_password_page() {
    let h = admin_harness();
    let who = signed_in_admin(&h).await;

    let r = page(&h, &who, "/admin").await;

    assert_eq!(r.status, 200);
    assert_secure(&r);
    assert!(
        r.body.contains("type=\"password\"") && r.body.contains("action=\"/admin/unlock\""),
        "{}",
        r.body
    );
    assert!(
        !r.body.contains("accounts") && !r.body.contains("Overview"),
        "nothing of the admin pages: {}",
        r.body
    );
    assert!(!r.body.contains("autocomplete=\"off\"") || r.body.contains("current-password"));
    for path in ["/admin/accounts", "/admin/devices", "/admin/kicks"] {
        let r = page(&h, &who, path).await;
        assert_eq!(
            (r.status, r.header("location")),
            (303, Some("/admin")),
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_right_password_opens_the_pages_and_the_cookie_is_the_same_session_cookie() {
    let h = admin_harness();
    let who = signed_in_admin(&h).await;

    let r = admin_post(&h, &who, "/admin/unlock", &password_field(ADMIN_PASSWORD)).await;

    assert_eq!((r.status, r.header("location")), (303, Some("/admin")));
    assert!(
        !r.headers.contains_key("set-cookie"),
        "no new cookie: the session is the proof"
    );
    let overview = page(&h, &who, "/admin").await;
    assert_eq!(overview.status, 200);
    assert!(
        overview.body.contains("Overview") && overview.body.contains("accounts"),
        "{}",
        overview.body
    );
    assert!(!overview.body.contains(ADMIN_PASSWORD));
}

#[tokio::test]
async fn every_way_of_failing_to_unlock_looks_the_same_and_the_password_is_never_shown() {
    // Wrong password.
    let h = admin_harness();
    let who = signed_in_admin(&h).await;
    let wrong = admin_post(
        &h,
        &who,
        "/admin/unlock",
        &password_field("not the password!"),
    )
    .await;
    assert_eq!(wrong.status, 403);
    assert!(wrong.body.contains("That did not work"), "{}", wrong.body);
    assert_secure(&wrong);
    assert!(
        !wrong.body.contains("not the password"),
        "the guess is not echoed"
    );

    // An admin who has no password yet.
    let h2 = two_accounts();
    h2.app.store.lock().unwrap().set_admin(1, true).unwrap();
    let who2 = signed_in_admin(&h2).await;
    let none = admin_post(&h2, &who2, "/admin/unlock", &password_field(ADMIN_PASSWORD)).await;

    // Locked out: five wrong tries, then the right password.
    let h3 = admin_harness();
    let who3 = signed_in_admin(&h3).await;
    for _ in 0..5 {
        admin_post(
            &h3,
            &who3,
            "/admin/unlock",
            &password_field("not the password!"),
        )
        .await;
    }
    let locked = admin_post(&h3, &who3, "/admin/unlock", &password_field(ADMIN_PASSWORD)).await;

    let normalise = |r: &Resp| r.body.replace(&csrf_in(&r.body), "TOKEN");
    for other in [&none, &locked] {
        assert_eq!(other.status, 403);
        assert_eq!(
            normalise(other),
            normalise(&wrong),
            "the same page whatever was wrong"
        );
    }
    let after = page(&h3, &who3, "/admin/accounts").await;
    assert_eq!(after.status, 303, "still locked out");
}

#[tokio::test]
async fn the_unlock_form_needs_the_sessions_token_and_this_site() {
    let h = admin_harness();
    let who = signed_in_admin(&h).await;
    let with_cookie = [("cookie", who.header.as_str())];
    let good = format!("csrf={}&{}", who.csrf, password_field(ADMIN_PASSWORD));

    for body in [
        password_field(ADMIN_PASSWORD),
        format!("csrf=wrong&{}", password_field(ADMIN_PASSWORD)),
        format!(
            "csrf={}&csrf={}&{}",
            who.csrf,
            who.csrf,
            password_field(ADMIN_PASSWORD)
        ),
    ] {
        assert_eq!(
            post(&h, "/admin/unlock", &body, &with_cookie).await.status,
            403,
            "{body}"
        );
    }
    let cross = call_raw(
        &h,
        "POST",
        "/admin/unlock",
        &[
            FORM,
            ("sec-fetch-site", "cross-site"),
            ("origin", "https://evil.example"),
            with_cookie[0],
        ],
        good.as_bytes(),
    )
    .await;
    assert_eq!(cross.status, 403);
    assert_eq!(
        page(&h, &who, "/admin/accounts").await.status,
        303,
        "nothing unlocked"
    );
    assert_eq!(
        post(&h, "/admin/unlock", &good, &with_cookie).await.status,
        303
    );
}

#[tokio::test]
async fn the_unlock_lasts_half_an_hour_and_the_lock_button_ends_it() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    assert_eq!(page(&h, &who, "/admin/accounts").await.status, 200);

    h.now.store(T0 + 30 * 60 - 1, Ordering::SeqCst);
    assert_eq!(page(&h, &who, "/admin/accounts").await.status, 200);
    h.now.store(T0 + 30 * 60, Ordering::SeqCst);
    assert_eq!(
        page(&h, &who, "/admin/accounts").await.status,
        303,
        "over at the half hour"
    );
    assert!(
        page(&h, &who, "/admin")
            .await
            .body
            .contains("type=\"password\"")
    );

    h.now.store(T0 + 10, Ordering::SeqCst);
    admin_post(&h, &who, "/admin/unlock", &password_field(ADMIN_PASSWORD)).await;
    assert_eq!(page(&h, &who, "/admin/accounts").await.status, 200);
    let r = admin_post(&h, &who, "/admin/lock", "").await;
    assert_eq!((r.status, r.header("location")), (303, Some("/admin")));
    assert_eq!(page(&h, &who, "/admin/accounts").await.status, 303);
}

// ---- who gets in ----

#[tokio::test]
async fn a_signed_out_visitor_and_an_ordinary_account_are_not_admins_for_the_gate() {
    let h = admin_harness();
    let headers = |cookie: Option<&str>| {
        let mut map = axum::http::HeaderMap::new();
        if let Some(value) = cookie {
            map.insert(
                "cookie",
                format!("{}={value}", cookie::SESSION_COOKIE)
                    .parse()
                    .unwrap(),
            );
        }
        map
    };
    assert!(!h.app.admin_gate(&headers(None)));
    assert!(!h.app.admin_gate(&headers(Some("nonsense"))));
    let sam = h.app.store.lock().unwrap().create_session(2, T0).unwrap();
    assert!(
        !h.app.admin_gate(&headers(Some(&sam.cookie))),
        "an ordinary account"
    );
    let lao = h.app.store.lock().unwrap().create_session(1, T0).unwrap();
    assert!(
        h.app.admin_gate(&headers(Some(&lao.cookie))),
        "an admin, locked or not"
    );

    h.app.store.lock().unwrap().set_admin(1, false).unwrap();
    assert!(
        !h.app.admin_gate(&headers(Some(&lao.cookie))),
        "taking admin away is at once"
    );
}

#[test]
fn the_admin_paths_are_exactly_these_and_the_ordinary_ones_do_not_include_them() {
    for yes in [
        "/admin",
        "/admin/unlock",
        "/admin/lock",
        "/admin/accounts",
        "/admin/devices",
        "/admin/devices/remove",
        "/admin/kicks",
        "/admin/kicks/lift",
    ] {
        assert!(App::is_admin_path(yes), "{yes}");
        assert!(
            !App::handles(yes),
            "{yes}: it is the gate that lets these through"
        );
    }
    for no in [
        "/admin/",
        "/Admin",
        "/admin/x",
        "/admin/accounts/",
        "/admin//accounts",
        "/administrator",
        "/account",
        "",
    ] {
        assert!(!App::is_admin_path(no), "{no}");
    }
}

#[tokio::test]
async fn the_admin_routes_take_the_right_methods_and_say_which() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let with_cookie = [("cookie", who.header.as_str())];
    for (method, path, allow) in [
        ("POST", "/admin", "GET, HEAD"),
        ("GET", "/admin/unlock", "POST"),
        ("GET", "/admin/lock", "POST"),
        ("DELETE", "/admin/accounts", "GET, HEAD, POST"),
        ("PUT", "/admin/kicks", "GET, HEAD, POST"),
        ("GET", "/admin/devices/remove", "POST"),
        ("GET", "/admin/kicks/lift", "POST"),
        ("POST", "/admin/devices", "GET, HEAD"),
    ] {
        let r = call_raw(&h, method, path, &with_cookie, b"").await;
        assert_eq!(r.status, 405, "{method} {path}");
        assert_eq!(r.header("allow"), Some(allow), "{method} {path}");
    }
}

// ---- the pages ----

#[tokio::test]
async fn the_overview_lists_a_server_that_is_switched_off_as_being_fixed_with_no_count() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let board = Board::new();
    let mut off = server_node(Health::BeingFixed, false);
    off.reading = None;
    off.problem = None;
    board.set_for_test(vec![off], T0);
    h.app.connect_poller(board, Arc::new(|| {}));

    let r = page(&h, &who, "/admin").await;

    assert!(r.body.contains("<td>Being fixed</td>"), "{}", r.body);
    assert!(r.body.contains("<td>unknown</td>"), "never a count of 0");
    assert!(!r.body.contains("0 of 0"), "{}", r.body);
}

#[tokio::test]
async fn the_overview_counts_things_and_shows_unknown_for_servers_with_no_reading_never_zero() {
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
        store
            .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
            .unwrap();
    }
    let who = unlocked_admin(&h).await;

    // No poller connected.
    let none = page(&h, &who, "/admin").await;
    assert!(
        none.body
            .contains("<strong>2</strong><span>accounts</span>"),
        "{}",
        none.body
    );
    assert!(none.body.contains("<strong>2</strong><span>devices</span>"));
    assert!(
        none.body
            .contains("<strong>0</strong><span>kicks in force</span>")
    );
    assert!(
        none.body.contains("state of the servers is unknown"),
        "{}",
        none.body
    );

    // A poller whose node answered, and one that did not.
    let board = Board::new();
    let mut up = server_node(Health::Online, true);
    up.reading.as_mut().unwrap().online = 3;
    up.reading.as_mut().unwrap().peers_total = 7;
    let mut down = server_node(Health::NotResponding, false);
    down.name = "dallas".into();
    down.title = "Dallas".into();
    down.problem = Some(crate::poller::Problem::Link(
        crate::link::LinkProblem::Unreachable,
    ));
    board.set_for_test(vec![up, down], T0);
    h.app.connect_poller(board, Arc::new(|| {}));

    let r = page(&h, &who, "/admin").await;

    assert!(
        r.body.contains("<td class=\"text\">Toronto, Canada</td>")
            && r.body.contains("<td>3 of 7</td>"),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("<td class=\"text\">Dallas, Canada</td>"),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("<td>Not responding</td>") && r.body.contains("<td>unknown</td>"),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("cannot connect"),
        "the reason is for the admin: {}",
        r.body
    );
    assert!(
        !r.body.contains("0 of 0"),
        "an unanswered server has no count"
    );
    assert!(!r.body.contains(SERVER_PUBLIC), "no key on the page");
    assert!(r.body.contains("version 1"), "{}", r.body);
}

#[tokio::test]
async fn an_account_is_made_with_a_label_and_optionally_an_address_that_is_kept_only_as_a_fingerprint()
 {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;

    let r = admin_post(
        &h,
        &who,
        "/admin/accounts",
        "label=Anna&email=anna%40example.com",
    )
    .await;

    assert_eq!(
        (r.status, r.header("location")),
        (303, Some("/admin/accounts")),
        "{}",
        r.body
    );
    let list = page(&h, &who, "/admin/accounts").await;
    assert!(list.body.contains("\">Anna</a></td>"), "{}", list.body);
    assert!(
        list.body.contains("<td>yes</td>"),
        "she has an address: {}",
        list.body
    );
    assert!(
        !list.body.contains("anna@example.com") && !list.body.contains("anna%40"),
        "never shown"
    );
    let fp = h.app.keys.email_fingerprint("anna@example.com");
    assert!(
        h.app
            .store
            .lock()
            .unwrap()
            .account_for_email_fp(&fp)
            .unwrap()
            .is_some()
    );
    let stored: i64 = count_rows(&h, "SELECT COUNT(*) FROM accounts WHERE label = 'Anna'");
    assert_eq!(stored, 1);

    let no_email = admin_post(&h, &who, "/admin/accounts", "label=Bo&email=").await;
    assert_eq!(no_email.status, 303);
    let again = h
        .app
        .store
        .lock()
        .unwrap()
        .account_for_email_fp(&h.app.keys.email_fingerprint("bo@example.com"))
        .unwrap();
    assert!(again.is_none());
}

#[tokio::test]
async fn a_bad_label_a_bad_address_or_a_used_address_make_nothing_and_say_why() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let before = count_rows(&h, "SELECT COUNT(*) FROM accounts");
    admin_post(
        &h,
        &who,
        "/admin/accounts",
        "label=Anna&email=anna%40example.com",
    )
    .await;
    let with_anna = count_rows(&h, "SELECT COUNT(*) FROM accounts");
    assert_eq!(with_anna, before + 1);

    for (fields, status, why) in [
        ("label=&email=", 400, "1 to 64 characters"),
        ("label=%20%20&email=", 400, "1 to 64 characters"),
        ("label=a%0Ab&email=", 400, "1 to 64 characters"),
        ("label=Cy&email=not-an-address", 400, "does not look right"),
        ("label=Cy&email=a%40b", 400, "does not look right"),
        ("label=Cy&email=ANNA%40example.com", 409, "already"),
        ("label=Cy&email=%20anna%40example.com%20", 409, "already"),
    ] {
        let r = admin_post(&h, &who, "/admin/accounts", fields).await;
        assert_eq!(r.status, status, "{fields}");
        assert!(r.body.contains(why), "{fields}: {}", r.body);
    }
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM accounts"),
        with_anna,
        "nothing was made"
    );
}

#[tokio::test]
async fn a_label_with_markup_is_text_on_the_accounts_page() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    admin_post(
        &h,
        &who,
        "/admin/accounts",
        "label=%3Cscript%3Ealert(1)%3C%2Fscript%3E&email=",
    )
    .await;

    let list = page(&h, &who, "/admin/accounts").await;

    assert!(
        list.body
            .contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
        "{}",
        list.body
    );
    assert!(!list.body.contains("<script"));
}

#[tokio::test]
async fn devices_are_listed_with_their_owner_and_an_admin_can_remove_one_and_the_poller_is_told() {
    let h = admin_harness();
    let pokes = with_server(&h);
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
        store
            .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
            .unwrap();
    }
    let who = unlocked_admin(&h).await;

    let list = page(&h, &who, "/admin/devices").await;
    assert!(
        list.body.contains("<td class=\"text\">phone</td>")
            && list.body.contains("<td class=\"text\">lao</td>"),
        "{}",
        list.body
    );
    assert!(
        list.body.contains("<td class=\"text\">tablet</td>")
            && list.body.contains("<td class=\"text\">sam</td>")
    );
    assert!(list.body.contains("10.77.0.2") && list.body.contains("10.77.0.3"));

    let r = admin_post(&h, &who, "/admin/devices/remove", "device=2").await;

    assert_eq!(
        (r.status, r.header("location")),
        (303, Some("/admin/devices"))
    );
    assert_eq!(
        device_count(&h, 2),
        0,
        "sam's device is gone: an admin may remove anyone's"
    );
    assert_eq!(device_count(&h, 1), 1);
    assert_eq!(pokes.load(Ordering::SeqCst), 1);
    for bad in ["device=99", "device=abc", "device=", ""] {
        let r = admin_post(&h, &who, "/admin/devices/remove", bad).await;
        assert_eq!(r.status, 404, "{bad:?}");
    }
    assert_eq!(pokes.load(Ordering::SeqCst), 1, "a refusal does not poke");
}

#[tokio::test]
async fn a_kick_needs_a_length_records_the_admin_and_can_be_lifted_and_the_poller_is_told() {
    let h = admin_harness();
    let pokes = with_server(&h);
    h.app
        .store
        .lock()
        .unwrap()
        .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
        .unwrap();
    let who = unlocked_admin(&h).await;

    for fields in [
        "device=1&length=&reason=x",
        "device=1&reason=x",
        "device=1&length=soon",
        "device=1&length=0m",
        "device=1&length=5",
    ] {
        let r = admin_post(&h, &who, "/admin/kicks", fields).await;
        assert_eq!(r.status, 400, "{fields}");
        assert!(r.body.contains("needs a length"), "{fields}");
    }
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM kicks"),
        0,
        "no length, no kick"
    );

    let r = admin_post(
        &h,
        &who,
        "/admin/kicks",
        "device=1&length=2h&reason=testing+it",
    )
    .await;

    assert_eq!(
        (r.status, r.header("location")),
        (303, Some("/admin/kicks")),
        "{}",
        r.body
    );
    let (by, reason, until): (String, String, i64) = h
        .app
        .store
        .lock()
        .unwrap()
        .conn
        .query_row("SELECT kicked_by, reason, until FROM kicks", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(
        (by.as_str(), reason.as_str()),
        ("lao", "testing it"),
        "recorded under the admin's label"
    );
    assert_eq!(until, (T0 + 2 * 3600) as i64);
    assert_eq!(pokes.load(Ordering::SeqCst), 1);
    let list = page(&h, &who, "/admin/kicks").await;
    assert!(
        list.body.contains("action=\"/admin/kicks/lift\""),
        "{}",
        list.body
    );
    assert!(list.body.contains("testing it") && list.body.contains("tablet"));
    let devices = page(&h, &who, "/admin/devices").await;
    assert!(devices.body.contains("<td>kicked</td>"), "{}", devices.body);
    let overview = page(&h, &who, "/admin").await;
    assert!(
        overview
            .body
            .contains("<strong>1</strong><span>kicks in force</span>"),
        "{}",
        overview.body
    );

    let r = admin_post(&h, &who, "/admin/kicks/lift", "device=1").await;

    assert_eq!(
        (r.status, r.header("location")),
        (303, Some("/admin/kicks"))
    );
    let (lifted_by,): (String,) = h
        .app
        .store
        .lock()
        .unwrap()
        .conn
        .query_row("SELECT lifted_by FROM kicks", [], |row| Ok((row.get(0)?,)))
        .unwrap();
    assert_eq!(lifted_by, "lao");
    assert_eq!(pokes.load(Ordering::SeqCst), 2);
    let after = page(&h, &who, "/admin/kicks").await;
    assert!(after.body.contains("No kicks in force"), "{}", after.body);
    assert!(
        after.body.contains("lifted") || after.body.contains("UTC"),
        "kept as history"
    );
}

#[tokio::test]
async fn kicking_forever_a_missing_device_or_a_bad_reason_is_handled() {
    let h = admin_harness();
    h.app
        .store
        .lock()
        .unwrap()
        .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
        .unwrap();
    let who = unlocked_admin(&h).await;

    let forever = admin_post(&h, &who, "/admin/kicks", "device=1&length=forever&reason=").await;
    assert_eq!(forever.status, 303);
    assert!(
        page(&h, &who, "/admin/kicks")
            .await
            .body
            .contains("until lifted")
    );
    assert_eq!(
        admin_post(&h, &who, "/admin/kicks", "device=99&length=1h&reason=")
            .await
            .status,
        404
    );
    assert_eq!(
        admin_post(&h, &who, "/admin/kicks", "device=x&length=1h&reason=")
            .await
            .status,
        404
    );
    let long = "r".repeat(201);
    let r = admin_post(
        &h,
        &who,
        "/admin/kicks",
        &format!("device=1&length=1h&reason={long}"),
    )
    .await;
    assert_eq!(r.status, 400);
    assert!(r.body.contains("at most 200"), "{}", r.body);
    assert_eq!(
        admin_post(&h, &who, "/admin/kicks/lift", "device=99")
            .await
            .status,
        404
    );
    assert_eq!(count_rows(&h, "SELECT COUNT(*) FROM kicks"), 1);
}

#[tokio::test]
async fn every_admin_change_needs_the_unlock_the_token_and_this_site() {
    let h = admin_harness();
    h.app
        .store
        .lock()
        .unwrap()
        .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
        .unwrap();
    let locked = signed_in_admin(&h).await;
    let cases = [
        ("/admin/accounts", "label=Anna&email="),
        ("/admin/devices/remove", "device=1"),
        ("/admin/kicks", "device=1&length=1h&reason="),
        ("/admin/kicks/lift", "device=1"),
    ];

    for (path, fields) in cases {
        // Not unlocked: sent to the password page, nothing done.
        let r = admin_post(&h, &locked, path, fields).await;
        assert_eq!(
            (r.status, r.header("location")),
            (303, Some("/admin")),
            "{path} while locked"
        );
    }
    let unlocked = unlocked_admin(&h).await;
    let with_cookie = [("cookie", unlocked.header.as_str())];
    for (path, fields) in cases {
        let no_token = post(&h, path, fields, &with_cookie).await;
        assert_eq!(no_token.status, 403, "{path} without the token");
        let wrong = post(&h, path, &format!("csrf=wrong&{fields}"), &with_cookie).await;
        assert_eq!(wrong.status, 403, "{path} with a wrong token");
        let cross = call_raw(
            &h,
            "POST",
            path,
            &[
                FORM,
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://evil.example"),
                with_cookie[0],
            ],
            format!("csrf={}&{fields}", unlocked.csrf).as_bytes(),
        )
        .await;
        assert_eq!(cross.status, 403, "{path} from another site");
    }
    assert_eq!(count_rows(&h, "SELECT COUNT(*) FROM accounts"), 2);
    assert_eq!(count_rows(&h, "SELECT COUNT(*) FROM kicks"), 0);
    assert_eq!(device_count(&h, 2), 1);
}

#[tokio::test]
async fn an_ordinary_account_cannot_use_any_admin_handler_even_if_it_gets_that_far() {
    let h = admin_harness();
    let sam = h.app.store.lock().unwrap().create_session(2, T0).unwrap();
    let header = session_header(&sam.cookie);
    let with_cookie = [("cookie", header.as_str())];
    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/devices",
        "/admin/kicks",
    ] {
        let r = call_raw(&h, "GET", path, &with_cookie, b"").await;
        assert_eq!(r.status, 404, "{path}");
        assert!(
            !r.body.contains("Overview") && !r.body.contains("password"),
            "{path}: {}",
            r.body
        );
    }
    for (path, fields) in [
        (
            "/admin/unlock",
            format!("csrf={}&{}", sam.csrf, password_field(ADMIN_PASSWORD)),
        ),
        (
            "/admin/accounts",
            format!("csrf={}&label=x&email=", sam.csrf),
        ),
        (
            "/admin/devices/remove",
            format!("csrf={}&device=1", sam.csrf),
        ),
        (
            "/admin/kicks",
            format!("csrf={}&device=1&length=1h&reason=", sam.csrf),
        ),
    ] {
        let r = post(&h, path, &fields, &with_cookie).await;
        assert_eq!(r.status, 404, "{path}");
    }
    assert_eq!(count_rows(&h, "SELECT COUNT(*) FROM accounts"), 2);
}

#[tokio::test]
async fn taking_admin_away_ends_the_session_s_access_on_the_next_request() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    assert_eq!(page(&h, &who, "/admin/accounts").await.status, 200);

    h.app.store.lock().unwrap().set_admin(1, false).unwrap();

    assert_eq!(page(&h, &who, "/admin/accounts").await.status, 404);
    let r = admin_post(&h, &who, "/admin/accounts", "label=Late&email=").await;
    assert_eq!(r.status, 404);
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM accounts WHERE label = 'Late'"),
        0
    );
}

#[tokio::test]
async fn every_admin_page_carries_the_app_headers_and_loads_nothing_from_outside() {
    let h = admin_harness();
    with_server(&h);
    let who = unlocked_admin(&h).await;

    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/devices",
        "/admin/kicks",
    ] {
        let r = page(&h, &who, path).await;
        assert_eq!(r.status, 200, "{path}");
        assert_secure(&r);
        assert!(!r.body.contains("<script"), "{path}");
        assert!(!r.body.contains("style="), "{path}");
        // The one address out is a plain link to the public source, in the menu and the footer.
        let link = "href=\"https://github.com/LAOUUUUU/opensourced\" rel=\"noopener noreferrer\"";
        assert_eq!(r.body.matches(link).count(), 2, "{path}: the source link");
        let body = r.body.replace(link, "");
        assert!(
            !body.contains("http://") && !body.contains("https://"),
            "{path}: nothing from outside"
        );
        assert!(
            r.body.contains("action=\"/admin/lock\""),
            "{path}: a lock button"
        );
    }
}

#[tokio::test]
async fn the_account_page_links_to_the_admin_pages_only_for_an_admin() {
    let h = admin_harness();
    let who = signed_in_admin(&h).await;
    let admin_page = get(&h, "/account", Some(&who.cookie)).await;
    assert!(
        admin_page.body.contains("href=\"/admin\""),
        "{}",
        admin_page.body
    );

    let sam = h.app.store.lock().unwrap().create_session(2, T0).unwrap();
    let plain = get(&h, "/account", Some(&sam.cookie)).await;
    assert!(!plain.body.contains("/admin"), "{}", plain.body);
}

#[tokio::test]
async fn the_pages_for_someone_signed_in_have_no_get_started_button_in_the_menu() {
    // "Get started" is for a visitor who is not in yet; on the account and admin pages the
    // menu keeps the account link and drops the button.
    let h = admin_harness();
    let account = "<a href=\"/account\">Account</a>";
    let signed_in = signed_in_admin(&h).await;
    for path in ["/account", "/admin"] {
        // `/admin` here is the password page, shown to an admin who has not unlocked yet.
        let r = page(&h, &signed_in, path).await;
        assert_eq!(r.status, 200, "{path}");
        assert!(!r.body.contains("Get started"), "{path}: {}", r.body);
        assert!(r.body.contains(account), "{path}");
    }
    let who = unlocked_admin(&h).await;
    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/devices",
        "/admin/kicks",
    ] {
        let r = page(&h, &who, path).await;
        assert_eq!(r.status, 200, "{path}");
        assert!(!r.body.contains("Get started"), "{path}: {}", r.body);
        assert!(r.body.contains(account), "{path}");
    }
    // The sign-in page, for someone who is not in, still has it.
    let signin = get(&h, "/signin", None).await;
    assert!(
        signin
            .body
            .contains("<a class=\"button\" href=\"/signin\">Get started</a>"),
        "{}",
        signin.body
    );
}

#[test]
fn a_time_on_an_admin_page_is_a_date_and_a_minute_in_utc() {
    assert_eq!(stamp(0), "1970-01-01 00:00 UTC");
    assert_eq!(stamp(86_399), "1970-01-01 23:59 UTC");
    assert_eq!(stamp(T0), "2024-10-04 00:16 UTC");
}

// ---- details that a run of deliberate breakages showed were not pinned yet ----

/// The `<tr>…</tr>` block of `body` that holds `needle`.
fn row_with<'a>(body: &'a str, needle: &str) -> &'a str {
    let at = body
        .find(needle)
        .unwrap_or_else(|| panic!("{needle} in {body}"));
    let start = body[..at]
        .rfind("<tr>")
        .unwrap_or_else(|| panic!("a row around {needle} in {body}"));
    let end = at + body[at..].find("</tr>").unwrap();
    &body[start..end]
}

fn cookie_headers(cookie: &str) -> axum::http::HeaderMap {
    let mut map = axum::http::HeaderMap::new();
    map.insert(
        "cookie",
        format!("{}={cookie}", cookie::SESSION_COOKIE)
            .parse()
            .unwrap(),
    );
    map
}

#[tokio::test]
async fn the_accounts_page_shows_each_accounts_id_devices_address_admin_flag_and_day() {
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
        store.add_account("kim", 3 * 86_400).unwrap();
    }
    let who = unlocked_admin(&h).await;

    let body = page(&h, &who, "/admin/accounts").await.body;

    let lao = row_with(&body, "\">lao</a></td>");
    assert!(lao.contains("<td>1</td>"), "{lao}");
    assert!(lao.contains("<td>1 of 3</td>"), "{lao}");
    assert_eq!(
        lao.matches("<td>yes</td>").count(),
        2,
        "has an address and is an admin: {lao}"
    );
    assert!(lao.contains("<td>1970-01-01</td>"), "{lao}");
    let sam = row_with(&body, "\">sam</a></td>");
    assert!(
        sam.contains("<td>2</td>") && sam.contains("<td>0 of 3</td>"),
        "{sam}"
    );
    assert!(
        sam.contains("<td>yes</td>") && sam.contains("<td>no</td>") && !sam.contains("none"),
        "has an address, is not an admin: {sam}"
    );
    let kim = row_with(&body, "\">kim</a></td>");
    assert!(kim.contains("<td>3</td>"), "{kim}");
    assert!(
        kim.contains("<td>none</td>") && kim.contains("<td>no</td>") && !kim.contains("yes"),
        "{kim}"
    );
    assert!(kim.contains("<td>1970-01-04</td>"), "{kim}");
}

#[tokio::test]
async fn the_devices_page_shows_each_devices_id_day_and_a_remove_button_for_that_device() {
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
        store
            .add_device(
                2,
                "tablet",
                &KeyPair::from_private([2; 32]).public_key,
                T0 + 5 * 86_400,
            )
            .unwrap();
    }
    let who = unlocked_admin(&h).await;

    let body = page(&h, &who, "/admin/devices").await.body;

    let phone = row_with(&body, "<td class=\"text\">phone</td>");
    assert!(phone.contains("<td>1</td>"), "{phone}");
    assert!(phone.contains("<td>2024-10-04</td>"), "{phone}");
    assert!(phone.contains("<td>ok</td>"), "{phone}");
    assert!(phone.contains("name=\"device\" value=\"1\""), "{phone}");
    let tablet = row_with(&body, "<td class=\"text\">tablet</td>");
    assert!(tablet.contains("<td>2</td>"), "{tablet}");
    assert!(tablet.contains("<td>2024-10-09</td>"), "{tablet}");
    assert!(tablet.contains("name=\"device\" value=\"2\""), "{tablet}");
}

#[tokio::test]
async fn the_kicks_page_separates_what_is_in_force_from_what_is_over_and_says_who_and_when() {
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        for (account, name, seed) in [
            (1, "phone", 1u8),
            (1, "laptop", 2),
            (1, "watch", 3),
            (2, "tablet", 4),
        ] {
            store
                .add_device(
                    account,
                    name,
                    &KeyPair::from_private([seed; 32]).public_key,
                    T0,
                )
                .unwrap();
        }
    }
    let who = unlocked_admin(&h).await;
    for fields in [
        "device=1&length=30m&reason=still+on",
        "device=2&length=30m&reason=let+off",
        "device=3&length=forever&reason=gone",
        "device=4&length=1m&reason=short",
    ] {
        let r = admin_post(&h, &who, "/admin/kicks", fields).await;
        assert_eq!(r.status, 303, "{fields}");
    }
    let r = admin_post(&h, &who, "/admin/kicks/lift", "device=2").await;
    assert_eq!(r.status, 303);
    for removed in ["device=3", "device=4"] {
        let r = admin_post(&h, &who, "/admin/devices/remove", removed).await;
        assert_eq!(r.status, 303, "{removed}");
    }
    // The one-minute kick ends exactly now: a kick is over at its end, not after it.
    h.now.store(T0 + 60, Ordering::SeqCst);

    let body = page(&h, &who, "/admin/kicks").await.body;

    let (before, history) = body
        .split_once("<h2 class=\"section-title\">History</h2>")
        .expect("a history section");
    let (_, active) = before
        .split_once("In force now</h2>")
        .expect("an in-force section");
    assert!(
        active.contains("<td class=\"text\">1 phone</td>"),
        "{active}"
    );
    assert!(active.contains("<td class=\"text\">lao</td>") && active.contains("still on"));
    assert!(
        active.contains(&format!("<td>{}</td>", stamp(T0))),
        "{active}"
    );
    assert!(
        active.contains(&format!("<td>{}</td>", stamp(T0 + 1_800))),
        "when it ends: {active}"
    );
    assert!(
        active.contains("name=\"device\" value=\"1\""),
        "the lift button is for that device: {active}"
    );
    // A removed device's kick that has not ended still holds its account (decision 012),
    // so it stays in force, marked removed, and can be lifted.
    let watch = row_with(active, "<td class=\"text\">3 watch (removed)</td>");
    assert!(
        watch.contains("gone") && watch.contains("until lifted"),
        "{watch}"
    );
    assert!(watch.contains("name=\"device\" value=\"3\""), "{watch}");
    for over in ["laptop", "tablet"] {
        assert!(!active.contains(over), "{over} is not in force: {active}");
    }
    for in_force in ["phone", "still on", "watch"] {
        assert!(!history.contains(in_force), "{in_force}: {history}");
    }

    let tablet = row_with(history, "<td class=\"text\">4 tablet (removed)</td>");
    assert!(tablet.contains("short"), "{tablet}");
    let laptop = row_with(history, "<td class=\"text\">2 laptop</td>");
    assert!(laptop.contains("<td class=\"text\">lao</td>"), "{laptop}");
    assert!(
        laptop.contains(&format!("<td>{} by lao</td>", stamp(T0))),
        "who lifted it, and when: {laptop}"
    );
    assert!(
        history.find("tablet").unwrap() < history.find("laptop").unwrap(),
        "newest first: {history}"
    );

    // If the clock steps back before a kick began, the kick has not begun: the same rule the
    // list of peers uses, so the page and the servers agree.
    h.now.store(T0 - 10, Ordering::SeqCst);
    let early = page(&h, &who, "/admin/kicks").await.body;
    assert!(early.contains("No kicks in force"), "{early}");

    // The removed watch's kick can be lifted from the page, which frees its account.
    h.now.store(T0 + 120, Ordering::SeqCst);
    let r = admin_post(&h, &who, "/admin/kicks/lift", "device=3").await;
    assert_eq!(r.status, 303);
    let body = page(&h, &who, "/admin/kicks").await.body;
    let (before, history) = body
        .split_once("<h2 class=\"section-title\">History</h2>")
        .unwrap();
    assert!(!before.contains("watch"), "{before}");
    let watch = row_with(history, "<td class=\"text\">3 watch (removed)</td>");
    assert!(
        watch.contains(&format!("<td>{} by lao</td>", stamp(T0 + 120))),
        "{watch}"
    );
}

#[tokio::test]
async fn the_kick_history_shows_the_newest_hundred_and_no_more() {
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
        for i in 0..101 {
            let end = crate::cli::parse_length("1m", T0).unwrap();
            store
                .kick(1, end, "lao", &format!("round {i:03}"), T0)
                .unwrap();
        }
    }
    h.now.store(T0 + 3_600, Ordering::SeqCst);
    let who = unlocked_admin(&h).await;

    let body = page(&h, &who, "/admin/kicks").await.body;

    assert!(
        body.contains("round 100") && body.contains("round 001"),
        "newest hundred"
    );
    assert!(!body.contains("round 000"), "the oldest is dropped");
    assert!(body.contains("No kicks in force"));
}

#[tokio::test]
async fn a_server_that_stopped_answering_shows_unknown_never_its_old_count_or_a_note() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let board = Board::new();
    let mut stale = server_node(Health::NotResponding, true);
    stale.reading.as_mut().unwrap().online = 4;
    stale.reading.as_mut().unwrap().peers_total = 9;
    stale.in_sync = false;
    let mut behind = server_node_named("dallas", "Dallas", "Canada", Health::Online, true);
    behind.reading.as_mut().unwrap().online = 2;
    behind.reading.as_mut().unwrap().peers_total = 5;
    behind.in_sync = false;
    let mut unknown = server_node_named("newark", "Newark", "USA", Health::Unknown, false);
    unknown.in_sync = false;
    board.set_for_test(vec![stale, behind, unknown], T0);
    h.app.connect_poller(board, Arc::new(|| {}));

    let body = page(&h, &who, "/admin").await.body;

    let toronto = row_with(&body, "<td class=\"text\">Toronto, Canada</td>");
    assert!(
        toronto.contains("<td>unknown</td>") && !toronto.contains("4 of 9"),
        "{toronto}"
    );
    assert!(!toronto.contains("does not hold"), "{toronto}");
    let dallas = row_with(&body, "<td class=\"text\">Dallas, Canada</td>");
    assert!(dallas.contains("<td>2 of 5</td>"), "{dallas}");
    assert!(
        dallas.contains("does not hold the current list yet"),
        "{dallas}"
    );
    let newark = row_with(&body, "<td class=\"text\">Newark, USA</td>");
    assert!(
        newark.contains("<td>unknown</td>") && !newark.contains("does not hold"),
        "{newark}"
    );
    assert!(
        body.contains("The list the servers are given is at version 1."),
        "{body}"
    );
}

#[tokio::test]
async fn with_a_poller_but_no_list_yet_the_overview_says_so() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    h.app.connect_poller(Board::new(), Arc::new(|| {}));

    let body = page(&h, &who, "/admin").await.body;

    assert!(
        body.contains("No list has been published to the servers yet."),
        "{body}"
    );
    assert!(
        body.contains("No server is registered"),
        "no servers, no table: {body}"
    );
}

#[tokio::test]
async fn a_dead_or_missing_session_gets_nothing_from_any_admin_page_even_if_it_gets_that_far() {
    let h = admin_harness();
    let lao = h.app.store.lock().unwrap().create_session(1, T0).unwrap();
    assert!(
        h.app.admin_gate(&cookie_headers(&lao.cookie)),
        "alive: an admin"
    );
    // Sixty-one days on, that session has run out.
    h.now.store(T0 + 61 * 86_400, Ordering::SeqCst);
    assert!(
        !h.app.admin_gate(&cookie_headers(&lao.cookie)),
        "a session that ran out is not an admin"
    );
    let header = session_header(&lao.cookie);

    for (what, extra) in [
        ("no cookie", Vec::new()),
        ("a session that ran out", vec![("cookie", header.as_str())]),
    ] {
        for path in [
            "/admin",
            "/admin/accounts",
            "/admin/devices",
            "/admin/kicks",
        ] {
            let r = call_raw(&h, "GET", path, &extra, b"").await;
            assert_eq!(r.status, 404, "{what}: {path}");
            assert!(
                !r.body.contains("Overview") && !r.body.contains("type=\"password\""),
                "{what}: {path}: {}",
                r.body
            );
        }
    }
}

#[tokio::test]
async fn when_the_database_fails_the_gate_says_no_and_the_pages_say_server_error() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    assert!(h.app.admin_gate(&cookie_headers(&who.cookie)), "before");
    h.app
        .store
        .lock()
        .unwrap()
        .conn
        .execute_batch("ALTER TABLE sessions RENAME TO sessions_gone")
        .unwrap();

    assert!(
        !h.app.admin_gate(&cookie_headers(&who.cookie)),
        "when in doubt, the answer is no"
    );
    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/devices",
        "/admin/kicks",
    ] {
        let r = page(&h, &who, path).await;
        assert_eq!(r.status, 500, "{path}: {}", r.body);
        assert!(
            !r.body.contains("Overview") && !r.body.contains("lao"),
            "{path}: no page from a failing database: {}",
            r.body
        );
    }
}

/// Every `<form …>…</form>` in `html`.
fn forms_in(html: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<form ") {
        let tail = &rest[start..];
        let end = tail.find("</form>").expect("a form is closed") + "</form>".len();
        found.push(&tail[..end]);
        rest = &tail[end..];
    }
    found
}

#[tokio::test]
async fn every_form_on_every_admin_page_would_work_in_a_browser() {
    // The tests above post by hand. This one reads the forms as the page gives them: each
    // must post, to an admin route, with the session's own token, or the button does nothing
    // useful for the person who clicks it.
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
    }
    let locked = signed_in_admin(&h).await;
    let unlock_page = page(&h, &locked, "/admin").await;
    let who = unlocked_admin(&h).await;
    let r = admin_post(&h, &who, "/admin/kicks", "device=1&length=1h&reason=").await;
    assert_eq!(r.status, 303);

    let mut seen = Vec::new();
    for (path, html) in [
        ("/admin (password)", unlock_page.body),
        ("/admin", page(&h, &who, "/admin").await.body),
        (
            "/admin/accounts",
            page(&h, &who, "/admin/accounts").await.body,
        ),
        (
            "/admin/devices",
            page(&h, &who, "/admin/devices").await.body,
        ),
        ("/admin/kicks", page(&h, &who, "/admin/kicks").await.body),
    ] {
        let token = if path.contains("password") {
            &locked.csrf
        } else {
            &who.csrf
        };
        let (theme, forms): (Vec<_>, Vec<_>) = forms_in(&html)
            .into_iter()
            .partition(|form| form.starts_with("<form class=\"theme\""));
        // The footer's theme buttons are the same public form on every page: no token.
        assert_eq!(theme.len(), 1, "{path}");
        assert!(theme[0].contains("action=\"/theme\"") && !theme[0].contains("csrf"));
        assert!(!forms.is_empty(), "{path} has a form");
        for form in forms {
            assert!(
                form.starts_with("<form method=\"post\" action=\"/"),
                "{path}: {form}"
            );
            let action = form
                .split("action=\"")
                .nth(1)
                .and_then(|t| t.split('"').next())
                .unwrap();
            assert!(
                App::is_admin_path(action),
                "{path}: {action} is an admin route"
            );
            assert!(
                form.contains(&format!(
                    "<input type=\"hidden\" name=\"csrf\" value=\"{token}\">"
                )),
                "{path}: the form to {action} carries the session's token: {form}"
            );
            seen.push(action.to_string());
        }
    }
    for needed in [
        "/admin/unlock",
        "/admin/lock",
        "/admin/accounts",
        "/admin/devices/remove",
        "/admin/kicks",
        "/admin/kicks/lift",
    ] {
        assert!(seen.iter().any(|a| a == needed), "a form posts to {needed}");
    }
}

#[tokio::test]
async fn the_kick_form_ignores_spaces_around_what_was_typed() {
    let h = admin_harness();
    h.app
        .store
        .lock()
        .unwrap()
        .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
        .unwrap();
    let who = unlocked_admin(&h).await;

    let r = admin_post(
        &h,
        &who,
        "/admin/kicks",
        "device=+1+&length=+2h+&reason=+too+loud+",
    )
    .await;

    assert_eq!(r.status, 303, "{}", r.body);
    let (reason, until): (String, i64) = h
        .app
        .store
        .lock()
        .unwrap()
        .conn
        .query_row("SELECT reason, until FROM kicks", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(reason, "too loud");
    assert_eq!(until, (T0 + 2 * 3_600) as i64);
}

#[tokio::test]
async fn an_empty_devices_page_says_so_and_a_lift_of_nonsense_is_a_plain_refusal() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;

    let body = page(&h, &who, "/admin/devices").await.body;

    assert!(body.contains("No devices yet."), "{body}");
    assert!(!body.contains("<table"), "{body}");
    for nonsense in ["device=x", "device=", ""] {
        let r = admin_post(&h, &who, "/admin/kicks/lift", nonsense).await;
        assert_eq!(r.status, 404, "{nonsense:?}");
    }
}

#[tokio::test]
async fn the_four_pages_also_answer_head_requests() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let with_cookie = [("cookie", who.header.as_str())];
    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/devices",
        "/admin/kicks",
    ] {
        let r = call_raw(&h, "HEAD", path, &with_cookie, b"").await;
        assert_eq!(r.status, 200, "HEAD {path}");
    }
}

// ---- after a look in a real browser (2026-11-10) ----

#[tokio::test]
async fn the_admin_menu_marks_the_page_you_are_on() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/devices",
        "/admin/kicks",
    ] {
        let body = page(&h, &who, path).await.body;
        let nav = body
            .split("<nav class=\"admin-nav\"")
            .nth(1)
            .unwrap()
            .split("</nav>")
            .next()
            .unwrap();
        assert_eq!(
            nav.matches("aria-current=\"page\"").count(),
            1,
            "{path}: {nav}"
        );
        assert!(
            nav.contains(&format!("<a href=\"{path}\" aria-current=\"page\">")),
            "{path}: {nav}"
        );
    }
}

#[tokio::test]
async fn each_remove_kick_and_lift_control_says_which_device_it_is_for() {
    let h = admin_harness();
    {
        let mut store = h.app.store.lock().unwrap();
        store
            .add_device(1, "phone", &KeyPair::from_private([1; 32]).public_key, T0)
            .unwrap();
        store
            .add_device(2, "tablet", &KeyPair::from_private([2; 32]).public_key, T0)
            .unwrap();
    }
    let who = unlocked_admin(&h).await;

    let devices = page(&h, &who, "/admin/devices").await.body;
    let phone = row_with(&devices, "<td class=\"text\">phone</td>");
    assert!(
        phone.contains("aria-label=\"Remove device 1, phone\""),
        "{phone}"
    );
    assert!(
        phone.contains("<a class=\"textlink\" href=\"/admin/kicks?device=1\" aria-label=\"Kick device 1, phone\">Kick</a>"),
        "{phone}"
    );
    let tablet = row_with(&devices, "<td class=\"text\">tablet</td>");
    assert!(
        tablet.contains("aria-label=\"Remove device 2, tablet\""),
        "{tablet}"
    );

    let r = admin_post(&h, &who, "/admin/kicks", "device=2&length=1h&reason=").await;
    assert_eq!(r.status, 303);
    let kicks = page(&h, &who, "/admin/kicks").await.body;
    let row = row_with(&kicks, "2 tablet");
    assert!(
        row.contains("aria-label=\"Lift the kick on device 2, tablet\""),
        "{row}"
    );
    let devices = page(&h, &who, "/admin/devices").await.body;
    assert!(
        !row_with(&devices, "<td class=\"text\">tablet</td>").contains("?device=2"),
        "a kicked device is not offered for another kick"
    );
}

#[tokio::test]
async fn the_kick_link_fills_in_the_device_and_nothing_else_gets_in() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let field = |body: &str| -> String {
        let at = body.find("id=\"kick-device\"").unwrap();
        let start = body[..at].rfind("<input").unwrap();
        let end = at + body[at..].find('>').unwrap();
        body[start..=end].to_string()
    };

    let filled = page(&h, &who, "/admin/kicks?device=42").await;
    assert_eq!(filled.status, 200);
    assert!(
        field(&filled.body).contains("value=\"42\""),
        "{}",
        field(&filled.body)
    );

    for query in [
        "",
        "?device=",
        "?device=abc",
        "?device=4%222",
        "?device=1234567890123",
        "?device=-1",
        "?x=1&device=7",
        "?device=7&device=8",
    ] {
        let r = page(&h, &who, &format!("/admin/kicks{query}")).await;
        assert_eq!(r.status, 200, "{query}");
        assert!(
            !field(&r.body).contains("value="),
            "{query}: {}",
            field(&r.body)
        );
    }
}

#[tokio::test]
async fn the_overview_says_how_the_last_backup_went() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let dir = std::env::temp_dir().join(format!("bf-admin-backup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let status = dir.join("backup-status");
    let _ = std::fs::remove_file(&status);

    // Not told where the status is: a warning too.
    let overview = page(&h, &who, "/admin").await;
    assert!(
        overview.body.contains(
            "<p class=\"note warn\">This program was not told where the backup status is"
        ),
        "{}",
        overview.body
    );

    h.app.set_backup_status(status.clone());

    let overview = page(&h, &who, "/admin").await;
    assert_eq!(overview.status, 200);
    assert!(
        overview
            .body
            .contains("<p class=\"note warn\">No backup has run yet.</p>"),
        "{}",
        overview.body
    );

    let now = h.now.load(std::sync::atomic::Ordering::SeqCst);
    std::fs::write(
        &status,
        format!("finished={}\nfile=control-x.tar.age\nsent=192.0.2.176 198.51.100.185\nfailed=\nerror=\n", now - 600),
    )
    .unwrap();
    let overview = page(&h, &who, "/admin").await;
    let line = format!(
        "<p class=\"note\">Last backup {} UTC, sent to 2 of 2 servers.</p>",
        super::super::utc_minute(now - 600)
    );
    assert!(overview.body.contains(&line), "{}", overview.body);

    std::fs::write(&status, "garbage").unwrap();
    let overview = page(&h, &who, "/admin").await;
    assert_eq!(
        overview.status, 200,
        "a bad status file is a warning, not an error"
    );
    assert!(
        overview
            .body
            .contains("class=\"note warn\">The backup status is not as expected")
    );
}

// ---- one account's page, and deleting an account ----

/// sam (account 2) with a phone that is kicked and a laptop.
fn sam_with_devices(h: &Harness) -> (i64, i64) {
    let key = |n: u8| crate::keys::KeyPair::from_private([n; 32]).public_key;
    let mut store = h.app.store.lock().unwrap();
    let phone = store.add_device(2, "sams-phone", &key(21), 1_000).unwrap();
    let laptop = store.add_device(2, "sams-laptop", &key(22), 1_001).unwrap();
    store
        .kick(
            phone.id,
            crate::store::KickEnd::UntilLifted,
            "admin",
            "spam",
            1_002,
        )
        .unwrap();
    (phone.id, laptop.id)
}

#[tokio::test]
async fn the_accounts_list_links_each_account_to_its_page() {
    let h = admin_harness();
    let who = unlocked_admin(&h).await;
    let r = page(&h, &who, "/admin/accounts").await;
    assert!(
        r.body.contains("href=\"/admin/account?id=2\""),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("href=\"/admin/account?id=1\""),
        "{}",
        r.body
    );
}

#[tokio::test]
async fn an_accounts_page_shows_its_devices_kicks_and_how_to_delete_it() {
    let h = admin_harness();
    let (phone, laptop) = sam_with_devices(&h);
    // A device of lao's, which sam's page must not show.
    h.app
        .store
        .lock()
        .unwrap()
        .add_device(
            1,
            "laos-desk",
            &crate::keys::KeyPair::from_private([23; 32]).public_key,
            1_003,
        )
        .unwrap();
    let who = unlocked_admin(&h).await;
    let r = page(&h, &who, "/admin/account?id=2").await;
    assert_eq!(r.status, 200, "{}", r.body);
    for wanted in [
        "sam",
        "sams-phone",
        "sams-laptop",
        "spam",
        "Delete this account",
    ] {
        assert!(r.body.contains(wanted), "{wanted}: {}", r.body);
    }
    assert!(
        r.body.contains(&format!("/admin/kicks?device={laptop}")),
        "{}",
        r.body
    );
    assert!(
        r.body
            .contains(&format!("name=\"device\" value=\"{phone}\"")),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("action=\"/admin/accounts/delete\""),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("name=\"account\" value=\"2\""),
        "{}",
        r.body
    );
    assert!(
        !r.body.contains("laos-desk"),
        "only this account's devices: {}",
        r.body
    );

    // Your own account: shown, but no way to delete it here.
    let own = page(&h, &who, "/admin/account?id=1").await;
    assert_eq!(own.status, 200);
    assert!(
        !own.body.contains("action=\"/admin/accounts/delete\""),
        "{}",
        own.body
    );
    assert!(own.body.contains("your own account"), "{}", own.body);

    for bad in [
        "/admin/account",
        "/admin/account?id=99",
        "/admin/account?id=x",
    ] {
        assert_eq!(page(&h, &who, bad).await.status, 404, "{bad}");
    }
}

#[tokio::test]
async fn deleting_an_account_needs_its_label_typed_and_never_your_own() {
    let h = admin_harness();
    sam_with_devices(&h);
    let who = unlocked_admin(&h).await;

    let wrong = admin_post(&h, &who, "/admin/accounts/delete", "account=2&confirm=Sam").await;
    assert_eq!(wrong.status, 400, "{}", wrong.body);
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM accounts WHERE id = 2"),
        1
    );

    let own = admin_post(&h, &who, "/admin/accounts/delete", "account=1&confirm=lao").await;
    assert_eq!(own.status, 403, "{}", own.body);
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM accounts WHERE id = 1"),
        1
    );

    let done = admin_post(&h, &who, "/admin/accounts/delete", "account=2&confirm=sam").await;
    assert_eq!(
        (done.status, done.header("location")),
        (303, Some("/admin/accounts"))
    );
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM accounts WHERE id = 2"),
        0
    );
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM devices WHERE account_id = 2"),
        0
    );
    assert_eq!(count_rows(&h, "SELECT COUNT(*) FROM kicks"), 0);

    let again = admin_post(&h, &who, "/admin/accounts/delete", "account=2&confirm=sam").await;
    assert_eq!(again.status, 404, "{}", again.body);
}

#[tokio::test]
async fn a_locked_admin_cannot_delete_an_account() {
    let h = admin_harness();
    let who = signed_in_admin(&h).await;
    let r = admin_post(&h, &who, "/admin/accounts/delete", "account=2&confirm=sam").await;
    assert_eq!((r.status, r.header("location")), (303, Some("/admin")));
    assert_eq!(
        count_rows(&h, "SELECT COUNT(*) FROM accounts WHERE id = 2"),
        1
    );
}

#[tokio::test]
async fn deleting_an_account_asks_the_poller_for_a_pass() {
    let h = admin_harness();
    let pokes = with_server(&h);
    let who = unlocked_admin(&h).await;
    let done = admin_post(&h, &who, "/admin/accounts/delete", "account=2&confirm=sam").await;
    assert_eq!(done.status, 303, "{}", done.body);
    assert_eq!(pokes.load(Ordering::SeqCst), 1);
}
