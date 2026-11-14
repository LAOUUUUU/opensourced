//! Sign-in through a real server on a real socket: the whole way from asking for a code to
//! signing out, with a recording mailer in place of Resend, and the check that the public
//! pages are untouched and sign-in is simply absent when it is not configured.

use std::sync::Arc;
use std::time::Duration;

use bf_control::app::App;
use bf_control::mail::RecordingMailer;
use bf_control::secrets::ControlKeys;
use bf_control::store::Store;
use bf_control::web::serve_with;
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use tokio::net::TcpListener;

// Since the footer's theme buttons (specs/cookies.md), the public pages have a form too, so
// both policies let a form go to this site and nowhere else.
const PUBLIC_POLICY_FORM: &str = "form-action 'self'";
const APP_POLICY_FORM: &str = "form-action 'self'";

fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

fn keys() -> ControlKeys {
    ControlKeys::from_parts([1; 32], [2; 32])
}

/// A server with sign-in on, and the mailer it was given.
async fn server_with_sign_in() -> (String, Arc<RecordingMailer>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut store = Store::open_in_memory().unwrap();
    let account = store.add_account("lao", 1_000).unwrap();
    store
        .set_email_fp(account.id, &keys().email_fingerprint("lao@example.com"))
        .unwrap();
    let mailer = Arc::new(RecordingMailer::new());
    let clock = Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let app = App::new(store, keys(), mailer.clone(), vec![base.clone()], clock);
    tokio::spawn(async move {
        let _ = serve_with(listener, Some(app), std::future::pending()).await;
    });
    (base, mailer)
}

async fn server_without_sign_in() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = serve_with(listener, None, std::future::pending()).await;
    });
    base
}

fn policy(response: &reqwest::Response) -> String {
    response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn without_sign_in_set_up_the_site_is_the_same_and_the_sign_in_paths_are_plain_404s() {
    let base = server_without_sign_in().await;
    let c = client();

    for path in ["/signin", "/verify", "/account", "/signout"] {
        let r = c.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(policy(&r).contains(PUBLIC_POLICY_FORM), "{path}");
    }
    let r = c.post(format!("{base}/signin")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let front = c.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(front.status(), StatusCode::OK);
    assert!(front.text().await.unwrap().contains("Closed beta"));
}

#[tokio::test]
async fn with_sign_in_the_public_pages_keep_their_strict_policy_and_the_sign_in_pages_get_theirs() {
    let (base, _) = server_with_sign_in().await;
    let c = client();

    let front = c.get(format!("{base}/")).send().await.unwrap();
    assert!(
        policy(&front).contains(PUBLIC_POLICY_FORM),
        "{}",
        policy(&front)
    );
    for path in ["/healthz", "/robots.txt", "/assets/site.css", "/nonsense"] {
        let r = c.get(format!("{base}{path}")).send().await.unwrap();
        assert!(policy(&r).contains(PUBLIC_POLICY_FORM), "{path}");
    }
    let signin = c.get(format!("{base}/signin")).send().await.unwrap();
    assert_eq!(signin.status(), StatusCode::OK);
    assert!(policy(&signin).contains(APP_POLICY_FORM));
    assert_eq!(signin.headers()["cache-control"], "no-store");
    assert_eq!(signin.headers()["x-robots-tag"], "noindex");
    // Every page sends a referrer only to this site, so that browsers put the real `Origin`
    // on a form post (with `no-referrer` they write `Origin: null`, which the same-origin
    // check rightly refuses). The public pages have the theme buttons, so they need it too.
    assert_eq!(front.headers()["referrer-policy"], "same-origin");
    assert_eq!(signin.headers()["referrer-policy"], "same-origin");
}

#[tokio::test]
async fn the_whole_sign_in_works_over_a_real_socket() {
    let (base, mailer) = server_with_sign_in().await;
    let c = client();
    let origin = base.clone();

    // Ask for a code.
    let asked = c
        .post(format!("{base}/signin"))
        .header("origin", &origin)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("email=lao%40example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(asked.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        asked.headers()["location"],
        "/verify",
        "a clean address: the typed address is not in it"
    );
    // The browser is asked to remember the address, for ten minutes, for this site only.
    let pending_header = asked.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(
        pending_header.starts_with("__Host-bf_pending="),
        "{pending_header}"
    );
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=600",
    ] {
        assert!(
            pending_header.contains(attribute),
            "{attribute}: {pending_header}"
        );
    }
    assert!(
        !pending_header.contains("lao@example.com"),
        "not in the clear"
    );
    let pending = pending_header.split(';').next().unwrap().to_string();

    // The verify page names the address, and without that cookie it is not available.
    let verify = c
        .get(format!("{base}/verify"))
        .header("cookie", &pending)
        .send()
        .await
        .unwrap();
    assert_eq!(verify.status(), StatusCode::OK);
    assert!(verify.text().await.unwrap().contains("lao@example.com"));
    let bare = c.get(format!("{base}/verify")).send().await.unwrap();
    assert_eq!(bare.status(), StatusCode::SEE_OTHER);
    assert_eq!(bare.headers()["location"], "/signin");
    let by_url = c
        .get(format!("{base}/verify?email=lao%40example.com"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        by_url.status(),
        StatusCode::SEE_OTHER,
        "the address is not read from the URL"
    );
    let code = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(mail) = mailer.sent().first() {
                break mail.code.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the email was sent");
    assert_eq!(mailer.sent()[0].to, "lao@example.com");

    // A form from another site is refused.
    let refused = c
        .post(format!("{base}/verify"))
        .header("origin", "https://evil.example")
        .header("cookie", &pending)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("code={code}"))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    // Type the code.
    let signed_in = c
        .post(format!("{base}/verify"))
        .header("origin", &origin)
        .header("cookie", &pending)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("code={code}"))
        .send()
        .await
        .unwrap();
    assert_eq!(signed_in.status(), StatusCode::SEE_OTHER);
    assert_eq!(signed_in.headers()["location"], "/account");
    let all_cookies: Vec<String> = signed_in
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    assert_eq!(all_cookies.len(), 2, "{all_cookies:?}");
    assert!(
        all_cookies
            .iter()
            .any(|c| c.starts_with("__Host-bf_pending=;") && c.contains("Max-Age=0")),
        "the remembered address is let go: {all_cookies:?}"
    );
    let set_cookie = signed_in.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("__Host-bf_session="), "{set_cookie}");
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=",
    ] {
        assert!(set_cookie.contains(attribute), "{attribute}: {set_cookie}");
    }
    let cookie = set_cookie.split(';').next().unwrap().to_string();

    // The account page.
    let account = c
        .get(format!("{base}/account"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(account.status(), StatusCode::OK);
    let page = account.text().await.unwrap();
    assert!(page.contains("lao"));
    let token = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_string();

    // Sign out needs the token.
    let without = c
        .post(format!("{base}/signout"))
        .header("origin", &origin)
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(without.status(), StatusCode::FORBIDDEN);
    let out = c
        .post(format!("{base}/signout"))
        .header("origin", &origin)
        .header("cookie", &cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("csrf={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(out.status(), StatusCode::SEE_OTHER);
    assert!(
        out.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );

    let after = c
        .get(format!("{base}/account"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
    assert_eq!(after.headers()["location"], "/signin");
}
