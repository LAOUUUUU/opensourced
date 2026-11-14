//! The Resend client: sends one email through `POST /emails` and maps what comes back.
//!
//! What it does about each answer (from Resend's documentation, read 2026-11-10):
//! 2xx with an `id` is sent; 409 means this idempotency key was used already, so the
//! first send stands; 429 with `daily_quota_exceeded` or `monthly_quota_exceeded` means
//! mail is paused; any other 429 and any 5xx are retried once; 401 and 403 are a problem
//! with the key or the sending domain and are not retried; other answers are refused.
//! Redirects are never followed, so the key cannot be forwarded anywhere. The key is kept
//! out of `Debug`, out of every error, and marked sensitive in the request.

use std::fmt;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use reqwest::{Url, redirect};

use crate::mail::{Email, MailError, MailFuture, Mailer, SendOutcome, check_address, signin_email};

/// What is read of an answer. Resend's answers are tiny; a bigger one is not Resend.
const MAX_ANSWER_BYTES: usize = 16 * 1024;
/// A reason that came from Resend is shown at most this long.
const MAX_REASON_CHARS: usize = 200;
/// The longest a `retry-after` is obeyed, and the pause when there is none.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(5);
const SERVER_ERROR_DELAY: Duration = Duration::from_millis(500);

/// Where Resend lives.
pub const DEFAULT_BASE_URL: &str = "https://api.resend.com";

/// The whole request, connecting and reading, has this long.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// An API key. Never shown by `Debug` and never put in an error.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    /// Takes the key as read from a file: surrounding whitespace (the final newline) is
    /// dropped; what is left must be 1 to 256 visible ASCII characters.
    pub fn new(text: &str) -> Result<ApiKey, MailError> {
        let key = text.trim();
        if key.is_empty() || key.len() > 256 || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(MailError::BadKey);
        }
        Ok(ApiKey(key.to_string()))
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey([hidden])")
    }
}

/// Sends mail through Resend.
#[derive(Clone)]
pub struct ResendClient {
    http: reqwest::Client,
    url: String,
    key: ApiKey,
    from: String,
    server_error_delay: Duration,
    max_retry_after: Duration,
}

impl fmt::Debug for ResendClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResendClient")
            .field("url", &self.url)
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

/// Whether `url` names this computer: exactly `localhost`, or a loopback address
/// (`127.0.0.1.example.com` is neither). Only such an address may be reached without TLS.
pub(crate) fn url_is_on_this_computer(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

impl ResendClient {
    /// A client for Resend at `base_url` (HTTPS, or plain HTTP on this computer only),
    /// sending as `from` (for example `Barely-Free VPN <noreply@barely-free.com>`).
    pub fn new(base_url: &str, key: ApiKey, from: &str) -> Result<ResendClient, MailError> {
        let base = Url::parse(base_url).map_err(|_| MailError::BadUrl)?;
        let on_this_computer = url_is_on_this_computer(&base);
        let scheme_ok = base.scheme() == "https" || (base.scheme() == "http" && on_this_computer);
        let plain = base.username().is_empty()
            && base.password().is_none()
            && base.query().is_none()
            && base.fragment().is_none()
            && base.path() == "/";
        if !scheme_ok || !plain {
            return Err(MailError::BadUrl);
        }
        let from = from.trim();
        if from.is_empty() || from.chars().count() > 200 || from.chars().any(char::is_control) {
            return Err(MailError::Rejected(
                "the sender must be 1 to 200 characters without control characters".to_string(),
            ));
        }
        let endpoint = base.join("emails").map_err(|_| MailError::BadUrl)?;
        Ok(ResendClient {
            http: build_http(TIMEOUT)?,
            url: endpoint.to_string(),
            key,
            from: from.to_string(),
            server_error_delay: SERVER_ERROR_DELAY,
            max_retry_after: MAX_RETRY_AFTER,
        })
    }

    /// The same client with another time limit. For tests.
    pub fn with_timeout(mut self, limit: Duration) -> ResendClient {
        if let Ok(http) = build_http(limit) {
            self.http = http;
        }
        self
    }

    /// The same client that does not wait before its one retry. For tests.
    pub fn without_retry_delays(mut self) -> ResendClient {
        self.server_error_delay = Duration::ZERO;
        self.max_retry_after = Duration::ZERO;
        self
    }

    /// Sends `email` to one address. `idempotency_key` makes a repeat of the same send
    /// safe: Resend keeps it for 24 hours.
    pub async fn send(
        &self,
        to: &str,
        email: &Email,
        idempotency_key: &str,
    ) -> Result<SendOutcome, MailError> {
        check_address(to)?;
        check_idempotency_key(idempotency_key)?;
        let body = serde_json::to_vec(&serde_json::json!({
            "from": self.from,
            "to": [to],
            "subject": email.subject,
            "html": email.html,
            "text": email.text,
        }))
        .map_err(|_| MailError::BadAnswer)?;

        let mut attempt = 0;
        loop {
            attempt += 1;
            let answer = self.post(&body, idempotency_key).await?;
            match self.judge(&answer) {
                Judged::Done(outcome) => return Ok(outcome),
                Judged::Failed(error) => return Err(error),
                Judged::Retry(wait, error) => {
                    if attempt >= 2 {
                        return Err(error);
                    }
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
    }

    /// One request. The key goes in a header marked sensitive, never in the body or URL.
    async fn post(&self, body: &[u8], idempotency_key: &str) -> Result<Answer, MailError> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", self.key.0))
            .map_err(|_| MailError::BadKey)?;
        authorization.set_sensitive(true);
        let mut response = self
            .http
            .post(&self.url)
            .header(AUTHORIZATION, authorization)
            .header("Idempotency-Key", idempotency_key)
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| self.network(e))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.trim().parse::<u64>().ok());
        let mut bytes = Vec::new();
        let mut cut_off = false;
        while let Some(chunk) = response.chunk().await.map_err(|e| self.network(e))? {
            if bytes.len() + chunk.len() > MAX_ANSWER_BYTES {
                cut_off = true;
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Answer {
            status,
            retry_after,
            bytes,
            cut_off,
        })
    }

    fn network(&self, error: reqwest::Error) -> MailError {
        let why = if error.is_timeout() {
            "timed out".to_string()
        } else {
            self.scrub(&error.without_url().to_string())
        };
        MailError::Network(why)
    }

    /// Takes the key out of text that came from outside, in case something echoed it.
    fn scrub(&self, text: &str) -> String {
        text.replace(&self.key.0, "[hidden]")
    }

    /// What an answer means.
    fn judge(&self, answer: &Answer) -> Judged {
        let json: Option<serde_json::Value> = serde_json::from_slice(&answer.bytes).ok();
        let name = json.as_ref().and_then(|j| j["name"].as_str()).unwrap_or("");
        let reason = {
            let message = json
                .as_ref()
                .and_then(|j| j["message"].as_str())
                .unwrap_or("");
            let plain: String = message
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            // Addresses go before the cut, so half an address cannot slip through.
            let clean: String = without_addresses(&plain)
                .chars()
                .take(MAX_REASON_CHARS)
                .collect();
            let clean = self.scrub(clean.trim());
            if clean.is_empty() {
                format!("HTTP {}", answer.status)
            } else {
                clean
            }
        };
        match answer.status {
            200..=299 => {
                let id = json.as_ref().and_then(|j| j["id"].as_str()).unwrap_or("");
                if answer.cut_off || id.is_empty() {
                    Judged::Failed(MailError::BadAnswer)
                } else {
                    Judged::Done(SendOutcome::Sent { id: id.to_string() })
                }
            }
            409 if name == "concurrent_idempotent_requests"
                || name == "invalid_idempotent_request" =>
            {
                Judged::Done(SendOutcome::AlreadySent)
            }
            429 if name == "daily_quota_exceeded" || name == "monthly_quota_exceeded" => {
                Judged::Failed(MailError::QuotaExhausted)
            }
            429 => {
                let asked = Duration::from_secs(answer.retry_after.unwrap_or(1));
                Judged::Retry(asked.min(self.max_retry_after), MailError::RateLimited)
            }
            401 | 403 => Judged::Failed(MailError::Config(reason)),
            500..=599 => Judged::Retry(self.server_error_delay, MailError::Unavailable),
            400 | 422 => Judged::Failed(MailError::Rejected(reason)),
            other => Judged::Failed(MailError::Rejected(format!(
                "unexpected answer (HTTP {other})"
            ))),
        }
    }
}

/// `text` with every email address in it replaced by `[address]`. Resend's reasons can name
/// the recipient or the account owner, and they end up in the website's log, which the
/// privacy policy says holds no email address.
pub(crate) fn without_addresses(text: &str) -> String {
    fn part_of_address(c: char) -> bool {
        c.is_alphanumeric() || "._%+-".contains(c)
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut done = 0;
    for (at, &c) in chars.iter().enumerate() {
        if c != '@' || at < done {
            continue;
        }
        let mut start = at;
        while start > done && part_of_address(chars[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < chars.len() && part_of_address(chars[end]) {
            end += 1;
        }
        // A full stop that ends the sentence is not part of the address.
        while end > at + 1 && chars[end - 1] == '.' {
            end -= 1;
        }
        if start == at || end == at + 1 {
            continue;
        }
        out.extend(&chars[done..start]);
        out.push_str("[address]");
        done = end;
    }
    out.extend(&chars[done..]);
    out
}

/// What came back, before it is judged.
struct Answer {
    status: u16,
    retry_after: Option<u64>,
    bytes: Vec<u8>,
    cut_off: bool,
}

enum Judged {
    Done(SendOutcome),
    Failed(MailError),
    /// Try once more after this long; if that fails too, report this error.
    Retry(Duration, MailError),
}

/// An HTTP client that follows no redirects, so the key cannot be forwarded elsewhere.
fn build_http(limit: Duration) -> Result<reqwest::Client, MailError> {
    reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(limit)
        .user_agent(format!("barely-free-control/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| MailError::Network(e.without_url().to_string()))
}

fn check_idempotency_key(key: &str) -> Result<(), MailError> {
    if key.is_empty() || key.len() > 256 || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(MailError::BadIdempotencyKey);
    }
    Ok(())
}

impl Mailer for ResendClient {
    fn send_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
        idempotency_key: &'a str,
    ) -> MailFuture<'a> {
        Box::pin(async move {
            let email = signin_email(code)?;
            self.send(to, &email, idempotency_key).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::{Request, State};
    use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
    use tokio::net::TcpListener;

    const KEY: &str = "re_TESTKEY_abc123XYZ";

    /// One scripted answer of the fake Resend.
    #[derive(Clone)]
    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
        delay: Duration,
    }

    fn reply(status: u16, body: &str) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    fn ok() -> Reply {
        reply(200, r#"{"id":"49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"}"#)
    }

    fn error(status: u16, name: &str, message: &str) -> Reply {
        reply(
            status,
            // Built as JSON, so a message with quotes in it stays one valid answer.
            &serde_json::json!({"statusCode": status, "name": name, "message": message})
                .to_string(),
        )
    }

    /// What the fake saw.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    struct Shared {
        script: Vec<Reply>,
        seen: Mutex<Vec<Seen>>,
    }

    async fn handle(State(shared): State<Arc<Shared>>, request: Request) -> Response<Body> {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 1 << 20).await.unwrap_or_default().to_vec();
        let headers = parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or("<not text>").to_string(),
                )
            })
            .collect();
        let index = {
            let mut seen = shared.seen.lock().unwrap();
            seen.push(Seen {
                method: parts.method.to_string(),
                path: parts.uri.path().to_string(),
                headers,
                body,
            });
            seen.len() - 1
        };
        let scripted = shared.script[index.min(shared.script.len() - 1)].clone();
        if !scripted.delay.is_zero() {
            tokio::time::sleep(scripted.delay).await;
        }
        let mut response = Response::new(Body::from(scripted.body));
        *response.status_mut() = StatusCode::from_u16(scripted.status).unwrap();
        for (name, value) in scripted.headers {
            response.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_str(&value).unwrap(),
            );
        }
        response
    }

    /// Starts a fake Resend that answers with `script` in order (the last answer repeats)
    /// and returns its address and what it has seen.
    async fn fake_resend(script: Vec<Reply>) -> (String, Arc<Shared>) {
        let shared = Arc::new(Shared {
            script,
            seen: Mutex::new(Vec::new()),
        });
        let app = Router::new().fallback(handle).with_state(shared.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, shared)
    }

    fn client(url: &str) -> ResendClient {
        ResendClient::new(
            url,
            ApiKey::new(KEY).unwrap(),
            "Barely-Free VPN <noreply@barely-free.com>",
        )
        .unwrap()
        .without_retry_delays()
    }

    fn email() -> Email {
        signin_email("482917").unwrap()
    }

    fn requests(shared: &Shared) -> usize {
        shared.seen.lock().unwrap().len()
    }

    #[tokio::test]
    async fn it_sends_one_email_with_the_request_resend_documents() {
        let (url, shared) = fake_resend(vec![ok()]).await;

        let outcome = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await
            .unwrap();

        assert_eq!(
            outcome,
            SendOutcome::Sent {
                id: "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794".to_string()
            }
        );
        let seen = shared.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let request = &seen[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/emails");
        assert_eq!(request.headers["authorization"], format!("Bearer {KEY}"));
        assert_eq!(request.headers["idempotency-key"], "signin/17");
        assert_eq!(request.headers["content-type"], "application/json");
        assert!(request.headers["user-agent"].starts_with("barely-free-control/"));

        let json: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(json["from"], "Barely-Free VPN <noreply@barely-free.com>");
        assert_eq!(json["to"], serde_json::json!(["lao@example.com"]));
        assert_eq!(json["subject"], "Your Barely-free sign-in code");
        assert!(json["html"].as_str().unwrap().contains(">482917</td>"));
        assert!(json["text"].as_str().unwrap().contains("482917"));
        assert!(
            !String::from_utf8_lossy(&request.body).contains(KEY),
            "the key is a header only"
        );
    }

    #[tokio::test]
    async fn the_mailer_trait_builds_the_sign_in_email_from_a_code() {
        let (url, shared) = fake_resend(vec![ok()]).await;
        let mailer: Box<dyn Mailer> = Box::new(client(&url));

        mailer
            .send_code("lao@example.com", "004217", "signin/1")
            .await
            .unwrap();
        assert!(
            mailer
                .send_code("lao@example.com", "12", "signin/2")
                .await
                .is_err()
        );

        let seen = shared.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "a bad code is refused before any request");
        assert!(String::from_utf8_lossy(&seen[0].body).contains("004217"));
    }

    #[tokio::test]
    async fn a_repeat_of_a_known_idempotency_key_counts_as_already_sent_and_is_not_retried() {
        for name in [
            "concurrent_idempotent_requests",
            "invalid_idempotent_request",
        ] {
            let (url, shared) = fake_resend(vec![error(409, name, "already")]).await;

            let outcome = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;

            assert_eq!(outcome, Ok(SendOutcome::AlreadySent), "{name}");
            assert_eq!(requests(&shared), 1, "{name}");
        }
    }

    #[tokio::test]
    async fn a_used_up_quota_pauses_mail_and_is_not_retried() {
        for name in ["daily_quota_exceeded", "monthly_quota_exceeded"] {
            let (url, shared) = fake_resend(vec![error(429, name, "quota")]).await;

            let outcome = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;

            assert_eq!(outcome, Err(MailError::QuotaExhausted), "{name}");
            assert_eq!(requests(&shared), 1, "{name}");
        }
    }

    #[tokio::test]
    async fn a_rate_limit_is_retried_once_and_then_reported() {
        let mut limited = error(429, "rate_limit_exceeded", "slow down");
        limited.headers.push(("retry-after", "0".to_string()));

        let (url, shared) = fake_resend(vec![limited.clone(), ok()]).await;
        let sent = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await;
        assert!(matches!(sent, Ok(SendOutcome::Sent { .. })), "{sent:?}");
        assert_eq!(requests(&shared), 2);
        {
            let seen = shared.seen.lock().unwrap();
            assert_eq!(
                seen[0].headers["idempotency-key"], seen[1].headers["idempotency-key"],
                "the retry uses the same key, so it cannot send twice"
            );
        }

        let (url, shared) = fake_resend(vec![limited]).await;
        let sent = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await;
        assert_eq!(sent, Err(MailError::RateLimited));
        assert_eq!(requests(&shared), 2, "one retry, no more");
    }

    #[tokio::test]
    async fn a_server_error_is_retried_once_and_then_reported() {
        let (url, shared) = fake_resend(vec![error(500, "application_error", "oops"), ok()]).await;
        let sent = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await;
        assert!(matches!(sent, Ok(SendOutcome::Sent { .. })), "{sent:?}");
        assert_eq!(requests(&shared), 2);

        for status in [500, 502, 503] {
            let (url, shared) =
                fake_resend(vec![error(status, "service_unavailable", "later")]).await;
            let sent = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;
            assert_eq!(sent, Err(MailError::Unavailable), "{status}");
            assert_eq!(requests(&shared), 2, "{status}");
        }
    }

    #[tokio::test]
    async fn a_key_or_domain_resend_does_not_accept_is_reported_once_without_retry_or_the_key() {
        let cases = [
            error(401, "validation_error", "API key is invalid"),
            error(401, "missing_api_key", "Missing API key"),
            error(
                403,
                "validation_error",
                "The barely-free.com domain is not verified",
            ),
            error(403, "restricted_api_key", "API key is not active"),
            // Even a message that echoed the key back must not get it into our error.
            error(401, "validation_error", &format!("bad key {KEY}")),
        ];
        for case in cases {
            let (url, shared) = fake_resend(vec![case]).await;

            let outcome = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;

            let Err(MailError::Config(why)) = &outcome else {
                panic!("{outcome:?}");
            };
            assert!(!why.is_empty());
            assert!(!why.contains(KEY), "{why}");
            assert!(!format!("{outcome:?}").contains(KEY));
            assert_eq!(requests(&shared), 1, "no retry");
        }
    }

    #[tokio::test]
    async fn a_refused_message_is_reported_once_with_resends_reason() {
        for (status, name) in [(400, "validation_error"), (422, "missing_required_field")] {
            let (url, shared) =
                fake_resend(vec![error(status, name, "the to field is wrong")]).await;

            let outcome = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;

            assert_eq!(
                outcome,
                Err(MailError::Rejected("the to field is wrong".to_string())),
                "{status}"
            );
            assert_eq!(requests(&shared), 1, "{status}");
        }
    }

    #[tokio::test]
    async fn an_email_address_in_resends_reason_never_reaches_our_error() {
        // The reason ends up in the website's log, and the privacy policy says that log
        // holds no email address (specs/legal-and-support.md). Resend's messages can name
        // the recipient or the account owner.
        let cases = [
            (
                422,
                "validation_error",
                "Invalid `to` field. The email address needs to follow the `lao@example.com` format.",
                "Invalid `to` field. The email address needs to follow the `[address]` format.",
            ),
            (
                403,
                "validation_error",
                "You can only send testing emails to your own email address (owner+test@mail.example.org). Verify a domain.",
                "You can only send testing emails to your own email address ([address]). Verify a domain.",
            ),
            (
                400,
                "validation_error",
                "bad addresses: a@b.c, \"d.e@f.gh\" and <x@y.z>.",
                "bad addresses: [address], \"[address]\" and <[address]>.",
            ),
        ];
        for (status, name, message, expected) in cases {
            let (url, _) = fake_resend(vec![error(status, name, message)]).await;
            let outcome = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;
            let why = match &outcome {
                Err(MailError::Rejected(why)) | Err(MailError::Config(why)) => why.clone(),
                other => panic!("{other:?}"),
            };
            assert_eq!(why, expected, "{status}");
            assert!(!format!("{outcome:?}").contains('@'), "{outcome:?}");
        }
    }

    #[tokio::test]
    async fn an_answer_that_is_not_what_the_documentation_promises_is_an_error() {
        for body in ["{}", "not json", r#"{"id":""}"#, r#"{"id":5}"#, ""] {
            let (url, _) = fake_resend(vec![reply(200, body)]).await;
            let outcome = client(&url)
                .send("lao@example.com", &email(), "signin/17")
                .await;
            assert_eq!(outcome, Err(MailError::BadAnswer), "{body:?}");
        }
        // A huge answer is cut off and refused, not stored.
        let (url, _) = fake_resend(vec![reply(200, &"x".repeat(2 << 20))]).await;
        let outcome = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await;
        assert_eq!(outcome, Err(MailError::BadAnswer));
        // A status we do not know is refused with that status, not guessed at.
        let (url, shared) = fake_resend(vec![reply(418, "")]).await;
        let outcome = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await;
        assert!(
            matches!(outcome, Err(MailError::Rejected(_))),
            "{outcome:?}"
        );
        assert_eq!(requests(&shared), 1);
    }

    #[tokio::test]
    async fn a_slow_resend_runs_into_the_time_limit() {
        let mut slow = ok();
        slow.delay = Duration::from_secs(3);
        let (url, _) = fake_resend(vec![slow]).await;
        let started = std::time::Instant::now();

        let outcome = client(&url)
            .with_timeout(Duration::from_millis(200))
            .send("lao@example.com", &email(), "signin/17")
            .await;

        assert!(matches!(outcome, Err(MailError::Network(_))), "{outcome:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(TIMEOUT, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_so_the_key_goes_nowhere_else() {
        let mut moved = reply(307, "");
        moved.headers.push(("location", "/elsewhere".to_string()));
        let (url, shared) = fake_resend(vec![moved, ok()]).await;

        let outcome = client(&url)
            .send("lao@example.com", &email(), "signin/17")
            .await;

        assert!(
            matches!(outcome, Err(MailError::Rejected(_))),
            "{outcome:?}"
        );
        assert_eq!(requests(&shared), 1, "the redirect target was never asked");
    }

    #[tokio::test]
    async fn a_nothing_is_sent_for_a_bad_address_or_idempotency_key() {
        let (url, shared) = fake_resend(vec![ok()]).await;
        let client = client(&url);

        for bad in [
            "",
            "Lao <lao@example.com>",
            "a@b.com, c@d.com",
            "lao@example.com\r\nBcc: x@y.com",
        ] {
            assert_eq!(
                client.send(bad, &email(), "signin/1").await,
                Err(MailError::BadAddress),
                "{bad:?}"
            );
        }
        for bad in [
            "",
            "has space",
            "line\nbreak",
            "tab\t",
            "ünï",
            &"k".repeat(257),
        ] {
            assert_eq!(
                client.send("lao@example.com", &email(), bad).await,
                Err(MailError::BadIdempotencyKey),
                "{bad:?}"
            );
        }
        let longest = "k".repeat(256);
        assert!(
            client
                .send("lao@example.com", &email(), &longest)
                .await
                .is_ok()
        );
        assert_eq!(requests(&shared), 1, "only the good one went out");
    }

    #[test]
    fn only_https_addresses_are_accepted_and_plain_http_only_on_this_computer() {
        let key = || ApiKey::new(KEY).unwrap();
        let from = "Barely-Free VPN <noreply@barely-free.com>";

        for good in [
            "https://api.resend.com",
            "https://api.resend.com/",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            assert!(ResendClient::new(good, key(), from).is_ok(), "{good}");
        }
        for bad in [
            "http://api.resend.com",
            "http://example.com",
            "http://127.0.0.1.example.com",
            "http://localhost.example.com",
            "ftp://127.0.0.1",
            "api.resend.com",
            "",
            "https://user:pass@api.resend.com",
            "https://api.resend.com/?x=1",
            "file:///etc/passwd",
        ] {
            assert_eq!(
                ResendClient::new(bad, key(), from).err(),
                Some(MailError::BadUrl),
                "{bad:?}"
            );
        }
        assert!(ResendClient::new("https://api.resend.com", key(), "").is_err());
        assert!(ResendClient::new("https://api.resend.com", key(), "a\nb").is_err());
    }

    #[test]
    fn a_key_is_one_to_256_visible_characters_and_never_shown() {
        assert!(ApiKey::new(KEY).is_ok());
        assert!(
            ApiKey::new(&format!("{KEY}\n")).is_ok(),
            "the newline from a file is dropped"
        );
        assert!(ApiKey::new(&"k".repeat(256)).is_ok());

        for bad in [
            "",
            "   ",
            "\n",
            "has space",
            "tab\tin",
            "ünï",
            "nul\u{0}",
            &"k".repeat(257),
        ] {
            assert_eq!(ApiKey::new(bad).err(), Some(MailError::BadKey), "{bad:?}");
        }

        let key = ApiKey::new(KEY).unwrap();
        assert!(!format!("{key:?}").contains(KEY));
        let client =
            ResendClient::new("https://api.resend.com", key, "Me <me@example.com>").unwrap();
        assert!(!format!("{client:?}").contains(KEY));
        for error in [
            MailError::BadKey,
            MailError::Config("x".into()),
            MailError::Network("y".into()),
        ] {
            assert!(!error.to_string().contains(KEY));
        }
    }
}
