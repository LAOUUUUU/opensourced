//! Mail: the sign-in email itself, and (below it) the client that sends it through Resend.
//!
//! The email is built from two real files, `mail/signin.html` and `mail/signin.txt`, with
//! one `{{code}}` in each. It holds no images, no links and no tracking, so a mail client
//! loads nothing from outside, and the code is kept out of the subject and the hidden
//! preview line, which inbox previews and lock screens show.

use std::fmt;

/// Who mail comes from unless `BC_MAIL_FROM` says otherwise. This address works today
/// (the domain is verified in Resend); one on barely-free.com needs DNS records first.
pub const DEFAULT_FROM: &str = "Barely-Free VPN <noreply@barely-free.com>";

/// The subject. It does not hold the code: subjects show on locked phone screens.
pub const SIGNIN_SUBJECT: &str = "Your Barely-free sign-in code";

const SIGNIN_HTML: &str = include_str!("../mail/signin.html");
const SIGNIN_TEXT: &str = include_str!("../mail/signin.txt");

/// Why mail could not be built or sent. The text never contains a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    /// A sign-in code is exactly six ASCII digits.
    BadCode,
    /// Not something that can be an email address.
    BadAddress,
    /// The API key is empty or has characters a key cannot have.
    BadKey,
    /// The Resend address is not HTTPS (plain HTTP is allowed only on this computer) or is not a plain address.
    BadUrl,
    /// An idempotency key is 1 to 256 visible ASCII characters.
    BadIdempotencyKey,
    /// Resend's daily or monthly quota is used up: mail is paused until it resets.
    QuotaExhausted,
    /// Resend is slowing us down and a retry did not help.
    RateLimited,
    /// The key or the sending domain is not accepted (401 or 403). Retrying will not help.
    Config(String),
    /// Resend refused this message (400, 422 or an answer we do not know).
    Rejected(String),
    /// Resend had a problem (5xx) and a retry did not help.
    Unavailable,
    /// Resend said yes but not in the shape its documentation promises.
    BadAnswer,
    /// The network failed or the 10-second limit ran out.
    Network(String),
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::BadCode => write!(f, "a sign-in code is six digits"),
            MailError::BadAddress => write!(f, "that is not an email address"),
            MailError::BadKey => write!(
                f,
                "the Resend key is empty or has characters a key cannot have"
            ),
            MailError::BadUrl => write!(
                f,
                "the Resend address must be https (http only on this computer)"
            ),
            MailError::BadIdempotencyKey => {
                write!(f, "an idempotency key is 1 to 256 visible characters")
            }
            MailError::QuotaExhausted => write!(f, "Resend's sending quota is used up for now"),
            MailError::RateLimited => write!(f, "Resend is rate limiting us"),
            MailError::Config(why) => write!(
                f,
                "Resend does not accept the key or the sending domain: {why}"
            ),
            MailError::Rejected(why) => write!(f, "Resend refused the message: {why}"),
            MailError::Unavailable => write!(f, "Resend is having a problem"),
            MailError::BadAnswer => write!(f, "Resend answered in a way we do not understand"),
            MailError::Network(why) => write!(f, "could not reach Resend: {why}"),
        }
    }
}

impl std::error::Error for MailError {}

/// What happened to a message that Resend took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Accepted; Resend's id for it.
    Sent { id: String },
    /// Resend had this idempotency key already (409): the first send stands.
    AlreadySent,
}

/// What a mailer returns: the send happens later, so the answer is a future.
pub type MailFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<SendOutcome, MailError>> + Send + 'a>,
>;

/// Something that can send a sign-in code. The real one talks to Resend; tests use a fake.
pub trait Mailer: Send + Sync {
    fn send_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
        idempotency_key: &'a str,
    ) -> MailFuture<'a>;
}

/// Whether `address` can be one email address and nothing more. Strict on purpose: no
/// spaces, no display names (`Name <x@y>`), no lists (`a@b, c@d`), no quotes or comments,
/// ASCII only. A plain address that fails this is refused rather than sent.
pub fn check_address(address: &str) -> Result<(), MailError> {
    let bad = || Err(MailError::BadAddress);
    if address.len() < 3 || address.len() > 254 {
        return bad();
    }
    if !address.bytes().all(|b| b.is_ascii_graphic()) {
        return bad();
    }
    if address.bytes().any(|b| b"<>,;:\\\"()[]".contains(&b)) {
        return bad();
    }
    let mut parts = address.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return bad();
    };
    let local_ok = !local.is_empty() && local.len() <= 64;
    let labels_ok = domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.len() <= 63
        });
    if local_ok && labels_ok { Ok(()) } else { bad() }
}

/// One email, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    /// Fixed text for the sign-in email; the login alerts name the server.
    pub subject: std::borrow::Cow<'static, str>,
    pub html: String,
    pub text: String,
}

/// The sign-in email for `code`, which must be six ASCII digits (leading zeros kept).
/// Nothing else is ever put into the template, so there is nothing to escape.
pub fn signin_email(code: &str) -> Result<Email, MailError> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MailError::BadCode);
    }
    Ok(Email {
        subject: SIGNIN_SUBJECT.into(),
        html: SIGNIN_HTML.replace("{{code}}", code),
        text: SIGNIN_TEXT.replace("{{code}}", code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_html_and_the_text_both_carry_the_code_once_and_the_expiry() {
        let email = signin_email("482917").unwrap();

        assert_eq!(email.html.matches("482917").count(), 1, "once, in the box");
        assert!(
            email.html.contains(">482917</td>"),
            "in the code box, with nothing around it"
        );
        assert_eq!(email.text.matches("482917").count(), 1);
        assert!(
            email.text.lines().any(|line| line.trim() == "482917"),
            "on a line of its own, easy to select"
        );
        for body in [&email.html, &email.text] {
            assert!(body.contains("10 minutes"));
            assert!(body.contains("Ignore this email"), "{body}");
        }
        assert!(email.html.contains("<h1"), "a heading");
    }

    #[test]
    fn the_code_is_not_in_the_subject_or_the_hidden_preview_line() {
        let email = signin_email("482917").unwrap();

        assert!(!email.subject.contains("482917"));
        assert_eq!(email.subject, SIGNIN_SUBJECT);
        let preview = email
            .html
            .split("display:none")
            .nth(1)
            .and_then(|rest| rest.split("</div>").next())
            .expect("a hidden preview line");
        assert!(!preview.contains("482917"), "{preview}");
        assert!(preview.contains("10 minutes"));
    }

    #[test]
    fn the_html_loads_nothing_and_links_nowhere() {
        let html = signin_email("482917").unwrap().html;

        for forbidden in [
            "<img",
            "<a ",
            "<script",
            "<link",
            "<iframe",
            "<form",
            "<video",
            "<audio",
            "@import",
            "url(",
            "http://",
            "https://",
            "background=",
            "src=",
            "href=",
        ] {
            assert!(!html.contains(forbidden), "{forbidden}");
        }
        assert_eq!(
            html.matches("<style>").count(),
            1,
            "one style block, the rest inline"
        );
    }

    #[test]
    fn the_html_has_a_light_default_and_a_dark_and_a_phone_version() {
        let html = signin_email("482917").unwrap().html;

        assert!(html.contains("prefers-color-scheme: dark"));
        assert!(html.contains("max-width: 480px"));
        assert!(html.contains("<meta name=\"color-scheme\" content=\"light dark\">"));
        assert!(html.contains("<meta name=\"viewport\""));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(
            html.len() < 40_000,
            "mail clients cut long messages off; this one is {} bytes",
            html.len()
        );
    }

    #[test]
    fn a_code_with_leading_zeros_survives_and_no_placeholder_is_left() {
        let email = signin_email("004217").unwrap();

        assert!(email.html.contains(">004217</td>"));
        assert!(email.text.contains("004217"));
        for body in [&email.html, &email.text] {
            assert!(!body.contains("{{") && !body.contains("}}"), "{body}");
        }
    }

    #[test]
    fn an_address_is_one_plain_ascii_address_and_nothing_more() {
        for good in [
            "lao@example.com",
            "a.b+c@mail.example.co.uk",
            "x_y-z@sub-domain.example.org",
        ] {
            assert_eq!(check_address(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "a@b",
            "@example.com",
            "lao@",
            "lao@@example.com",
            "lao example@example.com",
            "lao@exa mple.com",
            "Lao <lao@example.com>",
            "a@example.com, b@example.com",
            "a@example.com;b@example.com",
            "\"lao\"@example.com",
            "lao@example.com\n",
            "lao@example.com\r\nBcc: x@y.com",
            "lao@.example.com",
            "lao@example..com",
            "lao@-example.com",
            "lao@example-.com",
            "lão@example.com",
            "lao@exämple.com",
            "lao@(comment)example.com",
            "lao\\@example.com",
            "la\\o@example.com",
        ] {
            assert_eq!(check_address(bad), Err(MailError::BadAddress), "{bad:?}");
        }
        let long_local = format!("{}@example.com", "a".repeat(65));
        assert!(check_address(&long_local).is_err());
        let long_all = format!("a@{}.com", "b".repeat(250));
        assert!(check_address(&long_all).is_err());
    }

    #[test]
    fn anything_that_is_not_six_ascii_digits_is_refused() {
        for bad in [
            "",
            "12345",
            "1234567",
            "12345a",
            "123 456",
            " 123456",
            "123456\n",
            "١٢٣٤٥٦",
            "１２３４５６",
            "<b>12</b>",
            "{{code}}",
            "12345\u{0}",
        ] {
            assert_eq!(signin_email(bad), Err(MailError::BadCode), "{bad:?}");
        }
    }
}

/// One email a [`RecordingMailer`] was asked to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMail {
    pub to: String,
    pub code: String,
    pub idempotency_key: String,
}

/// A mailer that sends nothing: it writes down what it was asked and answers as told.
/// For tests and dry runs.
pub struct RecordingMailer {
    sent: std::sync::Mutex<Vec<SentMail>>,
    answer: std::sync::Mutex<Result<SendOutcome, MailError>>,
    delay: std::time::Duration,
}

impl RecordingMailer {
    /// One that says every send worked.
    pub fn new() -> RecordingMailer {
        RecordingMailer {
            sent: std::sync::Mutex::new(Vec::new()),
            answer: std::sync::Mutex::new(Ok(SendOutcome::Sent {
                id: "test-id".to_string(),
            })),
            delay: std::time::Duration::ZERO,
        }
    }

    /// One that takes `delay` over each send, like a slow network.
    pub fn slow(delay: std::time::Duration) -> RecordingMailer {
        RecordingMailer {
            delay,
            ..RecordingMailer::new()
        }
    }

    /// From now on every send answers `answer`.
    pub fn answer_with(&self, answer: Result<SendOutcome, MailError>) {
        *self.answer.lock().unwrap_or_else(|e| e.into_inner()) = answer;
    }

    /// What it was asked to send so far.
    pub fn sent(&self) -> Vec<SentMail> {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Default for RecordingMailer {
    fn default() -> Self {
        RecordingMailer::new()
    }
}

impl Mailer for RecordingMailer {
    fn send_code<'a>(
        &'a self,
        to: &'a str,
        code: &'a str,
        idempotency_key: &'a str,
    ) -> MailFuture<'a> {
        Box::pin(async move {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            self.sent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(SentMail {
                    to: to.to_string(),
                    code: code.to_string(),
                    idempotency_key: idempotency_key.to_string(),
                });
            self.answer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        })
    }
}
