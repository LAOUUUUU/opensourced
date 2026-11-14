//! `bf-control mail-test <address>`: sends one real sign-in email, with a sample code,
//! through Resend, so the email can be seen in a real inbox before sign-in exists.
//!
//! It needs no database and no accounts. It reads the key from a file (never from the
//! command line or the environment), and it never prints the key.

use std::io::{Read, Write};
use std::path::PathBuf;

use bf_common::sign::hex;

use crate::mail::{MailError, SendOutcome, check_address, signin_email};
use crate::resend::{ApiKey, ResendClient};
use crate::secrets::{KeyError, read_secret_text};

/// The code shown in the test email. It is only a sample.
const SAMPLE_CODE: &str = "482917";

const USAGE: &str = "usage: bf-control mail-test <address>\n";

/// Where the key, Resend and the sender come from.
#[derive(Debug, Clone)]
pub struct Settings {
    pub key_file: PathBuf,
    pub base_url: String,
    pub from: String,
}

/// Runs the command. Returns the exit code: 0 sent, 1 refused or failed, 2 not understood.
pub fn run(args: &[String], settings: &Settings, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let [address] = args else {
        let _ = write!(err, "{USAGE}");
        return 2;
    };
    match send(address, settings) {
        Ok(SendOutcome::Sent { id }) => {
            let _ = writeln!(
                out,
                "sent a test sign-in email to {address} (Resend message id {id})"
            );
            let _ = writeln!(
                out,
                "Look in that inbox, and in spam if it is not there. The code in it ({SAMPLE_CODE}) is only a sample."
            );
            0
        }
        Ok(SendOutcome::AlreadySent) => {
            let _ = writeln!(
                out,
                "Resend had already taken this message; nothing more was sent"
            );
            0
        }
        Err(Failure(why)) => {
            let _ = writeln!(err, "bf-control: {why}");
            1
        }
    }
}

/// A reason to print. Never contains the key.
struct Failure(String);

impl From<MailError> for Failure {
    fn from(e: MailError) -> Self {
        Failure(e.to_string())
    }
}

fn send(address: &str, settings: &Settings) -> Result<SendOutcome, Failure> {
    // The address first: a typo should not need a key file to be noticed.
    check_address(address)?;
    let text = read_secret_text(&settings.key_file).map_err(|e| match e {
        KeyError::Missing => Failure(format!(
            "cannot read the key file {}: it does not exist",
            settings.key_file.display()
        )),
        other => Failure(format!("{other} ({})", settings.key_file.display())),
    })?;
    let key = ApiKey::new(&text)?;
    let client = ResendClient::new(&settings.base_url, key, &settings.from)?;
    let email = signin_email(SAMPLE_CODE)?;
    let key = idempotency_key().map_err(|e| Failure(format!("cannot make a random id: {e}")))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Failure(format!("cannot start the runtime: {e}")))?;
    Ok(runtime.block_on(client.send(address, &email, &key))?)
}

/// A new key every run, so a second test really sends (Resend remembers a key for 24 hours).
fn idempotency_key() -> std::io::Result<String> {
    let mut random = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(format!("mail-test/{}", hex(&random)))
}
