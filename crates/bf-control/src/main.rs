//! `bf-control` with no arguments serves the Barely-free website on localhost, behind the
//! Cloudflare tunnel. With arguments it is the admin tool (`bf-control account add ...`).

// Log lines are written without `eprintln!`, which panics when stderr cannot be written.
#![deny(clippy::print_stderr)]

use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;

fn log(message: &str) {
    let _ = writeln!(std::io::stderr(), "bf-control: {message}");
}

/// An environment setting. One that is set but not text is an error, never "not set":
/// falling back to the default could mean the production database.
fn setting(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be text")),
    }
}

fn main() -> ExitCode {
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(arg) => args.push(arg),
            Err(_) => {
                log("the arguments must be text");
                return ExitCode::from(2);
            }
        }
    }
    match args.first().map(String::as_str) {
        None => serve(),
        Some("mail-test") => mail_test(&args[1..]),
        Some("logins") => logins(&args[1..]),
        Some(_) => admin(&args),
    }
}

/// `bf-control mail-test <address>`: one real sign-in email through Resend. No database.
fn mail_test(args: &[String]) -> ExitCode {
    let settings = (|| -> Result<bf_control::mailtest::Settings, String> {
        let key_file = setting("BC_RESEND_KEY_FILE")?
            .unwrap_or_else(|| "/etc/barely-free/resend.key".to_string());
        let base_url = setting("BC_RESEND_URL")?
            .unwrap_or_else(|| bf_control::resend::DEFAULT_BASE_URL.to_string());
        let from =
            setting("BC_MAIL_FROM")?.unwrap_or_else(|| bf_control::mail::DEFAULT_FROM.to_string());
        Ok(bf_control::mailtest::Settings {
            key_file: key_file.into(),
            base_url,
            from,
        })
    })();
    let settings = match settings {
        Ok(settings) => settings,
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    let code = bf_control::mailtest::run(
        args,
        &settings,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code)
}

/// `bf-control logins learn < journal-lines`: adds those logins' pairs to the known-logins
/// file (`BC_KNOWN_LOGINS`), so they never cause an email. No database.
fn logins(args: &[String]) -> ExitCode {
    let path = match setting("BC_KNOWN_LOGINS") {
        Ok(path) => path.unwrap_or_else(|| bf_control::logins::KNOWN_FILE.to_string()),
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    ExitCode::from(bf_control::logins::run(
        args,
        std::path::Path::new(&path),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    ))
}

/// Runs one admin command. The exit code is the command's: 0 done, 1 refused or
/// failed, 2 not understood.
fn admin(args: &[String]) -> ExitCode {
    let db = match setting("BC_DB")
        .and_then(|value| bf_control::database_path(value.as_deref()).map_err(String::from))
    {
        Ok(db) => db,
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    let Ok(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
    else {
        log("the clock is set before 1970");
        return ExitCode::FAILURE;
    };
    let key_file = match setting("BC_KEY_FILE") {
        Ok(path) => path.unwrap_or_else(|| "/etc/barely-free/control.key".to_string()),
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    let nodes_dir = match nodes_dir() {
        Ok(dir) => dir,
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    let context = bf_control::cli::Context {
        key_file: Some(std::path::Path::new(&key_file)),
        nodes_dir: Some(&nodes_dir),
        connector: &bf_control::poller::HttpsConnector,
        password_input: Some(&read_password_input),
    };
    let code = bf_control::cli::run_in(
        args,
        &db,
        &context,
        now,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code)
}

/// What `admin set-password` is given: standard input, if it is a pipe (see
/// `bf_control::cli::read_password_input`).
fn read_password_input() -> std::io::Result<String> {
    use std::io::IsTerminal;
    bf_control::cli::read_password_input(
        &mut std::io::stdin().lock(),
        std::io::stdin().is_terminal(),
    )
}

/// `BC_NODES_DIR`: where each node's `<name>.secret` and `<name>.pem` are.
fn nodes_dir() -> Result<std::path::PathBuf, String> {
    Ok(setting("BC_NODES_DIR")?
        .unwrap_or_else(|| "/etc/barely-free/nodes".to_string())
        .into())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The poller, if the database is already there. It never makes the database: the admin
/// commands do, and until they have, the site runs as it always did. A node whose files
/// are missing or wrong only turns its own card to "Not responding".
fn start_poller(
    every: std::time::Duration,
    app: &Option<std::sync::Arc<bf_control::app::App>>,
) -> Option<bf_control::web::Live> {
    let started = (|| -> Result<bf_control::web::Live, String> {
        let db = bf_control::database_path(setting("BC_DB")?.as_deref()).map_err(String::from)?;
        if !db.exists() {
            return Err("there is no database yet (the admin commands make it)".to_string());
        }
        let nodes_dir = nodes_dir()?;
        let store = bf_control::store::Store::open(&db).map_err(|e| e.to_string())?;
        let poller = bf_control::poller::Poller::new(
            std::sync::Arc::new(std::sync::Mutex::new(store)),
            bf_control::poller::Settings::new(nodes_dir, every),
            std::sync::Arc::new(bf_control::poller::HttpsConnector),
            std::sync::Arc::new(now_secs),
            std::sync::Arc::new(log),
        );
        let live = bf_control::web::Live {
            board: poller.board(),
            clock: std::sync::Arc::new(now_secs),
            // A bad setting keeps sign-in off, with the reason in the log (`sign_in`); the
            // status page then uses the defaults rather than lose the poller too.
            busy: busy_setting().unwrap_or_default(),
        };
        if let Some(app) = app {
            // The account page can then add a device on a node that is up, and ask for a pass
            // at once so the node has the key before the QR code is scanned.
            let asked = poller.clone();
            app.connect_poller(poller.board(), std::sync::Arc::new(move || asked.poke()));
        }
        tokio::spawn(poller.run());
        Ok(live)
    })();
    match started {
        Ok(live) => {
            log("the node poller is on");
            Some(live)
        }
        Err(why) => {
            log(&format!("the node poller is off: {why}"));
            None
        }
    }
}

/// An email to the address in `BC_ALERT_TO_FILE` when a server stops answering and when it
/// is back (`research/alerts/RESEARCH.md`), through the same Resend settings as sign-in.
/// Without the file, or without a working Resend key, alerts are off and the log says why.
fn start_alerts(live: &bf_control::web::Live) {
    let started = (|| -> Result<(bf_control::resend::ResendClient, String), String> {
        let file = setting("BC_ALERT_TO_FILE")?
            .unwrap_or_else(|| bf_control::alerts::ADDRESS_FILE.to_string());
        let to = bf_control::alerts::address_from(std::path::Path::new(&file))?;
        let key_file = setting("BC_RESEND_KEY_FILE")?
            .unwrap_or_else(|| "/etc/barely-free/resend.key".to_string());
        let text = bf_control::secrets::read_secret_text(std::path::Path::new(&key_file))
            .map_err(|e| format!("the Resend key file {key_file}: {e}"))?;
        let key = bf_control::resend::ApiKey::new(&text).map_err(|e| e.to_string())?;
        let url = setting("BC_RESEND_URL")?
            .unwrap_or_else(|| bf_control::resend::DEFAULT_BASE_URL.to_string());
        let from =
            setting("BC_MAIL_FROM")?.unwrap_or_else(|| bf_control::mail::DEFAULT_FROM.to_string());
        let client =
            bf_control::resend::ResendClient::new(&url, key, &from).map_err(|e| e.to_string())?;
        Ok((client, to))
    })();
    match started {
        Ok((client, to)) => {
            let logins = match login_watch() {
                Ok(watch) => {
                    log("login alerts are on: a login from somewhere new is emailed about");
                    Some(watch)
                }
                Err(why) => {
                    log(&format!("login alerts are off: {why}"));
                    None
                }
            };
            tokio::spawn(bf_control::alerts::run(
                live.board.clone(),
                logins,
                std::sync::Arc::new(client),
                to,
                std::sync::Arc::new(now_secs),
                std::sync::Arc::new(log),
            ));
            log("alerts are on: a server that stops answering is emailed about");
        }
        Err(why) => log(&format!("alerts are off: {why}")),
    }
}

/// The login alerts' files (`specs/login-alerts.md`): `BC_KNOWN_LOGINS` (default
/// `bf_control::logins::KNOWN_FILE`) and `BC_LOGINS_DIR`, where `bf-logins.timer` writes the
/// VM's own logins (default `bf_common::logins::DIR`).
fn login_watch() -> Result<bf_control::alerts::LoginWatch, String> {
    use bf_control::logins;
    let path = |name: &str, default: &str| -> Result<std::path::PathBuf, String> {
        Ok(setting(name)?.unwrap_or_else(|| default.to_string()).into())
    };
    let known = logins::Known::open(&path("BC_KNOWN_LOGINS", logins::KNOWN_FILE)?)?;
    Ok(bf_control::alerts::LoginWatch::new(
        known,
        path("BC_LOGINS_DIR", bf_common::logins::DIR)?,
    ))
}

/// When a server counts as busy: `BC_NODE_BUSY_ONLINE` and `BC_NODE_BUSY_LOAD`. "Closest to
/// you" skips a busy server and the status page calls it Overloaded, so both read this.
fn busy_setting() -> Result<bf_control::closest::Busy, String> {
    Ok(bf_control::closest::Busy {
        online: bf_control::closest::busy_online(setting("BC_NODE_BUSY_ONLINE")?.as_deref())?,
        load: bf_control::closest::busy_load(setting("BC_NODE_BUSY_LOAD")?.as_deref())?,
    })
}

/// The sign-in side, if it is fully set up; otherwise the reason it is off, in the log, and
/// the website runs without it exactly as before. Nothing is created to make it work:
/// no key file, and no database unless every other setting is already good.
fn sign_in() -> Option<std::sync::Arc<bf_control::app::App>> {
    let settings = (|| -> Result<bf_control::app::AppSettings, String> {
        let db = bf_control::database_path(setting("BC_DB")?.as_deref()).map_err(String::from)?;
        let key_file =
            setting("BC_KEY_FILE")?.unwrap_or_else(|| "/etc/barely-free/control.key".to_string());
        let resend_key_file = setting("BC_RESEND_KEY_FILE")?
            .unwrap_or_else(|| "/etc/barely-free/resend.key".to_string());
        let resend_url = setting("BC_RESEND_URL")?
            .unwrap_or_else(|| bf_control::resend::DEFAULT_BASE_URL.to_string());
        let mail_from =
            setting("BC_MAIL_FROM")?.unwrap_or_else(|| bf_control::mail::DEFAULT_FROM.to_string());
        let origins = setting("BC_ORIGINS")?
            .unwrap_or_else(|| "https://barely-free.com,https://www.barely-free.com".to_string())
            .split(',')
            .map(str::to_string)
            .collect();
        let open_signup =
            bf_control::app::check_open_signup(setting("BC_OPEN_SIGNUP")?.as_deref())?;
        let busy = busy_setting()?;
        Ok(bf_control::app::AppSettings {
            db,
            key_file: key_file.into(),
            resend_key_file: resend_key_file.into(),
            resend_url,
            mail_from,
            origins,
            open_signup,
            busy,
            backup_status: setting("BC_BACKUP_STATUS")?
                .unwrap_or_else(|| bf_control::backup::STATUS_FILE.to_string())
                .into(),
        })
    })();
    match settings.and_then(|settings| bf_control::app::build(&settings)) {
        Ok(app) => {
            log("sign-in pages are on");
            if app.signup_open() {
                log("sign-up is open: anyone can make an account with a sign-in code");
            }
            Some(app)
        }
        Err(why) => {
            log(&format!("sign-in is off: {why}"));
            None
        }
    }
}

fn serve() -> ExitCode {
    let addr = match setting("BC_LISTEN")
        .and_then(|value| bf_control::listen_address(value.as_deref()).map_err(String::from))
    {
        Ok(addr) => addr,
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    let every = match setting("BC_POLL_SECS")
        .and_then(|value| bf_control::poller::poll_interval(value.as_deref()).map_err(String::from))
    {
        Ok(every) => every,
        Err(why) => {
            log(&why);
            return ExitCode::FAILURE;
        }
    };
    let app = sign_in();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log(&format!("cannot start the runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let served = runtime.block_on(async {
        let listener = TcpListener::bind(addr).await?;
        log(&format!("serving the website on {addr}"));
        let live = start_poller(every, &app);
        if let Some(live) = &live {
            start_alerts(live);
        }
        bf_control::web::serve_site(listener, app, live, std::future::pending()).await
    });
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e.to_string());
            ExitCode::FAILURE
        }
    }
}
