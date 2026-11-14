//! `bf-agent` runs the node agent; `bf-agent probe` asks the local agent for its status.

// Log lines go through `bf_agent::log`: `eprintln!` panics when stderr cannot be written.
#![deny(clippy::print_stderr)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bf_agent::config::Config;
use bf_agent::logins::LoginFiles;
use bf_agent::nft::NftSet;
use bf_agent::secret::read_secret;
use bf_agent::service::{Agent, keep_matching};
use bf_agent::store::Store;
use bf_agent::wgcli::{WgCli, Wireguard};
use bf_agent::{client, log, server};
use bf_common::sign::Parts;
use tokio::net::TcpListener;

/// How often WireGuard is made to match the stored list again (a restarted interface
/// forgets its peers).
const RECONCILE_EVERY: Duration = Duration::from_secs(30);

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let words: Vec<Option<&str>> = args.iter().map(|arg| arg.to_str()).collect();
    match words.as_slice() {
        [] => run(),
        [Some("probe")] => probe(),
        [Some("trackers"), Some("build"), ..] if args.len() == 5 => {
            trackers_build(&args[2], &args[3], &args[4])
        }
        _ => {
            log::line("usage: bf-agent [probe | trackers build <list> <allow file> <zone file>]");
            ExitCode::from(2)
        }
    }
}

fn trackers_build(
    list: &std::ffi::OsStr,
    allow: &std::ffi::OsStr,
    zone: &std::ffi::OsStr,
) -> ExitCode {
    use std::path::Path;
    match bf_agent::trackers::build(Path::new(list), Path::new(allow), Path::new(zone)) {
        Ok(built) => {
            println!("trackers: {} names (was {})", built.names, built.previous);
            ExitCode::SUCCESS
        }
        Err(e) => {
            log::line(&format!("trackers: {e}"));
            ExitCode::FAILURE
        }
    }
}

fn settings() -> Result<(Config, Vec<u8>), String> {
    let config = Config::from_env().map_err(|e| e.to_string())?;
    let secret = read_secret(&config.secret_file)
        .map_err(|e| format!("{}: {e}", config.secret_file.display()))?;
    Ok((config, secret))
}

fn run() -> ExitCode {
    let (config, secret) = match settings() {
        Ok(found) => found,
        Err(why) => {
            log::line(&why);
            return ExitCode::FAILURE;
        }
    };
    let wg: Arc<dyn Wireguard> =
        Arc::new(WgCli::new(config.wg_bin.clone(), config.interface.clone()));
    // The clock at start: the floor for requests when no replay mark is on disk yet.
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut agent = Agent::new_at(
        wg,
        Store::new(config.state_dir.clone()),
        secret,
        config.online_secs,
        started_at,
    );
    if let Some(switch) = &config.trackers {
        log::line(&format!(
            "tracker switch on: set inet barely_free_dns {}",
            switch.set
        ));
        agent = agent.with_tracker_set(Arc::new(NftSet::new(switch)));
    }
    if let Some(dir) = &config.logins_dir {
        agent = agent.with_login_log(Arc::new(LoginFiles { dir: dir.clone() }));
        log::line(&format!(
            "logins: the status reports the last 15 minutes of SSH logins, from {}",
            dir.display()
        ));
    }
    let agent = Arc::new(agent);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log::line(&format!("cannot start the runtime: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let served = runtime.block_on(async {
        let listener = TcpListener::bind(config.listen).await?;
        log::line(&format!(
            "listening on {} for interface {}",
            config.listen, config.interface
        ));
        tokio::spawn(keep_matching(agent.clone(), RECONCILE_EVERY));
        server::serve(listener, agent, std::future::pending()).await
    });
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::line(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

fn probe() -> ExitCode {
    let (config, secret) = match settings() {
        Ok(found) => found,
        Err(why) => {
            log::line(&format!("probe: {why}"));
            return ExitCode::FAILURE;
        }
    };
    let nonce = match client::random_nonce() {
        Ok(nonce) => nonce,
        Err(e) => {
            log::line(&format!("probe: no random numbers: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let parts = Parts {
        method: "GET",
        path_and_query: "/v1/status",
        time: server::unix_now(),
        nonce: &nonce,
        body: b"",
    };
    match client::request(config.listen, &secret, &parts) {
        Ok((200, body)) => {
            println!("{body}");
            ExitCode::SUCCESS
        }
        Ok((status, body)) => {
            log::line(&format!("probe: the agent answered {status}"));
            println!("{body}");
            ExitCode::FAILURE
        }
        Err(e) => {
            log::line(&format!("probe: {e}"));
            ExitCode::FAILURE
        }
    }
}
