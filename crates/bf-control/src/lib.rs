//! The Barely-free control program. For now it serves the public website; accounts,
//! devices, the admin panel and the node poller come in later steps.

// Log lines are written without `eprintln!`, which panics when stderr cannot be written.
#![deny(clippy::print_stderr)]

use std::net::SocketAddr;
use std::path::PathBuf;

pub mod adminauth;
pub mod alerts;
pub mod app;
pub mod apps;
pub mod backup;
pub mod clashmi;
pub mod cli;
pub mod closest;
pub mod cookie;
pub mod form;
pub mod guard;
pub mod keys;
pub mod link;
pub mod logins;
pub mod mail;
pub mod mailtest;
pub mod nodes;
pub mod poller;
pub mod protocol;
pub mod resend;
pub mod secrets;
pub mod seen;
pub mod signin;
pub mod status;
pub mod store;
pub mod uptime;
pub mod web;
pub mod wgconf;

#[cfg(test)]
pub(crate) mod testagent;
#[cfg(test)]
#[path = "../tests/support/tls.rs"]
pub(crate) mod testtls;

/// Where to listen: `BC_LISTEN` if set, else `127.0.0.1:18500`. It must be a loopback
/// address, because the Cloudflare tunnel is the only way in.
pub fn listen_address(setting: Option<&str>) -> Result<SocketAddr, &'static str> {
    let addr: SocketAddr = setting
        .unwrap_or("127.0.0.1:18500")
        .parse()
        .map_err(|_| "BC_LISTEN must be an IP address and port")?;
    if !addr.ip().is_loopback() {
        return Err("BC_LISTEN must be on localhost: the Cloudflare tunnel is the way in");
    }
    Ok(addr)
}

/// Where the database lives: `BC_DB` if set, else `/var/lib/barely-free/control.db`.
pub fn database_path(setting: Option<&str>) -> Result<PathBuf, &'static str> {
    match setting {
        None => Ok(PathBuf::from("/var/lib/barely-free/control.db")),
        Some("") => Err("BC_DB must not be empty"),
        Some(path) => Ok(PathBuf::from(path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_is_where_bc_db_says_or_in_var_lib() {
        assert_eq!(
            database_path(None),
            Ok(PathBuf::from("/var/lib/barely-free/control.db"))
        );
        assert_eq!(
            database_path(Some("/tmp/x.db")),
            Ok(PathBuf::from("/tmp/x.db"))
        );
        assert!(database_path(Some("")).is_err());
    }

    #[test]
    fn it_listens_on_localhost_by_default_and_never_on_anything_else() {
        assert_eq!(listen_address(None), Ok("127.0.0.1:18500".parse().unwrap()));
        assert_eq!(
            listen_address(Some("[::1]:9000")),
            Ok("[::1]:9000".parse().unwrap())
        );

        for refused in ["0.0.0.0:18500", "192.0.2.1:18500", "localhost", "18500", ""] {
            assert!(listen_address(Some(refused)).is_err(), "{refused:?}");
        }
    }
}
