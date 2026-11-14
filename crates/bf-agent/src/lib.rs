//! The Barely-free node agent: reports WireGuard's state and applies the peer list the
//! control program sends. See `specs/agent.md`.

// Log lines go through `log::line`: `eprintln!` panics when stderr cannot be written.
#![deny(clippy::print_stderr)]

pub mod client;
pub mod config;
pub mod log;
pub mod logins;
pub mod nft;
pub mod reconcile;
pub mod secret;
pub mod server;
pub mod service;
pub mod store;
pub mod trackers;
pub mod wgcli;

#[cfg(any(test, feature = "testing"))]
pub mod testutil;
