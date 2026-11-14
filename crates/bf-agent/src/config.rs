//! The agent's settings, read from the environment (see `specs/agent.md`).

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub interface: String,
    pub secret_file: PathBuf,
    pub state_dir: PathBuf,
    pub online_secs: u64,
    pub wg_bin: String,
    /// The per-device tracker switch (`specs/trackers.md`), when `BF_TRACKERS=nft`.
    pub trackers: Option<TrackerSwitch>,
    /// The folder `bf-logins.timer` writes the recent SSH logins into
    /// (`specs/login-alerts.md`); `None` when `BF_LOGINS=off`.
    pub logins_dir: Option<PathBuf>,
}

/// How the agent keeps the set of devices whose trackers are not blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerSwitch {
    pub nft_bin: String,
    /// The set in the table `inet barely_free_dns`: `off_` and the interface name, with
    /// `.` and `-` written as `_`, so the two agents of a server never share one.
    pub set: String,
}

/// A setting that cannot be used. It names the setting, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub name: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.reason)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads the settings through `get`, which looks a setting up by name.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let listen = match get("BF_LISTEN") {
            None => SocketAddr::from(([127, 0, 0, 1], 9870)),
            Some(text) => {
                let addr: SocketAddr = text
                    .parse()
                    .map_err(|_| bad("BF_LISTEN", "must be an IP address and port"))?;
                if !addr.ip().is_loopback() {
                    return Err(bad("BF_LISTEN", "must be on localhost"));
                }
                addr
            }
        };
        let interface = match get("BF_INTERFACE") {
            None => "wg0".to_string(),
            Some(name) if valid_interface(&name) => name,
            Some(_) => {
                return Err(bad(
                    "BF_INTERFACE",
                    "must be letters, digits, '_', '.' or '-' (up to 15), not starting with '-' or '.'",
                ));
            }
        };
        let online_secs = match get("BF_ONLINE_SECS") {
            None => 180,
            // Below the time after which an idle device is forgotten (decision 020), so a
            // forgotten device never counts as online.
            Some(text) => match text.parse::<u64>() {
                Ok(secs) if secs > 0 && secs < bf_common::wg::FORGET_IDLE_AFTER_SECS => secs,
                _ => {
                    return Err(bad(
                        "BF_ONLINE_SECS",
                        "must be a positive whole number of seconds, under 5 minutes",
                    ));
                }
            },
        };
        let wg_bin = match get("BF_WG_BIN") {
            None => "wg".to_string(),
            Some(bin) if !bin.is_empty() => bin,
            Some(_) => return Err(bad("BF_WG_BIN", "must not be empty")),
        };
        let nft_bin = match get("BF_NFT_BIN") {
            None => "nft".to_string(),
            Some(bin) if !bin.is_empty() => bin,
            Some(_) => return Err(bad("BF_NFT_BIN", "must not be empty")),
        };
        let trackers = match get("BF_TRACKERS").as_deref() {
            None => None,
            Some("nft") => Some(TrackerSwitch {
                nft_bin,
                set: format!("off_{}", interface.replace(['.', '-'], "_")),
            }),
            Some(_) => return Err(bad("BF_TRACKERS", "must be nft, or not set")),
        };
        let dir = match get("BF_LOGINS_DIR") {
            None => PathBuf::from(bf_common::logins::DIR),
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            Some(_) => return Err(bad("BF_LOGINS_DIR", "must not be empty")),
        };
        let logins_dir = match get("BF_LOGINS").as_deref() {
            None | Some("files") => Some(dir),
            Some("off") => None,
            Some(_) => return Err(bad("BF_LOGINS", "must be files or off, or not set")),
        };
        Ok(Config {
            listen,
            interface,
            secret_file: get("BF_SECRET_FILE").map_or_else(
                || PathBuf::from("/etc/barely-free/agent.secret"),
                PathBuf::from,
            ),
            state_dir: get("BF_STATE_DIR")
                .map_or_else(|| PathBuf::from("/var/lib/barely-free"), PathBuf::from),
            online_secs,
            wg_bin,
            trackers,
            logins_dir,
        })
    }

    /// Reads the settings from the process environment.
    pub fn from_env() -> Result<Config, ConfigError> {
        Config::from_lookup(|name| std::env::var(name).ok())
    }
}

fn bad(name: &'static str, reason: &'static str) -> ConfigError {
    ConfigError { name, reason }
}

/// A name `wg` can take as an interface: it must never look like an option.
fn valid_interface(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_nothing_set_the_documented_defaults_apply() {
        let config = Config::from_lookup(|_| None).unwrap();

        assert_eq!(
            config,
            Config {
                listen: "127.0.0.1:9870".parse().unwrap(),
                interface: "wg0".to_string(),
                secret_file: PathBuf::from("/etc/barely-free/agent.secret"),
                state_dir: PathBuf::from("/var/lib/barely-free"),
                online_secs: 180,
                wg_bin: "wg".to_string(),
                trackers: None,
                logins_dir: Some(PathBuf::from("/var/lib/barely-free-logins")),
            }
        );
    }

    #[test]
    fn login_reporting_is_on_unless_switched_off() {
        let off = Config::from_lookup(lookup(&[("BF_LOGINS", "off")])).unwrap();
        assert_eq!(off.logins_dir, None);
        let other = Config::from_lookup(lookup(&[
            ("BF_LOGINS", "files"),
            ("BF_LOGINS_DIR", "/run/logins"),
        ]))
        .unwrap();
        assert_eq!(other.logins_dir, Some(PathBuf::from("/run/logins")));
    }

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn every_setting_can_be_overridden() {
        let config = Config::from_lookup(lookup(&[
            ("BF_LISTEN", "[::1]:9999"),
            ("BF_INTERFACE", "wg1"),
            ("BF_SECRET_FILE", "/run/secret"),
            ("BF_STATE_DIR", "/run/state"),
            ("BF_ONLINE_SECS", "90"),
            ("BF_WG_BIN", "/usr/bin/wg"),
        ]))
        .unwrap();

        assert_eq!(config.listen, "[::1]:9999".parse().unwrap());
        assert_eq!(config.interface, "wg1");
        assert_eq!(config.secret_file, PathBuf::from("/run/secret"));
        assert_eq!(config.state_dir, PathBuf::from("/run/state"));
        assert_eq!(config.online_secs, 90);
        assert_eq!(config.wg_bin, "/usr/bin/wg");
    }

    #[test]
    fn the_tracker_switch_is_off_unless_set_to_nft_and_then_its_set_is_named_after_the_interface() {
        let off = Config::from_lookup(|_| None).unwrap();
        assert_eq!(off.trackers, None);

        let on = Config::from_lookup(lookup(&[("BF_TRACKERS", "nft"), ("BF_INTERFACE", "awg0")]))
            .unwrap();
        assert_eq!(
            on.trackers,
            Some(TrackerSwitch {
                nft_bin: "nft".to_string(),
                set: "off_awg0".to_string(),
            })
        );

        let custom = Config::from_lookup(lookup(&[
            ("BF_TRACKERS", "nft"),
            ("BF_NFT_BIN", "/usr/sbin/nft"),
            ("BF_INTERFACE", "wg-a.1"),
        ]))
        .unwrap();
        assert_eq!(
            custom.trackers,
            Some(TrackerSwitch {
                nft_bin: "/usr/sbin/nft".to_string(),
                set: "off_wg_a_1".to_string(),
            })
        );
    }

    #[test]
    fn settings_that_are_unsafe_or_meaningless_are_refused_by_name() {
        for (name, value) in [
            ("BF_LISTEN", "0.0.0.0:9870"), // the agent stays on localhost
            ("BF_LISTEN", "192.0.2.1:9870"),
            ("BF_LISTEN", "localhost"),
            ("BF_INTERFACE", ""),
            ("BF_INTERFACE", "-h"), // would be read as an option by `wg`
            ("BF_INTERFACE", "wg0 evil"),
            ("BF_INTERFACE", "averyverylongname"), // Linux allows 15 characters
            ("BF_ONLINE_SECS", "0"),
            ("BF_ONLINE_SECS", "soon"),
            // A device the server has forgotten (decision 020) cannot still count as online.
            ("BF_ONLINE_SECS", "300"),
            ("BF_ONLINE_SECS", "3600"),
            ("BF_WG_BIN", ""),
            ("BF_TRACKERS", ""),
            ("BF_TRACKERS", "yes"),
            ("BF_TRACKERS", "NFT"),
            ("BF_NFT_BIN", ""),
            ("BF_LOGINS", ""),
            ("BF_LOGINS", "yes"),
            ("BF_LOGINS", "journal"),
            ("BF_LOGINS_DIR", ""),
        ] {
            let err = Config::from_lookup(lookup(&[(name, value)])).unwrap_err();
            assert_eq!(err.name, name, "{value:?}");
            assert!(
                !err.to_string().contains(value) || value.is_empty(),
                "{err}"
            );
        }
    }
}
