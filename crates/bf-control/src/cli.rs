//! The admin command line: `bf-control account add`, `device add`, `kick` and friends.
//!
//! Everything goes through [`run`], which takes its arguments, the database path, the
//! time and where to print, so tests can drive it without starting a process.

use std::io::Write;
use std::path::Path;

use crate::keys::KeyPair;
use crate::link::read_files;
use crate::mail::check_address;
use crate::poller::{Connector, HttpsConnector};
use crate::secrets::ControlKeys;
use crate::store::{KickEnd, Store, StoreError};

/// Why a command did not finish.
enum Failure {
    /// The command was not understood: print the usage, exit 2.
    Usage,
    /// It was understood and could not be done: print why, exit 1.
    Refused(String),
}

impl From<StoreError> for Failure {
    fn from(e: StoreError) -> Self {
        Failure::Refused(e.to_string())
    }
}

/// What `admin set-password` is given: all of `input` (standard input), at most 1 KiB (a
/// password is never longer, and this is not the place for a file), as text. Typed at a
/// terminal it would show on the screen and stay in the scrollback, so a terminal is refused
/// before anything is read; the password comes in through a pipe, which is what
/// `deploy/set-admin-password.sh` makes.
pub fn read_password_input(
    input: &mut dyn std::io::Read,
    is_terminal: bool,
) -> std::io::Result<String> {
    if is_terminal {
        return Err(std::io::Error::other(
            "the password is read from standard input, and typed here it would show on the screen; \
             set it with deploy/set-admin-password.sh, which asks for it with a hidden prompt",
        ));
    }
    use std::io::Read as _;
    let mut text = String::new();
    input.take(1025).read_to_string(&mut text)?;
    if text.len() > 1024 {
        return Err(std::io::Error::other("that is far too long for a password"));
    }
    Ok(text)
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Failure::Refused(e.to_string())
    }
}

/// Runs one admin command against the database at `db`. Results go to `out`, the
/// reason for a failure to `err`. Returns the exit code: 0 done, 1 refused or failed,
/// 2 not understood.
pub fn run(args: &[String], db: &Path, now: u64, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    run_with(args, db, None, now, out, err)
}

/// Like [`run`], and knows where the control key file is (`BC_KEY_FILE`), which the
/// commands that give an account a sign-in address need. The key file is made on first
/// use, readable by its owner only; without a path those commands are refused.
pub fn run_with(
    args: &[String],
    db: &Path,
    key_file: Option<&Path>,
    now: u64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let context = Context {
        key_file,
        nodes_dir: None,
        connector: &HttpsConnector,
        password_input: None,
    };
    run_in(args, db, &context, now, out, err)
}

/// What the commands need besides the database.
pub struct Context<'a> {
    /// `BC_KEY_FILE`, for the commands that give an account a sign-in address.
    pub key_file: Option<&'a Path>,
    /// `BC_NODES_DIR`, where each node's `<name>.secret` and `<name>.pem` are.
    pub nodes_dir: Option<&'a Path>,
    /// How `node check` reaches a node: the pinned HTTPS connection, or a fake in tests.
    pub connector: &'a dyn Connector,
    /// Where `admin set-password` reads the password from (standard input). It is never taken
    /// from the command line, where it would show in the process list and the shell history.
    pub password_input: Option<&'a dyn Fn() -> std::io::Result<String>>,
}

/// Like [`run_with`], with everything the commands may need in `context`.
pub fn run_in(
    args: &[String],
    db: &Path,
    context: &Context<'_>,
    now: u64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let had_database = db.exists();
    let result = command(&words, db, context, now, out);
    if !had_database && db.exists() {
        // A mistyped `BC_DB` would otherwise start a second, empty database unnoticed.
        let _ = writeln!(err, "bf-control: made a new database at {}", db.display());
    }
    match result {
        Ok(()) => 0,
        Err(Failure::Refused(why)) => {
            let _ = writeln!(err, "bf-control: {why}");
            1
        }
        Err(Failure::Usage) => {
            let _ = write!(err, "{USAGE}");
            2
        }
    }
}

const USAGE: &str = "\
usage:
  bf-control                                      serve the website
  bf-control account add <label> [--email <address>]
  bf-control account set-email <account-id> <address>
  bf-control account list
  bf-control device add <account-id> <name>
  bf-control device list
  bf-control device remove <device-id>
  bf-control kick <device-id> <length> [--by <who>] [--reason <text>]
  bf-control kick list [<device-id>]
  bf-control lift <device-id> [--by <who>]
  bf-control peers
  bf-control node add <name> <ip:port> <title> <place> --protocol <wireguard|amneziawg>
  bf-control node set-protocol <name> <wireguard|amneziawg>
  bf-control node set-location <name> <lat>,<lon>  where its server is, in degrees: 43.65,-79.38
  bf-control node list
  bf-control node enable <name>
  bf-control node disable <name>
  bf-control node remove <name>
  bf-control node check <name>                    ask the node for its status, the way the poller does
  bf-control list raise <n>                       make the next list's version higher than n
  bf-control backup <file>                        copy the database into a new file, safely, while it runs
  bf-control admin grant <account-id>             let the account use the admin pages (after a password)
  bf-control admin revoke <account-id>            take that away, and forget its admin password
  bf-control admin set-password <account-id>      read the admin password from standard input
  bf-control mail-test <address>                  send one test sign-in email through Resend

A kick length is a number and a unit (90s, 30m, 2h, 7d) or `forever`, which lasts
until the kick is lifted. The database is the file named by BC_DB.

A sign-in address is never kept as text: only a fingerprint made with the key file
(BC_KEY_FILE, made on first use), so a stolen database holds no addresses.
";

fn command(
    words: &[&str],
    db: &Path,
    context: &Context<'_>,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    let key_file = context.key_file;
    match words {
        ["account", "add", label, flags @ ..] => {
            let label = text(label)?;
            let flags = Flags::read(flags, &["--email"])?;
            let mut store = Store::open(db)?;
            // The address first: a bad one, or one another account has, stops the
            // command before an account is made.
            let fingerprint = match flags.get("--email") {
                Some(address) => Some(address_fingerprint(key_file, address)?),
                None => None,
            };
            if let Some(fp) = &fingerprint
                && store.account_for_email_fp(fp)?.is_some()
            {
                return Err(StoreError::EmailInUse.into());
            }
            // One transaction: never an account without the address it was given.
            let account = store.add_account_with_email(label, fingerprint.as_ref(), now)?;
            let sign_in = if fingerprint.is_some() {
                " (can sign in with the address given)"
            } else {
                ""
            };
            writeln!(
                out,
                "account {} created: {}{sign_in}",
                account.id, account.label
            )?;
        }
        ["account", "set-email", account_id, address] => {
            let account_id = id(account_id)?;
            let address = text(address)?;
            let fingerprint = address_fingerprint(key_file, address)?;
            Store::open(db)?.set_email_fp(account_id, &fingerprint)?;
            writeln!(
                out,
                "account {account_id}: can sign in with the address given"
            )?;
        }
        ["account", "list"] => {
            let accounts = Store::open(db)?.accounts_with_device_counts()?;
            if accounts.is_empty() {
                writeln!(out, "no accounts yet")?;
            }
            for (account, held) in accounts {
                writeln!(
                    out,
                    "{}  {}  {held} of {} devices",
                    account.id, account.label, account.device_limit
                )?;
            }
        }
        ["device", "add", account_id, name] => {
            let account_id = id(account_id)?;
            let name = text(name)?;
            let mut store = Store::open(db)?;
            let pair = KeyPair::generate()?;
            // The private key exists only in this text. It is written out before the
            // device is saved, so if it cannot be shown (or the process dies) no device
            // is kept that nobody holds the key of.
            store.add_device_with(account_id, name, &pair.public_key, now, |device| {
                let shown = format!(
                    "device {} created for account {account_id}\n\
                     name:        {}\n\
                     address:     {}\n\
                     public key:  {}\n\
                     private key: {}\n\
                     The private key is shown this once and is not stored. Put it in the device now.\n",
                    device.id,
                    device.name,
                    device.address,
                    device.public_key,
                    pair.private_key()
                );
                out.write_all(shown.as_bytes())
                    .and_then(|()| out.flush())
                    .map_err(|e| e.to_string())
            })?;
        }
        ["device", "list"] => {
            let store = Store::open(db)?;
            for device in store.devices()? {
                let state = if store.is_kicked(device.id, now)? {
                    "kicked"
                } else {
                    "active"
                };
                writeln!(
                    out,
                    "{}  account {}  {}  {state}  {}",
                    device.id, device.account_id, device.address, device.name
                )?;
            }
        }
        ["device", "remove", device_id] => {
            let device_id = id(device_id)?;
            let device = Store::open(db)?.remove_device(device_id, now)?;
            writeln!(
                out,
                "device {device_id} removed ({}); its address {} is free again and its kicks are kept",
                device.name, device.address
            )?;
        }
        ["kick", "list", rest @ ..] => {
            let device_id = match rest {
                [] => None,
                [device_id] => Some(id(device_id)?),
                _ => return Err(Failure::Usage),
            };
            let history = Store::open(db)?.kick_history(device_id)?;
            if history.is_empty() {
                writeln!(out, "no kicks")?;
            }
            for (kick, device_name, removed) in history {
                let removed = if removed { ", removed" } else { "" };
                let ends = match kick.until {
                    Some(until) => format!("until {until}"),
                    None => "until lifted".to_string(),
                };
                let reason = if kick.reason.is_empty() {
                    String::new()
                } else {
                    format!("  \"{}\"", kick.reason)
                };
                let lifted = match (kick.lifted_at, kick.lifted_by) {
                    (Some(at), Some(by)) => format!("  lifted by {by} at {at}"),
                    _ => String::new(),
                };
                writeln!(
                    out,
                    "kick {}  device {} ({device_name}{removed})  by {}  from {}  {ends}{lifted}{reason}",
                    kick.id, kick.device_id, kick.by, kick.started_at
                )?;
            }
        }
        ["kick", device_id, length, flags @ ..] => {
            let device_id = id(device_id)?;
            let end = parse_length(length, now).ok_or(Failure::Usage)?;
            let flags = Flags::read(flags, &["--by", "--reason"])?;
            let by = flags.get("--by").unwrap_or(DEFAULT_BY);
            let reason = flags.get("--reason").unwrap_or("");
            Store::open(db)?.kick(device_id, end, by, reason, now)?;
            match end {
                KickEnd::At(_) => writeln!(out, "device {device_id} kicked for {length}")?,
                KickEnd::UntilLifted => writeln!(out, "device {device_id} kicked until lifted")?,
            }
        }
        ["lift", device_id, flags @ ..] => {
            let device_id = id(device_id)?;
            let flags = Flags::read(flags, &["--by"])?;
            let by = flags.get("--by").unwrap_or(DEFAULT_BY);
            match Store::open(db)?.lift(device_id, by, now)? {
                0 => writeln!(out, "device {device_id} has no running kick")?,
                lifted => writeln!(out, "device {device_id}: {lifted} kick(s) lifted")?,
            }
        }
        ["backup", file] => {
            let copy = crate::backup::backup(db, Path::new(file)).map_err(Failure::Refused)?;
            writeln!(
                out,
                "backup written to {file}: schema version {}, {} bytes",
                copy.schema_version, copy.bytes
            )?;
        }
        ["peers"] => {
            let list = Store::open(db)?.publish(now)?;
            let json = serde_json::to_string_pretty(&list)
                .map_err(|e| Failure::Refused(format!("cannot write the list: {e}")))?;
            writeln!(out, "{json}")?;
        }
        ["node", rest @ ..] => node_command(rest, db, context, now, out)?,
        ["admin", rest @ ..] => admin_command(rest, db, context, out)?,
        ["list", rest @ ..] => list_command(rest, db, out)?,
        _ => return Err(Failure::Usage),
    }
    Ok(())
}

/// `bf-control node ...`: the registry of nodes, and a one-shot check of one.
fn node_command(
    words: &[&str],
    db: &Path,
    context: &Context<'_>,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    match words {
        ["add", name, address, title, place, flags @ ..] => {
            let (name, title, place) = (text(name)?, text(title)?, text(place)?);
            // What the agent's interface speaks decides which list it gets: required.
            let protocol = Flags::read(flags, &["--protocol"])?
                .get("--protocol")
                .ok_or(Failure::Usage)?;
            let protocol = protocol_word(protocol)?;
            let mut store = Store::open(db)?;
            let node = store.add_node_with(name, address, title, place, Some(protocol), now)?;
            let dir = context.nodes_dir.map_or_else(
                || "the nodes directory (BC_NODES_DIR)".to_string(),
                |d| d.display().to_string(),
            );
            writeln!(
                out,
                "added node {} at {}. Its signing secret goes in {dir}/{}.secret and its root certificate in {dir}/{}.pem.",
                node.name, node.address, node.name, node.name
            )?;
        }
        ["list"] => {
            let store = Store::open(db)?;
            let nodes = store.nodes()?;
            if nodes.is_empty() {
                writeln!(out, "no nodes")?;
            }
            for node in nodes {
                let files = match context.nodes_dir {
                    None => "files: BC_NODES_DIR is not set".to_string(),
                    Some(dir) => match read_files(dir, &node.name) {
                        Ok(_) => "files ok".to_string(),
                        Err(problem) => format!("files: {problem}"),
                    },
                };
                let location = node.location.map_or_else(
                    || "location not set".to_string(),
                    |at| format!("at {},{}", at.lat, at.lon),
                );
                writeln!(
                    out,
                    "{}  {}  {}  {}  \"{}, {}\"  {location}  {files}",
                    node.name,
                    node.address,
                    node.protocol
                        .map_or("protocol not set", crate::protocol::Protocol::as_str),
                    if node.enabled { "enabled" } else { "disabled" },
                    node.title,
                    node.place
                )?;
            }
        }
        ["set-protocol", name, protocol] => {
            let protocol = protocol_word(protocol)?;
            Store::open(db)?.set_node_protocol(text(name)?, protocol)?;
            writeln!(out, "{name} speaks {}", protocol.as_str())?;
        }
        ["set-location", name, at] => {
            let at = crate::closest::Location::parse(at).ok_or_else(|| {
                Failure::Refused(format!(
                    "{at:?} is not a location: write the latitude and longitude in degrees, like 43.65,-79.38"
                ))
            })?;
            Store::open(db)?.set_node_location(text(name)?, at)?;
            writeln!(out, "{name} is at {},{}", at.lat, at.lon)?;
        }
        ["enable", name] => {
            Store::open(db)?.set_node_enabled(text(name)?, true)?;
            writeln!(out, "{name} is enabled")?;
        }
        ["disable", name] => {
            Store::open(db)?.set_node_enabled(text(name)?, false)?;
            writeln!(
                out,
                "{name} is disabled, so the website says it is being fixed"
            )?;
        }
        ["remove", name] => {
            Store::open(db)?.remove_node(text(name)?)?;
            writeln!(
                out,
                "{name} is removed; its files are still in the nodes directory"
            )?;
        }
        ["check", name] => check_node(text(name)?, db, context, now, out)?,
        _ => return Err(Failure::Usage),
    }
    Ok(())
}

/// Asks one node for its status the way the poller does, and prints what it said.
fn check_node(
    name: &str,
    db: &Path,
    context: &Context<'_>,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    let Some(dir) = context.nodes_dir else {
        return Err(Failure::Refused(
            "BC_NODES_DIR is not set, so there is nowhere to read the node's files from"
                .to_string(),
        ));
    };
    let store = Store::open(db)?;
    let node = store.node(name)?.ok_or(StoreError::NoSuchNode)?;
    let files = read_files(dir, name).map_err(|problem| {
        Failure::Refused(format!("{name}: {problem} (looked in {})", dir.display()))
    })?;
    let link = context
        .connector
        .connect(&node, &files)
        .map_err(|problem| Failure::Refused(format!("{name}: {problem}")))?;
    let reading = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(link.status(now))
        .map_err(|problem| Failure::Refused(format!("{name} ({}): {problem}", node.address)))?;
    // Only looks: a check must not change the database (the poller publishes).
    let database = store.peek_list(now)?.version;

    writeln!(out, "{name} ({}): answered", node.address)?;
    writeln!(out, "  WireGuard public key: {}", reading.wg_public_key)?;
    writeln!(out, "  listen port: {}", reading.listen_port)?;
    writeln!(
        out,
        "  peers: {} total, {} online",
        reading.peers_total, reading.online
    )?;
    match reading.load1 {
        Some(load) => writeln!(out, "  load: {load:.2}")?,
        None => writeln!(out, "  load: unknown")?,
    }
    let list = match reading.desired_version {
        None => format!(
            "the node holds none yet; the database is at version {database} (the poller will send it)"
        ),
        Some(held) if held == database => format!(
            "the node holds version {held}, the database is at version {database} (in step)"
        ),
        Some(held) if held < database => format!(
            "the node holds version {held}, the database is at version {database} (the poller will send it)"
        ),
        Some(held) => format!(
            "the node holds version {held}, AHEAD of the database's version {database}; run `bf-control list raise {held}`"
        ),
    };
    writeln!(out, "  list: {list}")?;
    Ok(())
}

/// `bf-control admin ...`: who may use the admin pages, and their password. Admin rights can
/// be given only here; no web page sets them.
fn admin_command(
    words: &[&str],
    db: &Path,
    context: &Context<'_>,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    match words {
        ["grant", account] => {
            let account = id(account)?;
            let mut store = Store::open(db)?;
            let found = store.account(account)?.ok_or(StoreError::NoSuchAccount)?;
            store.set_admin(account, true)?;
            writeln!(
                out,
                "account {account} ({}) may now use the admin pages once it has an admin password: bf-control admin set-password {account}",
                found.label
            )?;
        }
        ["revoke", account] => {
            let account = id(account)?;
            let mut store = Store::open(db)?;
            store.set_admin(account, false)?;
            writeln!(
                out,
                "account {account} is no longer an admin; its admin password and every unlock are gone"
            )?;
        }
        ["set-password", account] => {
            let account = id(account)?;
            let Some(read) = context.password_input else {
                return Err(Failure::Refused(
                    "the password is read from standard input, and none is connected here"
                        .to_string(),
                ));
            };
            let typed = read()?;
            // The line ending the terminal or `printf` adds is not part of the password.
            let password = typed
                .strip_suffix("\r\n")
                .or_else(|| typed.strip_suffix('\n'))
                .unwrap_or(&typed);
            let mut store = Store::open(db)?;
            store
                .set_admin_password(account, password)
                .map_err(|e| Failure::Refused(e.to_string()))?;
            writeln!(out, "the admin password for account {account} is set")?;
        }
        _ => return Err(Failure::Usage),
    }
    Ok(())
}

/// `bf-control list raise <n>`.
fn list_command(words: &[&str], db: &Path, out: &mut dyn Write) -> Result<(), Failure> {
    let ["raise", n] = words else {
        return Err(Failure::Usage);
    };
    let n: u64 = n.parse().map_err(|_| Failure::Usage)?;
    let mut store = Store::open(db)?;
    if store.raise_version_floor(n)? {
        writeln!(out, "the next list will be version {}", n + 1)?;
    } else {
        let now_at = store.list_version()?.unwrap_or(0);
        writeln!(
            out,
            "nothing to do: the database is already at version {now_at}, which is not below {n}"
        )?;
    }
    Ok(())
}

/// Turns a sign-in address into the fingerprint that is stored in its place. The key file
/// is made on first use (readable by its owner only) and an existing one is never changed.
fn address_fingerprint(key_file: Option<&Path>, address: &str) -> Result<[u8; 32], Failure> {
    check_address(address).map_err(|e| Failure::Refused(e.to_string()))?;
    let Some(path) = key_file else {
        return Err(Failure::Refused(
            "there is no key file path (BC_KEY_FILE), so an address cannot be made into a fingerprint"
                .to_string(),
        ));
    };
    let keys = ControlKeys::load_or_create(path)
        .map_err(|e| Failure::Refused(format!("{e} ({})", path.display())))?;
    Ok(keys.email_fingerprint(address))
}

/// Who a kick or a lift is recorded under when `--by` is not given.
const DEFAULT_BY: &str = "admin";

/// The `--name value` pairs after a command's fixed arguments.
struct Flags<'a>(Vec<(&'a str, &'a str)>);

impl<'a> Flags<'a> {
    /// Every word must be one of `allowed` followed by its value, each at most once.
    fn read(words: &[&'a str], allowed: &[&str]) -> Result<Flags<'a>, Failure> {
        let mut pairs = Vec::new();
        for pair in words.chunks(2) {
            let &[name, value] = pair else {
                return Err(Failure::Usage);
            };
            if !allowed.contains(&name) || pairs.iter().any(|(seen, _)| *seen == name) {
                return Err(Failure::Usage);
            }
            pairs.push((name, value));
        }
        Ok(Flags(pairs))
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        self.0
            .iter()
            .find(|(seen, _)| *seen == name)
            .map(|(_, value)| *value)
    }
}

/// `wireguard` or `amneziawg`, exactly.
fn protocol_word(word: &str) -> Result<crate::protocol::Protocol, Failure> {
    crate::protocol::Protocol::parse(word).ok_or_else(|| {
        Failure::Refused(format!(
            "{word:?} is not a protocol: it is wireguard or amneziawg"
        ))
    })
}

/// A label or name on the command line. A word that starts with `-` is a mistyped flag
/// (`--help`), not a name.
fn text(word: &str) -> Result<&str, Failure> {
    if word.starts_with('-') {
        Err(Failure::Usage)
    } else {
        Ok(word)
    }
}

/// An id on the command line: a whole number above zero.
fn id(text: &str) -> Result<i64, Failure> {
    match text.parse::<i64>() {
        Ok(id) if id > 0 => Ok(id),
        _ => Err(Failure::Usage),
    }
}

/// Reads a kick length: `90s`, `30m`, `2h`, `7d`, or `forever` (until lifted). The
/// number must be whole and more than zero.
pub fn parse_length(text: &str, now: u64) -> Option<KickEnd> {
    if text == "forever" {
        return Some(KickEnd::UntilLifted);
    }
    let unit = text.chars().last()?;
    let seconds_per_unit: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return None,
    };
    let digits = &text[..text.len() - unit.len_utf8()];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let count: u64 = digits.parse().ok()?;
    if count == 0 {
        return None;
    }
    let end = now.checked_add(count.checked_mul(seconds_per_unit)?)?;
    Some(KickEnd::At(end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::KickEnd;
    use bf_common::peers::{PeerList, is_valid_key};
    use std::path::{Path, PathBuf};

    #[test]
    fn a_kick_length_is_a_number_with_a_unit_or_forever() {
        let now = 1_000;
        assert_eq!(parse_length("90s", now), Some(KickEnd::At(1_090)));
        assert_eq!(parse_length("30m", now), Some(KickEnd::At(1_000 + 30 * 60)));
        assert_eq!(
            parse_length("2h", now),
            Some(KickEnd::At(1_000 + 2 * 3_600))
        );
        assert_eq!(
            parse_length("7d", now),
            Some(KickEnd::At(1_000 + 7 * 86_400))
        );
        assert_eq!(parse_length("forever", now), Some(KickEnd::UntilLifted));

        for bad in [
            "",
            "0m",
            "m",
            "30",
            "30x",
            "-5m",
            "1.5h",
            "5 m",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_length(bad, now), None, "{bad:?}");
        }
    }

    /// A database path in a fresh directory of its own.
    fn temp_db(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-control-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("control.db")
    }

    /// Runs one command and returns its exit code and what it printed.
    fn run_at(db: &Path, now: u64, args: &[&str]) -> (u8, String) {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args, db, now, &mut out, &mut err);
        out.extend_from_slice(&err);
        (code, String::from_utf8(out).unwrap())
    }

    /// The value printed after `label` on a line of its own.
    fn field<'a>(output: &'a str, label: &str) -> &'a str {
        output
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .map(str::trim)
            .unwrap_or_else(|| panic!("no {label:?} line in:\n{output}"))
    }

    #[test]
    fn an_account_and_a_device_are_made_and_the_device_is_on_the_peer_list() {
        let db = temp_db("cli-device");

        let (code, out) = run_at(&db, 1_000, &["account", "add", "lao"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("account 1"), "{out}");

        let (code, out) = run_at(&db, 1_001, &["device", "add", "1", "phone"]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(field(&out, "address:"), "10.77.0.2");
        let public_key = field(&out, "public key:").to_string();
        let private_key = field(&out, "private key:").to_string();
        assert!(is_valid_key(&public_key), "{out}");
        assert!(is_valid_key(&private_key), "{out}");

        let (code, out) = run_at(&db, 1_002, &["peers"]);
        assert_eq!(code, 0, "{out}");
        let list: PeerList = serde_json::from_str(&out).unwrap();
        assert_eq!(list.version, 1);
        assert_eq!(list.peers.len(), 1);
        assert_eq!(list.peers[0].public_key, public_key);
        assert_eq!(list.peers[0].allowed_ips, ["10.77.0.2/32"]);

        // The private key was shown once and is nowhere in the database.
        let stored = std::fs::read(&db).unwrap();
        let needle = private_key.as_bytes();
        assert!(!stored.windows(needle.len()).any(|bytes| bytes == needle));
    }

    /// A database where account 1 holds device 1.
    fn db_with_device(name: &str) -> PathBuf {
        let db = temp_db(name);
        assert_eq!(run_at(&db, 1_000, &["account", "add", "lao"]).0, 0);
        assert_eq!(run_at(&db, 1_001, &["device", "add", "1", "phone"]).0, 0);
        db
    }

    fn peers_on_the_list(db: &Path, now: u64) -> usize {
        let (code, out) = run_at(db, now, &["peers"]);
        assert_eq!(code, 0, "{out}");
        serde_json::from_str::<PeerList>(&out).unwrap().peers.len()
    }

    #[test]
    fn a_kick_takes_a_length_every_time_and_a_lift_ends_it() {
        let db = db_with_device("cli-kick");

        let (code, out) = run_at(&db, 2_000, &["kick", "1"]);
        assert_eq!(code, 2, "a kick with no length is not understood: {out}");
        assert_eq!(peers_on_the_list(&db, 2_000), 1, "and it changes nothing");

        let kick = ["kick", "1", "10m", "--by", "lao", "--reason", "too loud"];
        let (code, out) = run_at(&db, 2_000, &kick);
        assert_eq!(code, 0, "{out}");
        assert_eq!(peers_on_the_list(&db, 2_001), 0);
        let (_, listed) = run_at(&db, 2_001, &["device", "list"]);
        assert!(listed.contains("kicked"), "{listed}");
        assert_eq!(peers_on_the_list(&db, 2_600), 1, "back after 10 minutes");

        assert_eq!(run_at(&db, 3_000, &["kick", "1", "forever"]).0, 0);
        assert_eq!(peers_on_the_list(&db, 9_000_000), 0);
        let (code, out) = run_at(&db, 9_000_001, &["lift", "1", "--by", "lao"]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(peers_on_the_list(&db, 9_000_001), 1);
        let (_, listed) = run_at(&db, 9_000_001, &["device", "list"]);
        assert!(!listed.contains("kicked"), "{listed}");
    }

    #[test]
    fn the_account_list_shows_each_account_with_its_device_count() {
        let db = temp_db("cli-accounts");
        let (code, out) = run_at(&db, 1_000, &["account", "list"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("no accounts"), "{out}");

        assert_eq!(run_at(&db, 1_000, &["account", "add", "lao"]).0, 0);
        assert_eq!(run_at(&db, 1_000, &["account", "add", "sam"]).0, 0);
        assert_eq!(run_at(&db, 1_001, &["device", "add", "1", "phone"]).0, 0);
        assert_eq!(run_at(&db, 1_002, &["device", "add", "1", "laptop"]).0, 0);

        let (code, out) = run_at(&db, 1_003, &["account", "list"]);
        assert_eq!(code, 0, "{out}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert_eq!(lines[0], "1  lao  2 of 3 devices");
        assert_eq!(lines[1], "2  sam  0 of 3 devices");
    }

    #[test]
    fn a_kicked_account_gets_no_new_device_and_no_key_is_printed() {
        let db = db_with_device("cli-kicked-add");
        assert_eq!(run_at(&db, 2_000, &["kick", "1", "forever"]).0, 0);

        let (code, out) = run_at(&db, 2_001, &["device", "add", "1", "laptop"]);

        assert_eq!(code, 1, "{out}");
        assert!(out.contains("kicked"), "{out}");
        assert!(!out.contains("private key"), "{out}");
        assert_eq!(run_at(&db, 2_002, &["lift", "1"]).0, 0);
        assert_eq!(run_at(&db, 2_003, &["device", "add", "1", "laptop"]).0, 0);
    }

    #[test]
    fn a_removed_device_leaves_the_list_and_its_address_is_used_again() {
        let db = db_with_device("cli-remove");
        assert_eq!(run_at(&db, 1_002, &["device", "add", "1", "laptop"]).0, 0);
        assert_eq!(peers_on_the_list(&db, 1_003), 2);

        let (code, out) = run_at(&db, 1_004, &["device", "remove", "1"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("device 1 removed"), "{out}");
        assert!(out.contains("10.77.0.2"), "{out}");
        assert_eq!(peers_on_the_list(&db, 1_005), 1);

        let (_, listed) = run_at(&db, 1_005, &["device", "list"]);
        assert!(!listed.contains("phone"), "{listed}");
        assert!(listed.contains("laptop"), "{listed}");

        // The freed address goes to the next device before any higher one.
        let (code, out) = run_at(&db, 1_006, &["device", "add", "1", "tablet"]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(field(&out, "address:"), "10.77.0.2");

        // Removing what is not there is refused, and a bad id is a usage error.
        let (code, out) = run_at(&db, 1_007, &["device", "remove", "9"]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("no device with that id"), "{out}");
        assert_eq!(run_at(&db, 1_007, &["device", "remove", "x"]).0, 2);
        assert_eq!(run_at(&db, 1_007, &["device", "remove"]).0, 2);
    }

    #[test]
    fn a_command_that_makes_a_new_database_file_says_so_on_stderr_once() {
        let db = temp_db("cli-new-db");
        let args: Vec<String> = ["account", "list"].map(String::from).into();

        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&args, &db, 1_000, &mut out, &mut err), 0);
        let told = String::from_utf8(err).unwrap();
        assert!(told.contains("new database"), "{told}");
        assert!(told.contains(&db.display().to_string()), "{told}");

        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&args, &db, 1_001, &mut out, &mut err), 0);
        assert!(err.is_empty(), "the file was there already");

        // A command that is not understood never gets as far as a database.
        let other = db.with_file_name("other.db");
        let bad: Vec<String> = ["kick", "1"].map(String::from).into();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(run(&bad, &other, 1_002, &mut out, &mut err), 2);
        assert!(!String::from_utf8(err).unwrap().contains("new database"));
        assert!(!other.exists());
    }

    #[test]
    fn the_kick_list_shows_every_kick_with_its_device_even_after_the_device_is_removed() {
        let db = db_with_device("cli-kick-list");
        assert_eq!(run_at(&db, 1_002, &["device", "add", "1", "laptop"]).0, 0);
        let kick = [
            "kick", "1", "forever", "--by", "lao", "--reason", "too loud",
        ];
        assert_eq!(run_at(&db, 2_000, &kick).0, 0);
        assert_eq!(run_at(&db, 2_001, &["kick", "2", "10m"]).0, 0);
        assert_eq!(run_at(&db, 2_002, &["lift", "1", "--by", "sam"]).0, 0);
        let (code, out) = run_at(&db, 2_003, &["device", "remove", "1"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("kicks are kept"), "{out}");

        let (code, out) = run_at(&db, 2_004, &["kick", "list"]);
        assert_eq!(code, 0, "{out}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        for part in [
            "kick 1",
            "device 1 (phone, removed)",
            "by lao",
            "too loud",
            "until lifted",
            "lifted by sam",
        ] {
            assert!(lines[0].contains(part), "{part:?} in {}", lines[0]);
        }
        for part in ["kick 2", "device 2 (laptop)", "by admin", "until 2601"] {
            assert!(lines[1].contains(part), "{part:?} in {}", lines[1]);
        }
        assert!(!lines[1].contains("removed"), "{}", lines[1]);

        let (code, out) = run_at(&db, 2_005, &["kick", "list", "2"]);
        assert_eq!((code, out.lines().count()), (0, 1), "{out}");
        let (code, out) = run_at(&db, 2_005, &["kick", "list", "9"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("no kicks"), "{out}");
        assert_eq!(run_at(&db, 2_006, &["kick", "list", "x"]).0, 2);
        assert_eq!(run_at(&db, 2_006, &["kick", "list", "1", "2"]).0, 2);
    }

    /// Something to write to that always fails, like a closed pipe.
    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_device_whose_private_key_could_not_be_shown_is_not_kept() {
        let db = temp_db("cli-lost-key");
        assert_eq!(run_at(&db, 1_000, &["account", "add", "lao"]).0, 0);

        let args: Vec<String> = ["device", "add", "1", "phone"].map(String::from).into();
        let mut err = Vec::new();
        let code = run(&args, &db, 1_001, &mut BrokenPipe, &mut err);

        assert_eq!(code, 1);
        assert!(!err.is_empty(), "the reason is told on stderr");
        let (_, listed) = run_at(&db, 1_002, &["device", "list"]);
        assert_eq!(listed, "", "no device nobody holds the key of");
        let (_, shown) = run_at(&db, 1_003, &["device", "add", "1", "phone"]);
        assert_eq!(
            field(&shown, "address:"),
            "10.77.0.2",
            "and the address is free"
        );
        assert_eq!(peers_on_the_list(&db, 1_004), 1);
    }

    #[test]
    fn kicks_and_lifts_are_recorded_under_admin_unless_somebody_else_is_named() {
        let db = db_with_device("cli-by");
        assert_eq!(run_at(&db, 2_000, &["kick", "1", "10m"]).0, 0);
        let (code, out) = run_at(&db, 2_001, &["lift", "1"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("1 kick(s) lifted"), "{out}");

        let kicks = Store::open(&db).unwrap().kicks(1).unwrap();
        assert_eq!(kicks[0].by, "admin");
        assert_eq!(kicks[0].reason, "");
        assert_eq!(kicks[0].lifted_by.as_deref(), Some("admin"));

        let (code, out) = run_at(&db, 2_002, &["lift", "1"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("has no running kick"), "{out}");
    }

    #[test]
    fn a_word_that_looks_like_a_flag_is_never_taken_as_a_name() {
        let db = db_with_device("cli-flags");

        for words in [
            &["account", "add", "--help"][..],
            &["account", "add", "-h"],
            &["device", "add", "1", "--help"],
            &["--help"],
            &["-h"],
        ] {
            let (code, out) = run_at(&db, 2_000, words);
            assert_eq!(code, 2, "{words:?}");
            assert!(out.contains("usage:"), "{words:?}: {out}");
        }
        let (_, accounts) = run_at(&db, 2_001, &["account", "list"]);
        assert_eq!(accounts.lines().count(), 1, "{accounts}");
        let (_, devices) = run_at(&db, 2_001, &["device", "list"]);
        assert_eq!(devices.lines().count(), 1, "{devices}");
    }

    /// Runs one command with a key file, the way `main` does.
    fn run_keyed(db: &Path, key_file: &Path, now: u64, args: &[&str]) -> (u8, String) {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_with(&args, db, Some(key_file), now, &mut out, &mut err);
        out.extend_from_slice(&err);
        (code, String::from_utf8(out).unwrap())
    }

    fn fingerprint_in(key_file: &Path, address: &str) -> [u8; 32] {
        crate::secrets::ControlKeys::load(key_file)
            .unwrap()
            .email_fingerprint(address)
    }

    #[test]
    fn an_account_can_be_made_with_a_sign_in_address_and_the_address_is_never_kept() {
        let db = temp_db("cli-email");
        let key_file = db.with_file_name("control.key");
        assert!(!key_file.exists());

        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_000,
            &["account", "add", "lao", "--email", "Lao@Example.com"],
        );

        assert_eq!(code, 0, "{out}");
        assert!(out.contains("account 1 created: lao"), "{out}");
        assert!(out.contains("can sign in"), "{out}");
        assert!(
            !out.to_lowercase().contains("example.com"),
            "the address is not echoed: {out}"
        );
        assert!(key_file.exists(), "the key file is made on first use");
        let store = Store::open(&db).unwrap();
        let found = store
            .account_for_email_fp(&fingerprint_in(&key_file, "lao@example.com"))
            .unwrap();
        assert_eq!(
            found.map(|a| a.id),
            Some(1),
            "found by the fingerprint, in any case"
        );
        let bytes = std::fs::read(&db).unwrap();
        for needle in ["example.com", "Example.com", "lao@", "Lao@"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle} is in the database file"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_made_private_once_and_reused_for_every_later_address() {
        use std::os::unix::fs::PermissionsExt;
        let db = temp_db("cli-key-reuse");
        let key_file = db.with_file_name("control.key");

        run_keyed(
            &db,
            &key_file,
            1_000,
            &["account", "add", "lao", "--email", "lao@example.com"],
        );
        let first = std::fs::read_to_string(&key_file).unwrap();
        run_keyed(
            &db,
            &key_file,
            1_001,
            &["account", "add", "sam", "--email", "sam@example.com"],
        );

        assert_eq!(
            std::fs::read_to_string(&key_file).unwrap(),
            first,
            "not made again"
        );
        assert_eq!(
            std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let store = Store::open(&db).unwrap();
        let sam = store
            .account_for_email_fp(&fingerprint_in(&key_file, "sam@example.com"))
            .unwrap();
        assert_eq!(sam.map(|a| a.label), Some("sam".to_string()));
    }

    #[test]
    fn an_account_can_be_given_or_moved_to_an_address_later() {
        let db = temp_db("cli-set-email");
        let key_file = db.with_file_name("control.key");
        assert_eq!(
            run_keyed(&db, &key_file, 1_000, &["account", "add", "lao"]).0,
            0
        );

        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_001,
            &["account", "set-email", "1", "lao@example.com"],
        );
        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("account 1") && out.contains("can sign in"),
            "{out}"
        );
        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_002,
            &["account", "set-email", "1", "new@example.com"],
        );
        assert_eq!(code, 0, "{out}");

        let store = Store::open(&db).unwrap();
        assert_eq!(
            store
                .account_for_email_fp(&fingerprint_in(&key_file, "lao@example.com"))
                .unwrap(),
            None,
            "the old address is let go"
        );
        assert!(
            store
                .account_for_email_fp(&fingerprint_in(&key_file, "new@example.com"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn an_address_one_account_has_cannot_be_given_to_another_and_nothing_changes() {
        let db = temp_db("cli-email-taken");
        let key_file = db.with_file_name("control.key");
        run_keyed(
            &db,
            &key_file,
            1_000,
            &["account", "add", "lao", "--email", "lao@example.com"],
        );

        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_001,
            &["account", "add", "sam", "--email", "LAO@example.com"],
        );
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("already has that email address"), "{out}");
        assert_eq!(
            run_keyed(&db, &key_file, 1_002, &["account", "list"])
                .1
                .lines()
                .count(),
            1,
            "no second account was made"
        );

        run_keyed(&db, &key_file, 1_003, &["account", "add", "sam"]);
        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_004,
            &["account", "set-email", "2", "lao@example.com"],
        );
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("already has that email address"), "{out}");
    }

    #[test]
    fn a_bad_address_an_unknown_account_or_no_key_file_is_refused_and_changes_nothing() {
        let db = temp_db("cli-email-bad");
        let key_file = db.with_file_name("control.key");
        run_keyed(&db, &key_file, 1_000, &["account", "add", "lao"]);

        for bad in [
            "not-an-address",
            "Lao <lao@example.com>",
            "a@b.com, c@d.com",
            "",
        ] {
            let (code, out) = run_keyed(&db, &key_file, 1_001, &["account", "set-email", "1", bad]);
            assert_eq!(code, 1, "{bad:?}: {out}");
            assert!(out.contains("not an email address"), "{bad:?}: {out}");
        }
        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_002,
            &["account", "add", "sam", "--email", "nope"],
        );
        assert_eq!(code, 1, "{out}");
        assert_eq!(
            run_keyed(&db, &key_file, 1_003, &["account", "list"])
                .1
                .lines()
                .count(),
            1,
            "the account was not made"
        );

        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_004,
            &["account", "set-email", "9", "x@example.com"],
        );
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("no account with that id"), "{out}");

        // Without a key file path (plain `run`) these commands cannot work.
        let (code, out) = run_at(
            &db,
            1_005,
            &["account", "set-email", "1", "lao@example.com"],
        );
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("key file"), "{out}");
    }

    #[test]
    fn a_key_file_that_is_not_a_good_key_file_is_refused_and_never_overwritten() {
        let db = temp_db("cli-email-badkey");
        let key_file = db.with_file_name("control.key");
        std::fs::write(&key_file, "not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        run_keyed(&db, &key_file, 1_000, &["account", "add", "lao"]);

        let (code, out) = run_keyed(
            &db,
            &key_file,
            1_001,
            &["account", "set-email", "1", "lao@example.com"],
        );

        assert_eq!(code, 1, "{out}");
        assert!(out.contains("key file"), "{out}");
        assert_eq!(std::fs::read_to_string(&key_file).unwrap(), "not a key");
    }

    #[test]
    fn the_new_commands_have_their_usage_and_a_missing_word_is_not_understood() {
        let db = temp_db("cli-email-usage");
        let key_file = db.with_file_name("control.key");
        for words in [
            &["account", "add", "lao", "--email"][..],
            &["account", "add", "lao", "--bogus", "x"],
            &[
                "account", "add", "lao", "--email", "a@b.com", "--email", "c@d.com",
            ],
            &["account", "set-email", "1"],
            &["account", "set-email", "x", "a@b.com"],
            &["account", "set-email"],
            &["account", "set-email", "1", "--help"],
        ] {
            let (code, out) = run_keyed(&db, &key_file, 1_000, words);
            assert_eq!(code, 2, "{words:?}: {out}");
            assert!(out.contains("usage:"), "{words:?}");
        }
        let (_, usage) = run_keyed(&db, &key_file, 1_000, &["frobnicate"]);
        assert!(
            usage.contains("account add <label> [--email <address>]"),
            "{usage}"
        );
        assert!(
            usage.contains("account set-email <account-id> <address>"),
            "{usage}"
        );
        assert!(
            !key_file.exists(),
            "a command that is not understood makes nothing"
        );
    }

    #[test]
    fn a_command_that_is_not_understood_prints_the_usage_and_a_refused_one_says_why() {
        let db = db_with_device("cli-errors");

        let not_understood: [&[&str]; 9] = [
            &[],
            &["frobnicate"],
            &["account"],
            &["account", "add"],
            &["device", "add", "one", "phone"],
            &["kick", "1", "soon"],
            &["kick", "1", "10m", "--because", "x"],
            &["kick", "1", "10m", "--by"],
            &["lift"],
        ];
        for words in not_understood {
            let (code, out) = run_at(&db, 2_000, words);
            assert_eq!(code, 2, "{words:?}");
            assert!(out.contains("usage:"), "{words:?}: {out}");
        }

        let (code, out) = run_at(&db, 2_000, &["device", "add", "7", "phone"]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("no account with that id"), "{out}");
        let (code, out) = run_at(&db, 2_000, &["kick", "9", "10m"]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("no device with that id"), "{out}");
    }

    // ---- backup ----

    /// A folder only its owner can open, next to the test database.
    fn private_folder(db: &Path) -> PathBuf {
        let folder = db.parent().unwrap().join("backups");
        std::fs::create_dir_all(&folder).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        folder
    }

    #[test]
    fn a_backup_copies_the_database_and_says_where() {
        let db = temp_db("backup-ok");
        assert_eq!(run_at(&db, 1_000, &["account", "add", "lao"]).0, 0);
        let out = private_folder(&db).join("copy.db");
        let (code, said) = run_at(&db, 1_001, &["backup", out.to_str().unwrap()]);
        assert_eq!(code, 0, "{said}");
        let bytes = std::fs::metadata(&out).unwrap().len();
        assert_eq!(
            said,
            format!(
                "backup written to {}: schema version 6, {bytes} bytes\n",
                out.display()
            )
        );
        let (_, listed) = run_at(&out, 1_002, &["account", "list"]);
        assert!(listed.contains("lao"), "{listed}");
    }

    #[test]
    fn a_backup_of_a_missing_database_refuses_and_makes_none() {
        let db = temp_db("backup-missing");
        let out = private_folder(&db).join("copy.db");
        let (code, said) = run_at(&db, 1_000, &["backup", out.to_str().unwrap()]);
        assert_eq!(code, 1, "{said}");
        assert!(said.contains("there is no database"), "{said}");
        assert!(!said.contains("made a new database"), "{said}");
        assert!(!db.exists());
        assert!(!out.exists());
    }

    #[test]
    fn a_backup_needs_exactly_one_file() {
        let db = temp_db("backup-usage");
        assert_eq!(run_at(&db, 1_000, &["backup"]).0, 2);
        assert_eq!(run_at(&db, 1_000, &["backup", "a", "b"]).0, 2);
        assert!(!db.exists());
    }
}

#[cfg(test)]
#[path = "cli_nodes_tests.rs"]
mod node_tests;

#[cfg(test)]
#[path = "cli_admin_tests.rs"]
mod admin_tests;
