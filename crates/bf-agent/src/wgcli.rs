//! Talking to WireGuard through the `wg` program, the documented interface.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bf_common::peers::Cidr;

/// What the agent needs from WireGuard. Tests swap in a fake.
pub trait Wireguard: Send + Sync {
    /// The raw text of `wg show <interface> dump`. It holds the interface's private key
    /// and preshared keys: parse it with `bf_common::wg::parse_dump` and never log it.
    fn dump(&self) -> Result<String, WgError>;

    fn remove_peer(&self, public_key: &str) -> Result<(), WgError>;

    /// Adds the peer, or replaces its allowed ranges if it exists. Other peers are not
    /// touched, so nobody is disconnected.
    fn set_peer(&self, public_key: &str, ranges: &[Cidr]) -> Result<(), WgError>;
}

/// A short description of what went wrong. It never holds `wg`'s standard output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgError(pub String);

impl std::fmt::Display for WgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WgError {}

/// How long one `wg` call may take before it is stopped. `wg` answers in milliseconds;
/// a call that hangs must not freeze the agent.
const DEADLINE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);

pub struct WgCli {
    bin: String,
    interface: String,
    deadline: Duration,
}

impl WgCli {
    pub fn new(bin: String, interface: String) -> Self {
        Self {
            bin,
            interface,
            deadline: DEADLINE,
        }
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Runs `wg` and returns what it printed (see [`run_program`]).
    fn run(&self, args: &[&str]) -> Result<String, WgError> {
        run_program(&self.bin, "wg", args, None, self.deadline)
    }
}

/// Runs a program (`name` is what errors call it), hands it `input` on standard input if
/// there is any, and returns what it printed. A call that outlives the deadline is killed
/// and is an error. A failure carries only the first line the program said on standard
/// error (error messages name keys, interfaces and sets, never secrets).
pub(crate) fn run_program(
    bin: &str,
    name: &str,
    args: &[&str],
    input: Option<&[u8]>,
    deadline: Duration,
) -> Result<String, WgError> {
    let verb = args.first().copied().unwrap_or("");
    let mut child = Command::new(bin)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| WgError(format!("cannot run {name}: {}", e.kind())))?;
    // Feed the input from its own thread, so a program that reads slowly or not at all
    // can never block the agent; the pipe closes when the thread is done.
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        let input = input.to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    // Read both pipes while waiting, or a big dump would fill a pipe and wedge the program.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let give_up_at = Instant::now() + deadline;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < give_up_at => thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                // Reap it in the background: a process stuck in the kernel may not die at once.
                thread::spawn(move || {
                    let _ = child.wait();
                });
                return Err(WgError(format!(
                    "{name} {verb} did not finish within {deadline:?} and was stopped"
                )));
            }
            Err(e) => {
                return Err(WgError(format!(
                    "{name} {verb} cannot be waited for: {}",
                    e.kind()
                )));
            }
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    if !status.success() {
        let said = String::from_utf8_lossy(&stderr);
        let first: String = said
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        return Err(WgError(format!("{name} {verb} failed ({status}): {first}")));
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Reads a pipe to the end on its own thread.
fn drain(pipe: Option<impl Read + Send + 'static>) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

impl Wireguard for WgCli {
    fn dump(&self) -> Result<String, WgError> {
        self.run(&["show", &self.interface, "dump"])
    }

    fn remove_peer(&self, public_key: &str) -> Result<(), WgError> {
        self.run(&["set", &self.interface, "peer", public_key, "remove"])
            .map(|_| ())
    }

    fn set_peer(&self, public_key: &str, ranges: &[Cidr]) -> Result<(), WgError> {
        let ranges: Vec<String> = ranges.iter().map(ToString::to_string).collect();
        self.run(&[
            "set",
            &self.interface,
            "peer",
            public_key,
            "allowed-ips",
            &ranges.join(","),
        ])
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::testutil::{K1, K2, K3, TempDir};

    fn script(dir: &TempDir, body: &str) -> String {
        let path = dir.path().join("fake-wg");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn it_runs_wg_with_the_documented_arguments_and_returns_the_dump() {
        let dir = TempDir::new("wgcli");
        let log = dir.path().join("calls.log");
        let bin = script(
            &dir,
            &format!(
                "echo \"$@\" >> '{}'\nif [ \"$1\" = show ]; then printf 'priv\\tpub\\t51820\\toff\\n'; fi",
                log.display()
            ),
        );
        let wg = WgCli::new(bin, "wg0".to_string());
        let ranges = [
            Cidr::parse("10.66.1.2/32").unwrap(),
            Cidr::parse("fd00::2/128").unwrap(),
        ];

        assert_eq!(wg.dump().unwrap(), "priv\tpub\t51820\toff\n");
        wg.set_peer(K1, &ranges).unwrap();
        wg.set_peer(K2, &[]).unwrap();
        wg.remove_peer(K3).unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            [
                "show wg0 dump".to_string(),
                format!("set wg0 peer {K1} allowed-ips 10.66.1.2/32,fd00::2/128"),
                format!("set wg0 peer {K2} allowed-ips "),
                format!("set wg0 peer {K3} remove"),
            ]
        );
    }

    #[test]
    fn a_failing_wg_is_an_error_with_the_first_line_it_said_and_nothing_it_printed() {
        let dir = TempDir::new("wgcli-fail");
        let bin = script(
            &dir,
            "echo 'SECRET-ON-STDOUT'\necho 'Unable to access interface: No such device' >&2\n\
             echo 'second line' >&2\nexit 1",
        );

        let err = WgCli::new(bin, "wg0".to_string()).dump().unwrap_err();

        assert!(
            err.0.contains("Unable to access interface: No such device"),
            "{err}"
        );
        assert!(
            !err.0.contains("second line") && !err.0.contains("SECRET-ON-STDOUT"),
            "{err}"
        );

        let missing = WgCli::new("/nonexistent/wg".to_string(), "wg0".to_string()).dump();
        assert!(missing.unwrap_err().0.contains("cannot run"));
    }

    #[test]
    fn a_wg_that_never_returns_is_stopped_at_the_deadline() {
        let dir = TempDir::new("wgcli-hang");
        let bin = script(&dir, "exec sleep 30");
        let wg = WgCli::new(bin, "wg0".to_string()).with_deadline(Duration::from_millis(300));

        let started = Instant::now();
        let err = wg.dump().unwrap_err();

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        assert!(err.0.contains("did not finish"), "{err}");
    }

    #[test]
    fn a_dump_bigger_than_a_pipe_holds_does_not_stall() {
        let dir = TempDir::new("wgcli-big");
        let bin = script(&dir, "head -c 400000 /dev/zero | tr '\\0' 'x'");

        let dump = WgCli::new(bin, "wg0".to_string()).dump().unwrap();

        assert_eq!(dump.len(), 400_000);
    }
}
