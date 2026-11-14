//! The one place that writes log lines.
//!
//! `eprintln!` panics when standard error cannot be written, and a panic in the reconcile
//! task would silently stop it. A log line must never be able to do that.

use std::io::Write;

/// Writes `bf-agent: <message>` to standard error. If that fails, the line is lost.
pub fn line(message: &str) {
    write_line(&mut std::io::stderr(), message);
}

fn write_line(out: &mut impl Write, message: &str) {
    let _ = writeln!(out, "bf-agent: {message}");
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_line_has_the_agent_prefix_and_a_newline() {
        let mut out = Vec::new();

        write_line(&mut out, "hello");

        assert_eq!(String::from_utf8(out).unwrap(), "bf-agent: hello\n");
    }

    #[test]
    fn a_line_that_cannot_be_written_is_lost_and_does_not_panic() {
        write_line(&mut Broken, "lost");
    }
}
