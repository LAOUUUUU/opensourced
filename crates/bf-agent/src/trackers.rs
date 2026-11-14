//! `bf-agent trackers build`: turns a downloaded EasyPrivacy into the zone the node's
//! resolver blocks (`specs/trackers.md`). It needs no secret and no network.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use bf_common::trackers::{FloorError, check_floor, names, names_in_zone, zone};

/// What a build wrote: the names now blocked and the names blocked before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Built {
    pub names: usize,
    pub previous: usize,
}

#[derive(Debug)]
pub enum BuildError {
    /// An input could not be read; names the input, never its content.
    Read(&'static str, io::ErrorKind),
    /// The new list broke the floor; the zone in force was left alone.
    Refused(FloorError),
    Write(io::ErrorKind),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::Read(what, kind) => write!(f, "cannot read the {what}: {kind}"),
            BuildError::Refused(why) => write!(f, "refused, the zone in force is kept: {why}"),
            BuildError::Write(kind) => write!(f, "cannot write the zone: {kind}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Reads the list and the allow file, and replaces `zone_file` with the new zone unless the
/// floor refuses it. A zone file that is missing or unreadable counts as 0 names.
pub fn build(list: &Path, allow: &Path, zone_file: &Path) -> Result<Built, BuildError> {
    let list = fs::read_to_string(list).map_err(|e| BuildError::Read("list", e.kind()))?;
    let allow = fs::read_to_string(allow).map_err(|e| BuildError::Read("allow file", e.kind()))?;
    let previous = fs::read_to_string(zone_file).map_or(0, |text| names_in_zone(&text));
    let blocked = names(&list, &allow);
    check_floor(blocked.len(), previous).map_err(BuildError::Refused)?;
    write_atomically(zone_file, zone(&blocked).as_bytes()).map_err(BuildError::Write)?;
    Ok(Built {
        names: blocked.len(),
        previous,
    })
}

/// Through `<file>.tmp` and a rename, so the resolver reads the old zone or the new one,
/// never half of one. Readable by all: it is a public list, and unbound must read it.
fn write_atomically(file: &Path, bytes: &[u8]) -> Result<(), io::ErrorKind> {
    let mut tmp_name = file.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = Path::new(&tmp_name);
    // A leftover from a crash could be anything, a symlink included: start clean.
    let _ = fs::remove_file(tmp);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(tmp)
        .map_err(|e| e.kind())?;
    out.write_all(bytes).map_err(|e| e.kind())?;
    out.sync_all().map_err(|e| e.kind())?;
    fs::rename(tmp, file).map_err(|e| e.kind())
}
