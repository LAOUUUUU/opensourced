//! The control program's own secrets: the keys that turn an email address into a
//! fingerprint (and, later, a sign-in code into a stored check value).
//!
//! The keys live in one file outside the database, so a stolen database alone gives
//! nobody an email address or a usable code. The file holds 64 random bytes as 128 hex
//! characters: 32 for the email fingerprints, 32 for the code checks. It is made once,
//! readable by its owner only, and never printed. It cannot be rebuilt: lose it and no
//! stored fingerprint matches an address again, so it is backed up with the database.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use bf_common::sign::{hex, unhex};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// The key file is 64 bytes as hex; anything much bigger is not a key file.
const MAX_FILE_BYTES: u64 = 4096;

/// Why the key file could not be used. The text never contains key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The file is not there (only [`ControlKeys::load_or_create`] turns this into a new file).
    Missing,
    /// The file is there but is not a usable key file.
    BadFile(&'static str),
    /// The disk refused.
    Io(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Missing => write!(f, "the key file does not exist"),
            KeyError::BadFile(why) => write!(f, "the key file {why}"),
            KeyError::Io(why) => write!(f, "cannot use the key file: {why}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The two secret keys. Kept out of `Debug` so a log line cannot leak them.
#[derive(Clone)]
pub struct ControlKeys {
    fp: [u8; 32],
    code: [u8; 32],
}

impl fmt::Debug for ControlKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlKeys").finish_non_exhaustive()
    }
}

impl ControlKeys {
    /// Keys from known bytes. For tests and for reading a key file.
    pub fn from_parts(fp: [u8; 32], code: [u8; 32]) -> ControlKeys {
        ControlKeys { fp, code }
    }

    /// Reads the key file at `path`, making it first if there is none.
    ///
    /// An existing file is never changed: a file that is not a good key file is an error,
    /// not something to write over.
    pub fn load_or_create(path: &Path) -> Result<ControlKeys, KeyError> {
        match read_existing(path) {
            Err(KeyError::Missing) => {
                create(path)?;
                read_existing(path)
            }
            other => other,
        }
    }

    /// Reads the key file at `path` and creates nothing: a missing file is
    /// [`KeyError::Missing`]. The web service uses this, so a mistake in a setting can
    /// never make it write a new key file (and so lose every stored fingerprint).
    pub fn load(path: &Path) -> Result<ControlKeys, KeyError> {
        read_existing(path)
    }

    /// The fingerprint of an email address: `HMAC-SHA256(key, lowercase(trim(email)))`.
    /// The same address in any case and with spaces around it gives the same fingerprint.
    pub fn email_fingerprint(&self, email: &str) -> [u8; 32] {
        hmac(&self.fp, &[email.trim().to_lowercase().as_bytes()])
    }

    /// The key the sign-in code checks are made with.
    pub fn code_key(&self) -> &[u8; 32] {
        &self.code
    }

    /// The fingerprint of a network address, for the sign-in limits:
    /// `HMAC-SHA256(key, "ip" NUL address)`. The NUL byte keeps it apart from an email
    /// fingerprint made with the same key (an email address cannot contain one).
    pub fn ip_fingerprint(&self, ip: &str) -> [u8; 32] {
        hmac(&self.fp, &[b"ip\0", ip.as_bytes()])
    }

    /// What is stored instead of a sign-in code: `HMAC-SHA256(code key, email
    /// fingerprint || code)`. A stolen database holds no code and cannot be used to guess
    /// one offline without the key.
    pub fn code_mac(&self, email_fp: &[u8; 32], code: &str) -> [u8; 32] {
        hmac(&self.code, &[email_fp, code.as_bytes()])
    }
}

/// `HMAC-SHA256(key, parts joined)`.
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    for part in parts {
        mac.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

/// `N` random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Whether two byte strings are equal, taking the same time whatever the bytes are
/// (as long as the lengths match).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    // `black_box` keeps the compiler from turning the loop back into an early exit.
    std::hint::black_box(difference) == 0
}

/// SHA-256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(bytes).as_slice());
    out
}

/// A six-digit code from `next`, a source of random 32-bit numbers. Numbers that would
/// make some codes more likely than others (the top sliver of the range, which does not
/// divide evenly by a million) are thrown away and another is drawn.
pub fn six_digit_code(mut next: impl FnMut() -> std::io::Result<u32>) -> std::io::Result<String> {
    // The largest multiple of a million that fits in 32 bits.
    const USABLE: u32 = 4_294_000_000;
    loop {
        let number = next()?;
        if number < USABLE {
            return Ok(format!("{:06}", number % 1_000_000));
        }
    }
}

/// A new sign-in code from the operating system's random source.
pub fn random_code() -> std::io::Result<String> {
    six_digit_code(|| random_bytes::<4>().map(u32::from_le_bytes))
}

fn io(e: std::io::Error) -> KeyError {
    KeyError::Io(e.to_string())
}

/// Reads a secret file as text: it must exist, be readable by its owner only (so a
/// systemd credential at mode 0400 is fine), be text and be small. The text comes back
/// as it is, newline and all; the caller decides what it means. An error never contains
/// what the file holds.
pub fn read_secret_text(path: &Path) -> Result<String, KeyError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // A missing directory is the same "not found"; tell the two apart.
            return match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                Some(dir) if !dir.is_dir() => Err(KeyError::Io(format!(
                    "the directory {} does not exist",
                    dir.display()
                ))),
                _ => Err(KeyError::Missing),
            };
        }
        Err(e) => return Err(io(e)),
    };
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() {
        return Err(KeyError::BadFile("is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyError::BadFile(
                "can be read by others; make it readable by its owner only (chmod 600)",
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(KeyError::BadFile("is far too big to be a key"));
    }
    String::from_utf8(bytes).map_err(|_| KeyError::BadFile("is not text"))
}

fn read_existing(path: &Path) -> Result<ControlKeys, KeyError> {
    let text = read_secret_text(path)?;
    let bytes = unhex(text.trim()).filter(|bytes| bytes.len() == 64);
    let Some(bytes) = bytes else {
        return Err(KeyError::BadFile(
            "must hold 128 hex characters (64 random bytes)",
        ));
    };
    let (mut fp, mut code) = ([0u8; 32], [0u8; 32]);
    fp.copy_from_slice(&bytes[..32]);
    code.copy_from_slice(&bytes[32..]);
    Ok(ControlKeys { fp, code })
}

/// Makes the file with new random keys, readable by its owner only, and only if nobody
/// has made it first: it is written under another name and then linked into place, so a
/// reader never sees half a file and two programs starting together end up with one set
/// of keys.
fn create(path: &Path) -> Result<(), KeyError> {
    let mut random = random_bytes::<64>().map_err(io)?;
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&temporary)
        .and_then(|mut file| writeln!(file, "{}", hex(&random)).and_then(|()| file.sync_all()));
    random.fill(0);
    if let Err(e) = written {
        let _ = fs::remove_file(&temporary);
        return Err(io(e));
    }
    let linked = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A key-file path in a fresh directory of its own.
    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bf-secrets-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("control.key")
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_missing_key_file_is_made_private_with_128_hex_characters_and_then_reused() {
        let path = temp_path("create");

        let first = ControlKeys::load_or_create(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), 128, "64 bytes as hex");
        assert!(text.trim().bytes().all(|b| b.is_ascii_hexdigit()));
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600);

        let again = ControlKeys::load_or_create(&path).unwrap();
        assert_eq!(
            first.email_fingerprint("lao@example.com"),
            again.email_fingerprint("lao@example.com"),
            "the same file gives the same keys"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            text,
            "left as it was"
        );

        let other = ControlKeys::load_or_create(&temp_path("create-other")).unwrap();
        assert_ne!(
            first.email_fingerprint("lao@example.com"),
            other.email_fingerprint("lao@example.com"),
            "every new file has new random keys"
        );
        assert_ne!(
            first.code_key(),
            &first.fp,
            "two different keys in one file"
        );
    }

    #[test]
    fn a_key_file_that_is_short_empty_or_not_hex_is_refused_and_never_overwritten() {
        for (name, content) in [
            ("empty", String::new()),
            ("short", "ab".repeat(63)),
            ("long", "ab".repeat(65)),
            ("not-hex", "zz".repeat(64)),
            ("odd", format!("{}a", "ab".repeat(64))),
        ] {
            let path = temp_path(name);
            std::fs::write(&path, &content).unwrap();
            #[cfg(unix)]
            set_mode(&path, 0o600);

            let result = ControlKeys::load_or_create(&path);

            assert!(
                matches!(result, Err(KeyError::BadFile(_))),
                "{name}: {result:?}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), content, "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_that_others_can_read_is_refused() {
        let path = temp_path("lax");
        ControlKeys::load_or_create(&path).unwrap();

        for mode in [0o644, 0o640, 0o604, 0o660] {
            set_mode(&path, mode);
            let result = ControlKeys::load_or_create(&path);
            assert!(
                matches!(result, Err(KeyError::BadFile(_))),
                "{mode:o}: {result:?}"
            );
        }
        set_mode(&path, 0o400);
        assert!(
            ControlKeys::load_or_create(&path).is_ok(),
            "read-only for the owner is fine: that is how systemd hands over a credential"
        );
    }

    #[test]
    fn load_reads_an_existing_file_and_never_makes_one() {
        let path = temp_path("load");
        assert_eq!(ControlKeys::load(&path).unwrap_err(), KeyError::Missing);
        assert!(!path.exists(), "nothing was created");

        let made = ControlKeys::load_or_create(&path).unwrap();
        let loaded = ControlKeys::load(&path).unwrap();
        assert_eq!(
            made.email_fingerprint("lao@example.com"),
            loaded.email_fingerprint("lao@example.com")
        );
        assert_eq!(made.code_key(), loaded.code_key());

        #[cfg(unix)]
        {
            set_mode(&path, 0o644);
            assert!(matches!(
                ControlKeys::load(&path),
                Err(KeyError::BadFile(_))
            ));
        }
    }

    #[test]
    fn a_key_file_in_a_directory_that_is_not_there_is_an_error_not_a_panic() {
        let path = temp_path("no-dir")
            .with_file_name("nowhere")
            .join("control.key");
        assert!(matches!(
            ControlKeys::load_or_create(&path),
            Err(KeyError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_file_is_read_as_it_is_but_only_if_private_small_text_and_a_real_file() {
        let path = temp_path("secret-text");
        std::fs::write(&path, "re_abc\n").unwrap();
        set_mode(&path, 0o600);
        assert_eq!(
            read_secret_text(&path).unwrap(),
            "re_abc\n",
            "returned untouched"
        );
        set_mode(&path, 0o400);
        assert!(
            read_secret_text(&path).is_ok(),
            "a systemd credential is 0400"
        );

        set_mode(&path, 0o644);
        assert!(matches!(read_secret_text(&path), Err(KeyError::BadFile(_))));

        std::fs::write(&path, "k".repeat(5000)).unwrap();
        set_mode(&path, 0o600);
        assert!(
            matches!(read_secret_text(&path), Err(KeyError::BadFile(_))),
            "too big"
        );

        std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
        assert!(
            matches!(read_secret_text(&path), Err(KeyError::BadFile(_))),
            "not text"
        );

        let dir = path.parent().unwrap();
        assert!(
            matches!(read_secret_text(dir), Err(KeyError::BadFile(_))),
            "a directory"
        );
        assert_eq!(
            read_secret_text(&dir.join("absent")).unwrap_err(),
            KeyError::Missing
        );
    }

    #[test]
    fn the_fingerprint_matches_an_independent_hmac_sha256() {
        // Vectors made with `openssl dgst -sha256 -mac HMAC -macopt hexkey:...`.
        let zeros = ControlKeys::from_parts([0; 32], [9; 32]);
        assert_eq!(
            bf_common::sign::hex(&zeros.email_fingerprint("lao@example.com")),
            "949215d226ab9380ab56f1f16b882778bedb078193ced252c20e5ff2b9aed7a0"
        );
        let mut counting = [0u8; 32];
        for (i, byte) in counting.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let counting = ControlKeys::from_parts(counting, [9; 32]);
        assert_eq!(
            bf_common::sign::hex(&counting.email_fingerprint("lao@example.com")),
            "2459ca17aa0d7d3e44e134c94b2b733d3c7b926b3dac995ba90bd0c05fbf2811"
        );
    }

    #[test]
    fn the_fingerprint_ignores_case_and_spaces_and_does_not_contain_the_email() {
        let keys = ControlKeys::from_parts([7; 32], [8; 32]);
        let plain = keys.email_fingerprint("lao@example.com");

        assert_eq!(plain, keys.email_fingerprint("  Lao@Example.COM \n"));
        assert_ne!(plain, keys.email_fingerprint("sam@example.com"));
        assert_ne!(plain, keys.email_fingerprint("lao@example.org"));
        assert_ne!(
            plain,
            ControlKeys::from_parts([6; 32], [8; 32]).email_fingerprint("lao@example.com"),
            "another key gives another fingerprint"
        );
        assert!(
            !plain.windows(3).any(|w| w == b"lao"),
            "not the address in disguise"
        );
    }

    #[test]
    fn the_network_fingerprint_and_the_code_check_match_an_independent_hmac_sha256() {
        // Vectors made with `openssl dgst -sha256 -mac HMAC -macopt hexkey:...`.
        let keys = ControlKeys::from_parts([0; 32], [9; 32]);
        assert_eq!(
            bf_common::sign::hex(&keys.ip_fingerprint("203.0.113.7")),
            "045c6e9b5f0a6d02483d47d8d9dd05ba043043f242faaf0f5a450d969218c9af"
        );
        assert_eq!(
            bf_common::sign::hex(&keys.ip_fingerprint("2001:db8::1")),
            "f8df235808ba3550bdf7d3dc5aaa24f47584b63f7a2265303ed7141a9a5f769e"
        );
        assert_eq!(
            bf_common::sign::hex(&keys.code_mac(&[1; 32], "482917")),
            "5431f8ae93f70826e0c67b9deb8252c9e8b07ed7b0795efa7b6139aa8caa6d64"
        );

        // A network address and an email with the same text are not the same fingerprint,
        // and a code check depends on the address it was made for and on the code.
        assert_ne!(
            keys.ip_fingerprint("a@b.c"),
            keys.email_fingerprint("a@b.c")
        );
        assert_ne!(
            keys.code_mac(&[1; 32], "482917"),
            keys.code_mac(&[2; 32], "482917")
        );
        assert_ne!(
            keys.code_mac(&[1; 32], "482917"),
            keys.code_mac(&[1; 32], "482918")
        );
        assert_ne!(
            keys.code_mac(&[1; 32], "000001"),
            keys.code_mac(&[1; 32], "000010"),
            "leading zeros count"
        );
    }

    #[test]
    fn random_bytes_have_the_length_asked_for_and_are_new_every_time() {
        let a = random_bytes::<32>().unwrap();
        let b = random_bytes::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
        assert_eq!(random_bytes::<0>().unwrap(), [0u8; 0]);
        assert_eq!(random_bytes::<7>().unwrap().len(), 7);
    }

    #[test]
    fn constant_time_eq_is_plain_equality_for_equal_lengths_and_false_for_different_ones() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"xbc"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(&[0xff; 32], &[0xff; 32]));
        let mut other = [0xff; 32];
        other[31] = 0xfe;
        assert!(!constant_time_eq(&[0xff; 32], &other));
    }

    #[test]
    fn sha256_matches_the_standard_test_vector() {
        assert_eq!(
            bf_common::sign::hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_code_is_six_digits_with_leading_zeros_and_every_value_is_reachable() {
        let from = |numbers: Vec<u32>| {
            let mut numbers = numbers.into_iter();
            six_digit_code(move || Ok(numbers.next().expect("asked for more numbers than given")))
                .unwrap()
        };
        assert_eq!(from(vec![0]), "000000");
        assert_eq!(from(vec![4_217]), "004217");
        assert_eq!(from(vec![999_999]), "999999");
        assert_eq!(from(vec![1_000_000]), "000000", "it wraps by modulo");
        assert_eq!(from(vec![482_917]), "482917");
    }

    #[test]
    fn numbers_from_the_uneven_top_of_the_range_are_thrown_away() {
        // 2^32 does not divide evenly by a million: 4_294_000_000 numbers are used, and the
        // 967_296 above them would make small codes more likely, so they are skipped.
        let mut numbers = vec![u32::MAX, 4_294_000_000, 4_294_000_001, 4_293_999_999].into_iter();
        let code = six_digit_code(move || Ok(numbers.next().unwrap())).unwrap();
        assert_eq!(
            code, "999999",
            "4_293_999_999 is the first number that counts"
        );

        let mut only_good = vec![4_293_999_999u32 - 482_917 + 1].into_iter();
        let code = six_digit_code(move || Ok(only_good.next().unwrap())).unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn a_failing_random_source_is_an_error_not_a_made_up_code() {
        let result = six_digit_code(|| Err(std::io::Error::other("no randomness")));
        assert!(result.is_err());
    }

    #[test]
    fn real_codes_are_six_digits_and_not_all_the_same() {
        let codes: Vec<String> = (0..50).map(|_| random_code().unwrap()).collect();
        for code in &codes {
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
        assert!(
            codes.iter().any(|c| c != &codes[0]),
            "fifty identical codes"
        );
    }

    #[test]
    fn the_keys_never_appear_in_debug_output_or_error_text() {
        let keys = ControlKeys::from_parts([0xAB; 32], [0xCD; 32]);
        let shown = format!("{keys:?}");
        assert!(
            !shown.contains("171") && !shown.to_lowercase().contains("abab"),
            "{shown}"
        );
        assert!(
            !shown.contains("205") && !shown.to_lowercase().contains("cdcd"),
            "{shown}"
        );

        let path = temp_path("error-text");
        std::fs::write(&path, "zz".repeat(64)).unwrap();
        #[cfg(unix)]
        set_mode(&path, 0o600);
        let why = ControlKeys::load_or_create(&path).unwrap_err().to_string();
        assert!(!why.contains("zz"), "{why}");
    }
}
