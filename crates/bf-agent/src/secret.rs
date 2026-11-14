//! The node's signing secret: a file holding at least 32 bytes as hex.

use std::fmt;
use std::path::Path;

use bf_common::sign::unhex;

/// Why the secret could not be used. It never holds any of the file's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    Unreadable,
    NotHex,
    TooShort,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreadable => "the secret file cannot be read",
            Self::NotHex => "the secret file does not hold hex",
            Self::TooShort => "the secret must be at least 32 bytes (64 hex characters)",
        })
    }
}

impl std::error::Error for SecretError {}

pub fn parse_secret(text: &str) -> Result<Vec<u8>, SecretError> {
    let bytes = unhex(text.trim()).ok_or(SecretError::NotHex)?;
    if bytes.len() < 32 {
        return Err(SecretError::TooShort);
    }
    Ok(bytes)
}

pub fn read_secret(path: &Path) -> Result<Vec<u8>, SecretError> {
    let text = std::fs::read_to_string(path).map_err(|_| SecretError::Unreadable)?;
    parse_secret(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn at_least_32_bytes_of_hex_is_a_secret_and_surrounding_whitespace_is_ignored() {
        let expected: Vec<u8> = (0..2u8).flat_map(|_| 0..16u8).map(|n| n * 0x11).collect();

        assert_eq!(parse_secret(HEX).unwrap(), expected);
        assert_eq!(parse_secret(&format!("  {HEX}\n")).unwrap(), expected);
        assert_eq!(parse_secret(&HEX.to_uppercase()).unwrap(), expected);
        assert_eq!(parse_secret(&format!("{HEX}ab")).unwrap().len(), 33);
    }

    #[test]
    fn anything_else_is_refused_without_quoting_it() {
        assert_eq!(parse_secret(""), Err(SecretError::TooShort));
        assert_eq!(parse_secret(&HEX[..62]), Err(SecretError::TooShort));
        assert_eq!(parse_secret(&HEX[..63]), Err(SecretError::NotHex)); // odd length
        assert_eq!(
            parse_secret(&format!("{}zz", &HEX[..62])),
            Err(SecretError::NotHex)
        );
        assert_eq!(
            parse_secret(&format!("{HEX} {HEX}")),
            Err(SecretError::NotHex)
        );
    }

    #[test]
    fn the_secret_is_read_from_its_file() {
        let dir = TempDir::new("secret");
        let file = dir.path().join("agent.secret");
        std::fs::write(&file, format!("{HEX}\n")).unwrap();

        assert_eq!(read_secret(&file).unwrap().len(), 32);
        assert_eq!(
            read_secret(&dir.path().join("missing")),
            Err(SecretError::Unreadable)
        );
    }
}
