//! Reading the body of a plain HTML form (`application/x-www-form-urlencoded`).
//!
//! Strict on purpose: a name that appears twice is refused (so a sign-in code or a token
//! cannot be sent twice with different values and be read differently by two parts of
//! the program), and so is anything that is not UTF-8 or has a broken percent escape.

/// The most fields a form may have.
pub const MAX_FIELDS: usize = 16;
/// The longest a name or a value may be, after decoding.
pub const MAX_PART_BYTES: usize = 1024;

/// The fields of a form, in the order they came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    fields: Vec<(String, String)>,
}

impl Form {
    /// The value of the field called `name`, if there is one. There is at most one.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Reads a form body. `None` if it is not a clean form (see the module comment).
pub fn parse(body: &[u8]) -> Option<Form> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for segment in body.split(|&b| b == b'&') {
        if segment.is_empty() {
            continue;
        }
        let (name, value) = match segment.iter().position(|&b| b == b'=') {
            Some(at) => (&segment[..at], &segment[at + 1..]),
            None => (segment, &segment[segment.len()..]),
        };
        let name = decode(name)?;
        let value = decode(value)?;
        if name.is_empty() || fields.iter().any(|(seen, _)| *seen == name) {
            return None;
        }
        fields.push((name, value));
        if fields.len() > MAX_FIELDS {
            return None;
        }
    }
    Some(Form { fields })
}

/// `+` is a space, `%XX` is a byte, and the result must be UTF-8 and not too long.
fn decode(raw: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let high = hex_digit(*raw.get(i + 1)?)?;
                let low = hex_digit(*raw.get(i + 2)?)?;
                out.push((high << 4) | low);
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
        if out.len() > MAX_PART_BYTES {
            return None;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(text: &str) -> Form {
        parse(text.as_bytes()).unwrap_or_else(|| panic!("{text:?} should parse"))
    }

    #[test]
    fn fields_are_read_in_order_and_looked_up_by_name() {
        let f = form("email=lao%40example.com&code=482917");
        assert_eq!(f.get("email"), Some("lao@example.com"));
        assert_eq!(f.get("code"), Some("482917"));
        assert_eq!(f.get("other"), None);
        assert_eq!(f.len(), 2);
        assert!(!f.is_empty());
    }

    #[test]
    fn an_empty_body_is_an_empty_form_and_stray_ampersands_are_ignored() {
        assert!(form("").is_empty());
        assert_eq!(form("&&a=1&&").len(), 1);
    }

    #[test]
    fn plus_is_a_space_and_percent_escapes_are_decoded_in_either_case() {
        let f = form("a=one+two&b=%41%62%7a%7A&c=%2B%2b");
        assert_eq!(f.get("a"), Some("one two"));
        assert_eq!(f.get("b"), Some("Abzz"));
        assert_eq!(f.get("c"), Some("++"));
    }

    #[test]
    fn a_value_may_hold_an_equals_sign_and_a_field_may_have_no_value() {
        let f = form("a=b=c&flag&empty=");
        assert_eq!(f.get("a"), Some("b=c"));
        assert_eq!(f.get("flag"), Some(""));
        assert_eq!(f.get("empty"), Some(""));
    }

    #[test]
    fn multi_byte_text_survives() {
        let f = form("label=caf%C3%A9+%E2%9C%93");
        assert_eq!(f.get("label"), Some("café ✓"));
    }

    #[test]
    fn names_are_decoded_too() {
        let f = form("na%6De=x");
        assert_eq!(f.get("name"), Some("x"));
    }

    #[test]
    fn a_broken_escape_or_bytes_that_are_not_utf_8_are_refused() {
        for bad in [
            "a=%zz", "a=%4", "a=%", "a=100%", "a=%ff", "a=%c3", "a=%80%80", "%=x",
        ] {
            assert_eq!(parse(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(
            parse(&[b'a', b'=', 0xff, 0xfe]),
            None,
            "raw bytes that are not UTF-8"
        );
    }

    #[test]
    fn a_name_that_comes_twice_is_refused_even_with_the_same_value() {
        assert_eq!(parse(b"code=1&code=2"), None);
        assert_eq!(parse(b"code=1&code=1"), None);
        assert_eq!(parse(b"a=1&b=2&a=3"), None);
        assert_eq!(
            parse(b"a=1&%61=2"),
            None,
            "the same name spelled with an escape"
        );
    }

    #[test]
    fn a_field_with_no_name_is_refused() {
        assert_eq!(parse(b"=x"), None);
        assert_eq!(parse(b"a=1&=x"), None);
    }

    #[test]
    fn too_many_fields_or_too_long_a_part_is_refused() {
        let sixteen: Vec<String> = (0..16).map(|i| format!("f{i}=1")).collect();
        assert!(parse(sixteen.join("&").as_bytes()).is_some());
        let seventeen: Vec<String> = (0..17).map(|i| format!("f{i}=1")).collect();
        assert_eq!(parse(seventeen.join("&").as_bytes()), None);

        let longest = "x".repeat(MAX_PART_BYTES);
        assert!(parse(format!("a={longest}").as_bytes()).is_some());
        assert_eq!(parse(format!("a={longest}x").as_bytes()), None);
        assert_eq!(parse(format!("{longest}x=1").as_bytes()), None);
        // Escapes count after decoding, so many short escapes cannot sneak a long value in.
        assert_eq!(
            parse(format!("a={}", "%41".repeat(MAX_PART_BYTES + 1)).as_bytes()),
            None
        );
    }

    #[test]
    fn control_characters_are_passed_on_for_the_caller_to_judge() {
        let f = form("a=%00%0a");
        assert_eq!(f.get("a"), Some("\0\n"));
    }
}
