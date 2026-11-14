//! The session cookie: how it is set, cleared and read.
//!
//! `__Host-` makes the browser accept it only over HTTPS, with no `Domain` and `Path=/`,
//! so a neighbouring subdomain cannot set or shadow it. `HttpOnly` keeps it away from any
//! script, `Secure` keeps it off plain HTTP, and `SameSite=Strict` keeps it from being
//! sent along with a request from another site.

/// The session cookie's name.
pub const SESSION_COOKIE: &str = "__Host-bf_session";

/// The name of the cookie that remembers, between the page where an address is typed and
/// the page where the code is typed, which address the code was asked for. It holds the
/// address (as hex) and nothing else: the server never stores an address, so the browser
/// carries it, for as long as the code works. It is no proof of anything: whoever sets it
/// still needs the code.
pub const PENDING_COOKIE: &str = "__Host-bf_pending";

/// The `Set-Cookie` value that starts a session. `value` is what the store made
/// (`<id>.<secret>`, lowercase hex and a dot): nothing that needs quoting.
pub fn set_session(value: &str, max_age_secs: u64) -> String {
    format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age_secs}; Secure; HttpOnly; SameSite=Strict"
    )
}

/// The `Set-Cookie` value that removes it.
pub fn clear_session() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
}

/// The `Set-Cookie` value that remembers which address a code was asked for. `value` is
/// hex: nothing that needs quoting.
pub fn set_pending(value: &str, max_age_secs: u64) -> String {
    format!(
        "{PENDING_COOKIE}={value}; Path=/; Max-Age={max_age_secs}; Secure; HttpOnly; SameSite=Strict"
    )
}

/// The `Set-Cookie` value that forgets it.
pub fn clear_pending() -> String {
    format!("{PENDING_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
}

/// The session cookie's value out of a `Cookie` header, if it is there. The first one
/// wins when there are several of that name.
pub fn session_from_header(header: Option<&str>) -> Option<&str> {
    value_of(header, SESSION_COOKIE)
}

/// The pending sign-in cookie's value out of a `Cookie` header, if it is there.
pub fn pending_from_header(header: Option<&str>) -> Option<&str> {
    value_of(header, PENDING_COOKIE)
}

/// The cookie that holds a theme chosen in the footer. Only `light` or `dark`; "system" is
/// no cookie at all. `Lax`, not `Strict`: following a link here from another site should
/// still show the page in the chosen colours, and the cookie says nothing about anyone.
pub const THEME_COOKIE: &str = "__Host-bf_theme";

/// A theme someone chose, as opposed to following the device's setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
}

impl Theme {
    /// The cookie's value, and the value of `data-theme` on a page.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
}

/// How long a chosen theme is kept: a year.
pub(crate) const THEME_MAX_AGE_SECS: u64 = 365 * 86_400;

/// The `Set-Cookie` value that keeps a chosen theme.
pub fn set_theme(theme: Theme) -> String {
    format!(
        "{THEME_COOKIE}={}; Path=/; Max-Age={THEME_MAX_AGE_SECS}; Secure; HttpOnly; SameSite=Lax",
        theme.as_str()
    )
}

/// The `Set-Cookie` value that forgets it (back to the device's setting).
pub fn clear_theme() -> String {
    format!("{THEME_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")
}

/// The chosen theme out of a `Cookie` header. Only exactly `light` or `dark` counts; the
/// value is never copied anywhere, only matched.
pub fn theme_from_header(header: Option<&str>) -> Option<Theme> {
    match value_of(header, THEME_COOKIE)? {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        _ => None,
    }
}

fn value_of<'a>(header: Option<&'a str>, wanted: &str) -> Option<&'a str> {
    header?.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name.trim() == wanted).then_some(value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALUE: &str = "0123456789abcdef0123456789abcdef.00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn the_session_cookie_has_every_protection_and_an_expiry_and_no_domain() {
        let header = set_session(VALUE, 5_184_000);

        let mut parts = header.split("; ");
        assert_eq!(
            parts.next(),
            Some(format!("{SESSION_COOKIE}={VALUE}").as_str())
        );
        let attributes: Vec<&str> = parts.collect();
        assert_eq!(
            attributes,
            [
                "Path=/",
                "Max-Age=5184000",
                "Secure",
                "HttpOnly",
                "SameSite=Strict"
            ]
        );
        assert!(!header.to_lowercase().contains("domain"));
        assert!(header.starts_with("__Host-"));
    }

    #[test]
    fn clearing_it_sets_it_empty_and_already_expired_with_the_same_protections() {
        let header = clear_session();

        assert!(header.starts_with("__Host-bf_session=;"), "{header}");
        assert!(header.contains("Max-Age=0"));
        for needed in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
            assert!(header.contains(needed), "{needed}");
        }
    }

    #[test]
    fn the_cookie_is_found_among_others_and_only_by_its_exact_name() {
        assert_eq!(
            session_from_header(Some(&format!("__Host-bf_session={VALUE}"))),
            Some(VALUE)
        );
        assert_eq!(
            session_from_header(Some(&format!("a=b; __Host-bf_session={VALUE}; c=d"))),
            Some(VALUE)
        );
        assert_eq!(
            session_from_header(Some(&format!("  a=b ;   __Host-bf_session = {VALUE}  "))),
            Some(VALUE),
            "spaces around the name and value do not matter"
        );
        for header in [
            "",
            "a=b",
            "bf_session=x",
            "x__Host-bf_session=x",
            "__Host-bf_sessionx=x",
            "__host-bf_session=x",
            "__Host-bf_session",
        ] {
            assert_eq!(session_from_header(Some(header)), None, "{header:?}");
        }
        assert_eq!(session_from_header(None), None);
    }

    #[test]
    fn the_pending_cookie_is_as_protected_as_the_session_and_lasts_as_long_as_it_is_told() {
        let header = set_pending("6c616f40", 600);

        let mut parts = header.split("; ");
        assert_eq!(parts.next(), Some("__Host-bf_pending=6c616f40"));
        assert_eq!(
            parts.collect::<Vec<_>>(),
            [
                "Path=/",
                "Max-Age=600",
                "Secure",
                "HttpOnly",
                "SameSite=Strict"
            ]
        );
        assert!(!header.to_lowercase().contains("domain"));

        let cleared = clear_pending();
        assert!(cleared.starts_with("__Host-bf_pending=;"), "{cleared}");
        for needed in [
            "Max-Age=0",
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
        ] {
            assert!(cleared.contains(needed), "{needed}");
        }
    }

    #[test]
    fn the_two_cookies_are_never_mistaken_for_each_other() {
        let both = format!("__Host-bf_pending=aa; __Host-bf_session={VALUE}; x=y");

        assert_eq!(pending_from_header(Some(&both)), Some("aa"));
        assert_eq!(session_from_header(Some(&both)), Some(VALUE));
        assert_eq!(
            pending_from_header(Some(&format!("__Host-bf_session={VALUE}"))),
            None
        );
        assert_eq!(session_from_header(Some("__Host-bf_pending=aa")), None);
        for header in [
            "",
            "__Host-bf_pending",
            "bf_pending=aa",
            "x__Host-bf_pending=aa",
        ] {
            assert_eq!(pending_from_header(Some(header)), None, "{header:?}");
        }
        assert_eq!(pending_from_header(None), None);
        assert_eq!(
            pending_from_header(Some("__Host-bf_pending=first; __Host-bf_pending=second")),
            Some("first")
        );
    }

    #[test]
    fn the_theme_cookie_lasts_a_year_is_lax_and_otherwise_as_protected_as_the_others() {
        assert_eq!(
            set_theme(Theme::Light),
            "__Host-bf_theme=light; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            set_theme(Theme::Dark),
            "__Host-bf_theme=dark; Path=/; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            clear_theme(),
            "__Host-bf_theme=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(THEME_COOKIE, "__Host-bf_theme");
    }

    #[test]
    fn only_exactly_light_or_dark_is_read_back_as_a_theme() {
        assert_eq!(
            theme_from_header(Some("__Host-bf_theme=light")),
            Some(Theme::Light)
        );
        assert_eq!(
            theme_from_header(Some(&format!(
                "__Host-bf_session={VALUE}; __Host-bf_theme=dark"
            ))),
            Some(Theme::Dark)
        );
        for header in [
            "",
            "__Host-bf_theme=",
            "__Host-bf_theme=system",
            "__Host-bf_theme=Light",
            "__Host-bf_theme=light dark",
            "__Host-bf_theme=\"dark\"",
            "__Host-bf_theme=dark\"><script>",
            "__Host-bf_theme=darker",
            "bf_theme=dark",
        ] {
            assert_eq!(theme_from_header(Some(header)), None, "{header:?}");
        }
        assert_eq!(theme_from_header(None), None);
        assert_eq!(Theme::Light.as_str(), "light");
        assert_eq!(Theme::Dark.as_str(), "dark");
    }

    #[test]
    fn when_the_cookie_comes_twice_the_first_is_used() {
        assert_eq!(
            session_from_header(Some("__Host-bf_session=first; __Host-bf_session=second")),
            Some("first")
        );
    }
}
