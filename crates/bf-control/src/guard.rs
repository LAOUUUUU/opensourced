//! Keeping other sites from making a person's browser submit our forms.
//!
//! The browser tells us where a request came from: `Sec-Fetch-Site` (modern browsers) and
//! `Origin` (all browsers, on every POST). A state-changing request is accepted only when
//! those say it came from this site. Neither header is proof from a program that is not a
//! browser, and that is fine: the protection is for people's browsers.

/// Whether a request that changes something may go ahead.
///
/// - If `Sec-Fetch-Site` is there it must be `same-origin` (`same-site` is refused: a
///   neighbouring subdomain is not this site).
/// - If `Origin` is there it must be one of `allowed` exactly (`null` never is).
/// - At least one of the two must be there: with neither, nothing says where it came from.
pub fn same_origin(sec_fetch_site: Option<&str>, origin: Option<&str>, allowed: &[String]) -> bool {
    if sec_fetch_site.is_none() && origin.is_none() {
        return false;
    }
    if let Some(site) = sec_fetch_site
        && !site.trim().eq_ignore_ascii_case("same-origin")
    {
        return false;
    }
    if let Some(origin) = origin {
        let origin = origin.trim();
        if !allowed.iter().any(|ok| ok == origin) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec![
            "https://barely-free.com".to_string(),
            "https://www.barely-free.com".to_string(),
        ]
    }

    #[test]
    fn a_request_the_browser_says_is_same_origin_goes_ahead() {
        assert!(same_origin(Some("same-origin"), None, &allowed()));
        assert!(same_origin(Some("Same-Origin"), None, &allowed()));
        assert!(same_origin(Some(" same-origin "), None, &allowed()));
        assert!(same_origin(
            None,
            Some("https://barely-free.com"),
            &allowed()
        ));
        assert!(same_origin(
            None,
            Some("https://www.barely-free.com"),
            &allowed()
        ));
        assert!(same_origin(
            Some("same-origin"),
            Some("https://barely-free.com"),
            &allowed()
        ));
    }

    #[test]
    fn another_site_a_neighbour_or_a_typed_address_is_refused() {
        for site in [
            "cross-site",
            "same-site",
            "none",
            "",
            "same-origin, cross-site",
        ] {
            assert!(!same_origin(Some(site), None, &allowed()), "{site:?}");
        }
        assert!(!same_origin(
            Some("cross-site"),
            Some("https://barely-free.com"),
            &allowed()
        ));
    }

    #[test]
    fn an_origin_must_match_exactly() {
        for origin in [
            "https://evil.example",
            "null",
            "",
            "https://barely-free.com.evil.example",
            "https://evilbarely-free.com",
            "http://barely-free.com",
            "https://barely-free.com:8443",
            "https://barely-free.com/",
            "https://BARELY-FREE.COM",
            "https://sub.barely-free.com",
        ] {
            assert!(!same_origin(None, Some(origin), &allowed()), "{origin:?}");
        }
    }

    #[test]
    fn a_foreign_origin_is_refused_even_when_sec_fetch_site_says_same_origin() {
        assert!(!same_origin(
            Some("same-origin"),
            Some("https://evil.example"),
            &allowed()
        ));
    }

    #[test]
    fn with_neither_header_nothing_says_where_it_came_from_so_it_is_refused() {
        assert!(!same_origin(None, None, &allowed()));
        assert!(!same_origin(None, Some("https://barely-free.com"), &[]));
    }
}
