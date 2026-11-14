//! The tracker list a node's resolver blocks: EasyPrivacy, read strictly, written as an RPZ
//! zone for unbound (`specs/trackers.md`).

use std::collections::BTreeSet;

/// The names to block in `list` (EasyPrivacy text), sorted.
///
/// Kept: rules that are exactly `||name^`. Freed again: a name that an exact `@@||name^` rule
/// or a line of `allow` names, every name under it, and any blocked name above it (blocking
/// the one above would block it too). Everything else in the list is skipped.
pub fn names(list: &str, allow: &str) -> Vec<String> {
    let blocked = exact_names(list, "||");
    let mut exempt = exact_names(list, "@@||");
    exempt.extend(
        allow
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && is_hostname(line))
            .map(str::to_ascii_lowercase),
    );
    let above_exempt: BTreeSet<&str> = exempt.iter().flat_map(|name| parents(name)).collect();
    let kept: BTreeSet<String> = blocked
        .into_iter()
        .filter(|name| {
            !above_exempt.contains(name.as_str())
                && !std::iter::once(name.as_str())
                    .chain(parents(name))
                    .any(|n| exempt.contains(n))
        })
        .collect();
    // A name under one that is kept is blocked by that one already.
    kept.iter()
        .filter(|name| !parents(name).any(|parent| kept.contains(parent)))
        .cloned()
        .collect()
}

/// An RPZ zone for unbound that answers NXDOMAIN (`CNAME .`) for each name and every name
/// under it. Owner names are relative to the zone's own name, which unbound's `rpz:` clause
/// sets.
pub fn zone(names: &[String]) -> String {
    let mut text = String::from(
        "$TTL 3600\n@ SOA localhost. nobody.invalid. 1 3600 600 86400 3600\n@ NS localhost.\n",
    );
    for name in names {
        text.push_str(&format!("{name} CNAME .\n*.{name} CNAME .\n"));
    }
    text
}

/// How many names a zone written by [`zone`] blocks: its `name CNAME .` lines that are not
/// the `*.` ones.
pub fn names_in_zone(zone: &str) -> usize {
    zone.lines()
        .filter_map(|line| line.strip_suffix(" CNAME ."))
        .filter(|name| !name.starts_with("*."))
        .count()
}

/// Fewer names than this is a broken download, not a list.
pub const MIN_NAMES: usize = 1_000;

/// Why a new list was refused, leaving the one in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorError {
    TooFew { found: usize },
    Shrank { found: usize, previous: usize },
}

impl std::fmt::Display for FloorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FloorError::TooFew { found } => {
                write!(f, "only {found} names; at least {MIN_NAMES} are expected")
            }
            FloorError::Shrank { found, previous } => {
                write!(f, "{found} names, under half of the {previous} in force")
            }
        }
    }
}

impl std::error::Error for FloorError {}

/// Whether a new list of `found` names may replace one of `previous` names: it needs at
/// least [`MIN_NAMES`] and at least half of `previous`.
pub fn check_floor(found: usize, previous: usize) -> Result<(), FloorError> {
    if found < MIN_NAMES {
        Err(FloorError::TooFew { found })
    } else if found.saturating_mul(2) < previous {
        Err(FloorError::Shrank { found, previous })
    } else {
        Ok(())
    }
}

/// The names of the rules that are exactly `<prefix>name^`, lowercased.
fn exact_names(list: &str, prefix: &str) -> BTreeSet<String> {
    list.lines()
        .filter_map(|line| line.strip_prefix(prefix)?.strip_suffix('^'))
        .filter(|name| is_hostname(name))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Every name above `name`: `a.b.c` gives `b.c` and `c`.
fn parents(name: &str) -> impl Iterator<Item = &str> {
    name.match_indices('.').map(move |(at, _)| &name[at + 1..])
}

/// The longest name the zone can hold: it is written as `*.<name>.trackers.rpz.barely-free.`,
/// and a whole name is at most 255 bytes on the wire (2 + 226 + 1 + 24 + 2). A longer one
/// would make unbound refuse the whole zone.
pub const MAX_NAME: usize = 226;

/// A name that is safe to block with everything under it: two labels or more (so a stray
/// `||com^` cannot take out a whole top-level domain), each 1 to 63 letters, digits or
/// `-` not at either end, [`MAX_NAME`] characters at most, and a last label that is not a
/// number (which also leaves out IPv4 addresses).
fn is_hostname(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= MAX_NAME
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_domain_rule_is_kept() {
        assert_eq!(names("||tracker.example^\n", ""), vec!["tracker.example"]);
    }

    #[test]
    fn names_are_lowercased_and_windows_line_ends_are_read() {
        assert_eq!(
            names("||Tracker.EXAMPLE^\r\n||b.example^\r\n", ""),
            vec!["b.example", "tracker.example"]
        );
    }

    #[test]
    fn an_exception_or_an_allowed_name_frees_itself_the_names_under_it_and_any_blocked_name_above_it()
     {
        let list = "\
||same.example^
@@||same.example^
||under.example^
||x.under.example^
@@||under.example^
||above.example^
@@||x.above.example^
||options.example^
@@||options.example^$script
||allowed.example^
||kept.example^
||neighbour-same.example^
";
        let allow = "# names that broke something\n  Allowed.Example  \n\nsame.example\n";
        assert_eq!(
            names(list, allow),
            vec!["kept.example", "neighbour-same.example", "options.example"]
        );
    }

    #[test]
    fn a_name_under_a_blocked_name_is_not_listed_again() {
        assert_eq!(
            names(
                "||a.b.example^\n||b.example^\n||x.y.b.example^\n||ab.example^\n",
                ""
            ),
            vec!["ab.example", "b.example"]
        );
    }

    #[test]
    fn the_zone_blocks_each_name_and_everything_under_it_with_nxdomain() {
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        assert_eq!(
            zone(&names),
            "\
$TTL 3600
@ SOA localhost. nobody.invalid. 1 3600 600 86400 3600
@ NS localhost.
a.example CNAME .
*.a.example CNAME .
b.example CNAME .
*.b.example CNAME .
"
        );
    }

    #[test]
    fn the_names_in_a_zone_are_counted_and_anything_else_counts_as_none() {
        let names: Vec<String> = (0..5).map(|i| format!("t{i}.example")).collect();
        assert_eq!(names_in_zone(&zone(&names)), 5);
        assert_eq!(names_in_zone(&zone(&[])), 0);
        assert_eq!(names_in_zone(""), 0);
        assert_eq!(names_in_zone("not a zone\nat all CNAME\n"), 0);
    }

    #[test]
    fn a_new_list_under_a_thousand_names_or_under_half_the_one_in_force_is_refused() {
        assert_eq!(check_floor(1_000, 0), Ok(()));
        assert_eq!(check_floor(999, 0), Err(FloorError::TooFew { found: 999 }));
        assert_eq!(check_floor(0, 0), Err(FloorError::TooFew { found: 0 }));
        assert_eq!(check_floor(1_000, 2_000), Ok(()));
        assert_eq!(
            check_floor(1_000, 2_001),
            Err(FloorError::Shrank {
                found: 1_000,
                previous: 2_001
            })
        );
        assert_eq!(check_floor(50_000, 20_000), Ok(()));
        assert_eq!(
            check_floor(999, 2_001).unwrap_err().to_string(),
            "only 999 names; at least 1000 are expected"
        );
        assert_eq!(
            check_floor(1_000, 2_001).unwrap_err().to_string(),
            "1000 names, under half of the 2001 in force"
        );
    }

    #[test]
    fn a_name_too_long_to_fit_the_zone_under_its_own_name_is_skipped() {
        // In the zone a name is written as `*.<name>.trackers.rpz.barely-free.`, and a whole
        // name may be 255 bytes on the wire: 226 characters is the most that fits.
        // Valid labels of 50 letters and one shorter one, then `.example`, `length` in all.
        let long = |length: usize| {
            let mut left = length - ".example".len();
            let mut labels = Vec::new();
            while left > 51 {
                labels.push("x".repeat(50));
                left -= 51;
            }
            labels.push("y".repeat(left));
            format!("{}.example", labels.join("."))
        };
        let fits = long(MAX_NAME);
        let too_long = long(MAX_NAME + 1);
        assert_eq!((fits.len(), too_long.len()), (226, 227));
        assert_eq!(
            names(&format!("||{fits}^\n||{too_long}^\n"), ""),
            vec![fits.clone()]
        );
        let wire = 2 + fits.len() + 1 + "trackers.rpz.barely-free".len() + 2;
        assert_eq!(wire, 255, "the longest owner name is exactly the limit");
    }

    #[test]
    fn any_rule_that_is_not_exactly_a_domain_rule_is_skipped() {
        let list = "\
[Adblock Plus 2.0]
! Title: EasyPrivacy
||third.example^$third-party
||script.example^$script
||path.example/collect^
||path2.example/^
||wild.*.example^
||star.example^*
/track[0-9]+/
|https://anchored.example^
||anchored.example^|
example.com##.tracking-pixel
example.com#@#.tracking-pixel
@@||exception.example^
||^
||.example^
||0.0.0.1^
||com^
||-bad.example^
||bad-.example^
||under_score.example^
||toolong.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example^
||double..example^
";
        assert_eq!(names(list, ""), Vec::<String>::new());
    }
}
