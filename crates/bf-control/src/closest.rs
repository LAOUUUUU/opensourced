//! "Closest to you": which server a new device goes to when the person lets the site choose
//! (decision 014, `research/trackers-and-closest/RESEARCH.md`).
//!
//! Where the person is comes from Cloudflare's visitor location headers. It is used in
//! memory for this one choice and is never stored or written to the log. Without it every
//! server counts as equally near, so the least loaded one is chosen.

use axum::http::HeaderMap;

/// A point on the Earth, in degrees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Location {
    pub lat: f64,
    pub lon: f64,
}

impl Location {
    /// A latitude from -90 to 90 and a longitude from -180 to 180, both finite.
    pub fn new(lat: f64, lon: f64) -> Option<Location> {
        let fits = lat.is_finite()
            && lon.is_finite()
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon);
        fits.then_some(Location { lat, lon })
    }

    /// `<lat>,<lon>`, as `node set-location` takes it: `43.65,-79.38`.
    pub fn parse(text: &str) -> Option<Location> {
        let (lat, lon) = text.split_once(',')?;
        Location::new(number(lat)?, number(lon)?)
    }
}

/// A plain decimal number: digits, at most one point, and a leading minus. No exponent, no
/// `inf` or `NaN`, no spaces inside.
fn number(text: &str) -> Option<f64> {
    let text = text.trim();
    let digits = text.strip_prefix('-').unwrap_or(text);
    let plain = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && digits.bytes().filter(|b| *b == b'.').count() <= 1
        && digits.bytes().any(|b| b.is_ascii_digit());
    if !plain {
        return None;
    }
    text.parse().ok()
}

/// Where Cloudflare says the person is: `cf-iplatitude` and `cf-iplongitude`, each sent
/// exactly once. Anything else (missing, repeated, not a plain number, out of range) is no
/// location at all.
pub fn from_headers(headers: &HeaderMap) -> Option<Location> {
    let one = |name: &str| -> Option<f64> {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        number(value.to_str().ok()?)
    };
    Location::new(one("cf-iplatitude")?, one("cf-iplongitude")?)
}

/// The great-circle distance between two points, in kilometres (haversine, on a sphere of
/// the Earth's mean radius).
pub fn distance_km(a: Location, b: Location) -> f64 {
    const EARTH_KM: f64 = 6_371.0;
    let (la1, la2) = (a.lat.to_radians(), b.lat.to_radians());
    let dlat = la2 - la1;
    let dlon = (b.lon - a.lon).to_radians();
    let h = (dlat / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_KM * h.sqrt().min(1.0).asin()
}

/// Servers whose distances from the person are within this many kilometres of the nearest
/// one's count as equally near; the less loaded of them wins.
pub const EQUAL_KM: f64 = 300.0;

/// When a server counts as busy and is skipped while another is not.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Busy {
    /// Devices online on the server, all its agents together (`BC_NODE_BUSY_ONLINE`).
    pub online: u64,
    /// The server's one-minute load average (`BC_NODE_BUSY_LOAD`).
    pub load: f64,
}

impl Default for Busy {
    fn default() -> Busy {
        Busy {
            online: 40,
            load: 0.9,
        }
    }
}

/// `BC_NODE_BUSY_ONLINE`: a whole number from 1 to 100000, 40 if not set.
pub fn busy_online(setting: Option<&str>) -> Result<u64, String> {
    let Some(text) = setting else {
        return Ok(Busy::default().online);
    };
    match text.parse::<u64>() {
        Ok(n) if text.bytes().all(|b| b.is_ascii_digit()) && (1..=100_000).contains(&n) => Ok(n),
        _ => Err(format!(
            "BC_NODE_BUSY_ONLINE must be a whole number from 1 to 100000 (or not set), not {text:?}"
        )),
    }
}

/// `BC_NODE_BUSY_LOAD`: a plain decimal number above 0 and at most 1000, 0.9 if not set.
pub fn busy_load(setting: Option<&str>) -> Result<f64, String> {
    let Some(text) = setting else {
        return Ok(Busy::default().load);
    };
    match number(text) {
        Some(n) if n > 0.0 && n <= 1000.0 && text == text.trim() => Ok(n),
        _ => Err(format!(
            "BC_NODE_BUSY_LOAD must be a number above 0 and at most 1000, like 0.9 (or not set), not {text:?}"
        )),
    }
}

/// One server that could take the new device: it has an agent of the chosen protocol that is
/// online and has a reading.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// Where the server is, if `node set-location` was run for it.
    pub location: Option<Location>,
    /// Devices online on it now, all its agents together.
    pub online: u64,
    /// Its one-minute load average, the highest its agents report, if any does.
    pub load: Option<f64>,
}

impl Candidate {
    /// Counts one agent's reading: its devices online are added to the server's, and the
    /// highest load its agents report is kept.
    pub fn add_reading(&mut self, online: u64, load: Option<f64>) {
        self.online = self.online.saturating_add(online);
        self.load = match (self.load, load) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    /// Whether this server counts as busy by `busy`'s numbers.
    pub fn is_busy(&self, busy: &Busy) -> bool {
        self.online >= busy.online || self.load.is_some_and(|load| load >= busy.load)
    }
}

/// Which of `candidates` (by its place in the slice) a new device goes to, given where the
/// person is. `None` only when there is no candidate.
///
/// Busy servers are skipped. Of the rest, the nearest ones (within [`EQUAL_KM`] of the
/// nearest) count as equal and the less loaded wins: fewer devices online, then the lower
/// load, then the nearer, then the earlier in the slice. A server with no location is
/// further than any with one. Without the person's location all are equally near. When
/// every server is busy, the one furthest under its cap of online devices is chosen.
pub fn pick(candidates: &[Candidate], from: Option<Location>, busy: &Busy) -> Option<usize> {
    // `min_by` keeps the first of equals, so a full tie goes to the earlier server.
    let lighter = |a: usize, b: usize| {
        let (a, b) = (&candidates[a], &candidates[b]);
        a.online
            .cmp(&b.online)
            .then(a.load.unwrap_or(0.0).total_cmp(&b.load.unwrap_or(0.0)))
    };
    let free: Vec<usize> = (0..candidates.len())
        .filter(|&i| !candidates[i].is_busy(busy))
        .collect();
    if free.is_empty() {
        return (0..candidates.len()).min_by(|&a, &b| lighter(a, b));
    }
    let distance = |i: usize| match (from, candidates[i].location) {
        (Some(from), Some(at)) => distance_km(from, at),
        (Some(_), None) => f64::INFINITY,
        (None, _) => 0.0,
    };
    let nearest = free
        .iter()
        .map(|&i| distance(i))
        .fold(f64::INFINITY, f64::min);
    free.into_iter()
        .filter(|&i| distance(i) <= nearest + EQUAL_KM)
        .min_by(|&a, &b| lighter(a, b).then(distance(a).total_cmp(&distance(b))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const TORONTO: Location = Location {
        lat: 43.65,
        lon: -79.38,
    };
    const DALLAS: Location = Location {
        lat: 32.78,
        lon: -96.80,
    };
    const MONTREAL: Location = Location {
        lat: 45.50,
        lon: -73.57,
    };
    const NEW_YORK: Location = Location {
        lat: 40.71,
        lon: -74.01,
    };
    const HOUSTON: Location = Location {
        lat: 29.76,
        lon: -95.37,
    };

    fn server(location: Option<Location>, online: u64, load: Option<f64>) -> Candidate {
        Candidate {
            location,
            online,
            load,
        }
    }

    fn toronto_and_dallas(toronto_online: u64, dallas_online: u64) -> Vec<Candidate> {
        vec![
            server(Some(TORONTO), toronto_online, Some(0.1)),
            server(Some(DALLAS), dallas_online, Some(0.1)),
        ]
    }

    #[test]
    fn distances_are_great_circle_kilometres() {
        let km = distance_km(TORONTO, DALLAS);
        assert!((1_925.0..1_950.0).contains(&km), "Toronto-Dallas {km}");
        assert!(distance_km(TORONTO, TORONTO).abs() < 1e-9);
        let ny = distance_km(NEW_YORK, TORONTO);
        assert!((540.0..560.0).contains(&ny), "New York-Toronto {ny}");
        let antipodes = distance_km(
            Location { lat: 0.0, lon: 0.0 },
            Location {
                lat: 0.0,
                lon: 180.0,
            },
        );
        assert!((antipodes - 6_371.0 * std::f64::consts::PI).abs() < 1e-6);
    }

    #[test]
    fn people_go_to_the_server_nearest_them() {
        let busy = Busy::default();
        let servers = toronto_and_dallas(5, 5);
        assert_eq!(pick(&servers, Some(TORONTO), &busy), Some(0));
        assert_eq!(pick(&servers, Some(MONTREAL), &busy), Some(0));
        assert_eq!(
            pick(&servers, Some(NEW_YORK), &busy),
            Some(0),
            "New York is about four times closer to Toronto"
        );
        assert_eq!(pick(&servers, Some(DALLAS), &busy), Some(1));
        assert_eq!(pick(&servers, Some(HOUSTON), &busy), Some(1));
        // Even when the nearer one has more devices: it is not busy.
        assert_eq!(
            pick(&toronto_and_dallas(30, 0), Some(MONTREAL), &busy),
            Some(0)
        );
    }

    #[test]
    fn a_busy_nearest_server_is_skipped() {
        let busy = Busy::default();
        assert_eq!(
            pick(&toronto_and_dallas(40, 0), Some(MONTREAL), &busy),
            Some(1),
            "40 online is the cap"
        );
        assert_eq!(
            pick(&toronto_and_dallas(39, 0), Some(MONTREAL), &busy),
            Some(0),
            "39 is under it"
        );
        let mut servers = toronto_and_dallas(1, 1);
        servers[0].load = Some(0.9);
        assert_eq!(
            pick(&servers, Some(MONTREAL), &busy),
            Some(1),
            "load 0.9 is busy"
        );
        servers[0].load = Some(0.89);
        assert_eq!(pick(&servers, Some(MONTREAL), &busy), Some(0));
        servers[0].load = None;
        assert_eq!(
            pick(&servers, Some(MONTREAL), &busy),
            Some(0),
            "no load reported is not busy"
        );
        let tight = Busy {
            online: 3,
            load: 5.0,
        };
        assert_eq!(
            pick(&toronto_and_dallas(3, 0), Some(MONTREAL), &tight),
            Some(1),
            "the cap is a setting"
        );
    }

    #[test]
    fn when_every_server_is_busy_the_one_furthest_under_its_cap_is_chosen() {
        let busy = Busy::default();
        assert_eq!(
            pick(&toronto_and_dallas(45, 41), Some(MONTREAL), &busy),
            Some(1)
        );
        let mut servers = toronto_and_dallas(3, 5);
        servers[0].load = Some(1.5);
        servers[1].load = Some(0.95);
        assert_eq!(
            pick(&servers, Some(HOUSTON), &busy),
            Some(0),
            "busy by load: the fewest devices online"
        );
        // A tie on devices goes to the lower load.
        servers[1].online = 3;
        assert_eq!(pick(&servers, Some(MONTREAL), &busy), Some(1));
    }

    #[test]
    fn without_a_location_the_least_loaded_server_is_chosen() {
        let busy = Busy::default();
        assert_eq!(pick(&toronto_and_dallas(5, 2), None, &busy), Some(1));
        assert_eq!(pick(&toronto_and_dallas(2, 5), None, &busy), Some(0));
        let mut servers = toronto_and_dallas(2, 2);
        servers[0].load = Some(0.5);
        assert_eq!(pick(&servers, None, &busy), Some(1), "then the lower load");
        servers[0].load = Some(0.1);
        assert_eq!(
            pick(&servers, None, &busy),
            Some(0),
            "then the first in the list"
        );
        // A busy one is still skipped.
        let mut servers = toronto_and_dallas(0, 5);
        servers[0].load = Some(2.0);
        assert_eq!(pick(&servers, None, &busy), Some(1));
    }

    #[test]
    fn servers_within_300_km_of_each_other_count_as_equal_and_the_less_loaded_wins() {
        let busy = Busy::default();
        // Buffalo is about 95 km from Toronto, for a person in Toronto.
        let buffalo = Location {
            lat: 42.89,
            lon: -78.88,
        };
        let servers = vec![
            server(Some(TORONTO), 10, Some(0.1)),
            server(Some(buffalo), 2, Some(0.1)),
        ];
        assert_eq!(pick(&servers, Some(TORONTO), &busy), Some(1));
        // Same load: the nearer.
        let servers = vec![
            server(Some(buffalo), 2, Some(0.1)),
            server(Some(TORONTO), 2, Some(0.1)),
        ];
        assert_eq!(pick(&servers, Some(TORONTO), &busy), Some(1));
        // Ottawa is about 350 km from Toronto: no longer equal.
        let ottawa = Location {
            lat: 45.42,
            lon: -75.70,
        };
        let servers = vec![
            server(Some(TORONTO), 10, Some(0.1)),
            server(Some(ottawa), 2, Some(0.1)),
        ];
        assert_eq!(pick(&servers, Some(TORONTO), &busy), Some(0));
    }

    #[test]
    fn a_server_with_no_location_comes_after_those_with_one() {
        let busy = Busy::default();
        let servers = vec![server(None, 0, None), server(Some(TORONTO), 20, Some(0.5))];
        assert_eq!(pick(&servers, Some(MONTREAL), &busy), Some(1));
        let servers = vec![server(None, 0, None), server(None, 3, None)];
        assert_eq!(
            pick(&servers, Some(MONTREAL), &busy),
            Some(0),
            "with none located, the least loaded"
        );
        let servers = vec![server(Some(TORONTO), 40, None), server(None, 3, None)];
        assert_eq!(
            pick(&servers, Some(MONTREAL), &busy),
            Some(1),
            "but before a busy one"
        );
    }

    #[test]
    fn no_candidate_is_no_choice() {
        assert_eq!(pick(&[], Some(TORONTO), &Busy::default()), None);
        assert_eq!(pick(&[], None, &Busy::default()), None);
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn cloudflare_location_headers_are_read() {
        let found = from_headers(&headers(&[
            ("cf-iplatitude", "43.65320"),
            ("cf-iplongitude", "-79.38320"),
        ]));
        assert_eq!(
            found,
            Some(Location {
                lat: 43.6532,
                lon: -79.3832
            })
        );
        assert_eq!(
            from_headers(&headers(&[
                ("cf-iplatitude", "-90"),
                ("cf-iplongitude", "180")
            ])),
            Some(Location {
                lat: -90.0,
                lon: 180.0
            })
        );
        assert_eq!(
            from_headers(&headers(&[("cf-iplatitude", "0"), ("cf-iplongitude", "0")])),
            Some(Location { lat: 0.0, lon: 0.0 })
        );
    }

    #[test]
    fn anything_else_in_those_headers_is_no_location() {
        for (lat, lon) in [
            ("NaN", "1"),
            ("1", "nan"),
            ("inf", "1"),
            ("1", "-inf"),
            ("90.1", "0"),
            ("-90.1", "0"),
            ("0", "180.5"),
            ("0", "-181"),
            ("abc", "1"),
            ("", "1"),
            ("1", ""),
            ("1e1", "1"),
            ("0x10", "1"),
            ("1.2.3", "1"),
            ("43.6,1", "1"),
            ("- 1", "1"),
            ("-", "1"),
            (".", "1"),
            ("+43", "1"),
        ] {
            assert_eq!(
                from_headers(&headers(&[("cf-iplatitude", lat), ("cf-iplongitude", lon)])),
                None,
                "{lat:?} {lon:?}"
            );
        }
        assert_eq!(from_headers(&headers(&[("cf-iplatitude", "43")])), None);
        assert_eq!(from_headers(&headers(&[("cf-iplongitude", "43")])), None);
        assert_eq!(from_headers(&HeaderMap::new()), None);
        assert_eq!(
            from_headers(&headers(&[
                ("cf-iplatitude", "43"),
                ("cf-iplatitude", "44"),
                ("cf-iplongitude", "-79"),
            ])),
            None,
            "two values"
        );
        let mut map = headers(&[("cf-iplongitude", "-79")]);
        map.insert("cf-iplatitude", HeaderValue::from_bytes(b"43\xff").unwrap());
        assert_eq!(from_headers(&map), None, "not text");
    }

    #[test]
    fn a_location_on_the_command_line_is_lat_comma_lon() {
        assert_eq!(Location::parse("43.65,-79.38"), Some(TORONTO));
        assert_eq!(Location::parse("32.78, -96.80"), Some(DALLAS));
        for bad in [
            "",
            "43.65",
            "43.65,-79.38,1",
            "-79.38;43.65",
            "91,0",
            "0,181",
            "NaN,0",
            "a,b",
            "43.65,",
            ",-79.38",
        ] {
            assert_eq!(Location::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_busy_settings_have_defaults_and_refuse_anything_odd() {
        assert_eq!(busy_online(None), Ok(40));
        assert_eq!(busy_online(Some("1")), Ok(1));
        assert_eq!(busy_online(Some("100000")), Ok(100_000));
        for bad in ["0", "-1", "100001", "", " 5", "5 ", "4.5", "+5", "lots"] {
            let why = busy_online(Some(bad)).unwrap_err();
            assert!(why.contains("BC_NODE_BUSY_ONLINE"), "{bad:?}: {why}");
        }
        assert_eq!(busy_load(None), Ok(0.9));
        assert_eq!(busy_load(Some("1.5")), Ok(1.5));
        assert_eq!(busy_load(Some("1000")), Ok(1000.0));
        for bad in [
            "0", "0.0", "-1", "1000.1", "", " 1", "NaN", "inf", "1e2", "x",
        ] {
            let why = busy_load(Some(bad)).unwrap_err();
            assert!(why.contains("BC_NODE_BUSY_LOAD"), "{bad:?}: {why}");
        }
    }
}
