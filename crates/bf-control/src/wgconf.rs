//! A device's WireGuard configuration file and the QR code of it.
//!
//! The private key is in the file and nowhere else: it is made when the device is added, shown
//! once and never stored (`keys.rs`), so what is built here is handed to the person and dropped.

use std::net::{IpAddr, Ipv4Addr};

/// The resolver a device uses: its server's own, at the first address of the device's /16
/// (10.77.0.1 on AmneziaWG, 10.78.0.1 on WireGuard). Port 53 there blocks trackers unless
/// the device's switch is off (`specs/trackers.md`).
pub fn dns_for(address: Ipv4Addr) -> Ipv4Addr {
    let [a, b, _, _] = address.octets();
    Ipv4Addr::new(a, b, 0, 1)
}

/// AmneziaWG obfuscation values. A client must use the exact values configured on its server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaParams {
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

impl AmneziaParams {
    /// Reject values outside the ranges accepted by AmneziaWG and inconsistent padding.
    pub fn validate(self) -> Result<Self, AmneziaParamsError> {
        if self.jc > 128
            || self.jmin >= self.jmax
            || self.jmax > 1280
            || self.s1 > 1132
            || self.s2 > 1188
            || self.s1.saturating_add(56) == self.s2
        {
            return Err(AmneziaParamsError);
        }
        if [self.h1, self.h2, self.h3, self.h4]
            .iter()
            .any(|header| *header < 5 || *header > 2_147_483_647)
            || [self.h1, self.h2, self.h3, self.h4]
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != 4
        {
            return Err(AmneziaParamsError);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmneziaParamsError;

impl std::fmt::Display for AmneziaParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid AmneziaWG parameters")
    }
}

impl std::error::Error for AmneziaParamsError {}

/// Everything a device's file says.
///
/// `Debug` is written by hand and leaves the private key out, the way `KeyPair`'s is, so a
/// stray `{:?}` in a log line or a failed assertion cannot print the key.
#[derive(Clone)]
pub struct ClientConfig<'a> {
    pub private_key: &'a str,
    /// The device's address inside the tunnel.
    pub address: Ipv4Addr,
    /// The node's WireGuard public key.
    pub server_public_key: &'a str,
    pub endpoint_ip: IpAddr,
    pub endpoint_port: u16,
}

impl std::fmt::Debug for ClientConfig<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("address", &self.address)
            .field("server_public_key", &self.server_public_key)
            .field("endpoint_ip", &self.endpoint_ip)
            .field("endpoint_port", &self.endpoint_port)
            .finish_non_exhaustive()
    }
}

impl ClientConfig<'_> {
    /// The `.conf` text every WireGuard app reads. All traffic goes through the tunnel,
    /// including IPv6, which the nodes do not carry: sending it in means it is dropped, not
    /// sent around the VPN.
    pub fn render(&self) -> String {
        let endpoint = match self.endpoint_ip {
            IpAddr::V4(ip) => format!("{ip}:{}", self.endpoint_port),
            IpAddr::V6(ip) => format!("[{ip}]:{}", self.endpoint_port),
        };
        format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = {}/32\n\
             DNS = {}\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = {endpoint}\n\
             PersistentKeepalive = 25\n",
            self.private_key,
            self.address,
            dns_for(self.address),
            self.server_public_key,
        )
    }

    /// Renders an AmneziaWG profile. The caller must use the exact obfuscation parameters
    /// from a server that is already running AmneziaWG; this is not interchangeable with a
    /// regular WireGuard profile when any masking option is enabled.
    pub fn render_amnezia(&self, params: AmneziaParams) -> Result<String, AmneziaParamsError> {
        let params = params.validate()?;
        let mut text = self.render();
        let private_key = text.find("\n\n[Peer]\n").ok_or(AmneziaParamsError)?;
        text.insert_str(
            private_key + 1,
            &format!(
                "Jc = {}\nJmin = {}\nJmax = {}\nS1 = {}\nS2 = {}\nH1 = {}\nH2 = {}\nH3 = {}\nH4 = {}\n",
                params.jc,
                params.jmin,
                params.jmax,
                params.s1,
                params.s2,
                params.h1,
                params.h2,
                params.h3,
                params.h4,
            ),
        );
        Ok(text)
    }
}

/// `text` as the body of a `data:` address: everything but unreserved characters is
/// percent-encoded, so it is safe in an attribute and survives line breaks.
pub fn data_url_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A file name stem for a device: lowercase letters, digits and dashes only, at most 10
/// characters, never empty. `bf-<stem>.conf` stays under WireGuard's 15-character tunnel name.
pub fn file_stem(device_name: &str) -> String {
    let mut stem = String::new();
    for c in device_name.chars() {
        let c = if c.is_ascii_alphanumeric() {
            c.to_ascii_lowercase()
        } else {
            '-'
        };
        if c != '-' || !(stem.is_empty() || stem.ends_with('-')) {
            stem.push(c);
        }
    }
    let stem: String = stem.chars().take(10).collect();
    let stem = stem.trim_matches('-');
    if stem.is_empty() {
        "device".to_string()
    } else {
        stem.to_string()
    }
}

/// The text does not fit in a QR code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrError;

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the text does not fit in a QR code")
    }
}

impl std::error::Error for QrError {}

/// The QR code of `text` as an inline `<svg>` (no XML prolog, no `style`, no script): black
/// modules on a white square with a quiet border, which any scanner reads on a dark page.
pub fn qr_svg(text: &str) -> Result<String, QrError> {
    use qrcode::QrCode;
    use qrcode::render::svg::Color;

    let code = QrCode::new(text.as_bytes()).map_err(|_| QrError)?;
    let svg = code
        .render::<Color<'_>>()
        .min_dimensions(256, 256)
        .dark_color(Color("#000000"))
        .light_color(Color("#ffffff"))
        .quiet_zone(true)
        .build();
    // The library writes an XML prolog; an inline svg in a page needs none, and no address.
    let start = svg.find("<svg").ok_or(QrError)?;
    Ok(svg[start..].replace(" xmlns=\"http://www.w3.org/2000/svg\"", ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const SERVER: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    fn config(ip: &str) -> ClientConfig<'static> {
        ClientConfig {
            private_key: PRIVATE,
            address: "10.77.0.2".parse().unwrap(),
            server_public_key: SERVER,
            endpoint_ip: ip.parse().unwrap(),
            endpoint_port: 51820,
        }
    }

    #[test]
    fn the_file_is_exactly_what_a_wireguard_app_reads() {
        let text = config("192.0.2.7").render();

        assert_eq!(
            text,
            "[Interface]\n\
             PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
             Address = 10.77.0.2/32\n\
             DNS = 10.77.0.1\n\
             \n\
             [Peer]\n\
             PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = 192.0.2.7:51820\n\
             PersistentKeepalive = 25\n"
        );
    }

    #[test]
    fn dns_goes_to_the_servers_own_resolver_in_the_devices_range_and_nowhere_else() {
        // The server is the first address of the device's /16 on both protocols
        // (`specs/trackers.md`): 10.77.0.1 for AmneziaWG, 10.78.0.1 for WireGuard.
        for (device, server) in [
            ("10.77.0.2", "10.77.0.1"),
            ("10.77.200.17", "10.77.0.1"),
            ("10.78.0.2", "10.78.0.1"),
            ("10.78.3.4", "10.78.0.1"),
        ] {
            let mut c = config("192.0.2.7");
            c.address = device.parse().unwrap();
            let text = c.render();
            let dns: Vec<&str> = text.lines().filter(|l| l.starts_with("DNS")).collect();
            assert_eq!(dns, [format!("DNS = {server}")], "{text}");
        }
        let amnezia = config("192.0.2.7")
            .render_amnezia(AmneziaParams {
                jc: 4,
                jmin: 40,
                jmax: 70,
                s1: 15,
                s2: 20,
                h1: 1_000_000_001,
                h2: 1_000_000_002,
                h3: 1_000_000_003,
                h4: 1_000_000_004,
            })
            .unwrap();
        assert!(amnezia.contains("\nDNS = 10.77.0.1\n"), "{amnezia}");
        assert!(!amnezia.contains("1.1.1.1"), "{amnezia}");
    }

    #[test]
    fn debug_output_never_contains_the_private_key() {
        let c = config("192.0.2.7");

        for text in [format!("{c:?}"), format!("{c:#?}")] {
            assert!(!text.contains(PRIVATE), "the private key leaked: {text}");
            assert!(text.contains("10.77.0.2"), "{text}");
            assert!(text.contains(SERVER), "{text}");
        }
    }

    #[test]
    fn an_ipv6_endpoint_is_in_brackets_and_the_port_is_the_nodes() {
        let mut c = config("2001:db8::1");
        c.endpoint_port = 443;

        assert!(
            c.render().contains("Endpoint = [2001:db8::1]:443\n"),
            "{}",
            c.render()
        );
    }

    #[test]
    fn an_amnezia_profile_uses_the_validated_server_parameters() {
        let params = AmneziaParams {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 0,
            s2: 0,
            h1: 1_000_000_001,
            h2: 1_000_000_002,
            h3: 1_000_000_003,
            h4: 1_000_000_004,
        };
        let text = config("192.0.2.7").render_amnezia(params).unwrap();
        assert!(text.contains("Jc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\n"));
        assert!(text.contains(
            "H1 = 1000000001\nH2 = 1000000002\nH3 = 1000000003\nH4 = 1000000004\n\n[Peer]"
        ));
        assert!(text.contains("PrivateKey = "));
    }

    #[test]
    fn invalid_amnezia_parameters_are_rejected() {
        let bad = AmneziaParams {
            jc: 129,
            jmin: 70,
            jmax: 40,
            s1: 0,
            s2: 0,
            h1: 1,
            h2: 1,
            h3: 1,
            h4: 1,
        };
        assert_eq!(
            config("192.0.2.7").render_amnezia(bad),
            Err(AmneziaParamsError)
        );
    }

    #[test]
    fn the_file_has_one_private_key_no_trailing_spaces_and_ends_with_a_newline() {
        let text = config("192.0.2.7").render();

        assert_eq!(text.matches("PrivateKey").count(), 1);
        assert_eq!(text.matches(PRIVATE).count(), 1);
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
        assert!(text.lines().all(|line| line == line.trim_end()));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn a_data_address_percent_encodes_everything_but_the_unreserved_characters() {
        assert_eq!(
            data_url_text("[Interface]\nKey = a+b/c=\n"),
            "%5BInterface%5D%0AKey%20%3D%20a%2Bb%2Fc%3D%0A"
        );
        assert_eq!(data_url_text("AZaz09-._~"), "AZaz09-._~");
        let all = data_url_text(&config("192.0.2.7").render());
        assert!(
            all.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b))
        );
    }

    #[test]
    fn a_data_address_decodes_back_to_the_same_text() {
        let text = config("192.0.2.7").render();
        let encoded = data_url_text(&text);
        let mut bytes = Vec::new();
        let raw = encoded.as_bytes();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                bytes.push(u8::from_str_radix(&encoded[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                bytes.push(raw[i]);
                i += 1;
            }
        }
        assert_eq!(String::from_utf8(bytes).unwrap(), text);
        assert_eq!(data_url_text("é"), "%C3%A9", "bytes, not characters");
    }

    #[test]
    fn a_file_stem_is_short_lowercase_and_never_a_path() {
        assert_eq!(file_stem("My Phone"), "my-phone");
        assert_eq!(file_stem("phone"), "phone");
        assert_eq!(file_stem("../../etc/passwd"), "etc-passwd");
        assert_eq!(file_stem("A very long device name"), "a-very-lon");
        assert_eq!(file_stem("   "), "device");
        assert_eq!(file_stem(""), "device");
        assert_eq!(file_stem("日本語"), "device");
        assert_eq!(file_stem("--x--"), "x");
        assert_eq!(file_stem("Sam's iPhone 15 Pro"), "sam-s-ipho");
        for name in ["a", "ÀÉ", "x y z", "../../..", "CON", "a\nb"] {
            let stem = file_stem(name);
            assert!(!stem.is_empty() && stem.len() <= 10, "{name:?} -> {stem:?}");
            assert!(
                stem.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{name:?} -> {stem:?}"
            );
            assert!(!stem.starts_with('-') && !stem.ends_with('-'));
        }
    }

    #[test]
    fn the_qr_code_is_an_inline_svg_that_a_strict_page_allows() {
        let svg = qr_svg(&config("192.0.2.7").render()).unwrap();

        assert!(svg.starts_with("<svg"), "{}", &svg[..80]);
        assert!(svg.trim_end().ends_with("</svg>"));
        for forbidden in [
            "<?xml",
            "<!DOCTYPE",
            "style=",
            "<script",
            "<style",
            "href=",
            "http://www.w3.org/1999/xlink",
        ] {
            assert!(!svg.contains(forbidden), "{forbidden}");
        }
        assert!(svg.contains("viewBox"), "it scales");
        assert!(svg.contains("#000000") && svg.contains("#ffffff"));
    }

    #[test]
    fn the_qr_code_changes_with_the_text_and_a_text_too_big_for_a_code_is_an_error() {
        let one = qr_svg("one").unwrap();
        let two = qr_svg("two").unwrap();

        assert_ne!(one, two);
        assert_eq!(one, qr_svg("one").unwrap());
        assert!(qr_svg(&"x".repeat(5000)).is_err());
    }

    #[test]
    fn the_qr_code_holds_the_whole_file_which_fits_with_room_to_spare() {
        let text = config("2001:db8:1234:5678:9abc:def0:1234:5678").render();
        assert!(text.len() < 400, "{}", text.len());

        assert!(qr_svg(&text).is_ok());
        // A version-13 code is 69 modules wide, which a phone camera reads from a laptop screen.
        // Even the longest file (an IPv6 endpoint) stays at or under version 14 (73 modules).
        let width = qrcode::QrCode::new(text.as_bytes()).unwrap().width();
        assert!(width <= 73, "{width}");
    }
}
