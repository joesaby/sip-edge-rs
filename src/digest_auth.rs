// digest_auth.rs - RFC 2617 HTTP/SIP Digest authentication for registering with Cisco registrars

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref DIGEST_PARAM_RE: Regex = Regex::new(r#"(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))"#).unwrap();
}

/// A parsed `WWW-Authenticate` / `Proxy-Authenticate` Digest challenge
#[derive(Debug, Clone, PartialEq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub qop: Option<String>,
    pub algorithm: String,
    pub stale: bool,
}

impl DigestChallenge {
    /// Parse a `Digest realm="...", nonce="...", ...` header value
    pub fn parse(header_value: &str) -> Option<Self> {
        let value = header_value.trim();
        let value = value.strip_prefix("Digest").unwrap_or(value).trim();

        let mut realm = None;
        let mut nonce = None;
        let mut opaque = None;
        let mut qop = None;
        let mut algorithm = "MD5".to_string();
        let mut stale = false;

        for cap in DIGEST_PARAM_RE.captures_iter(value) {
            let key = cap.get(1)?.as_str().to_lowercase();
            let val = cap
                .get(2)
                .or_else(|| cap.get(3))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            match key.as_str() {
                "realm" => realm = Some(val),
                "nonce" => nonce = Some(val),
                "opaque" => opaque = Some(val),
                "qop" => qop = Some(val),
                "algorithm" => algorithm = val,
                "stale" => stale = val.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }

        Some(DigestChallenge {
            realm: realm?,
            nonce: nonce?,
            opaque,
            qop,
            algorithm,
            stale,
        })
    }

    /// Returns "auth" if the server offered it among a comma-separated qop-options list
    pub fn preferred_qop(&self) -> Option<&'static str> {
        self.qop
            .as_deref()?
            .split(',')
            .map(|s| s.trim())
            .find(|s| *s == "auth")
            .map(|_| "auth")
    }
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn compute_ha1(username: &str, realm: &str, password: &str) -> String {
    md5_hex(&format!("{}:{}:{}", username, realm, password))
}

fn compute_ha2(method: &str, uri: &str) -> String {
    md5_hex(&format!("{}:{}", method, uri))
}

/// Parameters required to compute an RFC 2617 Digest `response` value
pub struct DigestParams<'a> {
    pub username: &'a str,
    pub realm: &'a str,
    pub password: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    pub nonce: &'a str,
    pub qop: Option<&'a str>,
    pub cnonce: Option<&'a str>,
    pub nc: Option<u32>,
}

/// Compute the Digest `response` value per RFC 2617 section 3.2.2.1
pub fn compute_response(params: &DigestParams) -> String {
    let ha1 = compute_ha1(params.username, params.realm, params.password);
    let ha2 = compute_ha2(params.method, params.uri);

    let input = match (params.qop, params.cnonce, params.nc) {
        (Some(qop), Some(cnonce), Some(nc)) => {
            format!("{}:{}:{:08x}:{}:{}:{}", ha1, params.nonce, nc, cnonce, qop, ha2)
        }
        _ => format!("{}:{}:{}", ha1, params.nonce, ha2),
    };

    md5_hex(&input)
}

/// Build a full `Authorization`/`Proxy-Authorization` header value in response to a challenge
#[allow(clippy::too_many_arguments)]
pub fn build_authorization_header(
    username: &str,
    challenge: &DigestChallenge,
    password: &str,
    method: &str,
    uri: &str,
    cnonce: Option<&str>,
    nc: Option<u32>,
) -> String {
    let qop = challenge.preferred_qop();

    let response = compute_response(&DigestParams {
        username,
        realm: &challenge.realm,
        password,
        method,
        uri,
        nonce: &challenge.nonce,
        qop,
        cnonce,
        nc,
    });

    let mut header = format!(
        r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}", algorithm={}"#,
        username, challenge.realm, challenge.nonce, uri, response, challenge.algorithm
    );

    if let (Some(qop), Some(cnonce), Some(nc)) = (qop, cnonce, nc) {
        header.push_str(&format!(r#", qop={}, cnonce="{}", nc={:08x}"#, qop, cnonce, nc));
    }

    if let Some(opaque) = &challenge.opaque {
        header.push_str(&format!(r#", opaque="{}""#, opaque));
    }

    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_challenge_with_qop() {
        let header = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let challenge = DigestChallenge::parse(header).unwrap();

        assert_eq!(challenge.realm, "testrealm@host.com");
        assert_eq!(challenge.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(challenge.opaque.as_deref(), Some("5ccc069c403ebaf9f0171e9517f40e41"));
        assert_eq!(challenge.preferred_qop(), Some("auth"));
        assert_eq!(challenge.algorithm, "MD5");
        assert!(!challenge.stale);
    }

    #[test]
    fn test_parse_cisco_style_challenge_no_qop() {
        // Many Cisco CUCM/CUBE registrars challenge without qop
        let header = r#"Digest realm="ciscoSystemSIPRealm", nonce="1a2b3c4d5e6f7890""#;
        let challenge = DigestChallenge::parse(header).unwrap();

        assert_eq!(challenge.realm, "ciscoSystemSIPRealm");
        assert_eq!(challenge.nonce, "1a2b3c4d5e6f7890");
        assert_eq!(challenge.preferred_qop(), None);
    }

    #[test]
    fn test_parse_missing_required_field_returns_none() {
        let header = r#"Digest qop="auth""#;
        assert!(DigestChallenge::parse(header).is_none());
    }

    // RFC 2617 section 3.5 canonical worked example
    #[test]
    fn test_rfc2617_worked_example() {
        let ha1 = compute_ha1("Mufasa", "testrealm@host.com", "Circle Of Life");
        assert_eq!(ha1, "939e7578ed9e3c518a452acee763bce9");

        let ha2 = compute_ha2("GET", "/dir/index.html");
        assert_eq!(ha2, "39aff3a2bab6126f332b942af96d3366");

        let response = compute_response(&DigestParams {
            username: "Mufasa",
            realm: "testrealm@host.com",
            password: "Circle Of Life",
            method: "GET",
            uri: "/dir/index.html",
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            qop: Some("auth"),
            cnonce: Some("0a4f113b"),
            nc: Some(1),
        });

        assert_eq!(response, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn test_build_authorization_header_without_qop() {
        let challenge = DigestChallenge {
            realm: "ciscoSystemSIPRealm".to_string(),
            nonce: "1a2b3c4d5e6f7890".to_string(),
            opaque: None,
            qop: None,
            algorithm: "MD5".to_string(),
            stale: false,
        };

        let header = build_authorization_header(
            "tenant1",
            &challenge,
            "s3cret",
            "REGISTER",
            "sip:cube.example.com",
            None,
            None,
        );

        assert!(header.contains(r#"username="tenant1""#));
        assert!(header.contains(r#"realm="ciscoSystemSIPRealm""#));
        assert!(header.contains(r#"uri="sip:cube.example.com""#));
        assert!(!header.contains("qop="));
    }

    #[test]
    fn test_build_authorization_header_with_qop() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: "MD5".to_string(),
            stale: false,
        };

        let header = build_authorization_header(
            "Mufasa",
            &challenge,
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            Some("0a4f113b"),
            Some(1),
        );

        assert!(header.contains(r#"response="6629fae49393a05397450978507c4ef1""#));
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains(r#"cnonce="0a4f113b""#));
    }
}
