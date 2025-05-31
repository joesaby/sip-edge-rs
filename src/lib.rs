// lib.rs - High-performance SIP parser with security hardening

use bytes::{Bytes, BytesMut};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while, take_while1},
    character::complete::{char, crlf, digit1, line_ending, space0, space1},
    combinator::{map, map_res, opt, recognize},
    multi::{many0, many1},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use thiserror::Error;

pub mod codec;
pub mod security;
pub mod transport;
pub mod utils;

// Security limits based on RFC recommendations and common attack vectors
pub const MAX_HEADER_LENGTH: usize = 8192;
pub const MAX_HEADERS: usize = 256;
pub const MAX_URI_LENGTH: usize = 2048;
pub const MAX_BODY_LENGTH: usize = 65536;
pub const MAX_VIA_HEADERS: usize = 70; // RFC 3261 recommendation
pub const MAX_ROUTE_HEADERS: usize = 20;

#[derive(Error, Debug)]
pub enum SipParseError {
    #[error("Header too long: {0} bytes (max: {1})")]
    HeaderTooLong(usize, usize),

    #[error("Too many headers: {0} (max: {1})")]
    TooManyHeaders(usize, usize),

    #[error("URI too long: {0} bytes (max: {1})")]
    UriTooLong(usize, usize),

    #[error("Body too long: {0} bytes (max: {1})")]
    BodyTooLong(usize, usize),

    #[error("Invalid SIP version: {0}")]
    InvalidVersion(String),

    #[error("Invalid method: {0}")]
    InvalidMethod(String),

    #[error("Invalid status code: {0}")]
    InvalidStatusCode(u16),

    #[error("Missing required header: {0}")]
    MissingRequiredHeader(String),

    #[error("Malformed header: {0}")]
    MalformedHeader(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Info,
    Update,
    Prack,
    Subscribe,
    Notify,
    Refer,
    Message,
    Publish,
    Other(String),
}

impl FromStr for SipMethod {
    type Err = SipParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Validate method length to prevent DoS
        if s.len() > 32 {
            return Err(SipParseError::InvalidMethod(s.to_string()));
        }

        // Only allow alphanumeric methods
        if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(SipParseError::InvalidMethod(s.to_string()));
        }

        Ok(match s.to_uppercase().as_str() {
            "REGISTER" => SipMethod::Register,
            "INVITE" => SipMethod::Invite,
            "ACK" => SipMethod::Ack,
            "BYE" => SipMethod::Bye,
            "CANCEL" => SipMethod::Cancel,
            "OPTIONS" => SipMethod::Options,
            "INFO" => SipMethod::Info,
            "UPDATE" => SipMethod::Update,
            "PRACK" => SipMethod::Prack,
            "SUBSCRIBE" => SipMethod::Subscribe,
            "NOTIFY" => SipMethod::Notify,
            "REFER" => SipMethod::Refer,
            "MESSAGE" => SipMethod::Message,
            "PUBLISH" => SipMethod::Publish,
            method => SipMethod::Other(method.to_string()),
        })
    }
}

impl fmt::Display for SipMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipMethod::Register => write!(f, "REGISTER"),
            SipMethod::Invite => write!(f, "INVITE"),
            SipMethod::Ack => write!(f, "ACK"),
            SipMethod::Bye => write!(f, "BYE"),
            SipMethod::Cancel => write!(f, "CANCEL"),
            SipMethod::Options => write!(f, "OPTIONS"),
            SipMethod::Info => write!(f, "INFO"),
            SipMethod::Update => write!(f, "UPDATE"),
            SipMethod::Prack => write!(f, "PRACK"),
            SipMethod::Subscribe => write!(f, "SUBSCRIBE"),
            SipMethod::Notify => write!(f, "NOTIFY"),
            SipMethod::Refer => write!(f, "REFER"),
            SipMethod::Message => write!(f, "MESSAGE"),
            SipMethod::Publish => write!(f, "PUBLISH"),
            SipMethod::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SipUri {
    pub scheme: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub parameters: HashMap<String, Option<String>>,
    pub headers: HashMap<String, String>,
}

impl SipUri {
    pub fn new(scheme: &str, host: &str) -> Self {
        Self {
            scheme: scheme.to_string(),
            user: None,
            password: None,
            host: host.to_string(),
            port: None,
            parameters: HashMap::new(),
            headers: HashMap::new(),
        }
    }

    pub fn validate(&self) -> Result<(), SipParseError> {
        // Validate URI length
        let uri_str = self.to_string();
        if uri_str.len() > MAX_URI_LENGTH {
            return Err(SipParseError::UriTooLong(uri_str.len(), MAX_URI_LENGTH));
        }

        // Validate scheme
        if !matches!(self.scheme.as_str(), "sip" | "sips" | "tel") {
            return Err(SipParseError::ParseError(format!(
                "Invalid URI scheme: {}",
                self.scheme
            )));
        }

        // Validate host (prevent various injection attacks)
        if self.host.is_empty() || self.host.len() > 255 {
            return Err(SipParseError::ParseError("Invalid host in URI".to_string()));
        }

        // Check for suspicious characters that might indicate injection attempts
        let suspicious_chars = ['<', '>', '"', '{', '}', '|', '\\', '^', '~', '[', ']', '`'];
        if self.host.chars().any(|c| suspicious_chars.contains(&c)) {
            return Err(SipParseError::SecurityViolation(
                "Suspicious characters in URI host".to_string(),
            ));
        }

        Ok(())
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;

        if let Some(user) = &self.user {
            write!(f, "{}", user)?;
            if let Some(password) = &self.password {
                write!(f, ":{}", password)?;
            }
            write!(f, "@")?;
        }

        write!(f, "{}", self.host)?;

        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }

        for (key, value) in &self.parameters {
            write!(f, ";{}", key)?;
            if let Some(val) = value {
                write!(f, "={}", val)?;
            }
        }

        if !self.headers.is_empty() {
            write!(f, "?")?;
            let headers: Vec<String> = self
                .headers
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            write!(f, "{}", headers.join("&"))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SipRequest {
    pub method: SipMethod,
    pub uri: SipUri,
    pub version: String,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Option<Bytes>,
}

#[derive(Debug, Clone)]
pub struct SipResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: HashMap<String, Vec<String>>,
    pub body: Option<Bytes>,
}

#[derive(Debug, Clone)]
pub enum SipMessage {
    Request(SipRequest),
    Response(SipResponse),
}

impl SipMessage {
    pub fn headers(&self) -> &HashMap<String, Vec<String>> {
        match self {
            SipMessage::Request(req) => &req.headers,
            SipMessage::Response(resp) => &resp.headers,
        }
    }

    pub fn headers_mut(&mut self) -> &mut HashMap<String, Vec<String>> {
        match self {
            SipMessage::Request(req) => &mut req.headers,
            SipMessage::Response(resp) => &mut resp.headers,
        }
    }

    pub fn body(&self) -> Option<&Bytes> {
        match self {
            SipMessage::Request(req) => req.body.as_ref(),
            SipMessage::Response(resp) => resp.body.as_ref(),
        }
    }

    pub fn validate(&self) -> Result<(), SipParseError> {
        // Validate headers count
        if self.headers().len() > MAX_HEADERS {
            return Err(SipParseError::TooManyHeaders(
                self.headers().len(),
                MAX_HEADERS,
            ));
        }

        // Validate required headers
        let required_headers = ["via", "from", "to", "call-id", "cseq"];
        for header in &required_headers {
            if !self.headers().contains_key(*header) {
                return Err(SipParseError::MissingRequiredHeader(header.to_string()));
            }
        }

        // Validate Via headers count (loop detection)
        if let Some(via_headers) = self.headers().get("via") {
            if via_headers.len() > MAX_VIA_HEADERS {
                return Err(SipParseError::SecurityViolation(format!(
                    "Too many Via headers: {} (max: {})",
                    via_headers.len(),
                    MAX_VIA_HEADERS
                )));
            }
        }

        // Validate Route headers count
        if let Some(route_headers) = self.headers().get("route") {
            if route_headers.len() > MAX_ROUTE_HEADERS {
                return Err(SipParseError::SecurityViolation(format!(
                    "Too many Route headers: {} (max: {})",
                    route_headers.len(),
                    MAX_ROUTE_HEADERS
                )));
            }
        }

        // Validate Content-Length if present
        if let Some(content_length_vals) = self.headers().get("content-length") {
            if let Some(content_length_str) = content_length_vals.first() {
                match content_length_str.parse::<usize>() {
                    Ok(content_length) => {
                        let actual_length = self.body().map(|b| b.len()).unwrap_or(0);
                        if content_length != actual_length {
                            return Err(SipParseError::SecurityViolation(format!(
                                "Content-Length mismatch: header={}, actual={}",
                                content_length, actual_length
                            )));
                        }
                        if content_length > MAX_BODY_LENGTH {
                            return Err(SipParseError::BodyTooLong(
                                content_length,
                                MAX_BODY_LENGTH,
                            ));
                        }
                    }
                    Err(_) => {
                        return Err(SipParseError::MalformedHeader(
                            "Invalid Content-Length".to_string(),
                        ));
                    }
                }
            }
        }

        // Additional validation for requests
        if let SipMessage::Request(req) = self {
            req.uri.validate()?;

            // Validate Max-Forwards to prevent loops
            if req.method != SipMethod::Ack && req.method != SipMethod::Cancel {
                if let Some(max_forwards) = self.headers().get("max-forwards") {
                    if let Some(max_fwd_str) = max_forwards.first() {
                        match max_fwd_str.parse::<u32>() {
                            Ok(0) => {
                                return Err(SipParseError::SecurityViolation(
                                    "Max-Forwards reached 0".to_string(),
                                ));
                            }
                            Err(_) => {
                                return Err(SipParseError::MalformedHeader(
                                    "Invalid Max-Forwards value".to_string(),
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

// Parser functions using nom
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-.!%*_+`'~".contains(c)
}

fn parse_token(input: &str) -> IResult<&str, &str> {
    take_while1(is_token_char)(input)
}

fn parse_method(input: &str) -> IResult<&str, SipMethod> {
    map_res(parse_token, SipMethod::from_str)(input)
}

fn parse_sip_version(input: &str) -> IResult<&str, &str> {
    recognize(tuple((tag("SIP"), char('/'), digit1, char('.'), digit1)))(input)
}

fn parse_uri_scheme(input: &str) -> IResult<&str, &str> {
    alt((tag("sip"), tag("sips"), tag("tel")))(input)
}

fn parse_uri(input: &str) -> IResult<&str, SipUri> {
    // Simplified URI parser - in production, use a more complete implementation
    let (input, scheme) = terminated(parse_uri_scheme, char(':'))(input)?;
    let (input, _) = opt(tag("//"))(input)?;

    // Parse user info
    let (input, user_info) = opt(terminated(
        recognize(many1(take_while1(|c: char| c != '@' && c != ':'))),
        char('@'),
    ))(input)?;

    // Parse host and port
    let (input, host) = take_while1(|c: char| c != ':' && c != ';' && c != '?' && c != ' ')(input)?;
    let (input, port) = opt(preceded(char(':'), map_res(digit1, str::parse)))(input)?;

    // Parse parameters
    let (input, params) = many0(preceded(
        char(';'),
        separated_pair(parse_token, opt(char('=')), opt(parse_token)),
    ))(input)?;

    let mut uri = SipUri::new(scheme, host);
    uri.port = port;

    if let Some(user) = user_info {
        uri.user = Some(user.trim_end_matches('@').to_string());
    }

    for (key, value) in params {
        uri.parameters
            .insert(key.to_string(), value.map(|v| v.to_string()));
    }

    Ok((input, uri))
}

fn parse_header_name(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-')(input)
}

fn parse_header_value(input: &str) -> IResult<&str, &str> {
    // Simple approach: take until CRLF
    take_while(|c: char| c != '\r' && c != '\n')(input)
}

fn parse_header(input: &str) -> IResult<&str, (&str, &str)> {
    let (input, name) = parse_header_name(input)?;
    let (input, _) = tuple((space0, char(':'), space0))(input)?;
    let (input, value) = parse_header_value(input)?;
    let (input, _) = line_ending(input)?;

    Ok((input, (name, value.trim())))
}

fn parse_headers(input: &str) -> IResult<&str, HashMap<String, Vec<String>>> {
    let (input, headers_vec) = many0(parse_header)(input)?;
    let (input, _) = line_ending(input)?; // Empty line after headers

    let mut headers = HashMap::new();
    for (name, value) in headers_vec {
        let normalized_name = name.to_lowercase();
        headers
            .entry(normalized_name)
            .or_insert_with(Vec::new)
            .push(value.to_string());
    }

    Ok((input, headers))
}

fn parse_request_line(input: &str) -> IResult<&str, (SipMethod, SipUri, &str)> {
    let (input, method) = parse_method(input)?;
    let (input, _) = space1(input)?;
    let (input, uri) = parse_uri(input)?;
    let (input, _) = space1(input)?;
    let (input, version) = parse_sip_version(input)?;
    let (input, _) = line_ending(input)?;

    Ok((input, (method, uri, version)))
}

fn parse_status_line(input: &str) -> IResult<&str, (&str, u16, &str)> {
    let (input, version) = parse_sip_version(input)?;
    let (input, _) = space1(input)?;
    let (input, status_code) = map_res(digit1, str::parse)(input)?;
    let (input, _) = space1(input)?;
    let (input, reason) = take_until("\r\n")(input)?;
    let (input, _) = line_ending(input)?;

    Ok((input, (version, status_code, reason)))
}

pub fn parse_sip_message(input: &[u8]) -> Result<SipMessage, SipParseError> {
    // Security check: validate input size
    if input.len() > MAX_HEADER_LENGTH + MAX_BODY_LENGTH {
        return Err(SipParseError::SecurityViolation(
            "Message too large".to_string(),
        ));
    }

    let input_str = std::str::from_utf8(input)
        .map_err(|_| SipParseError::ParseError("Invalid UTF-8".to_string()))?;

    // Try parsing as request first
    if let Ok((remaining, (method, uri, version))) = parse_request_line(input_str) {
        let (remaining, headers) = parse_headers(remaining)
            .map_err(|_| SipParseError::ParseError("Failed to parse headers".to_string()))?;

        let body = if !remaining.is_empty() {
            Some(Bytes::copy_from_slice(remaining.as_bytes()))
        } else {
            None
        };

        let request = SipRequest {
            method,
            uri,
            version: version.to_string(),
            headers,
            body,
        };

        let message = SipMessage::Request(request);
        message.validate()?;

        return Ok(message);
    }

    // Try parsing as response
    if let Ok((remaining, (version, status_code, reason_phrase))) = parse_status_line(input_str) {
        let (remaining, headers) = parse_headers(remaining)
            .map_err(|_| SipParseError::ParseError("Failed to parse headers".to_string()))?;

        let body = if !remaining.is_empty() {
            Some(Bytes::copy_from_slice(remaining.as_bytes()))
        } else {
            None
        };

        let response = SipResponse {
            version: version.to_string(),
            status_code,
            reason_phrase: reason_phrase.to_string(),
            headers,
            body,
        };

        let message = SipMessage::Response(response);
        message.validate()?;

        return Ok(message);
    }

    Err(SipParseError::ParseError(
        "Failed to parse SIP message".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_request() {
        let request = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Content-Length: 0\r\n\
                       \r\n";

        let result = parse_sip_message(request);
        assert!(result.is_ok());

        if let Ok(SipMessage::Request(req)) = result {
            assert_eq!(req.method, SipMethod::Invite);
            assert_eq!(req.uri.scheme, "sip");
            assert_eq!(req.uri.host, "bob@example.com");
            assert_eq!(req.version, "SIP/2.0");
            assert!(req.headers.contains_key("via"));
            assert!(req.headers.contains_key("from"));
            assert!(req.headers.contains_key("to"));
            assert!(req.headers.contains_key("call-id"));
            assert!(req.headers.contains_key("cseq"));
        } else {
            panic!("Expected request");
        }
    }

    #[test]
    fn test_parse_response() {
        let response = b"SIP/2.0 200 OK\r\n\
                        Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                        From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                        To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
                        Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Content-Length: 0\r\n\
                        \r\n";

        let result = parse_sip_message(response);
        assert!(result.is_ok());

        if let Ok(SipMessage::Response(resp)) = result {
            assert_eq!(resp.status_code, 200);
            assert_eq!(resp.reason_phrase, "OK");
            assert_eq!(resp.version, "SIP/2.0");
        } else {
            panic!("Expected response");
        }
    }

    #[test]
    fn test_security_header_too_long() {
        let mut request = b"INVITE sip:bob@example.com SIP/2.0\r\n".to_vec();
        request.extend_from_slice(b"X-Long-Header: ");
        request.extend(vec![b'A'; MAX_HEADER_LENGTH]);
        request.extend_from_slice(b"\r\n\r\n");

        let result = parse_sip_message(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_too_many_via_headers() {
        let mut request = b"INVITE sip:bob@example.com SIP/2.0\r\n".to_vec();

        // Add required headers
        request.extend_from_slice(b"From: <sip:alice@example.com>\r\n");
        request.extend_from_slice(b"To: <sip:bob@example.com>\r\n");
        request.extend_from_slice(b"Call-ID: test123\r\n");
        request.extend_from_slice(b"CSeq: 1 INVITE\r\n");

        // Add too many Via headers
        for i in 0..MAX_VIA_HEADERS + 1 {
            request.extend_from_slice(format!("Via: SIP/2.0/UDP host{}.com\r\n", i).as_bytes());
        }

        request.extend_from_slice(b"Content-Length: 0\r\n\r\n");

        let result = parse_sip_message(&request);
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
    }

    #[test]
    fn test_content_length_mismatch() {
        let request = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com\r\n\
                       From: <sip:alice@example.com>\r\n\
                       To: <sip:bob@example.com>\r\n\
                       Call-ID: test123\r\n\
                       CSeq: 1 INVITE\r\n\
                       Content-Length: 10\r\n\
                       \r\n\
                       Hello";

        let result = parse_sip_message(request);
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
    }

    #[test]
    fn test_debug_complex_request() {
        let request = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                       Via: SIP/2.0/UDP bigbox3.site3.atlanta.com\r\n\
                       Max-Forwards: 70\r\n\
                       From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                       To: Bob <sip:bob@biloxi.com>\r\n\
                       Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Contact: <sip:alice@pc33.atlanta.com>\r\n\
                       Authorization: Digest username=\"alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\"\r\n\
                       Content-Type: application/sdp\r\n\
                       Content-Length: 164\r\n\
                       \r\n\
                       v=0\r\n\
                       o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n\
                       s=Session Description\r\n\
                       c=IN IP4 pc33.atlanta.com\r\n\
                       t=0 0\r\n\
                       m=audio 49170 RTP/AVP 0\r\n\
                       a=rtpmap:0 PCMU/8000\r\n";

        println!("Request length: {}", request.len());
        println!("Request:\n{}", String::from_utf8_lossy(request));

        let result = parse_sip_message(request);
        match &result {
            Ok(message) => {
                println!("Parse successful!");
                match message {
                    SipMessage::Request(req) => {
                        println!("Method: {}", req.method);
                        println!("URI: {}", req.uri);
                        println!("Headers count: {}", req.headers.len());
                        if let Some(body) = &req.body {
                            println!("Body length: {}", body.len());
                            println!("Expected body length: 164");
                        }
                    }
                    SipMessage::Response(resp) => {
                        println!("Status: {}", resp.status_code);
                    }
                }
            }
            Err(e) => {
                println!("Parse error: {}", e);
            }
        }

        assert!(result.is_ok(), "Complex request should parse successfully");
    }

    #[test]
    fn test_debug_response() {
        let response = b"SIP/2.0 200 OK\r\n\
                        Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
                        From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                        To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
                        Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Contact: <sip:bob@192.0.2.4>\r\n\
                        Content-Type: application/sdp\r\n\
                        Content-Length: 149\r\n\
                        \r\n\
                        v=0\r\n\
                        o=bob 2890844527 2890844527 IN IP4 biloxi.com\r\n\
                        s=Session Description\r\n\
                        c=IN IP4 biloxi.com\r\n\
                        t=0 0\r\n\
                        m=audio 3456 RTP/AVP 0\r\n\
                        a=rtpmap:0 PCMU/8000\r\n";

        println!("Response length: {}", response.len());
        println!("Response:\n{}", String::from_utf8_lossy(response));

        let result = parse_sip_message(response);
        match &result {
            Ok(message) => {
                println!("Parse successful!");
                match message {
                    SipMessage::Request(req) => {
                        println!("Method: {}", req.method);
                        println!("URI: {}", req.uri);
                        println!("Headers count: {}", req.headers.len());
                        if let Some(body) = &req.body {
                            println!("Body length: {}", body.len());
                        }
                    }
                    SipMessage::Response(resp) => {
                        println!("Status: {}", resp.status_code);
                        println!("Headers count: {}", resp.headers.len());
                        if let Some(body) = &resp.body {
                            println!("Body length: {}", body.len());
                            println!("Expected body length: 149");
                        }
                    }
                }
            }
            Err(e) => {
                println!("Parse error: {}", e);
            }
        }

        assert!(result.is_ok(), "Response should parse successfully");
    }
}
