// utils.rs - Helper functions and utilities

use crate::{SipMessage, SipMethod, SipRequest, SipResponse};
use std::collections::HashMap;
use std::net::SocketAddr;
use bytes::Bytes;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref BRANCH_REGEX: Regex = Regex::new(r"branch=([^;]+)").unwrap();
    static ref TAG_REGEX: Regex = Regex::new(r"tag=([^;]+)").unwrap();
}

/// Generate a unique branch parameter for Via header
pub fn generate_branch() -> String {
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;
    
    let random: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    
    format!("z9hG4bK{}", random)
}

/// Generate a unique tag
pub fn generate_tag() -> String {
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;
    
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

/// Generate a unique Call-ID
pub fn generate_call_id(domain: &str) -> String {
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;
    
    let random: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    
    format!("{}@{}", random, domain)
}

/// Extract branch from Via header
pub fn extract_branch(via: &str) -> Option<String> {
    BRANCH_REGEX.captures(via)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract tag from From/To header
pub fn extract_tag(header: &str) -> Option<String> {
    TAG_REGEX.captures(header)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

/// Build a SIP response from a request
pub fn build_response_from_request(
    request: &SipRequest,
    status_code: u16,
    reason_phrase: &str,
) -> SipResponse {
    let mut headers = HashMap::new();
    
    // Copy essential headers from request
    if let Some(via) = request.headers.get("via") {
        headers.insert("via".to_string(), via.clone());
    }
    
    if let Some(from) = request.headers.get("from") {
        headers.insert("from".to_string(), from.clone());
    }
    
    if let Some(to) = request.headers.get("to") {
        let mut to_values = to.clone();
        // Add tag if not present (for non-100 responses)
        if status_code != 100 && !to_values.iter().any(|v| v.contains("tag=")) {
            if let Some(first) = to_values.first_mut() {
                *first = format!("{};tag={}", first, generate_tag());
            }
        }
        headers.insert("to".to_string(), to_values);
    }
    
    if let Some(call_id) = request.headers.get("call-id") {
        headers.insert("call-id".to_string(), call_id.clone());
    }
    
    if let Some(cseq) = request.headers.get("cseq") {
        headers.insert("cseq".to_string(), cseq.clone());
    }
    
    // Add Content-Length: 0 if no body
    headers.insert("content-length".to_string(), vec!["0".to_string()]);
    
    SipResponse {
        version: request.version.clone(),
        status_code,
        reason_phrase: reason_phrase.to_string(),
        headers,
        body: None,
    }
}

/// Add or update a header value
pub fn add_header(message: &mut SipMessage, name: &str, value: String) {
    let headers = message.headers_mut();
    headers.entry(name.to_lowercase())
        .or_insert_with(Vec::new)
        .push(value);
}

/// Set a header value (replacing existing values)
pub fn set_header(message: &mut SipMessage, name: &str, value: String) {
    let headers = message.headers_mut();
    headers.insert(name.to_lowercase(), vec![value]);
}

/// Get the first value of a header
pub fn get_header<'a>(message: &'a SipMessage, name: &str) -> Option<&'a str> {
    message.headers()
        .get(&name.to_lowercase())
        .and_then(|values| values.first())
        .map(|s| s.as_str())
}

/// Get all values of a header
pub fn get_header_values<'a>(message: &'a SipMessage, name: &str) -> Option<&'a Vec<String>> {
    message.headers().get(&name.to_lowercase())
}

/// Parse a SIP URI from a header value (extracts URI from angle brackets if present)
pub fn parse_uri_from_header(header: &str) -> Option<&str> {
    if let Some(start) = header.find('<') {
        if let Some(end) = header.find('>') {
            return Some(&header[start + 1..end]);
        }
    }
    
    // If no angle brackets, try to extract the URI part
    header.split_whitespace().next()
}

/// Calculate Content-Length for a message
pub fn calculate_content_length(body: Option<&Bytes>) -> usize {
    body.map(|b| b.len()).unwrap_or(0)
}

/// Check if a message is a request
pub fn is_request(message: &SipMessage) -> bool {
    matches!(message, SipMessage::Request(_))
}

/// Check if a message is a response
pub fn is_response(message: &SipMessage) -> bool {
    matches!(message, SipMessage::Response(_))
}

/// Get the method of a request (returns None for responses)
pub fn get_method(message: &SipMessage) -> Option<&SipMethod> {
    match message {
        SipMessage::Request(req) => Some(&req.method),
        SipMessage::Response(_) => None,
    }
}

/// Get the status code of a response (returns None for requests)
pub fn get_status_code(message: &SipMessage) -> Option<u16> {
    match message {
        SipMessage::Request(_) => None,
        SipMessage::Response(resp) => Some(resp.status_code),
    }
}

/// Check if a response is a final response (2xx-6xx)
pub fn is_final_response(message: &SipMessage) -> bool {
    match message {
        SipMessage::Response(resp) => resp.status_code >= 200,
        _ => false,
    }
}

/// Check if a response is a provisional response (1xx)
pub fn is_provisional_response(message: &SipMessage) -> bool {
    match message {
        SipMessage::Response(resp) => resp.status_code >= 100 && resp.status_code < 200,
        _ => false,
    }
}

/// Extract transaction ID from a message (branch + method for requests, branch + CSeq for responses)
pub fn get_transaction_id(message: &SipMessage) -> Option<String> {
    let via = get_header(message, "via")?;
    let branch = extract_branch(via)?;
    
    match message {
        SipMessage::Request(req) => {
            Some(format!("{}-{}", branch, req.method))
        }
        SipMessage::Response(_) => {
            let cseq = get_header(message, "cseq")?;
            Some(format!("{}-{}", branch, cseq))
        }
    }
}

/// Extract dialog ID from a message (Call-ID + from-tag + to-tag)
pub fn get_dialog_id(message: &SipMessage) -> Option<String> {
    let call_id = get_header(message, "call-id")?;
    let from = get_header(message, "from")?;
    let to = get_header(message, "to")?;
    
    let from_tag = extract_tag(from)?;
    let to_tag = extract_tag(to);
    
    if let Some(to_tag) = to_tag {
        Some(format!("{}-{}-{}", call_id, from_tag, to_tag))
    } else {
        // For initial requests, dialog ID is not complete
        None
    }
}

/// Format a socket address for use in Via header
pub fn format_via_address(addr: &SocketAddr, transport: &str, branch: &str) -> String {
    match addr {
        SocketAddr::V4(v4) => {
            format!("SIP/2.0/{} {}:{};branch={}", transport, v4.ip(), v4.port(), branch)
        }
        SocketAddr::V6(v6) => {
            format!("SIP/2.0/{} [{}]:{};branch={}", transport, v6.ip(), v6.port(), branch)
        }
    }
}

/// Parse CSeq header value
pub fn parse_cseq(cseq: &str) -> Option<(u32, String)> {
    let parts: Vec<&str> = cseq.split_whitespace().collect();
    if parts.len() == 2 {
        if let Ok(seq) = parts[0].parse::<u32>() {
            return Some((seq, parts[1].to_string()));
        }
    }
    None
}

/// Increment CSeq number
pub fn increment_cseq(cseq: &str) -> Option<String> {
    let (seq, method) = parse_cseq(cseq)?;
    Some(format!("{} {}", seq + 1, method))
}

/// Check if a method requires authentication
pub fn requires_authentication(method: &SipMethod) -> bool {
    match method {
        SipMethod::Register | 
        SipMethod::Invite | 
        SipMethod::Subscribe | 
        SipMethod::Refer |
        SipMethod::Publish => true,
        _ => false,
    }
}

/// Check if a method can have a message body
pub fn can_have_body(method: &SipMethod) -> bool {
    match method {
        SipMethod::Invite |
        SipMethod::Ack |
        SipMethod::Options |
        SipMethod::Info |
        SipMethod::Update |
        SipMethod::Prack |
        SipMethod::Message |
        SipMethod::Notify => true,
        _ => false,
    }
}

/// Helper to create common SIP headers
pub struct HeaderBuilder {
    headers: HashMap<String, Vec<String>>,
}

impl HeaderBuilder {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn via(mut self, value: &str) -> Self {
        self.headers.entry("via".to_string())
            .or_insert_with(Vec::new)
            .push(value.to_string());
        self
    }

    pub fn from(mut self, uri: &str, tag: Option<&str>) -> Self {
        let value = if let Some(tag) = tag {
            format!("<{}>;tag={}", uri, tag)
        } else {
            format!("<{}>;tag={}", uri, generate_tag())
        };
        self.headers.insert("from".to_string(), vec![value]);
        self
    }

    pub fn to(mut self, uri: &str, tag: Option<&str>) -> Self {
        let value = if let Some(tag) = tag {
            format!("<{}>;tag={}", uri, tag)
        } else {
            format!("<{}>", uri)
        };
        self.headers.insert("to".to_string(), vec![value]);
        self
    }

    pub fn call_id(mut self, call_id: &str) -> Self {
        self.headers.insert("call-id".to_string(), vec![call_id.to_string()]);
        self
    }

    pub fn cseq(mut self, seq: u32, method: &str) -> Self {
        self.headers.insert("cseq".to_string(), vec![format!("{} {}", seq, method)]);
        self
    }

    pub fn max_forwards(mut self, max_forwards: u32) -> Self {
        self.headers.insert("max-forwards".to_string(), vec![max_forwards.to_string()]);
        self
    }

    pub fn contact(mut self, uri: &str) -> Self {
        self.headers.insert("contact".to_string(), vec![format!("<{}>", uri)]);
        self
    }

    pub fn content_type(mut self, content_type: &str) -> Self {
        self.headers.insert("content-type".to_string(), vec![content_type.to_string()]);
        self
    }

    pub fn content_length(mut self, length: usize) -> Self {
        self.headers.insert("content-length".to_string(), vec![length.to_string()]);
        self
    }

    pub fn user_agent(mut self, user_agent: &str) -> Self {
        self.headers.insert("user-agent".to_string(), vec![user_agent.to_string()]);
        self
    }

    pub fn expires(mut self, seconds: u32) -> Self {
        self.headers.insert("expires".to_string(), vec![seconds.to_string()]);
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.entry(name.to_lowercase())
            .or_insert_with(Vec::new)
            .push(value.to_string());
        self
    }

    pub fn build(self) -> HashMap<String, Vec<String>> {
        self.headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_generation() {
        let branch1 = generate_branch();
        let branch2 = generate_branch();
        
        assert!(branch1.starts_with("z9hG4bK"));
        assert!(branch2.starts_with("z9hG4bK"));
        assert_ne!(branch1, branch2);
    }

    #[test]
    fn test_extract_branch() {
        let via = "SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1";
        let branch = extract_branch(via);
        assert_eq!(branch, Some("z9hG4bK776asdhds".to_string()));
    }

    #[test]
    fn test_extract_tag() {
        let from = "Alice <sip:alice@atlanta.com>;tag=1928301774";
        let tag = extract_tag(from);
        assert_eq!(tag, Some("1928301774".to_string()));
        
        let to = "Bob <sip:bob@biloxi.com>";
        let tag = extract_tag(to);
        assert_eq!(tag, None);
    }

    #[test]
    fn test_parse_cseq() {
        let cseq = "314159 INVITE";
        let parsed = parse_cseq(cseq);
        assert_eq!(parsed, Some((314159, "INVITE".to_string())));
    }

    #[test]
    fn test_increment_cseq() {
        let cseq = "314159 INVITE";
        let incremented = increment_cseq(cseq);
        assert_eq!(incremented, Some("314160 INVITE".to_string()));
    }

    #[test]
    fn test_parse_uri_from_header() {
        let header = "Alice <sip:alice@atlanta.com>;tag=1928301774";
        let uri = parse_uri_from_header(header);
        assert_eq!(uri, Some("sip:alice@atlanta.com"));
        
        let header = "sip:bob@biloxi.com";
        let uri = parse_uri_from_header(header);
        assert_eq!(uri, Some("sip:bob@biloxi.com"));
    }

    #[test]
    fn test_header_builder() {
        let headers = HeaderBuilder::new()
            .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds")
            .from("sip:alice@atlanta.com", Some("1928301774"))
            .to("sip:bob@biloxi.com", None)
            .call_id("a84b4c76e66710@pc33.atlanta.com")
            .cseq(314159, "INVITE")
            .max_forwards(70)
            .contact("sip:alice@pc33.atlanta.com")
            .content_length(0)
            .build();
        
        assert!(headers.contains_key("via"));
        assert!(headers.contains_key("from"));
        assert!(headers.contains_key("to"));
        assert!(headers.contains_key("call-id"));
        assert!(headers.contains_key("cseq"));
        assert!(headers.contains_key("max-forwards"));
        assert!(headers.contains_key("contact"));
        assert!(headers.contains_key("content-length"));
        
        assert_eq!(headers.get("cseq").unwrap().first().unwrap(), "314159 INVITE");
        assert_eq!(headers.get("max-forwards").unwrap().first().unwrap(), "70");
    }

    #[test]
    fn test_format_via_address() {
        let addr_v4 = "192.168.1.1:5060".parse().unwrap();
        let via = format_via_address(&addr_v4, "UDP", "z9hG4bK776asdhds");
        assert_eq!(via, "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhds");
        
        let addr_v6 = "[2001:db8::1]:5060".parse().unwrap();
        let via = format_via_address(&addr_v6, "TCP", "z9hG4bK776asdhds");
        assert_eq!(via, "SIP/2.0/TCP [2001:db8::1]:5060;branch=z9hG4bK776asdhds");
    }
}