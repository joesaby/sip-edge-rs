// security.rs - SIP security hardening and vulnerability protection

use crate::{SipMessage, SipParseError, SipRequest, SipUri};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tracing::{warn, error};

lazy_static! {
    // Regex patterns for validation
    static ref VALID_SIP_URI: Regex = Regex::new(
        r"^(sip|sips|tel):([^@]+@)?([a-zA-Z0-9\.\-]+)(:[0-9]+)?(/.*)?$"
    ).unwrap();
    
    static ref VALID_PHONE: Regex = Regex::new(
        r"^\+?[0-9\-\(\)\s]+$"
    ).unwrap();
    
    static ref SQL_INJECTION_PATTERN: Regex = Regex::new(
        r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|;--|/\*|\*/)"
    ).unwrap();
    
    static ref SCRIPT_INJECTION_PATTERN: Regex = Regex::new(
        r"(?i)(<script|javascript:|onerror=|onclick=|<iframe|<object|<embed)"
    ).unwrap();
    
    static ref COMMAND_INJECTION_PATTERN: Regex = Regex::new(
        r"[;&|`\$\(\)]"
    ).unwrap();
}

/// Security configuration for the SIP parser
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable SQL injection detection
    pub detect_sql_injection: bool,
    
    /// Enable script injection detection
    pub detect_script_injection: bool,
    
    /// Enable command injection detection
    pub detect_command_injection: bool,
    
    /// Maximum allowed registrations per IP
    pub max_registrations_per_ip: usize,
    
    /// Rate limit window
    pub rate_limit_window: Duration,
    
    /// Maximum requests per window
    pub max_requests_per_window: usize,
    
    /// Enable strict URI validation
    pub strict_uri_validation: bool,
    
    /// Blocked user agents
    pub blocked_user_agents: HashSet<String>,
    
    /// Allowed domains for requests
    pub allowed_domains: Option<HashSet<String>>,
    
    /// Enable response splitting detection
    pub detect_response_splitting: bool,
    
    /// Maximum allowed forwarded hops
    pub max_forwards: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            detect_sql_injection: true,
            detect_script_injection: true,
            detect_command_injection: true,
            max_registrations_per_ip: 100,
            rate_limit_window: Duration::from_secs(60),
            max_requests_per_window: 1000,
            strict_uri_validation: true,
            blocked_user_agents: HashSet::new(),
            allowed_domains: None,
            detect_response_splitting: true,
            max_forwards: 70,
        }
    }
}

/// Rate limiter for preventing DoS attacks
pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    config: SecurityConfig,
}

impl RateLimiter {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub fn check_rate_limit(&self, client_id: &str) -> Result<(), SipParseError> {
        let now = Instant::now();
        let mut requests = self.requests.write();
        
        let entries = requests.entry(client_id.to_string()).or_insert_with(Vec::new);
        
        // Remove old entries
        entries.retain(|&time| now.duration_since(time) < self.config.rate_limit_window);
        
        if entries.len() >= self.config.max_requests_per_window {
            return Err(SipParseError::SecurityViolation(
                format!("Rate limit exceeded for client: {}", client_id)
            ));
        }
        
        entries.push(now);
        Ok(())
    }

    pub fn cleanup_old_entries(&self) {
        let now = Instant::now();
        let mut requests = self.requests.write();
        
        requests.retain(|_, entries| {
            entries.retain(|&time| now.duration_since(time) < self.config.rate_limit_window);
            !entries.is_empty()
        });
    }
}

/// Security validator for SIP messages
pub struct SecurityValidator {
    config: SecurityConfig,
    rate_limiter: RateLimiter,
}

impl SecurityValidator {
    pub fn new(config: SecurityConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.clone());
        Self {
            config,
            rate_limiter,
        }
    }

    /// Validate a SIP message for security vulnerabilities
    pub fn validate_message(&self, message: &SipMessage, client_ip: &str) -> Result<(), SipParseError> {
        // Rate limiting
        self.rate_limiter.check_rate_limit(client_ip)?;
        
        // Check user agent
        if let Some(user_agents) = message.headers().get("user-agent") {
            for ua in user_agents {
                if self.config.blocked_user_agents.contains(ua) {
                    return Err(SipParseError::SecurityViolation(
                        format!("Blocked user agent: {}", ua)
                    ));
                }
            }
        }
        
        // Validate headers for injection attacks
        for (header_name, header_values) in message.headers() {
            for value in header_values {
                self.validate_header_value(header_name, value)?;
            }
        }
        
        // Additional validation for requests
        if let SipMessage::Request(request) = message {
            self.validate_request(request)?;
        }
        
        // Check for response splitting
        if self.config.detect_response_splitting {
            self.check_response_splitting(message)?;
        }
        
        // Validate Max-Forwards
        if let Some(max_fwd_values) = message.headers().get("max-forwards") {
            if let Some(max_fwd) = max_fwd_values.first() {
                match max_fwd.parse::<u32>() {
                    Ok(value) if value > self.config.max_forwards => {
                        return Err(SipParseError::SecurityViolation(
                            format!("Max-Forwards too high: {}", value)
                        ));
                    }
                    Err(_) => {
                        return Err(SipParseError::MalformedHeader(
                            "Invalid Max-Forwards value".to_string()
                        ));
                    }
                    _ => {}
                }
            }
        }
        
        Ok(())
    }

    fn validate_header_value(&self, header_name: &str, value: &str) -> Result<(), SipParseError> {
        // Check for SQL injection
        if self.config.detect_sql_injection && SQL_INJECTION_PATTERN.is_match(value) {
            return Err(SipParseError::SecurityViolation(
                format!("SQL injection attempt detected in header '{}': {}", header_name, value)
            ));
        }
        
        // Check for script injection
        if self.config.detect_script_injection && SCRIPT_INJECTION_PATTERN.is_match(value) {
            return Err(SipParseError::SecurityViolation(
                format!("Script injection attempt detected in header '{}': {}", header_name, value)
            ));
        }
        
        // Check for command injection
        if self.config.detect_command_injection && COMMAND_INJECTION_PATTERN.is_match(value) {
            return Err(SipParseError::SecurityViolation(
                format!("Command injection attempt detected in header '{}': {}", header_name, value)
            ));
        }
        
        // Check for null bytes
        if value.contains('\0') {
            return Err(SipParseError::SecurityViolation(
                format!("Null byte detected in header '{}': {}", header_name, value)
            ));
        }
        
        // Check for excessive length in specific headers
        match header_name.to_lowercase().as_str() {
            "to" | "from" | "contact" => {
                if value.len() > 512 {
                    return Err(SipParseError::HeaderTooLong(value.len(), 512));
                }
            }
            "via" => {
                if value.len() > 256 {
                    return Err(SipParseError::HeaderTooLong(value.len(), 256));
                }
            }
            _ => {}
        }
        
        Ok(())
    }

    fn validate_request(&self, request: &SipRequest) -> Result<(), SipParseError> {
        // Validate URI
        if self.config.strict_uri_validation {
            self.validate_uri(&request.uri)?;
        }
        
        // Check allowed domains
        if let Some(allowed_domains) = &self.config.allowed_domains {
            let domain = &request.uri.host;
            let base_domain = domain.split('@').last().unwrap_or(domain);
            
            if !allowed_domains.contains(base_domain) {
                return Err(SipParseError::SecurityViolation(
                    format!("Domain not allowed: {}", base_domain)
                ));
            }
        }
        
        // Validate specific methods
        match &request.method {
            crate::SipMethod::Register => {
                self.validate_register_request(request)?;
            }
            crate::SipMethod::Invite => {
                self.validate_invite_request(request)?;
            }
            _ => {}
        }
        
        Ok(())
    }

    fn validate_uri(&self, uri: &SipUri) -> Result<(), SipParseError> {
        // Basic URI validation is already done in SipUri::validate()
        uri.validate()?;
        
        // Additional strict validation
        if self.config.strict_uri_validation {
            let uri_str = uri.to_string();
            
            // Check against regex pattern
            if !VALID_SIP_URI.is_match(&uri_str) {
                return Err(SipParseError::ParseError(
                    format!("Invalid SIP URI format: {}", uri_str)
                ));
            }
            
            // Validate host is not an IP in certain contexts
            if uri.scheme == "sips" {
                if IpAddr::from_str(&uri.host).is_ok() {
                    warn!("SIPS URI with IP address: {}", uri.host);
                }
            }
            
            // Check for directory traversal attempts
            if uri_str.contains("../") || uri_str.contains("..\\") {
                return Err(SipParseError::SecurityViolation(
                    "Directory traversal attempt in URI".to_string()
                ));
            }
        }
        
        Ok(())
    }

    fn validate_register_request(&self, request: &SipRequest) -> Result<(), SipParseError> {
        // Check for registration flooding
        if let Some(expires_values) = request.headers.get("expires") {
            if let Some(expires) = expires_values.first() {
                match expires.parse::<u32>() {
                    Ok(0) => {
                        // Deregistration - allow
                    }
                    Ok(value) if value < 60 => {
                        return Err(SipParseError::SecurityViolation(
                            format!("Expires value too low: {}", value)
                        ));
                    }
                    Ok(value) if value > 86400 => {
                        return Err(SipParseError::SecurityViolation(
                            format!("Expires value too high: {}", value)
                        ));
                    }
                    Err(_) => {
                        return Err(SipParseError::MalformedHeader(
                            "Invalid Expires value".to_string()
                        ));
                    }
                    _ => {}
                }
            }
        }
        
        // Validate Contact header
        if let Some(contacts) = request.headers.get("contact") {
            if contacts.len() > 10 {
                return Err(SipParseError::SecurityViolation(
                    format!("Too many Contact headers: {}", contacts.len())
                ));
            }
        }
        
        Ok(())
    }

    fn validate_invite_request(&self, request: &SipRequest) -> Result<(), SipParseError> {
        // Check for malformed SDP in body
        if let Some(body) = &request.body {
            if let Some(content_type) = request.headers.get("content-type") {
                if content_type.iter().any(|ct| ct.contains("application/sdp")) {
                    self.validate_sdp(body)?;
                }
            }
        }
        
        Ok(())
    }

    fn validate_sdp(&self, body: &bytes::Bytes) -> Result<(), SipParseError> {
        let sdp_str = std::str::from_utf8(body)
            .map_err(|_| SipParseError::ParseError("Invalid UTF-8 in SDP".to_string()))?;
        
        // Basic SDP validation
        let lines: Vec<&str> = sdp_str.lines().collect();
        
        if lines.is_empty() || !lines[0].starts_with("v=") {
            return Err(SipParseError::ParseError("Invalid SDP: missing version".to_string()));
        }
        
        // Check for suspicious patterns in SDP
        for line in lines {
            if line.len() > 1024 {
                return Err(SipParseError::SecurityViolation(
                    "SDP line too long".to_string()
                ));
            }
            
            // Check for injection attempts in SDP attributes
            if self.config.detect_command_injection && COMMAND_INJECTION_PATTERN.is_match(line) {
                return Err(SipParseError::SecurityViolation(
                    "Command injection attempt in SDP".to_string()
                ));
            }
        }
        
        Ok(())
    }

    fn check_response_splitting(&self, message: &SipMessage) -> Result<(), SipParseError> {
        for (_, values) in message.headers() {
            for value in values {
                // Check for CRLF injection
                if value.contains("\r\n") || value.contains("\n") {
                    return Err(SipParseError::SecurityViolation(
                        "Response splitting attempt detected".to_string()
                    ));
                }
            }
        }
        
        Ok(())
    }
}

/// Security audit logger
pub struct SecurityAuditor {
    violations: Arc<RwLock<Vec<SecurityViolation>>>,
}

#[derive(Debug, Clone)]
pub struct SecurityViolation {
    pub timestamp: Instant,
    pub client_ip: String,
    pub violation_type: String,
    pub details: String,
    pub message_snippet: Option<String>,
}

impl SecurityAuditor {
    pub fn new() -> Self {
        Self {
            violations: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn log_violation(&self, client_ip: &str, violation_type: &str, details: &str, message_snippet: Option<String>) {
        let violation = SecurityViolation {
            timestamp: Instant::now(),
            client_ip: client_ip.to_string(),
            violation_type: violation_type.to_string(),
            details: details.to_string(),
            message_snippet,
        };
        
        error!("Security violation from {}: {} - {}", client_ip, violation_type, details);
        
        let mut violations = self.violations.write();
        violations.push(violation);
        
        // Keep only last 10000 violations
        if violations.len() > 10000 {
            violations.drain(0..1000);
        }
    }

    pub fn get_recent_violations(&self, duration: Duration) -> Vec<SecurityViolation> {
        let now = Instant::now();
        let violations = self.violations.read();
        
        violations
            .iter()
            .filter(|v| now.duration_since(v.timestamp) <= duration)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SipMethod, SipRequest};

    #[test]
    fn test_sql_injection_detection() {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config);
        
        let result = validator.validate_header_value("from", "user'; DROP TABLE users; --");
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
        
        let result = validator.validate_header_value("from", "<sip:user@example.com>");
        assert!(result.is_ok());
    }

    #[test]
    fn test_script_injection_detection() {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config);
        
        let result = validator.validate_header_value("user-agent", "Mozilla <script>alert('xss')</script>");
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
        
        let result = validator.validate_header_value("user-agent", "Mozilla/5.0 SIPClient/1.0");
        assert!(result.is_ok());
    }

    #[test]
    fn test_command_injection_detection() {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config);
        
        let result = validator.validate_header_value("to", "sip:user@example.com; rm -rf /");
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
        
        let result = validator.validate_header_value("to", "sip:user@example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = SecurityConfig::default();
        config.max_requests_per_window = 5;
        config.rate_limit_window = Duration::from_secs(1);
        
        let validator = SecurityValidator::new(config);
        let client_ip = "192.168.1.1";
        
        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(validator.rate_limiter.check_rate_limit(client_ip).is_ok());
        }
        
        // 6th request should fail
        assert!(matches!(
            validator.rate_limiter.check_rate_limit(client_ip),
            Err(SipParseError::SecurityViolation(_))
        ));
    }

    #[test]
    fn test_null_byte_detection() {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config);
        
        let result = validator.validate_header_value("from", "user\0@example.com");
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
    }

    #[test]
    fn test_response_splitting() {
        let config = SecurityConfig::default();
        let validator = SecurityValidator::new(config);
        
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), vec!["SIP/2.0/UDP client.com\r\nX-Injected: malicious".to_string()]);
        headers.insert("from".to_string(), vec!["<sip:user@example.com>".to_string()]);
        headers.insert("to".to_string(), vec!["<sip:target@example.com>".to_string()]);
        headers.insert("call-id".to_string(), vec!["test123".to_string()]);
        headers.insert("cseq".to_string(), vec!["1 INVITE".to_string()]);
        
        let request = SipRequest {
            method: SipMethod::Invite,
            uri: SipUri::new("sip", "target@example.com"),
            version: "SIP/2.0".to_string(),
            headers,
            body: None,
        };
        
        let message = SipMessage::Request(request);
        let result = validator.check_response_splitting(&message);
        assert!(matches!(result, Err(SipParseError::SecurityViolation(_))));
    }
}