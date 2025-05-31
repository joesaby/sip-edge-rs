// codec.rs - Tokio codec for SIP message framing

use crate::{parse_sip_message, SipMessage, SipParseError, MAX_BODY_LENGTH, MAX_HEADER_LENGTH};
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

/// SIP codec for framing messages over TCP/TLS
/// Implements proper message boundary detection based on Content-Length
pub struct SipCodec {
    /// Maximum allowed message size for security
    max_message_size: usize,
    /// Current parsing state
    state: CodecState,
    /// Expected content length from headers
    content_length: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
enum CodecState {
    Headers,
    Body(usize), // Expected body length
}

impl Default for SipCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl SipCodec {
    pub fn new() -> Self {
        Self {
            max_message_size: MAX_HEADER_LENGTH + MAX_BODY_LENGTH,
            state: CodecState::Headers,
            content_length: None,
        }
    }

    pub fn with_max_message_size(max_message_size: usize) -> Self {
        Self {
            max_message_size,
            state: CodecState::Headers,
            content_length: None,
        }
    }

    /// Find the end of headers (empty line)
    fn find_headers_end(buf: &[u8]) -> Option<usize> {
        // Look for \r\n\r\n
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(pos + 4);
        }
        
        // Also check for \n\n (non-standard but sometimes seen)
        if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
            return Some(pos + 2);
        }
        
        None
    }

    /// Extract Content-Length from headers buffer
    fn extract_content_length(headers: &[u8]) -> Result<Option<usize>, SipParseError> {
        let headers_str = std::str::from_utf8(headers)
            .map_err(|_| SipParseError::ParseError("Invalid UTF-8 in headers".to_string()))?;
        
        // Case-insensitive search for Content-Length
        for line in headers_str.lines() {
            let line = line.trim();
            if line.to_lowercase().starts_with("content-length:") {
                let value = line[15..].trim();
                match value.parse::<usize>() {
                    Ok(len) => {
                        // Validate content length
                        if len > MAX_BODY_LENGTH {
                            return Err(SipParseError::BodyTooLong(len, MAX_BODY_LENGTH));
                        }
                        return Ok(Some(len));
                    }
                    Err(_) => {
                        return Err(SipParseError::MalformedHeader(
                            format!("Invalid Content-Length: {}", value)
                        ));
                    }
                }
            }
        }
        
        Ok(None)
    }
}

impl Decoder for SipCodec {
    type Item = SipMessage;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                CodecState::Headers => {
                    // Check if we have complete headers
                    if let Some(headers_end) = Self::find_headers_end(buf) {
                        // Validate header size
                        if headers_end > MAX_HEADER_LENGTH {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                SipParseError::HeaderTooLong(headers_end, MAX_HEADER_LENGTH),
                            ));
                        }

                        // Extract content length
                        match Self::extract_content_length(&buf[..headers_end]) {
                            Ok(content_length) => {
                                self.content_length = content_length;
                                
                                if let Some(len) = content_length {
                                    if len > 0 {
                                        // We need to read the body
                                        self.state = CodecState::Body(len);
                                        continue;
                                    }
                                }
                                
                                // No body or zero-length body
                                let message_bytes = buf.split_to(headers_end);
                                self.state = CodecState::Headers;
                                self.content_length = None;
                                
                                match parse_sip_message(&message_bytes) {
                                    Ok(message) => {
                                        debug!("Decoded SIP message without body");
                                        return Ok(Some(message));
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse SIP message: {}", e);
                                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                                    }
                                }
                            }
                            Err(e) => {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                            }
                        }
                    } else {
                        // Need more data
                        if buf.len() > MAX_HEADER_LENGTH {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                SipParseError::HeaderTooLong(buf.len(), MAX_HEADER_LENGTH),
                            ));
                        }
                        return Ok(None);
                    }
                }
                
                CodecState::Body(expected_len) => {
                    // Find where headers end
                    if let Some(headers_end) = Self::find_headers_end(buf) {
                        let total_len = headers_end + expected_len;
                        
                        // Check total message size
                        if total_len > self.max_message_size {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                SipParseError::SecurityViolation(
                                    format!("Message too large: {} bytes", total_len)
                                ),
                            ));
                        }
                        
                        if buf.len() >= total_len {
                            // We have the complete message
                            let message_bytes = buf.split_to(total_len);
                            self.state = CodecState::Headers;
                            self.content_length = None;
                            
                            match parse_sip_message(&message_bytes) {
                                Ok(message) => {
                                    debug!("Decoded SIP message with {} byte body", expected_len);
                                    return Ok(Some(message));
                                }
                                Err(e) => {
                                    warn!("Failed to parse SIP message: {}", e);
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                                }
                            }
                        } else {
                            // Need more data
                            return Ok(None);
                        }
                    } else {
                        // This shouldn't happen if state management is correct
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid codec state",
                        ));
                    }
                }
            }
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If we have partial data at EOF, try to decode it
        if !buf.is_empty() {
            match self.decode(buf) {
                Ok(Some(msg)) => Ok(Some(msg)),
                Ok(None) => {
                    // Incomplete message at EOF
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Incomplete SIP message at EOF",
                    ))
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }
}

impl Encoder<SipMessage> for SipCodec {
    type Error = io::Error;

    fn encode(&mut self, message: SipMessage, buf: &mut BytesMut) -> Result<(), Self::Error> {
        // Validate message before encoding
        if let Err(e) = message.validate() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }

        // Pre-calculate required buffer size
        let estimated_size = match &message {
            SipMessage::Request(req) => {
                100 + // Request line
                req.headers.iter().map(|(k, v)| k.len() + v.iter().map(|val| val.len()).sum::<usize>() + 10).sum::<usize>() +
                req.body.as_ref().map(|b| b.len()).unwrap_or(0)
            }
            SipMessage::Response(resp) => {
                100 + // Status line
                resp.headers.iter().map(|(k, v)| k.len() + v.iter().map(|val| val.len()).sum::<usize>() + 10).sum::<usize>() +
                resp.body.as_ref().map(|b| b.len()).unwrap_or(0)
            }
        };

        buf.reserve(estimated_size);

        match message {
            SipMessage::Request(req) => {
                // Request line
                buf.put(req.method.to_string().as_bytes());
                buf.put_u8(b' ');
                buf.put(req.uri.to_string().as_bytes());
                buf.put_u8(b' ');
                buf.put(req.version.as_bytes());
                buf.put(&b"\r\n"[..]);

                // Headers
                for (name, values) in &req.headers {
                    for value in values {
                        buf.put(name.as_bytes());
                        buf.put(&b": "[..]);
                        buf.put(value.as_bytes());
                        buf.put(&b"\r\n"[..]);
                    }
                }

                // Empty line
                buf.put(&b"\r\n"[..]);

                // Body
                if let Some(body) = req.body {
                    buf.put(body);
                }
            }
            
            SipMessage::Response(resp) => {
                // Status line
                buf.put(resp.version.as_bytes());
                buf.put_u8(b' ');
                buf.put(resp.status_code.to_string().as_bytes());
                buf.put_u8(b' ');
                buf.put(resp.reason_phrase.as_bytes());
                buf.put(&b"\r\n"[..]);

                // Headers
                for (name, values) in &resp.headers {
                    for value in values {
                        buf.put(name.as_bytes());
                        buf.put(&b": "[..]);
                        buf.put(value.as_bytes());
                        buf.put(&b"\r\n"[..]);
                    }
                }

                // Empty line
                buf.put(&b"\r\n"[..]);

                // Body
                if let Some(body) = resp.body {
                    buf.put(body);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SipMethod, SipRequest, SipUri};
    use std::collections::HashMap;

    #[test]
    fn test_codec_simple_request() {
        let mut codec = SipCodec::new();
        let mut buf = BytesMut::new();
        
        buf.extend_from_slice(b"OPTIONS sip:server.com SIP/2.0\r\n");
        buf.extend_from_slice(b"Via: SIP/2.0/UDP client.com\r\n");
        buf.extend_from_slice(b"From: <sip:client@client.com>\r\n");
        buf.extend_from_slice(b"To: <sip:server@server.com>\r\n");
        buf.extend_from_slice(b"Call-ID: test123\r\n");
        buf.extend_from_slice(b"CSeq: 1 OPTIONS\r\n");
        buf.extend_from_slice(b"Content-Length: 0\r\n");
        buf.extend_from_slice(b"\r\n");

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_codec_request_with_body() {
        let mut codec = SipCodec::new();
        let mut buf = BytesMut::new();
        
        let body = b"Hello, World!";
        
        buf.extend_from_slice(b"MESSAGE sip:user@example.com SIP/2.0\r\n");
        buf.extend_from_slice(b"Via: SIP/2.0/UDP client.com\r\n");
        buf.extend_from_slice(b"From: <sip:sender@client.com>\r\n");
        buf.extend_from_slice(b"To: <sip:user@example.com>\r\n");
        buf.extend_from_slice(b"Call-ID: test456\r\n");
        buf.extend_from_slice(b"CSeq: 1 MESSAGE\r\n");
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        buf.extend_from_slice(b"Content-Type: text/plain\r\n");
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(body);

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
        
        if let Some(SipMessage::Request(req)) = result {
            assert_eq!(req.body.as_ref().unwrap().as_ref(), body);
        } else {
            panic!("Expected request with body");
        }
    }

    #[test]
    fn test_codec_partial_message() {
        let mut codec = SipCodec::new();
        let mut buf = BytesMut::new();
        
        // Add partial headers
        buf.extend_from_slice(b"INVITE sip:bob@example.com SIP/2.0\r\n");
        buf.extend_from_slice(b"Via: SIP/2.0/UDP client.com\r\n");
        
        // Should return None (need more data)
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
        
        // Add more headers
        buf.extend_from_slice(b"From: <sip:alice@client.com>\r\n");
        buf.extend_from_slice(b"To: <sip:bob@example.com>\r\n");
        buf.extend_from_slice(b"Call-ID: test789\r\n");
        buf.extend_from_slice(b"CSeq: 1 INVITE\r\n");
        buf.extend_from_slice(b"Content-Length: 0\r\n");
        buf.extend_from_slice(b"\r\n");
        
        // Now should decode successfully
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_codec_encode_request() {
        let mut codec = SipCodec::new();
        let mut buf = BytesMut::new();
        
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), vec!["SIP/2.0/UDP client.com".to_string()]);
        headers.insert("from".to_string(), vec!["<sip:alice@client.com>".to_string()]);
        headers.insert("to".to_string(), vec!["<sip:bob@server.com>".to_string()]);
        headers.insert("call-id".to_string(), vec!["test123".to_string()]);
        headers.insert("cseq".to_string(), vec!["1 INVITE".to_string()]);
        headers.insert("content-length".to_string(), vec!["0".to_string()]);
        
        let request = SipRequest {
            method: SipMethod::Invite,
            uri: SipUri::new("sip", "bob@server.com"),
            version: "SIP/2.0".to_string(),
            headers,
            body: None,
        };
        
        let message = SipMessage::Request(request);
        codec.encode(message, &mut buf).unwrap();
        
        // Verify the encoded message contains expected elements
        let encoded = std::str::from_utf8(&buf).unwrap();
        assert!(encoded.starts_with("INVITE sip:bob@server.com SIP/2.0\r\n"));
        assert!(encoded.contains("Via: SIP/2.0/UDP client.com\r\n"));
        assert!(encoded.contains("From: <sip:alice@client.com>\r\n"));
        assert!(encoded.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_codec_multiple_messages() {
        let mut codec = SipCodec::new();
        let mut buf = BytesMut::new();
        
        // Add two complete messages
        buf.extend_from_slice(b"OPTIONS sip:server1.com SIP/2.0\r\n");
        buf.extend_from_slice(b"Via: SIP/2.0/UDP client.com\r\n");
        buf.extend_from_slice(b"From: <sip:client@client.com>\r\n");
        buf.extend_from_slice(b"To: <sip:server@server1.com>\r\n");
        buf.extend_from_slice(b"Call-ID: test1\r\n");
        buf.extend_from_slice(b"CSeq: 1 OPTIONS\r\n");
        buf.extend_from_slice(b"Content-Length: 0\r\n");
        buf.extend_from_slice(b"\r\n");
        
        buf.extend_from_slice(b"OPTIONS sip:server2.com SIP/2.0\r\n");
        buf.extend_from_slice(b"Via: SIP/2.0/UDP client.com\r\n");
        buf.extend_from_slice(b"From: <sip:client@client.com>\r\n");
        buf.extend_from_slice(b"To: <sip:server@server2.com>\r\n");
        buf.extend_from_slice(b"Call-ID: test2\r\n");
        buf.extend_from_slice(b"CSeq: 2 OPTIONS\r\n");
        buf.extend_from_slice(b"Content-Length: 0\r\n");
        buf.extend_from_slice(b"\r\n");
        
        // Should decode first message
        let result1 = codec.decode(&mut buf).unwrap();
        assert!(result1.is_some());
        
        // Should decode second message
        let result2 = codec.decode(&mut buf).unwrap();
        assert!(result2.is_some());
        
        // Buffer should be empty
        assert!(buf.is_empty());
    }
}