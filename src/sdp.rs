// sdp.rs - SDP body inspection built on top of the sdp-rs parser (RFC 4566/8866)
//
// Used by the multi-tenant gateway to log/validate the media Cisco offers in an INVITE
// (codecs, connection address) without having to hand-roll SDP parsing.

use std::fmt;

/// A single `a=rtpmap` entry offered for a media stream
#[derive(Debug, Clone, PartialEq)]
pub struct OfferedCodec {
    pub payload_type: u32,
    pub encoding_name: String,
    pub clock_rate: i32,
}

/// A compact summary of an SDP session body
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SdpSummary {
    pub connection_addr: Option<String>,
    pub media_count: usize,
    pub codecs: Vec<OfferedCodec>,
}

#[derive(Debug)]
pub enum SdpError {
    InvalidUtf8,
    ParseError(String),
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpError::InvalidUtf8 => write!(f, "SDP body is not valid UTF-8"),
            SdpError::ParseError(e) => write!(f, "failed to parse SDP: {}", e),
        }
    }
}

impl std::error::Error for SdpError {}

/// Parse an SDP body and extract the offered codecs and connection address, primarily
/// for logging/diagnostics when routing calls to/from a Cisco endpoint.
pub fn summarize_sdp(body: &[u8]) -> Result<SdpSummary, SdpError> {
    let text = std::str::from_utf8(body).map_err(|_| SdpError::InvalidUtf8)?;
    let session: sdp_rs::SessionDescription = text
        .parse()
        .map_err(|e: sdp_rs::Error| SdpError::ParseError(e.to_string()))?;

    let connection_addr = session
        .connection
        .as_ref()
        .map(|c| c.to_string())
        .or_else(|| {
            session
                .media_descriptions
                .iter()
                .find_map(|m| m.connections.first().map(|c| c.to_string()))
        });

    let mut codecs = Vec::new();
    for media in &session.media_descriptions {
        for attr in &media.attributes {
            if let sdp_rs::lines::Attribute::Rtpmap(rtpmap) = attr {
                codecs.push(OfferedCodec {
                    payload_type: rtpmap.payload_type,
                    encoding_name: rtpmap.encoding_name.clone(),
                    clock_rate: rtpmap.clock_rate,
                });
            }
        }
    }

    Ok(SdpSummary {
        connection_addr,
        media_count: session.media_descriptions.len(),
        codecs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SDP: &str = "v=0\r\n\
o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n\
s=Session Description\r\n\
c=IN IP4 pc33.atlanta.com\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";

    #[test]
    fn test_summarize_sdp_extracts_codec_and_connection() {
        let summary = summarize_sdp(SAMPLE_SDP.as_bytes()).expect("valid SDP");

        assert_eq!(summary.media_count, 1);
        assert_eq!(summary.codecs.len(), 1);
        assert_eq!(summary.codecs[0].payload_type, 0);
        assert_eq!(summary.codecs[0].encoding_name, "PCMU");
        assert_eq!(summary.codecs[0].clock_rate, 8000);
        assert!(summary.connection_addr.unwrap().contains("pc33.atlanta.com"));
    }

    #[test]
    fn test_summarize_sdp_rejects_invalid_utf8() {
        let bytes = [0xff, 0xfe, 0xfd];
        assert!(matches!(summarize_sdp(&bytes), Err(SdpError::InvalidUtf8)));
    }

    #[test]
    fn test_summarize_sdp_rejects_garbage() {
        let result = summarize_sdp(b"not an sdp body at all");
        assert!(result.is_err());
    }
}
