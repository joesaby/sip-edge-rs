// examples/test_client.rs - Test client for SIP Router

use anyhow::Result;
use sip_edge_rs::{
    transport::{TransportProtocol},
    utils::{self, HeaderBuilder},
    SipMessage, SipMethod, SipRequest, SipUri,
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tracing::{info, error};
use bytes::{BytesMut, BufMut};

/// Simple SIP test client
struct SipTestClient {
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    socket: UdpSocket,
    call_id_counter: u32,
    cseq_counter: u32,
}

impl SipTestClient {
    async fn new(local_addr: &str, server_addr: &str) -> Result<Self> {
        let local_addr: SocketAddr = local_addr.parse()?;
        let server_addr: SocketAddr = server_addr.parse()?;
        let socket = UdpSocket::bind(local_addr).await?;
        
        Ok(Self {
            local_addr,
            server_addr,
            socket,
            call_id_counter: 0,
            cseq_counter: 1,
        })
    }

    async fn send_options(&mut self) -> Result<()> {
        let branch = utils::generate_branch();
        let tag = utils::generate_tag();
        let call_id = format!("{}@{}", self.call_id_counter, self.local_addr.ip());
        self.call_id_counter += 1;

        let headers = HeaderBuilder::new()
            .via(&format!("SIP/2.0/UDP {};branch={}", self.local_addr, branch))
            .from(&format!("sip:test@{}", self.local_addr.ip()), Some(&tag))
            .to(&format!("sip:server@{}", self.server_addr.ip()), None)
            .call_id(&call_id)
            .cseq(self.cseq_counter, "OPTIONS")
            .max_forwards(70)
            .user_agent("SIP Test Client/1.0")
            .content_length(0)
            .build();

        self.cseq_counter += 1;

        let request = SipRequest {
            method: SipMethod::Options,
            uri: SipUri::new("sip", &format!("server@{}", self.server_addr.ip())),
            version: "SIP/2.0".to_string(),
            headers,
            body: None,
        };

        let message = SipMessage::Request(request);
        
        // Encode message
        let mut buf = BytesMut::new();
        self.encode_message(&message, &mut buf)?;
        
        // Send message
        self.socket.send_to(&buf, self.server_addr).await?;
        info!("Sent OPTIONS request to {}", self.server_addr);
        
        // Wait for response
        let mut recv_buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_secs(5), self.socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((len, from))) => {
                info!("Received {} bytes from {}", len, from);
                if let Ok(response_str) = std::str::from_utf8(&recv_buf[..len]) {
                    info!("Response:\n{}", response_str);
                }
            }
            Ok(Err(e)) => error!("Receive error: {}", e),
            Err(_) => error!("Timeout waiting for response"),
        }
        
        Ok(())
    }

    async fn send_register(&mut self, user: &str, expires: u32) -> Result<()> {
        let branch = utils::generate_branch();
        let tag = utils::generate_tag();
        let call_id = format!("{}@{}", self.call_id_counter, self.local_addr.ip());
        self.call_id_counter += 1;

        let user_uri = format!("sip:{}@{}", user, self.server_addr.ip());
        
        let headers = HeaderBuilder::new()
            .via(&format!("SIP/2.0/UDP {};branch={}", self.local_addr, branch))
            .from(&user_uri, Some(&tag))
            .to(&user_uri, None)
            .call_id(&call_id)
            .cseq(self.cseq_counter, "REGISTER")
            .contact(&format!("sip:{}@{}", user, self.local_addr))
            .expires(expires)
            .max_forwards(70)
            .user_agent("SIP Test Client/1.0")
            .content_length(0)
            .build();

        self.cseq_counter += 1;

        let request = SipRequest {
            method: SipMethod::Register,
            uri: SipUri::new("sip", &self.server_addr.ip().to_string()),
            version: "SIP/2.0".to_string(),
            headers,
            body: None,
        };

        let message = SipMessage::Request(request);
        
        // Encode message
        let mut buf = BytesMut::new();
        self.encode_message(&message, &mut buf)?;
        
        // Send message
        self.socket.send_to(&buf, self.server_addr).await?;
        info!("Sent REGISTER request for user '{}' with expires={}", user, expires);
        
        // Wait for response
        let mut recv_buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_secs(5), self.socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((len, from))) => {
                info!("Received {} bytes from {}", len, from);
                if let Ok(response_str) = std::str::from_utf8(&recv_buf[..len]) {
                    info!("Response:\n{}", response_str);
                }
            }
            Ok(Err(e)) => error!("Receive error: {}", e),
            Err(_) => error!("Timeout waiting for response"),
        }
        
        Ok(())
    }

    async fn send_invite(&mut self, from_user: &str, to_user: &str) -> Result<()> {
        let branch = utils::generate_branch();
        let from_tag = utils::generate_tag();
        let call_id = format!("{}@{}", self.call_id_counter, self.local_addr.ip());
        self.call_id_counter += 1;

        let from_uri = format!("sip:{}@{}", from_user, self.local_addr.ip());
        let to_uri = format!("sip:{}@{}", to_user, self.server_addr.ip());
        
        // Simple SDP body
        let sdp = format!(
            "v=0\r\n\
             o={} {} {} IN IP4 {}\r\n\
             s=Test Session\r\n\
             c=IN IP4 {}\r\n\
             t=0 0\r\n\
             m=audio 49170 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n",
            from_user, 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            self.local_addr.ip(),
            self.local_addr.ip()
        );
        
        let headers = HeaderBuilder::new()
            .via(&format!("SIP/2.0/UDP {};branch={}", self.local_addr, branch))
            .from(&from_uri, Some(&from_tag))
            .to(&to_uri, None)
            .call_id(&call_id)
            .cseq(self.cseq_counter, "INVITE")
            .contact(&format!("<sip:{}@{}>", from_user, self.local_addr))
            .max_forwards(70)
            .user_agent("SIP Test Client/1.0")
            .content_type("application/sdp")
            .content_length(sdp.len())
            .build();

        self.cseq_counter += 1;

        let request = SipRequest {
            method: SipMethod::Invite,
            uri: SipUri::new("sip", &to_uri),
            version: "SIP/2.0".to_string(),
            headers,
            body: Some(sdp.into()),
        };

        let message = SipMessage::Request(request);
        
        // Encode message
        let mut buf = BytesMut::new();
        self.encode_message(&message, &mut buf)?;
        
        // Send message
        self.socket.send_to(&buf, self.server_addr).await?;
        info!("Sent INVITE from '{}' to '{}'", from_user, to_user);
        
        // Wait for response
        let mut recv_buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_secs(5), self.socket.recv_from(&mut recv_buf)).await {
            Ok(Ok((len, from))) => {
                info!("Received {} bytes from {}", len, from);
                if let Ok(response_str) = std::str::from_utf8(&recv_buf[..len]) {
                    info!("Response:\n{}", response_str);
                }
            }
            Ok(Err(e)) => error!("Receive error: {}", e),
            Err(_) => error!("Timeout waiting for response"),
        }
        
        Ok(())
    }

    fn encode_message(&self, message: &SipMessage, buf: &mut BytesMut) -> Result<()> {
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
                if let Some(body) = &req.body {
                    buf.put(body.clone());
                }
            }
            SipMessage::Response(_) => {
                // This is a client, we don't send responses
                return Err(anyhow::anyhow!("Cannot send response from client"));
            }
        }
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let local_addr = std::env::var("LOCAL_ADDR").unwrap_or_else(|_| "127.0.0.1:5070".to_string());
    let server_addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:5060".to_string());

    info!("Starting SIP test client");
    info!("Local address: {}", local_addr);
    info!("Server address: {}", server_addr);

    let mut client = SipTestClient::new(&local_addr, &server_addr).await?;

    // Test sequence
    info!("\n=== Testing OPTIONS ===");
    client.send_options().await?;
    sleep(Duration::from_secs(1)).await;

    info!("\n=== Testing REGISTER ===");
    client.send_register("alice", 3600).await?;
    sleep(Duration::from_secs(1)).await;

    client.send_register("bob", 3600).await?;
    sleep(Duration::from_secs(1)).await;

    info!("\n=== Testing INVITE ===");
    client.send_invite("alice", "bob").await?;
    sleep(Duration::from_secs(1)).await;

    info!("\n=== Testing Security (SQL Injection attempt) ===");
    client.send_register("user'; DROP TABLE users; --", 3600).await?;
    sleep(Duration::from_secs(1)).await;

    info!("\n=== Testing Rate Limiting ===");
    for i in 0..10 {
        info!("Sending request {} of 10", i + 1);
        client.send_options().await?;
        sleep(Duration::from_millis(100)).await;
    }

    info!("\nTest client completed");
    Ok(())
}