//! SIP Transport Layer
//!
//! Provides UDP, TCP, and TLS transport support for SIP messages with security validation.

use crate::{
    codec::SipCodec,
    security::{SecurityConfig, SecurityValidator},
    SipMessage,
};
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::{
    rustls::{self, Certificate, PrivateKey, ServerConfig, ServerName},
    TlsAcceptor, TlsStream,
};
use tokio_util::codec::{Encoder, Framed};
use tracing::{debug, error, info, warn};

/// Transport layer configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// TCP listen address
    pub tcp_listen_addr: SocketAddr,

    /// UDP listen address
    pub udp_listen_addr: SocketAddr,

    /// TLS listen address (optional)
    pub tls_listen_addr: Option<SocketAddr>,

    /// TLS certificate path
    pub tls_cert_path: Option<String>,

    /// TLS key path
    pub tls_key_path: Option<String>,

    /// Enable TCP keep-alive
    pub tcp_keepalive: bool,

    /// TCP no-delay (disable Nagle's algorithm)
    pub tcp_nodelay: bool,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Connection timeout
    pub connection_timeout: std::time::Duration,

    /// Security configuration
    pub security_config: SecurityConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tcp_listen_addr: "0.0.0.0:5060".parse().unwrap(),
            udp_listen_addr: "0.0.0.0:5060".parse().unwrap(),
            tls_listen_addr: Some("0.0.0.0:5061".parse().unwrap()),
            tls_cert_path: None,
            tls_key_path: None,
            tcp_keepalive: true,
            tcp_nodelay: true,
            max_connections: 10000,
            connection_timeout: std::time::Duration::from_secs(30),
            security_config: SecurityConfig::default(),
        }
    }
}

/// SIP transport event
#[derive(Debug)]
pub enum TransportEvent {
    /// Received a SIP message
    MessageReceived {
        message: SipMessage,
        source: SocketAddr,
        transport: TransportProtocol,
    },

    /// Connection established
    ConnectionEstablished {
        peer: SocketAddr,
        transport: TransportProtocol,
    },

    /// Connection closed
    ConnectionClosed {
        peer: SocketAddr,
        transport: TransportProtocol,
    },

    /// Transport error
    Error {
        error: String,
        peer: Option<SocketAddr>,
    },
}

/// Transport protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
    Tls,
}

/// SIP transport layer
pub struct SipTransport {
    config: TransportConfig,
    event_tx: mpsc::UnboundedSender<TransportEvent>,
    security_validator: Arc<SecurityValidator>,
}

impl SipTransport {
    pub fn new(config: TransportConfig) -> (Self, mpsc::UnboundedReceiver<TransportEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let security_validator = Arc::new(SecurityValidator::new(config.security_config.clone()));

        let transport = Self {
            config,
            event_tx,
            security_validator,
        };

        (transport, event_rx)
    }

    /// Start all transport listeners
    pub async fn start(&self) -> Result<()> {
        let mut handles = vec![];

        // Start UDP listener
        let udp_handle = self.start_udp_listener();
        handles.push(udp_handle);

        // Start TCP listener
        let tcp_handle = self.start_tcp_listener();
        handles.push(tcp_handle);

        // Start TLS listener if configured
        if let Some(tls_addr) = self.config.tls_listen_addr {
            if self.config.tls_cert_path.is_some() && self.config.tls_key_path.is_some() {
                let tls_handle = self.start_tls_listener(tls_addr);
                handles.push(tls_handle);
            } else {
                warn!("TLS address configured but certificate/key paths not provided");
            }
        }

        // Wait for all listeners
        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    /// Start UDP listener
    fn start_udp_listener(&self) -> tokio::task::JoinHandle<()> {
        let addr = self.config.udp_listen_addr;
        let event_tx = self.event_tx.clone();
        let security_validator = self.security_validator.clone();

        tokio::spawn(async move {
            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    info!("UDP listener started on {}", addr);
                    let mut buf = vec![0u8; 65535];

                    loop {
                        match socket.recv_from(&mut buf).await {
                            Ok((len, peer_addr)) => {
                                let data = &buf[..len];

                                // Parse and validate message
                                match crate::parse_sip_message(data) {
                                    Ok(message) => {
                                        // Security validation
                                        if let Err(e) = security_validator
                                            .validate_message(&message, &peer_addr.to_string())
                                        {
                                            warn!(
                                                "Security validation failed from {}: {}",
                                                peer_addr, e
                                            );
                                            let _ = event_tx.send(TransportEvent::Error {
                                                error: format!("Security validation failed: {}", e),
                                                peer: Some(peer_addr),
                                            });
                                            continue;
                                        }

                                        debug!("Received UDP message from {}", peer_addr);
                                        let _ = event_tx.send(TransportEvent::MessageReceived {
                                            message,
                                            source: peer_addr,
                                            transport: TransportProtocol::Udp,
                                        });
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to parse UDP message from {}: {}",
                                            peer_addr, e
                                        );
                                        let _ = event_tx.send(TransportEvent::Error {
                                            error: format!("Parse error: {}", e),
                                            peer: Some(peer_addr),
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                error!("UDP receive error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind UDP socket on {}: {}", addr, e);
                }
            }
        })
    }

    /// Start TCP listener
    fn start_tcp_listener(&self) -> tokio::task::JoinHandle<()> {
        let addr = self.config.tcp_listen_addr;
        let event_tx = self.event_tx.clone();
        let security_validator = self.security_validator.clone();
        let tcp_keepalive = self.config.tcp_keepalive;
        let tcp_nodelay = self.config.tcp_nodelay;

        tokio::spawn(async move {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!("TCP listener started on {}", addr);

                    loop {
                        match listener.accept().await {
                            Ok((stream, peer_addr)) => {
                                // Configure socket options
                                if tcp_nodelay {
                                    let _ = stream.set_nodelay(true);
                                }

                                debug!("TCP connection from {}", peer_addr);
                                let _ = event_tx.send(TransportEvent::ConnectionEstablished {
                                    peer: peer_addr,
                                    transport: TransportProtocol::Tcp,
                                });

                                let event_tx_clone = event_tx.clone();
                                let security_validator_clone = security_validator.clone();

                                tokio::spawn(async move {
                                    Self::handle_tcp_connection(
                                        stream,
                                        peer_addr,
                                        event_tx_clone,
                                        security_validator_clone,
                                        TransportProtocol::Tcp,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                error!("TCP accept error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind TCP listener to {}: {}", addr, e);
                }
            }
        })
    }

    /// Start TLS listener
    fn start_tls_listener(&self, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
        let event_tx = self.event_tx.clone();
        let security_validator = self.security_validator.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            // Load TLS configuration
            let tls_config = match Self::load_tls_config(&config).await {
                Ok(config) => Arc::new(config),
                Err(e) => {
                    error!("Failed to load TLS configuration: {}", e);
                    return;
                }
            };

            let acceptor = TlsAcceptor::from(tls_config);

            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!("TLS listener started on {}", addr);

                    loop {
                        match listener.accept().await {
                            Ok((stream, peer_addr)) => {
                                // Configure socket options
                                if config.tcp_nodelay {
                                    let _ = stream.set_nodelay(true);
                                }

                                debug!("TLS connection from {}", peer_addr);
                                let _ = event_tx.send(TransportEvent::ConnectionEstablished {
                                    peer: peer_addr,
                                    transport: TransportProtocol::Tls,
                                });

                                let acceptor = acceptor.clone();
                                let event_tx_clone = event_tx.clone();
                                let security_validator_clone = security_validator.clone();

                                tokio::spawn(async move {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            Self::handle_tls_connection(
                                                tokio_rustls::TlsStream::Server(tls_stream),
                                                peer_addr,
                                                event_tx_clone,
                                                security_validator_clone,
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            warn!("TLS handshake error with {}: {}", peer_addr, e);
                                            let _ = event_tx_clone.send(TransportEvent::Error {
                                                error: format!("TLS handshake error: {}", e),
                                                peer: Some(peer_addr),
                                            });
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!("TLS accept error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind TLS listener to {}: {}", addr, e);
                }
            }
        })
    }

    /// Handle TCP connection
    async fn handle_tcp_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        event_tx: mpsc::UnboundedSender<TransportEvent>,
        security_validator: Arc<SecurityValidator>,
        protocol: TransportProtocol,
    ) {
        let _ = event_tx.send(TransportEvent::ConnectionEstablished {
            peer: peer_addr,
            transport: protocol,
        });

        let framed = Framed::new(stream, SipCodec::new());
        let (sink, mut stream) = framed.split();

        // Message receiver task
        let event_tx_clone = event_tx.clone();
        let recv_task = async move {
            while let Some(result) = tokio_stream::StreamExt::next(&mut stream).await {
                match result {
                    Ok(message) => {
                        // Security validation
                        if let Err(e) =
                            security_validator.validate_message(&message, &peer_addr.to_string())
                        {
                            warn!("Security validation failed from {}: {}", peer_addr, e);
                            let _ = event_tx_clone.send(TransportEvent::Error {
                                error: format!("Security validation failed: {}", e),
                                peer: Some(peer_addr),
                            });
                            continue;
                        }

                        debug!(
                            "Received {} message from {}",
                            match protocol {
                                TransportProtocol::Tcp => "TCP",
                                TransportProtocol::Tls => "TLS",
                                _ => "Unknown",
                            },
                            peer_addr
                        );

                        let _ = event_tx_clone.send(TransportEvent::MessageReceived {
                            message,
                            source: peer_addr,
                            transport: protocol,
                        });
                    }
                    Err(e) => {
                        warn!("Connection error with {}: {}", peer_addr, e);
                        break;
                    }
                }
            }
        };

        recv_task.await;

        let _ = event_tx.send(TransportEvent::ConnectionClosed {
            peer: peer_addr,
            transport: protocol,
        });
    }

    /// Handle TLS connection
    async fn handle_tls_connection(
        stream: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        event_tx: mpsc::UnboundedSender<TransportEvent>,
        security_validator: Arc<SecurityValidator>,
    ) {
        Self::handle_stream_connection(
            stream,
            peer_addr,
            event_tx,
            security_validator,
            TransportProtocol::Tls,
        )
        .await;
    }

    /// Generic stream handler
    async fn handle_stream_connection<S>(
        stream: S,
        peer_addr: SocketAddr,
        event_tx: mpsc::UnboundedSender<TransportEvent>,
        security_validator: Arc<SecurityValidator>,
        protocol: TransportProtocol,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let _ = event_tx.send(TransportEvent::ConnectionEstablished {
            peer: peer_addr,
            transport: protocol,
        });

        let framed = Framed::new(stream, SipCodec::new());
        let (sink, mut stream) = framed.split();

        while let Some(result) = tokio_stream::StreamExt::next(&mut stream).await {
            match result {
                Ok(message) => {
                    // Security validation
                    if let Err(e) =
                        security_validator.validate_message(&message, &peer_addr.to_string())
                    {
                        warn!("Security validation failed from {}: {}", peer_addr, e);
                        let _ = event_tx.send(TransportEvent::Error {
                            error: format!("Security validation failed: {}", e),
                            peer: Some(peer_addr),
                        });
                        continue;
                    }

                    let _ = event_tx.send(TransportEvent::MessageReceived {
                        message,
                        source: peer_addr,
                        transport: protocol,
                    });
                }
                Err(e) => {
                    warn!("Stream error with {}: {}", peer_addr, e);
                    break;
                }
            }
        }

        let _ = event_tx.send(TransportEvent::ConnectionClosed {
            peer: peer_addr,
            transport: protocol,
        });
    }

    /// Load TLS configuration
    async fn load_tls_config(config: &TransportConfig) -> Result<ServerConfig> {
        let cert_path = config
            .tls_cert_path
            .as_ref()
            .context("TLS certificate path not configured")?;
        let key_path = config
            .tls_key_path
            .as_ref()
            .context("TLS key path not configured")?;

        // Load certificate
        let cert_file = tokio::fs::read(cert_path)
            .await
            .context("Failed to read certificate file")?;
        let cert_chain = rustls_pemfile::certs(&mut cert_file.as_slice())
            .map_err(|_| anyhow!("Failed to parse certificate"))?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();

        // Load private key
        let key_file = tokio::fs::read(key_path)
            .await
            .context("Failed to read key file")?;
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_file.as_slice())
            .map_err(|_| anyhow!("Failed to parse private key"))?
            .into_iter()
            .map(PrivateKey)
            .collect::<Vec<_>>();

        if keys.is_empty() {
            return Err(anyhow!("No private key found"));
        }

        let key = keys.remove(0);

        // Create TLS configuration
        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("Failed to create TLS configuration")?;

        Ok(tls_config)
    }

    /// Send a SIP message
    pub async fn send_message(
        &self,
        message: SipMessage,
        destination: SocketAddr,
        transport: TransportProtocol,
    ) -> Result<()> {
        match transport {
            TransportProtocol::Udp => self.send_udp_message(message, destination).await,
            TransportProtocol::Tcp => self.send_tcp_message(message, destination).await,
            TransportProtocol::Tls => self.send_tls_message(message, destination).await,
        }
    }

    async fn send_udp_message(&self, message: SipMessage, destination: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let mut buf = BytesMut::new();
        let mut codec = SipCodec::new();
        codec.encode(message, &mut buf)?;

        socket.send_to(&buf, destination).await?;
        debug!("Sent UDP message to {}", destination);

        Ok(())
    }

    async fn send_tcp_message(&self, message: SipMessage, destination: SocketAddr) -> Result<()> {
        let stream = TcpStream::connect(destination).await?;

        if self.config.tcp_nodelay {
            stream.set_nodelay(true)?;
        }

        let mut framed = Framed::new(stream, SipCodec::new());
        framed.send(message).await?;

        debug!("Sent TCP message to {}", destination);

        Ok(())
    }

    async fn send_tls_message(&self, message: SipMessage, destination: SocketAddr) -> Result<()> {
        // For client TLS, we need a client configuration
        // This is a simplified version - in production, you'd want proper certificate validation
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect(destination).await?;

        if self.config.tcp_nodelay {
            stream.set_nodelay(true)?;
        }

        let domain =
            ServerName::try_from("sip.example.com").map_err(|_| anyhow!("Invalid domain name"))?;

        let tls_stream = connector.connect(domain, stream).await?;
        let mut framed = Framed::new(tls_stream, SipCodec::new());

        framed.send(message).await?;

        debug!("Sent TLS message to {}", destination);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SipMethod, SipRequest, SipUri};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_transport_creation() {
        let config = TransportConfig::default();
        let (_transport, mut event_rx) = SipTransport::new(config);

        // Should be able to create transport
        assert!(event_rx.try_recv().is_err()); // No events yet
    }

    #[tokio::test]
    async fn test_udp_message_send() {
        let config = TransportConfig {
            udp_listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };

        let (transport, _event_rx) = SipTransport::new(config);

        // Create a test message
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), vec!["SIP/2.0/UDP test.com".to_string()]);
        headers.insert("from".to_string(), vec!["<sip:test@test.com>".to_string()]);
        headers.insert("to".to_string(), vec!["<sip:dest@test.com>".to_string()]);
        headers.insert("call-id".to_string(), vec!["test123".to_string()]);
        headers.insert("cseq".to_string(), vec!["1 OPTIONS".to_string()]);

        let request = SipRequest {
            method: SipMethod::Options,
            uri: SipUri::new("sip", "dest@test.com"),
            version: "SIP/2.0".to_string(),
            headers,
            body: None,
        };

        let message = SipMessage::Request(request);

        // This will fail to connect but should not panic
        let result = transport
            .send_message(
                message,
                "127.0.0.1:5060".parse().unwrap(),
                TransportProtocol::Udp,
            )
            .await;

        // We expect this to succeed (UDP doesn't require connection)
        assert!(result.is_ok());
    }
}
