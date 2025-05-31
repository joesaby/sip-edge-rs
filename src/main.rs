// main.rs - High-performance SIP router example

use anyhow::Result;
use sip_parser::{
    transport::{SipTransport, TransportConfig, TransportEvent, TransportProtocol},
    security::SecurityConfig,
    utils::{self, HeaderBuilder},
    SipMessage, SipMethod,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// SIP routing table entry
#[derive(Debug, Clone)]
struct RouteEntry {
    destination: SocketAddr,
    transport: TransportProtocol,
    priority: u8,
}

/// Simple SIP router
struct SipRouter {
    transport: Arc<SipTransport>,
    routes: Arc<RwLock<HashMap<String, Vec<RouteEntry>>>>,
    registrations: Arc<RwLock<HashMap<String, SocketAddr>>>,
}

impl SipRouter {
    fn new(transport: Arc<SipTransport>) -> Self {
        Self {
            transport,
            routes: Arc::new(RwLock::new(HashMap::new())),
            registrations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn handle_event(&self, event: TransportEvent) -> Result<()> {
        match event {
            TransportEvent::MessageReceived { message, source, transport } => {
                info!("Received message from {} via {:?}", source, transport);
                self.route_message(message, source, transport).await?;
            }
            TransportEvent::ConnectionEstablished { peer, transport } => {
                info!("Connection established with {} via {:?}", peer, transport);
            }
            TransportEvent::ConnectionClosed { peer, transport } => {
                info!("Connection closed with {} via {:?}", peer, transport);
            }
            TransportEvent::Error { error, peer } => {
                error!("Transport error from {:?}: {}", peer, error);
            }
        }
        Ok(())
    }

    async fn route_message(
        &self,
        message: SipMessage,
        source: SocketAddr,
        source_transport: TransportProtocol,
    ) -> Result<()> {
        match &message {
            SipMessage::Request(request) => {
                match &request.method {
                    SipMethod::Register => {
                        self.handle_register(message, source, source_transport).await?;
                    }
                    SipMethod::Invite => {
                        self.handle_invite(message, source, source_transport).await?;
                    }
                    SipMethod::Options => {
                        self.handle_options(message, source, source_transport).await?;
                    }
                    _ => {
                        self.forward_request(message, source, source_transport).await?;
                    }
                }
            }
            SipMessage::Response(_) => {
                self.forward_response(message, source, source_transport).await?;
            }
        }
        Ok(())
    }

    async fn handle_register(
        &self,
        message: SipMessage,
        source: SocketAddr,
        source_transport: TransportProtocol,
    ) -> Result<()> {
        if let SipMessage::Request(request) = &message {
            // Extract AOR (Address of Record) from To header
            if let Some(to) = utils::get_header(&message, "to") {
                if let Some(uri) = utils::parse_uri_from_header(to) {
                    // Store registration
                    let mut registrations = self.registrations.write().await;
                    registrations.insert(uri.to_string(), source);
                    info!("Registered {} at {}", uri, source);
                    
                    // Send 200 OK response
                    let response = utils::build_response_from_request(request, 200, "OK");
                    self.transport.send_message(
                        SipMessage::Response(response),
                        source,
                        source_transport,
                    ).await?;
                    
                    return Ok(());
                }
            }
        }
        
        // Send error response
        if let SipMessage::Request(request) = &message {
            let response = utils::build_response_from_request(request, 400, "Bad Request");
            self.transport.send_message(
                SipMessage::Response(response),
                source,
                source_transport,
            ).await?;
        }
        
        Ok(())
    }

    async fn handle_invite(
        &self,
        mut message: SipMessage,
        source: SocketAddr,
        source_transport: TransportProtocol,
    ) -> Result<()> {
        // Send 100 Trying immediately
        if let SipMessage::Request(request) = &message {
            let trying = utils::build_response_from_request(request, 100, "Trying");
            self.transport.send_message(
                SipMessage::Response(trying),
                source,
                source_transport,
            ).await?;
        }
        
        // Look up destination
        if let Some(to) = utils::get_header(&message, "to") {
            if let Some(uri) = utils::parse_uri_from_header(to) {
                let registrations = self.registrations.read().await;
                if let Some(&destination) = registrations.get(uri) {
                    // Add Via header for routing responses back
                    let branch = utils::generate_branch();
                    let via = utils::format_via_address(&source, "UDP", &branch);
                    utils::add_header(&mut message, "via", via);
                    
                    // Forward the INVITE
                    info!("Forwarding INVITE to {} at {}", uri, destination);
                    self.transport.send_message(
                        message,
                        destination,
                        TransportProtocol::Udp,
                    ).await?;
                    
                    return Ok(());
                }
            }
        }
        
        // User not found
        if let SipMessage::Request(request) = &message {
            let response = utils::build_response_from_request(request, 404, "Not Found");
            self.transport.send_message(
                SipMessage::Response(response),
                source,
                source_transport,
            ).await?;
        }
        
        Ok(())
    }

    async fn handle_options(
        &self,
        message: SipMessage,
        source: SocketAddr,
        source_transport: TransportProtocol,
    ) -> Result<()> {
        if let SipMessage::Request(request) = &message {
            // Build response with supported methods
            let mut response = utils::build_response_from_request(request, 200, "OK");
            utils::add_header(
                &mut SipMessage::Response(response.clone()),
                "allow",
                "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, MESSAGE".to_string(),
            );
            utils::add_header(
                &mut SipMessage::Response(response.clone()),
                "accept",
                "application/sdp".to_string(),
            );
            
            self.transport.send_message(
                SipMessage::Response(response),
                source,
                source_transport,
            ).await?;
        }
        
        Ok(())
    }

    async fn forward_request(
        &self,
        mut message: SipMessage,
        source: SocketAddr,
        source_transport: TransportProtocol,
    ) -> Result<()> {
        // Decrement Max-Forwards
        if let Some(max_fwd) = utils::get_header(&message, "max-forwards") {
            if let Ok(value) = max_fwd.parse::<u32>() {
                if value == 0 {
                    // Too many hops
                    if let SipMessage::Request(request) = &message {
                        let response = utils::build_response_from_request(
                            request,
                            483,
                            "Too Many Hops"
                        );
                        self.transport.send_message(
                            SipMessage::Response(response),
                            source,
                            source_transport,
                        ).await?;
                        return Ok(());
                    }
                }
                utils::set_header(&mut message, "max-forwards", (value - 1).to_string());
            }
        }
        
        // Add Via header
        let branch = utils::generate_branch();
        let via = utils::format_via_address(&source, "UDP", &branch);
        utils::add_header(&mut message, "via", via);
        
        // Route based on Request-URI
        if let SipMessage::Request(request) = &message {
            let uri_str = request.uri.to_string();
            let routes = self.routes.read().await;
            
            // Find best route
            if let Some(route_entries) = routes.get(&uri_str) {
                if let Some(route) = route_entries.iter().min_by_key(|r| r.priority) {
                    self.transport.send_message(
                        message,
                        route.destination,
                        route.transport,
                    ).await?;
                    return Ok(());
                }
            }
        }
        
        // No route found
        if let SipMessage::Request(request) = &message {
            let response = utils::build_response_from_request(request, 404, "Not Found");
            self.transport.send_message(
                SipMessage::Response(response),
                source,
                source_transport,
            ).await?;
        }
        
        Ok(())
    }

    async fn forward_response(
        &self,
        mut message: SipMessage,
        _source: SocketAddr,
        _source_transport: TransportProtocol,
    ) -> Result<()> {
        // Remove top Via header and use it to route response
        if let Some(via_values) = message.headers_mut().get_mut("via") {
            if !via_values.is_empty() {
                let top_via = via_values.remove(0);
                
                // Parse Via header to extract destination
                // In a real implementation, you'd maintain transaction state
                // For now, we'll just log
                debug!("Routing response based on Via: {}", top_via);
                
                // Here you would look up the transaction and route accordingly
            }
        }
        
        Ok(())
    }

    async fn add_static_route(&self, uri: String, destination: SocketAddr, transport: TransportProtocol) {
        let mut routes = self.routes.write().await;
        let entry = RouteEntry {
            destination,
            transport,
            priority: 10,
        };
        routes.entry(uri).or_insert_with(Vec::new).push(entry);
        info!("Added route: {} -> {} via {:?}", uri, destination, transport);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sip_parser=debug,sip_router=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting SIP Router");

    // Configure transport
    let mut transport_config = TransportConfig::default();
    
    // Configure security
    transport_config.security_config = SecurityConfig {
        detect_sql_injection: true,
        detect_script_injection: true,
        detect_command_injection: true,
        strict_uri_validation: true,
        max_registrations_per_ip: 100,
        rate_limit_window: std::time::Duration::from_secs(60),
        max_requests_per_window: 1000,
        ..Default::default()
    };

    // Override addresses from environment if available
    if let Ok(tcp_addr) = std::env::var("SIP_TCP_ADDR") {
        transport_config.tcp_listen_addr = tcp_addr.parse()?;
    }
    if let Ok(udp_addr) = std::env::var("SIP_UDP_ADDR") {
        transport_config.udp_listen_addr = udp_addr.parse()?;
    }
    if let Ok(tls_addr) = std::env::var("SIP_TLS_ADDR") {
        transport_config.tls_listen_addr = Some(tls_addr.parse()?);
    }
    
    // TLS configuration
    if let Ok(cert_path) = std::env::var("SIP_TLS_CERT") {
        transport_config.tls_cert_path = Some(cert_path);
    }
    if let Ok(key_path) = std::env::var("SIP_TLS_KEY") {
        transport_config.tls_key_path = Some(key_path);
    }

    // Create transport and router
    let (transport, mut event_rx) = SipTransport::new(transport_config);
    let transport = Arc::new(transport);
    let router = Arc::new(SipRouter::new(transport.clone()));

    // Add some example static routes
    router.add_static_route(
        "sip:test@example.com".to_string(),
        "127.0.0.1:5062".parse()?,
        TransportProtocol::Udp,
    ).await;

    // Start transport listeners
    let transport_handle = {
        let transport = transport.clone();
        tokio::spawn(async move {
            if let Err(e) = transport.start().await {
                error!("Transport error: {}", e);
            }
        })
    };

    // Process events
    let router_handle = {
        let router = router.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let Err(e) = router.handle_event(event).await {
                    error!("Error handling event: {}", e);
                }
            }
        })
    };

    info!("SIP Router started successfully");
    info!("TCP: {}", transport_config.tcp_listen_addr);
    info!("UDP: {}", transport_config.udp_listen_addr);
    if let Some(tls_addr) = transport_config.tls_listen_addr {
        info!("TLS: {}", tls_addr);
    }

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    // In a real implementation, you'd properly shut down the transport and router
    transport_handle.abort();
    router_handle.abort();

    Ok(())
}