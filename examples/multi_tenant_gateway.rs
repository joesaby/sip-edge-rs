// examples/multi_tenant_gateway.rs - Multi-tenant local gateway registering against Cisco
//
// Registers every tenant listed in a JSON config file (see config/tenants.example.json)
// against its Cisco registrar (CUCM/CUBE), keeping each registration refreshed and
// re-authenticating on 401/407 challenges. Meanwhile the shared listener (the same
// transport used elsewhere in this crate) accepts local REGISTERs, answers Cisco's OPTIONS
// keepalives, and logs the SDP codecs offered on any inbound INVITE.
//
// Usage:
//   TENANTS_CONFIG=config/tenants.example.json cargo run --example multi_tenant_gateway

use anyhow::Result;
use sip_edge_rs::{
    gateway::MultiTenantGateway,
    registration::{load_tenants_from_json, RegistrationState},
    sdp,
    security::SecurityConfig,
    transport::{SipTransport, TransportConfig, TransportEvent},
    utils, SipMessage, SipMethod,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

async fn handle_inbound_event(transport: &Arc<SipTransport>, event: TransportEvent) -> Result<()> {
    let TransportEvent::MessageReceived {
        message,
        source,
        transport: proto,
    } = event
    else {
        return Ok(());
    };

    let SipMessage::Request(request) = &message else {
        return Ok(());
    };

    match &request.method {
        SipMethod::Options => {
            let response = utils::build_response_from_request(request, 200, "OK");
            transport
                .send_message(SipMessage::Response(response), source, proto)
                .await?;
        }
        SipMethod::Register => {
            info!("Local REGISTER from {} ({:?})", source, proto);
            let response = utils::build_response_from_request(request, 200, "OK");
            transport
                .send_message(SipMessage::Response(response), source, proto)
                .await?;
        }
        SipMethod::Invite => {
            if let Some(body) = &request.body {
                match sdp::summarize_sdp(body) {
                    Ok(summary) => info!(
                        "INVITE from {} offers {} media stream(s), codecs: {:?}, connection: {:?}",
                        source, summary.media_count, summary.codecs, summary.connection_addr
                    ),
                    Err(e) => warn!("Failed to parse SDP in INVITE from {}: {}", source, e),
                }
            }

            // Call routing to an internal PBX/tenant endpoint is not implemented in this
            // example gateway; only registration and SDP inspection are demonstrated here.
            let response = utils::build_response_from_request(request, 501, "Not Implemented");
            transport
                .send_message(SipMessage::Response(response), source, proto)
                .await?;
        }
        _ => {
            let response = utils::build_response_from_request(request, 501, "Not Implemented");
            transport
                .send_message(SipMessage::Response(response), source, proto)
                .await?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sip_edge_rs=info,multi_tenant_gateway=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config_path = std::env::var("TENANTS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("config/tenants.example.json"));

    info!("Loading tenant configuration from {}", config_path.display());
    let tenants = load_tenants_from_json(&config_path).await?;

    let mut transport_config = TransportConfig::default();
    transport_config.security_config = SecurityConfig {
        max_registrations_per_ip: 1000,
        ..Default::default()
    };

    if let Ok(udp_addr) = std::env::var("SIP_UDP_ADDR") {
        transport_config.udp_listen_addr = udp_addr.parse()?;
    }
    if let Ok(tcp_addr) = std::env::var("SIP_TCP_ADDR") {
        transport_config.tcp_listen_addr = tcp_addr.parse()?;
    }

    let (transport, mut event_rx) = SipTransport::new(transport_config);
    let transport = Arc::new(transport);

    let transport_handle = {
        let transport = transport.clone();
        tokio::spawn(async move {
            if let Err(e) = transport.start().await {
                warn!("Transport error: {}", e);
            }
        })
    };

    let gateway = Arc::new(MultiTenantGateway::new());
    for tenant in tenants {
        info!(
            "Registering tenant '{}' ({}) against {}",
            tenant.tenant_id, tenant.domain, tenant.registrar_addr
        );
        gateway.add_tenant(tenant).await?;
    }

    let event_handle = {
        let transport = transport.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if let Err(e) = handle_inbound_event(&transport, event).await {
                    warn!("Error handling inbound event: {}", e);
                }
            }
        })
    };

    let status_gateway = gateway.clone();
    let status_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            for tenant_id in status_gateway.tenant_ids().await {
                if let Some(state) = status_gateway.state_of(&tenant_id).await {
                    match &state {
                        RegistrationState::Registered { .. } | RegistrationState::Unregistered => {
                            info!("Tenant '{}': {}", tenant_id, state)
                        }
                        _ => warn!("Tenant '{}': {}", tenant_id, state),
                    }
                }
            }
        }
    });

    info!("Multi-tenant gateway running. Press Ctrl+C to shut down.");
    tokio::signal::ctrl_c().await?;

    info!("Shutting down, de-registering all tenants...");
    gateway.shutdown().await;

    transport_handle.abort();
    event_handle.abort();
    status_handle.abort();

    Ok(())
}
