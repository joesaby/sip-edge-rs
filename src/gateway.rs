// gateway.rs - Multi-tenant SIP registration gateway
//
// Registers multiple tenants against a Cisco registrar (CUCM/CUBE) as a SIP UAC, handling
// Digest challenges, periodic refresh before expiry, and graceful de-registration. Each
// tenant owns a dedicated transport connection used only for its REGISTER transactions;
// inbound call signaling is expected to arrive on the shared listener configured via
// `transport::SipTransport` using the same `advertised_host`/`advertised_port` as the
// tenant's Contact.

use crate::codec::SipCodec;
use crate::digest_auth::{build_authorization_header, DigestChallenge};
use crate::registration::{RegistrationState, TenantConfig, TenantRegistration};
use crate::transport::TransportProtocol;
use crate::{utils, SipMessage, SipMethod, SipResponse};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{watch, RwLock};
use tokio_util::codec::{Encoder, Framed};
use tracing::{debug, info, warn};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// A dedicated connection to a tenant's registrar, used only for REGISTER transactions
enum RegistrarConn {
    Udp(UdpSocket),
    Tcp(Framed<TcpStream, SipCodec>),
}

impl RegistrarConn {
    async fn connect(config: &TenantConfig) -> Result<Self> {
        match config.transport {
            TransportProtocol::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.connect(config.registrar_addr).await?;
                Ok(RegistrarConn::Udp(socket))
            }
            TransportProtocol::Tcp => {
                let stream = TcpStream::connect(config.registrar_addr).await?;
                stream.set_nodelay(true).ok();
                Ok(RegistrarConn::Tcp(Framed::new(stream, SipCodec::new())))
            }
            TransportProtocol::Tls => Err(anyhow!(
                "TLS registrar connections are not yet supported by the registration gateway"
            )),
        }
    }

    async fn send(&mut self, message: SipMessage) -> Result<()> {
        match self {
            RegistrarConn::Udp(socket) => {
                let mut buf = BytesMut::new();
                SipCodec::new().encode(message, &mut buf)?;
                socket.send(&buf).await?;
                Ok(())
            }
            RegistrarConn::Tcp(framed) => {
                framed.send(message).await?;
                Ok(())
            }
        }
    }

    async fn recv(&mut self, timeout: Duration) -> Result<SipMessage> {
        match self {
            RegistrarConn::Udp(socket) => {
                let mut buf = vec![0u8; 65535];
                let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
                    .await
                    .map_err(|_| anyhow!("timed out waiting for response"))??;
                crate::parse_sip_message(&buf[..len]).map_err(|e| anyhow!("parse error: {}", e))
            }
            RegistrarConn::Tcp(framed) => {
                let item = tokio::time::timeout(timeout, framed.next())
                    .await
                    .map_err(|_| anyhow!("timed out waiting for response"))?
                    .ok_or_else(|| anyhow!("connection closed by registrar"))?;
                Ok(item?)
            }
        }
    }
}

/// Waits for the REGISTER response matching `call_id`, transparently answering any
/// unsolicited OPTIONS keepalive probes the registrar sends on the same flow meanwhile.
async fn wait_for_register_response(
    conn: &mut RegistrarConn,
    call_id: &str,
    overall_timeout: Duration,
) -> Result<SipResponse> {
    let deadline = Instant::now() + overall_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("timed out waiting for REGISTER response"));
        }

        match conn.recv(remaining).await? {
            SipMessage::Response(resp) => {
                let matches = resp
                    .headers
                    .get("call-id")
                    .and_then(|v| v.first())
                    .map(|v| v.as_str())
                    == Some(call_id);

                if matches {
                    return Ok(resp);
                }
                debug!("Ignoring response with mismatched Call-ID on registration flow");
            }
            SipMessage::Request(req) => {
                if req.method == SipMethod::Options {
                    let response = utils::build_response_from_request(&req, 200, "OK");
                    let _ = conn.send(SipMessage::Response(response)).await;
                } else {
                    debug!("Ignoring unsolicited {} request on registration flow", req.method);
                }
            }
        }
    }
}

fn extract_granted_expires(response: &SipResponse, requested: u32) -> u32 {
    if let Some(value) = response.headers.get("expires").and_then(|v| v.first()) {
        if let Ok(secs) = value.parse::<u32>() {
            return secs;
        }
    }

    if let Some(contacts) = response.headers.get("contact") {
        for contact in contacts {
            if let Some(pos) = contact.find("expires=") {
                let rest = &contact[pos + "expires=".len()..];
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(secs) = digits.parse::<u32>() {
                    return secs;
                }
            }
        }
    }

    requested
}

fn generate_cnonce() -> String {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    thread_rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect()
}

/// Send a REGISTER (or de-REGISTER when `expires == 0`), transparently handling a single
/// 401/407 Digest challenge round trip. Returns the registrar-granted expiry in seconds.
async fn perform_registration(
    reg: &mut TenantRegistration,
    conn: &mut RegistrarConn,
    expires: u32,
) -> Result<u32> {
    let cseq = reg.next_cseq();
    let request = reg.build_register(cseq, expires, None);
    conn.send(SipMessage::Request(request)).await?;

    let response = wait_for_register_response(conn, reg.call_id(), RESPONSE_TIMEOUT).await?;

    match response.status_code {
        200 => Ok(extract_granted_expires(&response, expires)),
        401 | 407 => {
            let header_name = if response.status_code == 401 {
                "www-authenticate"
            } else {
                "proxy-authenticate"
            };

            let challenge_value = response
                .headers
                .get(header_name)
                .and_then(|v| v.first())
                .ok_or_else(|| anyhow!("{} response missing {} header", response.status_code, header_name))?;

            let challenge = DigestChallenge::parse(challenge_value)
                .ok_or_else(|| anyhow!("failed to parse digest challenge"))?;

            let cnonce = generate_cnonce();
            let request_uri = format!("sip:{}", reg.config.domain);
            let auth_header = build_authorization_header(
                &reg.config.auth_user,
                &challenge,
                &reg.config.auth_password,
                "REGISTER",
                request_uri.as_str(),
                Some(cnonce.as_str()),
                Some(1),
            );

            let cseq2 = reg.next_cseq();
            let request2 = reg.build_register(cseq2, expires, Some(auth_header));
            conn.send(SipMessage::Request(request2)).await?;

            let response2 = wait_for_register_response(conn, reg.call_id(), RESPONSE_TIMEOUT).await?;
            if response2.status_code == 200 {
                Ok(extract_granted_expires(&response2, expires))
            } else {
                Err(anyhow!(
                    "registration rejected after authentication: {} {}",
                    response2.status_code,
                    response2.reason_phrase
                ))
            }
        }
        other => Err(anyhow!("registration failed: {} {}", other, response.reason_phrase)),
    }
}

async fn deregister(reg: &mut TenantRegistration) {
    let tenant_id = reg.config.tenant_id.clone();

    match RegistrarConn::connect(&reg.config).await {
        Ok(mut conn) => match perform_registration(reg, &mut conn, 0).await {
            Ok(_) => info!("Tenant '{}' de-registered", tenant_id),
            Err(e) => warn!("De-registration for '{}' did not complete cleanly: {}", tenant_id, e),
        },
        Err(e) => warn!("Failed to connect for de-registration of '{}': {}", tenant_id, e),
    }
}

async fn tenant_task(
    tenant_id: String,
    config: TenantConfig,
    state: Arc<RwLock<RegistrationState>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut reg = TenantRegistration::new(config);

    loop {
        if *shutdown.borrow() {
            break;
        }

        *state.write().await = RegistrationState::Registering;
        let expires = reg.config.expires;

        let attempt: Result<u32> = async {
            let mut conn = RegistrarConn::connect(&reg.config).await?;
            perform_registration(&mut reg, &mut conn, expires).await
        }
        .await;

        match attempt {
            Ok(granted_expires) => {
                info!("Tenant '{}' registered for {}s", tenant_id, granted_expires);
                *state.write().await = RegistrationState::Registered {
                    expires_secs: granted_expires,
                    registered_at: Instant::now(),
                };

                let refresh_after =
                    Duration::from_secs(granted_expires as u64 * 2 / 3).max(MIN_REFRESH_INTERVAL);

                tokio::select! {
                    _ = tokio::time::sleep(refresh_after) => {}
                    result = shutdown.changed() => {
                        // A dropped Sender (result.is_err()) means no one will ever signal
                        // shutdown again either; treat that the same as an explicit request.
                        if result.is_err() || *shutdown.borrow() {
                            deregister(&mut reg).await;
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Tenant '{}' registration failed: {}", tenant_id, e);
                let retry_interval = reg.config.retry_interval;
                *state.write().await = RegistrationState::Failed {
                    reason: e.to_string(),
                    next_attempt_at: Instant::now() + retry_interval,
                };

                tokio::select! {
                    _ = tokio::time::sleep(retry_interval) => {}
                    result = shutdown.changed() => {
                        if result.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        }
    }

    *state.write().await = RegistrationState::Unregistered;
}

struct TenantHandle {
    state: Arc<RwLock<RegistrationState>>,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// Manages registration lifecycles for any number of tenants against their (possibly
/// distinct) Cisco registrars.
pub struct MultiTenantGateway {
    tenants: RwLock<HashMap<String, TenantHandle>>,
}

impl Default for MultiTenantGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiTenantGateway {
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Start registering a new tenant. Spawns a background task that keeps the
    /// registration refreshed until `remove_tenant`/`shutdown` is called.
    pub async fn add_tenant(&self, config: TenantConfig) -> Result<()> {
        let tenant_id = config.tenant_id.clone();
        let mut tenants = self.tenants.write().await;

        if tenants.contains_key(&tenant_id) {
            return Err(anyhow!("tenant '{}' is already registered", tenant_id));
        }

        let state = Arc::new(RwLock::new(RegistrationState::Unregistered));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(tenant_task(tenant_id.clone(), config, state.clone(), shutdown_rx));

        tenants.insert(
            tenant_id,
            TenantHandle {
                state,
                shutdown_tx,
                task,
            },
        );

        Ok(())
    }

    /// Stop refreshing a tenant's registration and de-register it from the Cisco registrar.
    pub async fn remove_tenant(&self, tenant_id: &str) -> Result<()> {
        let handle = self
            .tenants
            .write()
            .await
            .remove(tenant_id)
            .ok_or_else(|| anyhow!("tenant '{}' not found", tenant_id))?;

        let _ = handle.shutdown_tx.send(true);
        let _ = handle.task.await;
        Ok(())
    }

    pub async fn state_of(&self, tenant_id: &str) -> Option<RegistrationState> {
        let tenants = self.tenants.read().await;
        let handle = tenants.get(tenant_id)?;
        Some(handle.state.read().await.clone())
    }

    pub async fn tenant_ids(&self) -> Vec<String> {
        self.tenants.read().await.keys().cloned().collect()
    }

    /// De-register and stop all tenants. Should be called before the process exits.
    pub async fn shutdown(&self) {
        for tenant_id in self.tenant_ids().await {
            if let Err(e) = self.remove_tenant(&tenant_id).await {
                warn!("Error shutting down tenant '{}': {}", tenant_id, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registration::TenantConfig as Cfg;
    use tokio::net::UdpSocket as TokioUdpSocket;

    fn tenant_config(registrar_addr: std::net::SocketAddr, tenant_id: &str) -> Cfg {
        Cfg {
            tenant_id: tenant_id.to_string(),
            registrar_addr,
            transport: TransportProtocol::Udp,
            domain: "tenant.example.com".to_string(),
            aor_user: "trunk".to_string(),
            auth_user: "trunk".to_string(),
            auth_password: "s3cret".to_string(),
            advertised_host: "127.0.0.1".parse().unwrap(),
            advertised_port: 15060,
            expires: 3600,
            user_agent: "sip-edge-rs-gateway/0.1".to_string(),
            retry_interval: Duration::from_millis(200),
        }
    }

    /// Minimal fake Cisco registrar: challenges the first REGISTER with a 401, then
    /// accepts the authenticated retry with a 200 OK.
    async fn run_fake_registrar(socket: TokioUdpSocket) {
        let mut buf = vec![0u8; 65535];
        let mut challenged = false;

        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };

            let message = match crate::parse_sip_message(&buf[..len]) {
                Ok(SipMessage::Request(req)) => req,
                _ => continue,
            };

            let status = if !challenged {
                challenged = true;
                (401u16, "Unauthorized")
            } else {
                (200u16, "OK")
            };

            let mut response = utils::build_response_from_request(&message, status.0, status.1);
            if status.0 == 401 {
                response.headers.insert(
                    "www-authenticate".to_string(),
                    vec![r#"Digest realm="testrealm", nonce="abc123""#.to_string()],
                );
            }

            let mut resp_buf = BytesMut::new();
            let _ = SipCodec::new().encode(SipMessage::Response(response), &mut resp_buf);
            let _ = socket.send_to(&resp_buf, peer).await;
        }
    }

    #[tokio::test]
    async fn test_tenant_registers_through_challenge() {
        let registrar_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registrar_addr = registrar_socket.local_addr().unwrap();
        tokio::spawn(run_fake_registrar(registrar_socket));

        let gateway = MultiTenantGateway::new();
        gateway
            .add_tenant(tenant_config(registrar_addr, "tenant1"))
            .await
            .unwrap();

        let mut registered = false;
        for _ in 0..50 {
            if let Some(RegistrationState::Registered { .. }) = gateway.state_of("tenant1").await {
                registered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(registered, "tenant should have completed registration");
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn test_add_duplicate_tenant_fails() {
        let registrar_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let registrar_addr = registrar_socket.local_addr().unwrap();
        drop(registrar_socket);

        let gateway = MultiTenantGateway::new();
        gateway
            .add_tenant(tenant_config(registrar_addr, "dup"))
            .await
            .unwrap();

        let result = gateway.add_tenant(tenant_config(registrar_addr, "dup")).await;
        assert!(result.is_err());

        // Not calling gateway.shutdown() here: the "dup" tenant is stuck retrying against
        // an address nothing listens on, and shutdown would block until that in-flight
        // attempt times out. Dropping `gateway` lets the per-test Tokio runtime reap the
        // spawned task on teardown instead.
    }
}
