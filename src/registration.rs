// registration.rs - Per-tenant SIP REGISTER client state for a multi-tenant Cisco local gateway

use crate::transport::TransportProtocol;
use crate::utils::{self, HeaderBuilder};
use crate::{SipMethod, SipRequest, SipUri};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Static configuration for a single tenant's registration with a Cisco registrar
/// (e.g. Cisco Unified Communications Manager or Cisco Unified Border Element/CUBE)
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// Unique local identifier for this tenant
    pub tenant_id: String,
    /// Address of the Cisco registrar (CUCM/CUBE)
    pub registrar_addr: SocketAddr,
    /// Transport used to reach the registrar
    pub transport: TransportProtocol,
    /// Domain/realm part of the tenant's Address of Record
    pub domain: String,
    /// User part of the tenant's Address of Record
    pub aor_user: String,
    /// Digest authentication username (defaults to `aor_user` if not distinct)
    pub auth_user: String,
    /// Digest authentication password
    pub auth_password: String,
    /// Address this gateway advertises in Via/Contact so the registrar can reach it back
    pub advertised_host: IpAddr,
    pub advertised_port: u16,
    /// Requested registration lifetime in seconds
    pub expires: u32,
    pub user_agent: String,
    /// Delay before retrying a failed registration attempt
    pub retry_interval: Duration,
}

/// Current registration lifecycle state for a tenant
#[derive(Debug, Clone, PartialEq)]
pub enum RegistrationState {
    Unregistered,
    Registering,
    Registered {
        expires_secs: u32,
        registered_at: std::time::Instant,
    },
    Failed {
        reason: String,
        next_attempt_at: std::time::Instant,
    },
}

impl fmt::Display for RegistrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationState::Unregistered => write!(f, "unregistered"),
            RegistrationState::Registering => write!(f, "registering..."),
            RegistrationState::Registered { expires_secs, .. } => {
                write!(f, "registered (expires in {}s)", expires_secs)
            }
            RegistrationState::Failed { reason, .. } => write!(f, "failed: {}", reason),
        }
    }
}

fn format_host_port(host: &IpAddr, port: u16) -> String {
    match host {
        IpAddr::V4(v4) => format!("{}:{}", v4, port),
        IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
    }
}

/// Builds successive REGISTER requests for one tenant, keeping the Call-ID and From-tag
/// stable across refreshes as required by RFC 3261.
pub struct TenantRegistration {
    pub config: TenantConfig,
    call_id: String,
    from_tag: String,
    cseq: u32,
}

impl TenantRegistration {
    pub fn new(config: TenantConfig) -> Self {
        let call_id = utils::generate_call_id(&config.domain);
        let from_tag = utils::generate_tag();
        Self {
            config,
            call_id,
            from_tag,
            cseq: 0,
        }
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn aor(&self) -> String {
        format!("sip:{}@{}", self.config.aor_user, self.config.domain)
    }

    fn contact_uri(&self) -> String {
        format!(
            "sip:{}@{}",
            self.config.aor_user,
            format_host_port(&self.config.advertised_host, self.config.advertised_port)
        )
    }

    pub fn next_cseq(&mut self) -> u32 {
        self.cseq += 1;
        self.cseq
    }

    /// Build a REGISTER request. Pass `expires = 0` to de-register.
    /// `authorization` supplies a pre-built `Authorization` header value when responding
    /// to a 401/407 challenge.
    pub fn build_register(&self, cseq: u32, expires: u32, authorization: Option<String>) -> SipRequest {
        let transport_name = match self.config.transport {
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Tls => "TLS",
        };

        let branch = utils::generate_branch();
        let via = format!(
            "SIP/2.0/{} {};branch={};rport",
            transport_name,
            format_host_port(&self.config.advertised_host, self.config.advertised_port),
            branch
        );

        let mut builder = HeaderBuilder::new()
            .via(&via)
            .from(&self.aor(), Some(&self.from_tag))
            .to(&self.aor(), None)
            .call_id(&self.call_id)
            .cseq(cseq, "REGISTER")
            .max_forwards(70)
            .contact(&self.contact_uri())
            .expires(expires)
            .user_agent(&self.config.user_agent)
            .content_length(0);

        if let Some(auth) = authorization {
            builder = builder.header("authorization", &auth);
        }

        SipRequest {
            method: SipMethod::Register,
            uri: SipUri::new("sip", &self.config.domain),
            version: "SIP/2.0".to_string(),
            headers: builder.build(),
            body: None,
        }
    }
}

/// Raw JSON shape for a tenant registration entry (see `config/tenants.example.json`)
#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfigFile {
    pub tenant_id: String,
    pub registrar_host: String,
    pub registrar_port: u16,
    #[serde(default = "default_transport")]
    pub transport: String,
    pub domain: String,
    pub aor_user: String,
    #[serde(default)]
    pub auth_user: Option<String>,
    pub auth_password: String,
    /// Literal IP address this gateway is reachable on (advertised in Via/Contact)
    pub advertised_host: String,
    pub advertised_port: u16,
    #[serde(default = "default_expires")]
    pub expires: u32,
    #[serde(default = "default_retry_secs")]
    pub retry_interval_secs: u64,
}

fn default_transport() -> String {
    "udp".to_string()
}

fn default_expires() -> u32 {
    3600
}

fn default_retry_secs() -> u64 {
    30
}

async fn resolve_tenant_config(file: TenantConfigFile) -> Result<TenantConfig> {
    let registrar_addr = tokio::net::lookup_host((file.registrar_host.as_str(), file.registrar_port))
        .await
        .with_context(|| format!("failed to resolve registrar host '{}'", file.registrar_host))?
        .next()
        .ok_or_else(|| anyhow!("no addresses found for registrar host '{}'", file.registrar_host))?;

    let advertised_host: IpAddr = file.advertised_host.parse().with_context(|| {
        format!(
            "invalid advertised_host '{}': must be a literal IP address",
            file.advertised_host
        )
    })?;

    let transport = match file.transport.to_lowercase().as_str() {
        "udp" => TransportProtocol::Udp,
        "tcp" => TransportProtocol::Tcp,
        "tls" => TransportProtocol::Tls,
        other => return Err(anyhow!("unsupported transport '{}' for tenant '{}'", other, file.tenant_id)),
    };

    let auth_user = file.auth_user.unwrap_or_else(|| file.aor_user.clone());

    Ok(TenantConfig {
        tenant_id: file.tenant_id,
        registrar_addr,
        transport,
        domain: file.domain,
        aor_user: file.aor_user,
        auth_user,
        auth_password: file.auth_password,
        advertised_host,
        advertised_port: file.advertised_port,
        expires: file.expires,
        user_agent: "sip-edge-rs-gateway/0.1".to_string(),
        retry_interval: Duration::from_secs(file.retry_interval_secs),
    })
}

/// Load a list of tenant configurations from a JSON file (an array of tenant objects)
pub async fn load_tenants_from_json(path: &std::path::Path) -> Result<Vec<TenantConfig>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read tenant config file '{}'", path.display()))?;
    let files: Vec<TenantConfigFile> = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse tenant config file '{}'", path.display()))?;

    let mut tenants = Vec::with_capacity(files.len());
    for file in files {
        tenants.push(resolve_tenant_config(file).await?);
    }
    Ok(tenants)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> TenantConfig {
        TenantConfig {
            tenant_id: "tenant1".to_string(),
            registrar_addr: "192.0.2.10:5060".parse().unwrap(),
            transport: TransportProtocol::Udp,
            domain: "tenant1.example.com".to_string(),
            aor_user: "trunk1".to_string(),
            auth_user: "trunk1".to_string(),
            auth_password: "s3cret".to_string(),
            advertised_host: "203.0.113.5".parse().unwrap(),
            advertised_port: 5060,
            expires: 3600,
            user_agent: "sip-edge-rs-gateway/0.1".to_string(),
            retry_interval: Duration::from_secs(30),
        }
    }

    #[test]
    fn test_aor_and_contact() {
        let reg = TenantRegistration::new(sample_config());
        assert_eq!(reg.aor(), "sip:trunk1@tenant1.example.com");
        assert_eq!(reg.contact_uri(), "sip:trunk1@203.0.113.5:5060");
    }

    #[test]
    fn test_build_register_headers() {
        let reg = TenantRegistration::new(sample_config());
        let request = reg.build_register(1, 3600, None);

        assert_eq!(request.method, SipMethod::Register);
        assert_eq!(request.uri.to_string(), "sip:tenant1.example.com");

        let headers = &request.headers;
        assert_eq!(headers.get("cseq").unwrap()[0], "1 REGISTER");
        assert_eq!(headers.get("expires").unwrap()[0], "3600");
        assert!(headers.get("contact").unwrap()[0].contains("203.0.113.5:5060"));
        assert!(headers.get("from").unwrap()[0].contains("tag="));
        assert!(headers.get("via").unwrap()[0].starts_with("SIP/2.0/UDP 203.0.113.5:5060"));
        assert!(!headers.contains_key("authorization"));
    }

    #[test]
    fn test_build_register_with_authorization() {
        let reg = TenantRegistration::new(sample_config());
        let request = reg.build_register(2, 3600, Some(r#"Digest username="trunk1""#.to_string()));

        assert_eq!(
            request.headers.get("authorization").unwrap()[0],
            r#"Digest username="trunk1""#
        );
    }

    #[test]
    fn test_deregister_uses_zero_expires() {
        let reg = TenantRegistration::new(sample_config());
        let request = reg.build_register(3, 0, None);
        assert_eq!(request.headers.get("expires").unwrap()[0], "0");
    }

    #[test]
    fn test_call_id_stable_across_builds() {
        let mut reg = TenantRegistration::new(sample_config());
        let call_id_before = reg.call_id().to_string();
        let cseq1 = reg.next_cseq();
        let cseq2 = reg.next_cseq();

        assert_eq!(cseq1, 1);
        assert_eq!(cseq2, 2);
        assert_eq!(reg.call_id(), call_id_before);
    }

    #[test]
    fn test_ipv6_advertised_host_formatting() {
        let mut config = sample_config();
        config.advertised_host = "2001:db8::1".parse().unwrap();
        let reg = TenantRegistration::new(config);

        assert_eq!(reg.contact_uri(), "sip:trunk1@[2001:db8::1]:5060");
    }

    #[tokio::test]
    async fn test_load_tenants_from_json() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sip_edge_rs_test_tenants_{}.json", std::process::id()));
        let json = r#"[
            {
                "tenant_id": "tenant1",
                "registrar_host": "127.0.0.1",
                "registrar_port": 5060,
                "domain": "tenant1.example.com",
                "aor_user": "trunk1",
                "auth_password": "s3cret",
                "advertised_host": "203.0.113.5",
                "advertised_port": 5060
            }
        ]"#;
        std::fs::write(&path, json).unwrap();

        let tenants = load_tenants_from_json(&path).await.unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(tenants.len(), 1);
        assert_eq!(tenants[0].tenant_id, "tenant1");
        assert_eq!(tenants[0].auth_user, "trunk1");
        assert_eq!(tenants[0].expires, 3600);
        assert_eq!(tenants[0].retry_interval, Duration::from_secs(30));
        assert_eq!(tenants[0].registrar_addr.port(), 5060);
        assert!(tenants[0].registrar_addr.ip().is_loopback());
    }
}
