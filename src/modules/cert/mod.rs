use std::net::ToSocketAddrs;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::config::schema::CertConfig;
use crate::core::threat::{ThreatEvent, ThreatSeverity, ThreatType};
use crate::modules::ScanModule;

/// TLS certificate monitoring module.
///
/// Connects to configured domains and checks certificate expiry dates.
pub struct CertModule {
    config: CertConfig,
}

impl CertModule {
    pub fn new(config: CertConfig) -> Self {
        Self { config }
    }

    fn check_domain(&self, domain: &str) -> Option<ThreatEvent> {
        let (host, port) = if let Some((h, p)) = domain.rsplit_once(':') {
            (h, p.parse::<u16>().unwrap_or(443))
        } else {
            (domain, 443)
        };

        let addr = match format!("{}:{}", host, port).to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => {
                    warn!(domain = %domain, "No addresses resolved");
                    return None;
                }
            },
            Err(e) => {
                warn!(domain = %domain, error = %e, "DNS resolution failed");
                return None;
            }
        };

        // Connect with rustls to read the certificate
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
            Ok(n) => n,
            Err(_) => {
                warn!(domain = %domain, "Invalid server name");
                return None;
            }
        };

        let mut conn = match rustls::ClientConnection::new(config, server_name) {
            Ok(c) => c,
            Err(e) => {
                warn!(domain = %domain, error = %e, "TLS connection setup failed");
                return None;
            }
        };

        let mut tcp =
            match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)) {
                Ok(s) => s,
                Err(e) => {
                    warn!(domain = %domain, error = %e, "TCP connection failed");
                    return None;
                }
            };

        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        // Trigger the handshake by attempting a zero-length write
        let _ = std::io::Write::write(&mut stream, &[]);

        // Get peer certificates
        let certs = conn.peer_certificates()?;
        let cert = certs.first()?;

        // Parse the certificate to get expiry
        let parsed = match x509_parser::parse_x509_certificate(cert.as_ref()) {
            Ok((_, parsed)) => parsed,
            Err(e) => {
                warn!(domain = %domain, error = %e, "Failed to parse certificate");
                return None;
            }
        };

        let not_after = parsed.validity().not_after.to_datetime();
        let now = chrono::Utc::now();
        let expiry_dt =
            chrono::DateTime::<chrono::Utc>::from_timestamp(not_after.unix_timestamp(), 0)?;
        let days_remaining = (expiry_dt - now).num_days();

        let severity = if days_remaining <= 0 {
            ThreatSeverity::Critical
        } else if days_remaining <= 3 {
            ThreatSeverity::High
        } else if days_remaining <= 7 {
            ThreatSeverity::Medium
        } else if days_remaining <= 14 {
            ThreatSeverity::Low
        } else if days_remaining <= self.config.warn_days as i64 {
            ThreatSeverity::Info
        } else {
            debug!(domain = %domain, days_remaining = days_remaining, "Certificate OK");
            return None;
        };

        let status = if days_remaining <= 0 {
            "EXPIRED"
        } else {
            "expiring soon"
        };

        let description = format!(
            "TLS certificate for {} {}: {} days remaining",
            domain, status, days_remaining
        );

        Some(
            ThreatEvent::new(ThreatType::CertExpiringSoon, "cert", &description)
                .with_severity(severity)
                .with_target(domain.to_string())
                .with_detail("days_remaining", days_remaining.to_string())
                .with_detail("expires", expiry_dt.to_rfc3339()),
        )
    }
}

#[async_trait]
impl ScanModule for CertModule {
    fn name(&self) -> &str {
        "cert"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        info!("Running TLS certificate check");
        let mut threats = Vec::new();

        for domain in &self.config.domains {
            if let Some(event) = self.check_domain(domain) {
                threats.push(event);
            }
        }

        info!(count = threats.len(), "Certificate check complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        false
    }
}
