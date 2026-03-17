pub mod checks;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::schema::AuditConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;

/// Result of a single CIS benchmark check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisCheckResult {
    pub id: String,
    pub title: String,
    pub pass: bool,
    pub details: String,
    pub remediation: String,
}

pub struct AuditModule {
    config: AuditConfig,
}

impl AuditModule {
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    /// Run all CIS benchmark checks for the given profile.
    pub async fn run_audit(&self, profile: &str) -> Result<Vec<CisCheckResult>> {
        let mut results = Vec::new();

        // SSH hardening checks
        results.extend(checks::ssh::check_ssh_hardening());

        // Firewall checks
        results.extend(checks::firewall::check_firewall());

        // File permissions checks
        results.extend(checks::permissions::check_permissions());

        // Services checks
        results.extend(checks::services::check_services(profile));

        // Kernel parameter checks
        results.extend(checks::kernel::check_kernel_params());

        info!(
            profile = profile,
            total = results.len(),
            passed = results.iter().filter(|r| r.pass).count(),
            "CIS audit complete"
        );

        Ok(results)
    }
}

#[async_trait]
impl ScanModule for AuditModule {
    fn name(&self) -> &str {
        "audit"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        let results = self.run_audit(&self.config.profile).await?;
        let threats: Vec<ThreatEvent> = results
            .iter()
            .filter(|r| !r.pass)
            .map(|r| {
                ThreatEvent::new(
                    ThreatType::CisBenchmarkFail,
                    "audit",
                    format!("[{}] {}: {}", r.id, r.title, r.details),
                )
                .with_detail("check_id", &r.id)
                .with_detail("remediation", &r.remediation)
            })
            .collect();

        Ok(threats)
    }
}
