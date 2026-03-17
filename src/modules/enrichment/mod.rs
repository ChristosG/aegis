use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::defaults::resolve_path;
use crate::config::schema::EnrichmentConfig;

/// Cached enrichment result for an IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub ip: String,
    pub abuseipdb: Option<AbuseIpDbResult>,
    pub shodan: Option<ShodanResult>,
    pub greynoise: Option<GreyNoiseResult>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbResult {
    pub abuse_confidence_score: u32,
    pub total_reports: u32,
    pub country_code: String,
    pub isp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanResult {
    pub ports: Vec<u16>,
    pub os: Option<String>,
    pub hostnames: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreyNoiseResult {
    pub classification: String,
    pub name: String,
    pub noise: bool,
    pub riot: bool,
}

pub struct EnrichmentService {
    config: EnrichmentConfig,
    cache_path: PathBuf,
    client: reqwest::Client,
}

impl EnrichmentService {
    pub fn new(config: EnrichmentConfig) -> Self {
        let cache_path = resolve_path("~/.aegis/enrichment_cache.json");
        let client = reqwest::Client::new();
        Self {
            config,
            cache_path,
            client,
        }
    }

    /// Enrich an IP address with threat intelligence from configured APIs.
    pub async fn enrich(&self, ip: &str) -> Result<EnrichmentResult> {
        // Check cache first
        if let Some(cached) = self.get_cached(ip) {
            return Ok(cached);
        }

        let mut result = EnrichmentResult {
            ip: ip.to_string(),
            abuseipdb: None,
            shodan: None,
            greynoise: None,
            cached_at: chrono::Utc::now(),
        };

        // Query AbuseIPDB
        if !self.config.abuseipdb_key.is_empty() {
            match self.query_abuseipdb(ip).await {
                Ok(r) => result.abuseipdb = Some(r),
                Err(e) => warn!(error = %e, "AbuseIPDB query failed"),
            }
        }

        // Query Shodan
        if !self.config.shodan_key.is_empty() {
            match self.query_shodan(ip).await {
                Ok(r) => result.shodan = Some(r),
                Err(e) => warn!(error = %e, "Shodan query failed"),
            }
        }

        // Query GreyNoise
        if !self.config.greynoise_key.is_empty() {
            match self.query_greynoise(ip).await {
                Ok(r) => result.greynoise = Some(r),
                Err(e) => warn!(error = %e, "GreyNoise query failed"),
            }
        }

        // Cache the result
        self.cache_result(&result);

        Ok(result)
    }

    fn get_cached(&self, ip: &str) -> Option<EnrichmentResult> {
        let cache = self.load_cache().ok()?;
        let entry = cache.get(ip)?;

        // Check TTL
        let ttl = crate::core::scheduler::Scheduler::parse_duration(&self.config.cache_ttl)
            .unwrap_or(std::time::Duration::from_secs(86400));
        let ttl_chrono = chrono::Duration::from_std(ttl).ok()?;
        let cutoff = chrono::Utc::now() - ttl_chrono;

        if entry.cached_at >= cutoff {
            Some(entry.clone())
        } else {
            None
        }
    }

    fn load_cache(&self) -> Result<HashMap<String, EnrichmentResult>> {
        let content = fs::read_to_string(&self.cache_path)?;
        Ok(serde_json::from_str(&content)?)
    }

    fn cache_result(&self, result: &EnrichmentResult) {
        let mut cache = self.load_cache().unwrap_or_default();
        cache.insert(result.ip.clone(), result.clone());

        // Prune old entries (keep max 1000)
        if cache.len() > 1000 {
            let cutoff = chrono::Utc::now() - chrono::Duration::hours(48);
            cache.retain(|_, v| v.cached_at >= cutoff);
        }

        if let Some(parent) = self.cache_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&cache) {
            let _ = fs::write(&self.cache_path, json);
        }
    }

    async fn query_abuseipdb(&self, ip: &str) -> Result<AbuseIpDbResult> {
        let resp = self
            .client
            .get("https://api.abuseipdb.com/api/v2/check")
            .header("Key", &self.config.abuseipdb_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;
        let data = &body["data"];

        Ok(AbuseIpDbResult {
            abuse_confidence_score: data["abuseConfidenceScore"].as_u64().unwrap_or(0) as u32,
            total_reports: data["totalReports"].as_u64().unwrap_or(0) as u32,
            country_code: data["countryCode"].as_str().unwrap_or("").to_string(),
            isp: data["isp"].as_str().unwrap_or("").to_string(),
        })
    }

    async fn query_shodan(&self, ip: &str) -> Result<ShodanResult> {
        let client = reqwest::Client::new();
        let url = format!("https://api.shodan.io/shodan/host/{}", ip);
        let resp = client
            .get(&url)
            .query(&[("key", &self.config.shodan_key)])
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        Ok(ShodanResult {
            ports: body["ports"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u16))
                        .collect()
                })
                .unwrap_or_default(),
            os: body["os"].as_str().map(String::from),
            hostnames: body["hostnames"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    async fn query_greynoise(&self, ip: &str) -> Result<GreyNoiseResult> {
        let client = reqwest::Client::new();
        let url = format!("https://api.greynoise.io/v3/community/{}", ip);
        let resp = client
            .get(&url)
            .header("key", &self.config.greynoise_key)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        Ok(GreyNoiseResult {
            classification: body["classification"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            name: body["name"].as_str().unwrap_or("").to_string(),
            noise: body["noise"].as_bool().unwrap_or(false),
            riot: body["riot"].as_bool().unwrap_or(false),
        })
    }
}
