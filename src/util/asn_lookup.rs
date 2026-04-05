//! ASN / destination reputation lookup (v2.6.0 Bucket C).
//!
//! Resolves an IP address's owning ASN / organisation / country via `whois`,
//! classifies it into a small set of categories, and caches the result on
//! disk with a 30-day TTL.
//!
//! This is a **progressive enhancement** to the Bucket A static safety pin:
//! the static CIDR list handles the common case (major CDNs, Anthropic,
//! GitHub, CloudFront, Google, Fastly) with zero runtime cost, and this
//! module handles the tail — new CDNs, newly-allocated provider ranges, and
//! IPs in ranges we haven't hardcoded.
//!
//! # Cache file format
//!
//! `{data_dir}/asn_cache.json` is a JSON map from IP string → `AsnInfo`.
//! The file is atomically replaced on write (tmp + rename) so a crash
//! mid-write cannot corrupt it.
//!
//! # Threading model
//!
//! - `is_known_infrastructure_cached()` is synchronous, cache-only, and
//!   suitable for calling on the response engine's hot path. O(1).
//! - `lookup()` is async because it may spawn a `whois` subprocess with
//!   a 5-second timeout. Suitable for background enrichment tasks.
//!
//! # Whois as a lookup source
//!
//! whois was chosen over a bundled BGP snapshot or a third-party REST API
//! because:
//! - Aegis already has `whois` as a runtime dependency (used by operators
//!   for manual triage — see `docs/TRIAGE_PHASE_A0.md`)
//! - ARIN/RIPE/APNIC whois servers are free, rate-limited per-region but
//!   very generous for the volumes Aegis will generate
//! - whois-reported ownership is stable enough for the hours-to-days
//!   decision timescale we care about (fine-grained BGP hijacks are out
//!   of scope for this feature)
//!
//! See docs/specs/2026-04-05-aegis-v2-design.md §4 for the full design.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Classification of an IP's owning organisation, used by the safety pin
/// and enrichment layers to decide how to treat the IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnClassification {
    /// Major CDN / code host / cloud-service provider infrastructure.
    /// Examples: Cloudflare, CloudFront, GitHub, Google, Anthropic, Fastly.
    /// The safety pin will never auto-block these.
    KnownInfrastructure,
    /// Cloud provider customer ranges (Azure VMs, EC2, GCP Compute).
    /// These are dual-use: lots of legitimate SaaS *and* lots of abuse.
    /// The safety pin does NOT protect these — a bad Azure VM can and
    /// should be blocked.
    MajorCloudCustomer,
    /// Dedicated hosting / colocation providers (OVH, Hetzner, Linode,
    /// DigitalOcean, Vultr, Contabo, etc.). Legitimate uses exist but
    /// the IPs are frequently sold/reassigned and often appear in abuse
    /// feeds.
    HostingProvider,
    /// Residential / consumer ISP allocations (Comcast, Deutsche Telekom,
    /// Free, OTE/Cosmote, etc.).
    ResidentialIsp,
    /// Could not classify — fall back to other signals.
    Unknown,
}

impl AsnClassification {
    /// Whether this classification represents infrastructure that the
    /// safety pin should protect from auto-blocking.
    pub fn is_known_infrastructure(&self) -> bool {
        matches!(self, AsnClassification::KnownInfrastructure)
    }
}

/// ASN / organisation info for a single IP, as returned by whois and
/// classified by `classify_org`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    /// The IP this record describes (stringified for JSON key ergonomics).
    pub ip: String,
    /// ASN number if the whois response included one. Not every whois
    /// server exposes this in a parseable way.
    pub asn: Option<u32>,
    /// OrgName / NetName / descr field from whois.
    pub org: String,
    /// ISO country code from whois, or empty if unavailable.
    pub country: String,
    /// Classification into one of the AsnClassification buckets.
    pub classification: AsnClassification,
    /// When this record was fetched. Used for TTL.
    pub last_updated: DateTime<Utc>,
}

/// TTL for cached ASN records. 30 days is short enough that reassignments
/// get picked up in reasonable time, long enough that we don't hammer
/// whois servers.
const CACHE_TTL: Duration = Duration::from_secs(30 * 86400);

/// Max entries in the cache before we start evicting the oldest.
/// 10k is plenty for a typical deployment — Aegis's daily threat volume
/// is in the low thousands of unique IPs at most.
const MAX_CACHE_ENTRIES: usize = 10_000;

/// Whois subprocess timeout. Long enough for slow ARIN/RIPE responses,
/// short enough that a single slow lookup doesn't hang a background task.
const WHOIS_TIMEOUT: Duration = Duration::from_secs(5);

/// ASN lookup service with on-disk cache and async whois fallback.
pub struct AsnLookup {
    cache_path: PathBuf,
    cache: RwLock<HashMap<IpAddr, AsnInfo>>,
}

impl AsnLookup {
    /// Create a new AsnLookup backed by `{data_dir}/asn_cache.json`.
    /// Loads existing cache from disk if present; empty cache otherwise.
    pub fn new(data_dir: &Path) -> Self {
        let cache_path = data_dir.join("asn_cache.json");
        let cache = Self::load_cache(&cache_path).unwrap_or_default();
        info!(
            entries = cache.len(),
            path = %cache_path.display(),
            "Loaded ASN cache"
        );
        Self {
            cache_path,
            cache: RwLock::new(cache),
        }
    }

    fn load_cache(path: &Path) -> Result<HashMap<IpAddr, AsnInfo>> {
        if !path.exists() {
            return Ok(HashMap::new());
        }
        // Path is derived from config.general.data_dir (trusted operator config),
        // not from user/network input. Consistent with existing nosemgrep
        // annotations throughout the project (see util/hash.rs, util/proc_parse.rs).
        let content = std::fs::read_to_string(path) // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            .with_context(|| format!("Failed to read ASN cache: {}", path.display()))?;
        // The on-disk format uses IP strings as keys (serde_json can't use
        // IpAddr as a map key). Parse into a String map then convert.
        let string_map: HashMap<String, AsnInfo> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse ASN cache: {}", path.display()))?;
        let mut ip_map = HashMap::with_capacity(string_map.len());
        for (k, v) in string_map {
            if let Ok(ip) = k.parse::<IpAddr>() {
                ip_map.insert(ip, v);
            }
        }
        Ok(ip_map)
    }

    /// Persist the current cache to disk. Best-effort — logs warnings on
    /// failure but never returns an error, since a cache write failure
    /// should not disrupt the calling code path.
    pub fn save_cache(&self) {
        let cache = match self.cache.read() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "ASN cache lock poisoned, skipping save");
                return;
            }
        };
        // Convert IpAddr keys to strings for JSON serialization.
        let string_map: HashMap<String, &AsnInfo> =
            cache.iter().map(|(k, v)| (k.to_string(), v)).collect();
        let json = match serde_json::to_string_pretty(&string_map) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "Failed to serialize ASN cache");
                return;
            }
        };
        // Atomic replace: write to tmp, then rename. All paths below derive
        // from self.cache_path which derives from data_dir — trusted operator
        // config, not user input. See the load_cache() comment above and the
        // existing nosemgrep annotations in util/proc_parse.rs for the
        // project-wide convention.
        let tmp = self.cache_path.with_extension("json.tmp");
        if let Some(parent) = self.cache_path.parent() {
            // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            let _ = std::fs::create_dir_all(parent);
        }
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        if let Err(e) = std::fs::write(&tmp, json) {
            warn!(error = %e, "Failed to write ASN cache temp file");
            return;
        }
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        if let Err(e) = std::fs::rename(&tmp, &self.cache_path) {
            warn!(error = %e, "Failed to rename ASN cache temp file");
            // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        debug!(entries = cache.len(), "ASN cache saved");
    }

    /// Synchronous cache-only lookup. Returns `Some(AsnInfo)` if the IP is
    /// in the cache and not expired; `None` otherwise.
    ///
    /// This is the method the response engine's hot path calls — it must
    /// be fast (lock-free except for the RwLock read) and never do I/O.
    pub fn lookup_cached(&self, ip: &IpAddr) -> Option<AsnInfo> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(ip)?;
        let age = Utc::now() - entry.last_updated;
        if age > chrono::Duration::from_std(CACHE_TTL).unwrap_or(chrono::Duration::days(30)) {
            None
        } else {
            Some(entry.clone())
        }
    }

    /// Synchronous cache-only check: is this IP classified as known
    /// infrastructure? Used by the response engine's safety pin layer.
    /// Returns false if the IP is not in the cache (fail-safe: we don't
    /// silently pin IPs we haven't verified).
    pub fn is_known_infrastructure_cached(&self, ip: &IpAddr) -> bool {
        self.lookup_cached(ip)
            .map(|info| info.classification.is_known_infrastructure())
            .unwrap_or(false)
    }

    /// Full async lookup. Checks cache first, falls back to whois if
    /// missing or expired. Updates the cache on success.
    pub async fn lookup(&self, ip: IpAddr) -> AsnInfo {
        if let Some(cached) = self.lookup_cached(&ip) {
            return cached;
        }

        let info = match Self::whois_lookup(ip).await {
            Ok(info) => info,
            Err(e) => {
                warn!(ip = %ip, error = %e, "ASN whois lookup failed");
                // Return an Unknown record so we at least cache the failure
                // and don't retry every single time.
                AsnInfo {
                    ip: ip.to_string(),
                    asn: None,
                    org: String::new(),
                    country: String::new(),
                    classification: AsnClassification::Unknown,
                    last_updated: Utc::now(),
                }
            }
        };

        // Insert into cache, evicting oldest entries if we're over the cap.
        if let Ok(mut cache) = self.cache.write() {
            if cache.len() >= MAX_CACHE_ENTRIES {
                // Evict the 10 oldest entries to avoid doing this every insert.
                let mut entries: Vec<(IpAddr, DateTime<Utc>)> =
                    cache.iter().map(|(k, v)| (*k, v.last_updated)).collect();
                entries.sort_by_key(|(_, ts)| *ts);
                for (k, _) in entries.into_iter().take(10) {
                    cache.remove(&k);
                }
            }
            cache.insert(ip, info.clone());
        }

        info
    }

    /// Spawn a whois subprocess and parse its output. Uses `tokio::process`
    /// so the call is non-blocking and respects the timeout.
    async fn whois_lookup(ip: IpAddr) -> Result<AsnInfo> {
        use tokio::process::Command;
        use tokio::time::timeout;

        let output = timeout(
            WHOIS_TIMEOUT,
            Command::new("whois").arg(ip.to_string()).output(),
        )
        .await
        .context("whois subprocess timed out")?
        .context("Failed to spawn whois subprocess")?;

        if !output.status.success() {
            anyhow::bail!(
                "whois exited with non-zero status: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let text = String::from_utf8_lossy(&output.stdout);
        Ok(parse_whois_output(ip, &text))
    }
}

/// Parse a whois response text into an AsnInfo. Handles both ARIN format
/// (`OrgName:`, `NetName:`, `Country:`, `OriginAS:`) and RIPE/APNIC format
/// (`netname:`, `descr:`, `country:`, `origin:`).
///
/// # Field priority for the `org` field
///
/// whois output can contain multiple identity fields at different levels of
/// human-readability. We pick the most informative one that's present:
///
/// 1. `OrgName` / `org-name` — ARIN's canonical organisation name (e.g.
///    `GitHub, Inc.`, `Anthropic, PBC`, `Cloudflare, Inc.`). Highest priority.
/// 2. `descr` / `organisation` / `owner` — RIPE/APNIC-style description
///    (e.g. `Cosmote Internet Services`). Second priority.
/// 3. `NetName` / `netname` — short machine handle like `GITHU`, `AP-2440`,
///    `CLOUDFLARENET`. Lowest priority, used only when nothing better exists.
///
/// This function is private so tests in this module can exercise it without
/// spawning real subprocesses.
fn parse_whois_output(ip: IpAddr, text: &str) -> AsnInfo {
    // Collect all candidate values by priority tier, then pick the best.
    let mut orgname: Option<String> = None; // tier 1
    let mut descr: Option<String> = None; // tier 2
    let mut netname: Option<String> = None; // tier 3
    let mut country = String::new();
    let mut asn: Option<u32> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
            continue;
        }

        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim().to_lowercase(), v.trim().to_string()),
            None => continue,
        };

        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            "orgname" | "org-name" => {
                // Tier 1 — always overwrite; if there are multiple (rare)
                // we keep the longest, most descriptive value.
                if orgname.as_ref().is_none_or(|old| old.len() < value.len()) {
                    orgname = Some(value);
                }
            }
            "descr" | "organisation" | "owner" => {
                if descr.as_ref().is_none_or(|old| old.len() < value.len()) {
                    descr = Some(value);
                }
            }
            "netname" => {
                if netname.is_none() {
                    netname = Some(value);
                }
            }
            "country" => {
                if country.is_empty() {
                    country = value.to_uppercase();
                }
            }
            "originas" | "origin" => {
                // Strip leading "AS" if present, parse digits
                let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                if !digits.is_empty() {
                    asn = digits.parse().ok();
                }
            }
            _ => {}
        }
    }

    // Pick the best tier. OrgName > descr > netname > empty.
    let org = orgname.or(descr).or(netname).unwrap_or_default();

    let classification = classify_org(&org);

    AsnInfo {
        ip: ip.to_string(),
        asn,
        org,
        country,
        classification,
        last_updated: Utc::now(),
    }
}

/// Classify an OrgName string into one of the AsnClassification buckets.
/// Case-insensitive substring matching against a curated list of known
/// providers.
///
/// # The Microsoft nuance
///
/// `OrgName: Microsoft Corporation` covers both MS's own infrastructure
/// (Office 365, Bing, Azure Front Door) and customer Azure VMs
/// (`20.x.x.x`, `4.x.x.x`, `40.x.x.x`, etc.). A bare string match would
/// misclassify Azure VMs as infrastructure. For v2.6.0 we classify all
/// Microsoft-owned IPs as `MajorCloudCustomer` by default — safer to
/// potentially block an MS service IP than to silently ignore a compromised
/// Azure VM. Users who depend on specific MS services can add those CIDRs
/// to the `whitelist` or `well_known_destinations` config.
pub fn classify_org(org: &str) -> AsnClassification {
    let o = org.to_lowercase();

    // Known provider infrastructure — must be auto-blocked NEVER.
    if o.contains("cloudflare")
        || o.contains("amazon technologies")  // AWS edge/CloudFront (not EC2 customers)
        || o.contains("github")
        || o.contains("google llc")
        || o.contains("anthropic")
        || o.contains("fastly")
        || o.contains("akamai")
        || o.contains("at-88-z")  // AWS CloudFront netname
        || o.contains("cloudflarenet")
    {
        return AsnClassification::KnownInfrastructure;
    }

    // Cloud provider customer ranges — dual-use, don't auto-pin.
    // Microsoft is here because the customer vs infra split is too blurred
    // to classify safely without CIDR-level data.
    if o.contains("microsoft corporation")
        || o.contains("amazon web services")
        || o.contains("amazon.com")
        || o.contains("oracle")
        || o.contains("digitalocean")
    {
        return AsnClassification::MajorCloudCustomer;
    }

    // Hosting providers — dual-use but often abused.
    if o.contains("ovh")
        || o.contains("hetzner")
        || o.contains("linode")
        || o.contains("vultr")
        || o.contains("contabo")
        || o.contains("leaseweb")
        || o.contains("hivelocity")
        || o.contains("inap")
    {
        return AsnClassification::HostingProvider;
    }

    // Residential ISPs — never auto-pin, often used by legitimate users AND
    // compromised home routers in botnets.
    if o.contains("comcast")
        || o.contains("deutsche telekom")
        || o.contains("cox")
        || o.contains("verizon")
        || o.contains("ote ")
        || o.contains("cosmote")
        || o.contains("vodafone")
        || o.contains("free sas")
    {
        return AsnClassification::ResidentialIsp;
    }

    AsnClassification::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_classify_org_cloudflare() {
        assert_eq!(
            classify_org("Cloudflare, Inc."),
            AsnClassification::KnownInfrastructure
        );
        assert_eq!(
            classify_org("CLOUDFLARENET"),
            AsnClassification::KnownInfrastructure
        );
    }

    #[test]
    fn test_classify_org_aws_cloudfront() {
        assert_eq!(
            classify_org("Amazon Technologies Inc."),
            AsnClassification::KnownInfrastructure
        );
        assert_eq!(
            classify_org("AT-88-Z"),
            AsnClassification::KnownInfrastructure
        );
    }

    #[test]
    fn test_classify_org_github() {
        assert_eq!(
            classify_org("GitHub, Inc."),
            AsnClassification::KnownInfrastructure
        );
    }

    #[test]
    fn test_classify_org_google() {
        assert_eq!(
            classify_org("Google LLC"),
            AsnClassification::KnownInfrastructure
        );
    }

    #[test]
    fn test_classify_org_microsoft_is_cloud_customer() {
        // Important: Microsoft is classified as MajorCloudCustomer, NOT
        // KnownInfrastructure, because 20.x.x.x ranges are mostly Azure VMs.
        assert_eq!(
            classify_org("Microsoft Corporation"),
            AsnClassification::MajorCloudCustomer
        );
    }

    #[test]
    fn test_classify_org_hosting_provider() {
        assert_eq!(classify_org("OVH SAS"), AsnClassification::HostingProvider);
        assert_eq!(
            classify_org("Hetzner Online GmbH"),
            AsnClassification::HostingProvider
        );
    }

    #[test]
    fn test_classify_org_residential_isp() {
        assert_eq!(
            classify_org("Cosmote Internet Services"),
            AsnClassification::ResidentialIsp
        );
    }

    #[test]
    fn test_classify_org_unknown() {
        assert_eq!(classify_org("Some Random ISP"), AsnClassification::Unknown);
        assert_eq!(classify_org(""), AsnClassification::Unknown);
    }

    #[test]
    fn test_parse_whois_arin_format() {
        // Real whois output for 140.82.112.26 (GitHub), trimmed.
        let text = r#"
            NetRange:       140.82.112.0 - 140.82.127.255
            CIDR:           140.82.112.0/20
            NetName:        GITHU
            OrgName:        GitHub, Inc.
            Country:        US
            OriginAS:       AS36459
        "#;
        let ip: IpAddr = "140.82.112.26".parse().unwrap();
        let info = parse_whois_output(ip, text);
        assert_eq!(info.org, "GitHub, Inc.");
        assert_eq!(info.country, "US");
        assert_eq!(info.asn, Some(36459));
        assert_eq!(info.classification, AsnClassification::KnownInfrastructure);
    }

    #[test]
    fn test_parse_whois_ripe_format() {
        // RIPE-style output (lowercase keys, descr field preferred).
        let text = r#"
            inetnum:        91.202.233.0 - 91.202.233.255
            netname:        RU-PROSPERO
            descr:          Prospero LLC
            country:        RU
            organisation:   ORG-PO83-RIPE
            origin:         AS12345
        "#;
        let ip: IpAddr = "91.202.233.33".parse().unwrap();
        let info = parse_whois_output(ip, text);
        assert_eq!(info.country, "RU");
        assert_eq!(info.asn, Some(12345));
        // Prospero LLC is not in any known list, should be Unknown.
        assert_eq!(info.classification, AsnClassification::Unknown);
    }

    #[test]
    fn test_parse_whois_anthropic() {
        // Real whois from the audit triage.
        let text = r#"
            NetRange:       160.79.104.0 - 160.79.111.255
            CIDR:           160.79.104.0/21
            NetName:        AP-2440
            OrgName:        Anthropic, PBC
            Country:        US
        "#;
        let ip: IpAddr = "160.79.104.10".parse().unwrap();
        let info = parse_whois_output(ip, text);
        assert_eq!(info.org, "Anthropic, PBC");
        assert_eq!(info.classification, AsnClassification::KnownInfrastructure);
    }

    #[test]
    fn test_cache_roundtrip() {
        let dir = tempdir().unwrap();
        let lookup = AsnLookup::new(dir.path());

        // Cache should be empty initially
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(lookup.lookup_cached(&ip).is_none());
        assert!(!lookup.is_known_infrastructure_cached(&ip));

        // Manually insert an entry
        {
            let mut cache = lookup.cache.write().unwrap();
            cache.insert(
                ip,
                AsnInfo {
                    ip: ip.to_string(),
                    asn: Some(15169),
                    org: "Google LLC".into(),
                    country: "US".into(),
                    classification: AsnClassification::KnownInfrastructure,
                    last_updated: Utc::now(),
                },
            );
        }

        // Now it should be findable and classified as infra
        assert!(lookup.lookup_cached(&ip).is_some());
        assert!(lookup.is_known_infrastructure_cached(&ip));

        // Save and reload into a fresh AsnLookup — verify persistence
        lookup.save_cache();
        drop(lookup);

        let reloaded = AsnLookup::new(dir.path());
        assert!(reloaded.lookup_cached(&ip).is_some());
        assert!(reloaded.is_known_infrastructure_cached(&ip));
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let dir = tempdir().unwrap();
        let lookup = AsnLookup::new(dir.path());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // Insert an entry that's 31 days old (past TTL)
        {
            let mut cache = lookup.cache.write().unwrap();
            cache.insert(
                ip,
                AsnInfo {
                    ip: ip.to_string(),
                    asn: None,
                    org: "Test".into(),
                    country: "US".into(),
                    classification: AsnClassification::KnownInfrastructure,
                    last_updated: Utc::now() - chrono::Duration::days(31),
                },
            );
        }

        // lookup_cached should return None because TTL is exceeded
        assert!(lookup.lookup_cached(&ip).is_none());
        assert!(!lookup.is_known_infrastructure_cached(&ip));
    }

    #[test]
    fn test_is_known_infrastructure_classification() {
        assert!(AsnClassification::KnownInfrastructure.is_known_infrastructure());
        assert!(!AsnClassification::MajorCloudCustomer.is_known_infrastructure());
        assert!(!AsnClassification::HostingProvider.is_known_infrastructure());
        assert!(!AsnClassification::ResidentialIsp.is_known_infrastructure());
        assert!(!AsnClassification::Unknown.is_known_infrastructure());
    }
}
