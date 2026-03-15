use std::net::IpAddr;

use anyhow::{Context, Result};
use maxminddb::Reader;
use tracing::{debug, info};

use crate::config::schema::GeoipConfig;

/// GeoIP lookup engine backed by a MaxMind MMDB database.
pub struct GeoIpLookup {
    reader: Reader<Vec<u8>>,
    config: GeoipConfig,
}

impl GeoIpLookup {
    /// Open the MMDB database at the configured path.
    pub fn new(config: &GeoipConfig) -> Result<Self> {
        let db_path = crate::config::defaults::resolve_path(&config.database_path);
        let reader = Reader::open_readfile(&db_path)
            .with_context(|| format!("Failed to open GeoIP database: {}", db_path.display()))?;
        info!(path = %db_path.display(), "GeoIP database loaded");
        Ok(Self {
            reader,
            config: config.clone(),
        })
    }

    /// Look up the ISO country code for an IP address.
    /// Returns None if the lookup fails or the IP is not in the database.
    pub fn lookup_country(&self, ip: &IpAddr) -> Option<String> {
        match self.reader.lookup::<maxminddb::geoip2::Country>(*ip) {
            Ok(result) => result
                .country
                .and_then(|c| c.iso_code)
                .map(|s| s.to_string()),
            Err(e) => {
                debug!(ip = %ip, error = %e, "GeoIP lookup failed");
                None
            }
        }
    }

    /// Check if an IP address should be blocked based on the GeoIP configuration.
    /// Returns Some(country_code) if the IP should be blocked, None otherwise.
    pub fn should_block(&self, ip: &IpAddr) -> Option<String> {
        let country = self.lookup_country(ip)?;

        // If allowed_countries is non-empty, only allow those countries
        if !self.config.allowed_countries.is_empty() {
            if !self
                .config
                .allowed_countries
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&country))
            {
                return Some(country);
            }
            return None;
        }

        // Otherwise, check blocked_countries
        if self
            .config
            .blocked_countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&country))
        {
            return Some(country);
        }

        None
    }
}
