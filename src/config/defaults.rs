use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::schema::AegisConfig;

/// Search order for the configuration file:
/// 1. Explicit path (from CLI --config)
/// 2. ./aegis.toml
/// 3. /etc/aegis/aegis.toml
/// 4. ~/.config/aegis/aegis.toml
pub fn find_config_path(explicit: Option<&PathBuf>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Some(p.clone());
        }
    }

    let candidates = vec![
        PathBuf::from("./aegis.toml"),
        PathBuf::from("/etc/aegis/aegis.toml"),
        dirs::config_dir()
            .map(|d| d.join("aegis").join("aegis.toml"))
            .unwrap_or_default(),
    ];

    candidates.into_iter().find(|p| p.exists())
}

/// Find the system configuration file for write operations (config-upgrade,
/// whitelist changes, fi toggle, etc.).  Skips `./aegis.toml` to avoid
/// accidentally modifying a development copy in the current working directory.
pub fn find_system_config_path() -> Option<PathBuf> {
    let candidates = vec![
        PathBuf::from("/etc/aegis/aegis.toml"),
        dirs::config_dir()
            .map(|d| d.join("aegis").join("aegis.toml"))
            .unwrap_or_default(),
    ];

    candidates.into_iter().find(|p| p.exists())
}

/// Return a fully-populated default configuration.
pub fn default_config() -> AegisConfig {
    AegisConfig::default()
}

/// Serialize the default configuration to a TOML string suitable for writing
/// to an aegis.toml file. Uses the embedded default config if available,
/// otherwise serializes the programmatic defaults.
pub fn generate_default_toml() -> String {
    // Try the embedded config first for the best formatting with comments.
    let embedded = include_str!("../../aegis.toml");
    if !embedded.is_empty() {
        return embedded.to_string();
    }
    // Fallback: serialize programmatic defaults.
    toml::to_string_pretty(&default_config())
        .expect("Default config should always serialize cleanly")
}

/// Load and parse an AegisConfig from a TOML file at the given path.
///
/// Missing keys are filled from the Default impl so that old config files
/// keep working after new options are added.  After deserialization the
/// config is validated; warnings are logged but do not prevent loading.
pub fn load_config(path: &Path) -> Result<AegisConfig> {
    debug!("Loading configuration from {}", path.display());
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let config: AegisConfig = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    // Validate after loading — log issues but don't fail for backward compat.
    let validation = super::validate::validate_config(&config);
    for w in &validation.warnings {
        warn!("Config warning: {}", w);
    }
    for e in &validation.errors {
        warn!("Config error: {}", e);
    }

    info!("Loaded configuration from {}", path.display());
    Ok(config)
}

/// Load config with automatic discovery. Searches standard locations
/// if no explicit path is provided.
pub fn load_or_default(explicit: Option<&PathBuf>) -> Result<AegisConfig> {
    match find_config_path(explicit) {
        Some(path) => load_config(&path),
        None => {
            warn!("No config file found, using defaults. Run 'aegis init' to generate one.");
            Ok(default_config())
        }
    }
}

/// Resolve a path string, expanding a leading `~` to the user's home directory.
///
/// If the path does not start with `~`, it is returned as-is (converted to PathBuf).
pub fn resolve_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

/// Merge missing keys/sections from the default config into an existing user
/// config file. Preserves all user values and comments, only appends new keys.
///
/// Returns the number of keys added, or an error.
pub fn merge_default_into(config_path: &Path) -> Result<usize> {
    let user_content =
        std::fs::read_to_string(config_path).context("Failed to read user config")?;
    let default_content = generate_default_toml();

    let mut user_doc: toml_edit::DocumentMut = user_content
        .parse()
        .context("Failed to parse user config as TOML")?;
    let default_doc: toml_edit::DocumentMut = default_content
        .parse()
        .context("Failed to parse default config as TOML")?;

    let mut added = 0usize;

    // Iterate over top-level items in the default config
    for (key, default_item) in default_doc.iter() {
        if !user_doc.contains_key(key) {
            // Entire section/key missing — add it
            user_doc[key] = default_item.clone();
            added += 1;
        } else if let (Some(default_table), Some(user_table)) =
            (default_item.as_table(), user_doc[key].as_table())
        {
            // Section exists — check for missing keys within it
            let mut missing_keys: Vec<(String, toml_edit::Item)> = Vec::new();
            for (sub_key, sub_item) in default_table.iter() {
                if !user_table.contains_key(sub_key) {
                    missing_keys.push((sub_key.to_string(), sub_item.clone()));
                    added += 1;
                }
            }
            // Apply missing keys (can't mutate while iterating)
            for (sub_key, sub_item) in missing_keys {
                user_doc[key][&sub_key] = sub_item;
            }
        }
    }

    if added > 0 {
        // Atomic write: write to temp file then rename, so a crash mid-write
        // cannot corrupt the config.
        let tmp_path = config_path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, user_doc.to_string())
            .context("Failed to write temp config file")?;
        std::fs::rename(&tmp_path, config_path)
            .context("Failed to rename temp config over original")?;
    }

    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config_is_valid() {
        let config = default_config();
        assert!(config.general.modules.contains(&"network".to_string()));
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_generate_default_toml_parses() {
        let toml_str = generate_default_toml();
        let _config: AegisConfig = toml::from_str(&toml_str).unwrap();
    }

    #[test]
    fn test_load_config_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[general]
log_level = "debug"
data_dir = "/tmp/aegis-test"
modules = ["network"]

[network]
enabled = true
syn_flood_threshold = 100
"#
        )
        .unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.network.syn_flood_threshold, 100);
        // Defaults should still fill in missing sections
        assert!(config.process.enabled);
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_config(Path::new("/nonexistent/path/aegis.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_path_tilde() {
        let resolved = resolve_path("~/.aegis/data");
        assert!(!resolved.to_string_lossy().starts_with('~'));
        assert!(resolved.to_string_lossy().ends_with(".aegis/data"));
    }

    #[test]
    fn test_resolve_path_absolute() {
        let resolved = resolve_path("/etc/aegis.toml");
        assert_eq!(resolved, PathBuf::from("/etc/aegis.toml"));
    }

    #[test]
    fn test_resolve_path_relative() {
        let resolved = resolve_path("relative/path");
        assert_eq!(resolved, PathBuf::from("relative/path"));
    }

    #[test]
    fn test_resolve_path_bare_tilde() {
        let resolved = resolve_path("~");
        assert!(!resolved.to_string_lossy().starts_with('~'));
    }
}
