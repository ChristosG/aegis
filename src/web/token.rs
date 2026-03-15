use std::fs;

use anyhow::{Context, Result};
use rand::Rng;
use tracing::info;

/// Generate a cryptographically secure 64-character hex token (32 random bytes).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Ensure a token file exists. If not, generate a new token and write it.
/// Returns the token string.
pub fn ensure_token(token_path: &str) -> Result<String> {
    let path = crate::config::defaults::resolve_path(token_path);

    if path.exists() {
        let token = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read token file: {}", path.display()))?
            .trim()
            .to_string();
        if token.len() >= 32 {
            return Ok(token);
        }
        // Token too short, regenerate
    }

    // Generate new token
    let token = generate_token();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create token directory: {}", parent.display()))?;
    }

    fs::write(&path, &token)
        .with_context(|| format!("Failed to write token file: {}", path.display()))?;

    // Set permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&path, perms);
    }

    info!(path = %path.display(), "Generated new API token");
    Ok(token)
}
