use anyhow::{Context, Result};
use tracing::info;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_RELEASES_URL: &str = "https://api.github.com/repos/ChristosG/aegis/releases/latest";

#[derive(serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    assets: Vec<GithubAsset>,
}

#[derive(serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

/// Check for or perform a self-update of Aegis.
pub async fn run_update(check_only: bool, force: bool) -> Result<()> {
    use colored::Colorize;

    println!("\n  Aegis Self-Update\n");
    println!("  Current version: v{}", CURRENT_VERSION);

    // Query GitHub Releases API
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(format!("aegis/{}", CURRENT_VERSION))
        .build()
        .context("Failed to build HTTP client")?;

    println!("  Checking for updates...");

    let release: GithubRelease = match client.get(GITHUB_RELEASES_URL).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                println!(
                    "  {} Could not check for updates (HTTP {})\n",
                    "WARN".yellow(),
                    resp.status()
                );
                return Ok(());
            }
            resp.json().await.context("Failed to parse release info")?
        }
        Err(e) => {
            println!("  {} Could not connect to GitHub: {}\n", "WARN".yellow(), e);
            return Ok(());
        }
    };

    let latest = release.tag_name.trim_start_matches('v');
    println!("  Latest version:  v{}", latest);

    if latest == CURRENT_VERSION && !force {
        println!(
            "\n  {} You are already on the latest version.\n",
            "OK".green()
        );
        return Ok(());
    }

    if check_only {
        if latest != CURRENT_VERSION {
            println!(
                "\n  {} A new version is available: v{}\n",
                "UPDATE".cyan().bold(),
                latest
            );
            println!("  Release: {}", release.html_url);
            println!("  Run `sudo aegis update` to install.");
        }
        return Ok(());
    }

    // Determine which asset to download
    let arch = std::env::consts::ARCH;
    let target = match arch {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => {
            println!(
                "  {} Unsupported architecture: {}. Please update manually.\n",
                "ERROR".red(),
                arch
            );
            return Ok(());
        }
    };

    let is_full = cfg!(feature = "web-dashboard");
    let prefix = if is_full { "aegis-full" } else { "aegis" };
    let asset_name = format!("{}-v{}-{}.tar.gz", prefix, latest, target);

    let asset = release.assets.iter().find(|a| a.name == asset_name);
    let asset = match asset {
        Some(a) => a,
        None => {
            println!(
                "  {} Could not find release asset: {}\n",
                "ERROR".red(),
                asset_name
            );
            println!("  Available assets:");
            for a in &release.assets {
                println!("    - {}", a.name);
            }
            return Ok(());
        }
    };

    println!("\n  Downloading {}...", asset.name);

    // Download to temp file
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("Failed to download update")?;

    if !response.status().is_success() {
        println!(
            "  {} Download failed (HTTP {})\n",
            "ERROR".red(),
            response.status()
        );
        return Ok(());
    }

    let bytes = response.bytes().await.context("Failed to read download")?;

    // Extract and replace binary
    let current_exe = std::env::current_exe().context("Failed to determine current binary path")?;
    let temp_dir = std::env::temp_dir().join("aegis-update");
    std::fs::create_dir_all(&temp_dir)?;
    let tarball_path = temp_dir.join(&asset.name);
    std::fs::write(&tarball_path, &bytes)?;

    // Extract tarball
    let output = std::process::Command::new("tar")
        .args([
            "xzf",
            &tarball_path.to_string_lossy(),
            "-C",
            &temp_dir.to_string_lossy(),
        ])
        .output()
        .context("Failed to extract tarball")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("  {} Failed to extract: {}\n", "ERROR".red(), stderr);
        return Ok(());
    }

    // Find the extracted binary
    let new_binary = temp_dir.join("aegis");
    if !new_binary.exists() {
        println!(
            "  {} Extracted archive does not contain 'aegis' binary\n",
            "ERROR".red()
        );
        return Ok(());
    }

    // Atomic replace: rename new over old
    let backup_path = current_exe.with_extension("old");
    if let Err(e) = std::fs::rename(&current_exe, &backup_path) {
        println!(
            "  {} Failed to backup current binary: {}\n",
            "ERROR".red(),
            e
        );
        return Ok(());
    }

    match std::fs::rename(&new_binary, &current_exe) {
        Ok(()) => {
            // Clean up
            let _ = std::fs::remove_file(&backup_path);
            let _ = std::fs::remove_dir_all(&temp_dir);

            println!(
                "\n  {} Updated successfully: v{} -> v{}\n",
                "OK".green().bold(),
                CURRENT_VERSION,
                latest
            );
            info!(from = CURRENT_VERSION, to = latest, "Self-update complete");
        }
        Err(e) => {
            // Restore backup
            let _ = std::fs::rename(&backup_path, &current_exe);
            println!("  {} Failed to install new binary: {}\n", "ERROR".red(), e);
        }
    }

    Ok(())
}
