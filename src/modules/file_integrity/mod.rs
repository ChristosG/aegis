use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use tracing::{debug, info, warn};

use crate::config::defaults::resolve_path;
use crate::config::schema::FileIntegrityConfig;
use crate::core::threat::{ThreatEvent, ThreatType};
use crate::modules::ScanModule;
use crate::util::hash::sha256_file;

/// File integrity monitoring module: compares filesystem state against a
/// stored baseline of SHA-256 hashes, detecting modifications, additions,
/// and deletions. Supports inotify-based real-time monitoring in daemon mode.
pub struct FileIntegrityModule {
    config: FileIntegrityConfig,
}

impl FileIntegrityModule {
    pub fn new(config: FileIntegrityConfig) -> Self {
        Self { config }
    }

    /// Load the baseline from disk. If no baseline exists, automatically
    /// generates one by hashing all files in the configured watch paths.
    fn load_or_create_baseline(&self) -> Result<Option<HashMap<PathBuf, String>>> {
        let baseline_path = resolve_path(&self.config.baseline_path);

        if !baseline_path.exists() {
            // Estimate the work: count watched directories to decide whether
            // to generate inline or defer to a manual `aegis baseline` call.
            // System paths like /usr/bin can have tens of thousands of files,
            // so only auto-generate if the total looks manageable.
            let heavy_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib"];
            let has_heavy = self.config.watch_paths.iter().any(|p| {
                let resolved = resolve_path(p);
                let s = resolved.to_string_lossy();
                heavy_paths
                    .iter()
                    .any(|hp| s.starts_with(hp) || s.as_ref() == *hp)
            });

            if has_heavy {
                // Large system paths — generate in the background to avoid
                // blocking the scan. Spawn a thread so it doesn't hold up the
                // scan pipeline.
                let config_clone = self.config.clone();
                let baseline_path_clone = baseline_path.clone();
                info!(
                    "No baseline found. Auto-generating in background (this may take a minute)..."
                );
                std::thread::spawn(move || {
                    let module = FileIntegrityModule::new(config_clone);
                    match module.generate_baseline(&baseline_path_clone) {
                        Ok(count) => {
                            info!(
                                files = count,
                                path = %baseline_path_clone.display(),
                                "Baseline auto-generated ({} files). Next scan will detect changes.",
                                count
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to auto-generate baseline");
                        }
                    }
                });
                return Ok(None);
            }

            // Small/custom paths — generate inline (fast).
            info!("No baseline found, auto-generating initial baseline...");
            return match self.generate_baseline(&baseline_path) {
                Ok(count) => {
                    info!(
                        files = count,
                        path = %baseline_path.display(),
                        "Initial baseline created ({} files). Next scan will detect changes.",
                        count
                    );
                    Ok(None)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to auto-generate baseline");
                    Ok(None)
                }
            };
        }

        let content = std::fs::read_to_string(&baseline_path).with_context(|| {
            format!("Failed to read baseline file: {}", baseline_path.display())
        })?;

        let baseline: HashMap<PathBuf, String> =
            serde_json::from_str(&content).with_context(|| {
                format!("Failed to parse baseline JSON: {}", baseline_path.display())
            })?;

        info!(
            path = %baseline_path.display(),
            entries = baseline.len(),
            "Loaded file integrity baseline"
        );

        Ok(Some(baseline))
    }

    /// Generate a baseline by hashing all files under the configured watch paths.
    /// Saves the result to the given path. Returns the number of files hashed.
    fn generate_baseline(&self, output_path: &Path) -> Result<usize> {
        let mut baseline: HashMap<PathBuf, String> = HashMap::new();

        for watch_path_str in &self.config.watch_paths {
            let watch_path = resolve_path(watch_path_str);
            if !watch_path.exists() {
                debug!(path = %watch_path.display(), "Watch path does not exist, skipping");
                continue;
            }

            if watch_path.is_file() {
                if !self.is_excluded(&watch_path) {
                    if let Ok(hash) = sha256_file(&watch_path) {
                        baseline.insert(watch_path, hash);
                    }
                }
            } else if watch_path.is_dir() {
                self.hash_directory(&watch_path, &mut baseline);
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create baseline directory: {}", parent.display())
            })?;
        }

        let json =
            serde_json::to_string_pretty(&baseline).context("Failed to serialize baseline")?;
        std::fs::write(output_path, json)
            .with_context(|| format!("Failed to write baseline: {}", output_path.display()))?;

        Ok(baseline.len())
    }

    /// Recursively hash all files in a directory into the baseline map.
    fn hash_directory(&self, dir: &Path, baseline: &mut HashMap<PathBuf, String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();

            if self.is_excluded(&path) {
                continue;
            }

            // Never follow symlinks — they can create infinite recursion
            // (e.g., /usr/bin/X11 -> .) and point outside watched dirs.
            if path.is_symlink() {
                continue;
            }

            if path.is_file() {
                if let Ok(hash) = sha256_file(&path) {
                    baseline.insert(path, hash);
                }
            } else if path.is_dir() {
                self.hash_directory(&path, baseline);
            }
        }
    }

    /// Recursively add inotify watches for a directory and all its subdirectories.
    /// Returns a map from WatchDescriptor to directory path for event path reconstruction.
    fn add_watches_recursive(
        &self,
        inotify: &mut Inotify,
        dir: &Path,
        watch_mask: WatchMask,
        wd_map: &mut HashMap<WatchDescriptor, PathBuf>,
    ) {
        if self.is_excluded(dir) {
            return;
        }

        // Skip symlinks to avoid infinite recursion
        if dir.is_symlink() {
            return;
        }

        match inotify.watches().add(dir, watch_mask) {
            Ok(wd) => {
                debug!(path = %dir.display(), "Added inotify watch");
                wd_map.insert(wd, dir.to_path_buf());
            }
            Err(e) => {
                warn!(path = %dir.display(), error = %e, "Failed to add inotify watch");
                return;
            }
        }

        // Recurse into subdirectories
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_symlink() {
                continue;
            }
            if path.is_dir() {
                self.add_watches_recursive(inotify, &path, watch_mask, wd_map);
            }
        }
    }

    /// Check whether a path should be excluded based on exclude_paths config.
    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for exclude in &self.config.exclude_paths {
            let exclude_path = resolve_path(exclude);
            let exclude_str = exclude_path.to_string_lossy();
            if path_str.starts_with(exclude_str.as_ref()) {
                return true;
            }
        }
        false
    }

    /// Detect modifications and deletions by comparing current state against the baseline.
    fn check_baseline_entries(&self, baseline: &HashMap<PathBuf, String>) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for (path, expected_hash) in baseline {
            if self.is_excluded(path) {
                debug!(path = %path.display(), "Skipping excluded path");
                continue;
            }

            if !path.exists() {
                let description = format!("Baselined file has been deleted: {}", path.display());
                let event =
                    ThreatEvent::new(ThreatType::FileDeleted, "file_integrity", &description)
                        .with_target(path.to_string_lossy().to_string())
                        .with_detail("expected_hash", expected_hash.clone());

                warn!(path = %path.display(), "File deleted (was in baseline)");
                threats.push(event);
                continue;
            }

            match sha256_file(path) {
                Ok(current_hash) => {
                    if current_hash != *expected_hash {
                        let description = format!("File has been modified: {}", path.display());
                        let event = ThreatEvent::new(
                            ThreatType::FileModified,
                            "file_integrity",
                            &description,
                        )
                        .with_target(path.to_string_lossy().to_string())
                        .with_detail("old_hash", expected_hash.clone())
                        .with_detail("new_hash", current_hash);

                        warn!(path = %path.display(), "File modified (hash mismatch)");
                        threats.push(event);
                    }
                }
                Err(e) => {
                    debug!(
                        path = %path.display(),
                        error = %e,
                        "Failed to hash file, skipping"
                    );
                }
            }
        }

        threats
    }

    /// Walk the watch_paths directories looking for files not present in the baseline.
    fn check_for_new_files(&self, baseline: &HashMap<PathBuf, String>) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for watch_path_str in &self.config.watch_paths {
            let watch_path = resolve_path(watch_path_str);

            if !watch_path.exists() {
                debug!(path = %watch_path.display(), "Watch path does not exist, skipping");
                continue;
            }

            if let Err(e) = self.walk_directory(&watch_path, baseline, &mut threats) {
                debug!(
                    path = %watch_path.display(),
                    error = %e,
                    "Error walking watch directory"
                );
            }
        }

        threats
    }

    /// Recursively walk a directory and report files not in the baseline.
    fn walk_directory(
        &self,
        dir: &Path,
        baseline: &HashMap<PathBuf, String>,
        threats: &mut Vec<ThreatEvent>,
    ) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                debug!(
                    path = %dir.display(),
                    error = %e,
                    "Cannot read directory, skipping"
                );
                return Ok(());
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    debug!(error = %e, "Failed to read directory entry");
                    continue;
                }
            };

            let path = entry.path();

            if self.is_excluded(&path) {
                continue;
            }

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    debug!(path = %path.display(), error = %e, "Cannot get file type");
                    continue;
                }
            };

            // Never follow symlinks (e.g., /usr/bin/X11 -> . causes infinite recursion)
            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                // Recurse into subdirectories
                if let Err(e) = self.walk_directory(&path, baseline, threats) {
                    debug!(path = %path.display(), error = %e, "Error recursing into directory");
                }
            } else if file_type.is_file() && !baseline.contains_key(&path) {
                let description =
                    format!("New file detected (not in baseline): {}", path.display());
                let event = ThreatEvent::new(ThreatType::FileAdded, "file_integrity", &description)
                    .with_target(path.to_string_lossy().to_string());

                debug!(path = %path.display(), "New file not in baseline");
                threats.push(event);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl ScanModule for FileIntegrityModule {
    fn name(&self) -> &str {
        "file_integrity"
    }

    async fn scan(&self) -> Result<Vec<ThreatEvent>> {
        info!(
            "Running file integrity scan (watch_paths={:?})",
            self.config.watch_paths
        );

        let baseline = match self.load_or_create_baseline()? {
            Some(b) => b,
            None => {
                // First run: baseline was just created, nothing to compare yet.
                return Ok(Vec::new());
            }
        };

        let mut threats = Vec::new();

        // Check for modifications and deletions
        threats.extend(self.check_baseline_entries(&baseline));

        // Check for new files not in the baseline
        threats.extend(self.check_for_new_files(&baseline));

        info!(count = threats.len(), "File integrity scan complete");
        Ok(threats)
    }

    fn supports_watch(&self) -> bool {
        self.config.use_inotify
    }

    async fn watch(
        &self,
        tx: tokio::sync::mpsc::Sender<ThreatEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        // First, run a one-shot scan and send results
        let threats = self.scan().await?;
        for threat in threats {
            let _ = tx.send(threat).await;
        }

        if !self.config.use_inotify {
            cancel.cancelled().await;
            return Ok(());
        }

        info!("Starting inotify watch on configured paths");

        let mut inotify = Inotify::init().context("Failed to initialize inotify")?;

        // Set inotify fd to non-blocking so reads don't hang on shutdown.
        {
            use std::os::unix::io::AsRawFd;
            let raw_fd = inotify.as_raw_fd();
            nix::fcntl::fcntl(
                raw_fd,
                nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
            )
            .context("Failed to set inotify fd to non-blocking")?;
        }

        let watch_mask = WatchMask::MODIFY
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO;

        // Recursively add watches for all directories under each watch path.
        let mut wd_map: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
        for watch_path_str in &self.config.watch_paths {
            let watch_path = resolve_path(watch_path_str);
            if watch_path.exists() {
                if watch_path.is_dir() {
                    self.add_watches_recursive(&mut inotify, &watch_path, watch_mask, &mut wd_map);
                } else {
                    match inotify.watches().add(&watch_path, watch_mask) {
                        Ok(wd) => {
                            debug!(path = %watch_path.display(), "Added inotify watch (file)");
                            wd_map.insert(wd, watch_path);
                        }
                        Err(e) => {
                            warn!(path = %watch_path.display(), error = %e, "Failed to add inotify watch");
                        }
                    }
                }
            } else {
                warn!(path = %watch_path.display(), "Watch path does not exist, skipping");
            }
        }

        info!(
            watch_count = wd_map.len(),
            "Inotify watches registered (recursive)"
        );

        // Non-blocking event loop: poll every 250ms, check cancellation via select.
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("File integrity watch cancelled");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                    // Drain all available events (non-blocking).
                    loop {
                        match inotify.read_events(&mut buf) {
                            Ok(events) => {
                                let owned: Vec<(WatchDescriptor, EventMask, Option<String>)> = events
                                    .map(|event| {
                                        let name = event.name
                                            .and_then(|n| n.to_str())
                                            .map(|s| s.to_string());
                                        (event.wd, event.mask, name)
                                    })
                                    .collect();

                                if owned.is_empty() {
                                    break;
                                }

                                for (wd, mask, name) in owned {
                                    // Reconstruct full path from watch descriptor directory + filename.
                                    let dir_path = wd_map.get(&wd);
                                    let full_path = match (dir_path, &name) {
                                        (Some(dir), Some(fname)) => dir.join(fname),
                                        (Some(dir), None) => dir.clone(),
                                        (None, Some(fname)) => PathBuf::from(fname),
                                        (None, None) => PathBuf::from("<unknown>"),
                                    };

                                    let full_path_str = full_path.to_string_lossy().to_string();

                                    if self.is_excluded(&full_path) {
                                        continue;
                                    }

                                    let (threat_type, description) = if mask.contains(EventMask::MODIFY) {
                                        (
                                            ThreatType::FileModified,
                                            format!("File modified (inotify): {}", full_path_str),
                                        )
                                    } else if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
                                        (
                                            ThreatType::FileAdded,
                                            format!("File created (inotify): {}", full_path_str),
                                        )
                                    } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
                                        (
                                            ThreatType::FileDeleted,
                                            format!("File deleted (inotify): {}", full_path_str),
                                        )
                                    } else {
                                        continue;
                                    };

                                    let event = ThreatEvent::new(threat_type, "file_integrity", &description)
                                        .with_target(&full_path_str);

                                    info!(file = %full_path_str, event_type = %event.threat_type, "inotify event");

                                    if tx.send(event).await.is_err() {
                                        debug!("Watch channel closed, stopping");
                                        return Ok(());
                                    }
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break; // No more events available
                            }
                            Err(e) => {
                                warn!(error = %e, "Error reading inotify events");
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
