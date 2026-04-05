//! The core Aegis engine that orchestrates security scanning modules,
//! processes threat events, coordinates automated responses, and manages
//! both one-shot scan and continuous daemon modes.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use colored::Colorize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::alerting::AlertManager;
use crate::cli::output::{self, ScanSummary};
use crate::config::defaults::resolve_path;
use crate::config::schema::AegisConfig;
use crate::core::event_bus::EventBus;
use crate::core::scheduler::Scheduler;
use crate::core::state::AppState;
use crate::core::threat::ThreatEvent;
use crate::modules::{self, ScanModule};
use crate::response::{ResponseAction, ResponseEngine};
use crate::storage::{SeenEntry, Storage};

/// The central Aegis engine that orchestrates scanning modules, processes
/// threat events, and coordinates automated responses.
pub struct Engine {
    /// Shared application state (threats, blocked IPs, posture, config).
    state: Arc<RwLock<AppState>>,
    /// Registered scanning modules (Arc for sharing with daemon tasks).
    modules: Vec<Arc<dyn ScanModule>>,
    /// Publish-subscribe bus for distributing threat events.
    event_bus: EventBus,
    /// Configuration snapshot.
    config: AegisConfig,
    /// Automated response engine (Arc for sharing with web dashboard).
    response_engine: Arc<ResponseEngine>,
    /// Alerting subsystem (email, webhook, log file) (Arc for sharing).
    alert_manager: Arc<AlertManager>,
    /// Persistence layer for threat logs and dedup state (Arc for sharing).
    storage: Arc<Storage>,
}

impl Engine {
    /// Create a new Engine, registering all modules enabled in the configuration.
    ///
    /// The engine initialises shared state from the configuration, creates an
    /// event bus with a 1024-event capacity, builds the response engine, and
    /// instantiates every scan module listed in `config.general.modules`.
    ///
    /// If a persisted block list exists on disk, it is loaded into state so
    /// that previously blocked IPs are remembered across runs.
    pub fn new(config: AegisConfig) -> Self {
        let event_bus = EventBus::new(1024);
        let data_dir = resolve_path(&config.general.data_dir);
        let response_engine = ResponseEngine::new(config.response.clone(), data_dir.clone());
        let alert_manager = AlertManager::new(config.alerting.clone());
        let enabled_modules = modules::create_modules(&config);

        info!(
            module_count = enabled_modules.len(),
            "Engine initialised with {} module(s)",
            enabled_modules.len()
        );

        // Build initial state and try to load persisted block list.
        let mut initial_state = AppState::with_config(config.clone());
        let storage = Storage::new(&data_dir);
        if let Ok(blocked) = storage.load_block_list() {
            if !blocked.is_empty() {
                // Filter out expired blocks before restoring
                let now = chrono::Utc::now();
                let active: std::collections::HashMap<_, _> = blocked
                    .into_iter()
                    .filter(|(_, entry)| entry.expires_at.is_none_or(|exp| exp > now))
                    .collect();

                if !active.is_empty() {
                    info!(
                        count = active.len(),
                        "Restoring {} blocked IP(s) from disk",
                        active.len()
                    );
                    // Re-apply firewall rules for persisted blocks
                    let mut restored = 0u32;
                    for ip in active.keys() {
                        if let Err(e) = response_engine.block_ip_firewall(ip) {
                            warn!(ip = %ip, error = %e, "Failed to restore firewall block");
                        } else {
                            restored += 1;
                        }
                    }
                    info!(restored, "Restored firewall rules for blocked IPs");
                    initial_state.blocked_ips = active;
                }
            }
        }

        // Restore strike history for repeat offender tracking.
        match storage.load_strike_history() {
            Ok(history) if !history.is_empty() => {
                info!(
                    count = history.len(),
                    "Restoring {} strike record(s) from disk",
                    history.len()
                );
                initial_state.strike_history = history;
            }
            Err(e) => {
                warn!(error = %e, "Failed to load strike history");
            }
            _ => {}
        }

        // Restore historical threats so the dashboard shows them on restart.
        match storage.load_threats() {
            Ok(threats) if !threats.is_empty() => {
                info!(
                    count = threats.len(),
                    "Restoring {} threat(s) from disk",
                    threats.len()
                );
                initial_state.add_threats(threats);
                // Cap immediately to prevent OOM from large threat logs.
                let evicted = initial_state.cap_threats();
                if evicted > 0 {
                    info!(evicted, "Capped in-memory threats on startup");
                }
            }
            _ => {}
        }

        Self {
            state: Arc::new(RwLock::new(initial_state)),
            modules: enabled_modules,
            event_bus,
            config,
            response_engine: Arc::new(response_engine),
            alert_manager: Arc::new(alert_manager),
            storage: Arc::new(storage),
        }
    }

    /// Register an additional scanning module at runtime.
    pub fn register_module(&mut self, module: Box<dyn ScanModule>) {
        info!(module = module.name(), "Registering additional module");
        self.modules.push(Arc::from(module));
    }

    /// Return a clone of the shared application state handle.
    pub fn state(&self) -> Arc<RwLock<AppState>> {
        Arc::clone(&self.state)
    }

    /// Return a reference to the event bus.
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Return a clone of the event bus (for web dashboard sharing).
    pub fn event_bus_clone(&self) -> EventBus {
        self.event_bus.clone()
    }

    /// Return the Arc-wrapped config for sharing.
    pub fn config(&self) -> &AegisConfig {
        &self.config
    }

    /// Return the Arc-wrapped response engine for sharing.
    pub fn response_engine(&self) -> Arc<ResponseEngine> {
        Arc::clone(&self.response_engine)
    }

    /// Return the Arc-wrapped alert manager for sharing.
    pub fn alert_manager(&self) -> Arc<AlertManager> {
        Arc::clone(&self.alert_manager)
    }

    /// Return the Arc-wrapped storage for sharing.
    pub fn storage(&self) -> Arc<Storage> {
        Arc::clone(&self.storage)
    }

    // -----------------------------------------------------------------------
    // Manual CLI block/unblock
    // -----------------------------------------------------------------------

    /// Block an IP manually (CLI). Adds firewall rule, updates state, persists.
    pub async fn cli_block_ip(&self, entry: crate::core::state::BlockEntry) -> Result<()> {
        if let Err(e) = self.response_engine.block_ip_firewall(&entry.ip) {
            warn!(ip = %entry.ip, error = %e, "Firewall block failed (may need root)");
        }
        let mut state = self.state.write().await;
        state.block_ip(entry);
        if let Err(e) = self.storage.save_block_list(&state.blocked_ips) {
            warn!(error = %e, "Failed to persist block list");
        }
        Ok(())
    }

    /// Unblock an IP manually (CLI). Removes firewall rule, updates state, persists.
    pub async fn cli_unblock_ip(&self, ip: &std::net::IpAddr) -> Result<bool> {
        if let Err(e) = self.response_engine.unblock_ip_firewall(ip) {
            warn!(ip = %ip, error = %e, "Firewall unblock failed");
        }
        let mut state = self.state.write().await;
        let removed = state.unblock_ip(ip);
        if removed {
            if let Err(e) = self.storage.save_block_list(&state.blocked_ips) {
                warn!(error = %e, "Failed to persist block list");
            }
        }
        Ok(removed)
    }

    // -----------------------------------------------------------------------
    // One-shot scan
    // -----------------------------------------------------------------------

    /// Run a one-shot scan across selected modules (or all if `module_filter`
    /// is `None`). Returns the collected threat events.
    ///
    /// If `auto_respond` is true the response engine is invoked for each
    /// detected threat after all modules have completed. IPs that are already
    /// blocked are skipped (no duplicate firewall rules).
    pub async fn run_scan(
        &self,
        module_filter: Option<Vec<String>>,
        auto_respond: bool,
    ) -> Result<Vec<ThreatEvent>> {
        let scan_start = Instant::now();
        let mut all_threats: Vec<ThreatEvent> = Vec::new();
        let mut modules_run: Vec<String> = Vec::new();

        // Record that a scan has started.
        {
            let mut state = self.state.write().await;
            state.record_scan();
        }

        output::print_banner();

        for module in &self.modules {
            // Apply module filter if specified.
            if let Some(ref filter) = module_filter {
                if !filter.iter().any(|f| f == module.name()) {
                    continue;
                }
            }

            output::print_scan_header(module.name());
            info!(module = module.name(), "Running scan module");

            match module.scan().await {
                Ok(threats) => {
                    info!(
                        module = module.name(),
                        count = threats.len(),
                        "Module scan complete"
                    );

                    // Print each threat and publish it on the event bus.
                    for threat in &threats {
                        output::print_threat(threat);
                        self.event_bus.try_publish(threat.clone());
                    }

                    all_threats.extend(threats);
                    modules_run.push(module.name().to_string());

                    // Mark module as run in shared state.
                    {
                        let mut state = self.state.write().await;
                        state.mark_module_run(module.name());
                    }
                }
                Err(e) => {
                    error!(
                        module = module.name(),
                        error = %e,
                        "Module scan failed"
                    );
                    eprintln!(
                        "  {} Module '{}' failed: {}",
                        "ERROR".red(),
                        module.name(),
                        e
                    );
                }
            }
        }

        // ---------------------------------------------------------------
        // Deduplication: filter out threats already seen within the TTL
        // ---------------------------------------------------------------
        let dedup_ttl = Scheduler::parse_duration(&self.config.general.dedup_ttl)
            .unwrap_or(std::time::Duration::from_secs(3600));
        let dedup_enabled = dedup_ttl.as_secs() > 0;

        let mut seen = self.storage.load_seen_threats().unwrap_or_default();
        // Prune entries older than 24h to keep file size bounded.
        Storage::prune_seen_threats(&mut seen, std::time::Duration::from_secs(86400));

        let mut suppressed_count: usize = 0;

        if dedup_enabled {
            let now = Utc::now();
            let ttl_chrono =
                chrono::Duration::from_std(dedup_ttl).unwrap_or(chrono::Duration::hours(1));
            let cutoff = now - ttl_chrono;

            let total_before = all_threats.len();
            all_threats.retain(|threat| {
                let fp = threat_fingerprint(threat);
                if let Some(entry) = seen.get(&fp) {
                    if entry.last_seen >= cutoff {
                        return false; // suppress
                    }
                }
                true
            });
            suppressed_count = total_before - all_threats.len();

            if suppressed_count > 0 {
                info!(
                    suppressed = suppressed_count,
                    "Suppressed previously seen threats within TTL"
                );
            }
        }

        // Auto-respond if enabled.
        if auto_respond && self.config.response.enabled {
            info!("Running auto-response for {} threat(s)", all_threats.len());
            self.auto_respond(&mut all_threats).await;

            // Persist the updated block list and strike history to disk.
            self.persist_block_list().await;
            {
                let state = self.state.read().await;
                if let Err(e) = self.storage.save_strike_history(&state.strike_history) {
                    warn!(error = %e, "Failed to persist strike history after scan");
                }
            }
        }

        // Update seen-threats with the new (non-suppressed) threats.
        let now = Utc::now();
        for threat in &all_threats {
            let fp = threat_fingerprint(threat);
            let entry = seen.entry(fp).or_insert_with(|| SeenEntry {
                first_seen: now,
                last_seen: now,
                count: 0,
                responded: false,
            });
            entry.last_seen = now;
            entry.count += 1;
            if threat.auto_responded {
                entry.responded = true;
            }
        }
        if let Err(e) = self.storage.save_seen_threats(&seen) {
            warn!(error = %e, "Failed to persist seen threats");
        }

        // Write threats to the JSONL log.
        if let Err(e) = self.storage.append_threats(&all_threats) {
            warn!(error = %e, "Failed to write threats to JSONL log");
        }

        // Send alerts (email, webhook, etc.) for each threat.
        for threat in &all_threats {
            if let Err(e) = self.alert_manager.alert(threat).await {
                warn!(error = %e, "Alert delivery failed");
            }
        }

        // Print summary (before moving threats into state to avoid a clone).
        let duration = scan_start.elapsed();
        let summary = ScanSummary::from_threats(
            &all_threats,
            duration,
            modules_run,
            suppressed_count,
            &self.config.general.dedup_ttl,
        );
        output::print_scan_summary(&summary);

        // Print the full threat table when there are results.
        if !all_threats.is_empty() {
            output::print_threats_table(&all_threats);
        }

        // Print response summary if auto-respond was active.
        if auto_respond {
            output::print_response_summary(&all_threats);
        }

        // Persist all threats in shared state (move, no clone needed).
        {
            let mut state = self.state.write().await;
            state.add_threats(all_threats.clone());
        }

        Ok(all_threats)
    }

    // -----------------------------------------------------------------------
    // Daemon (watch) mode
    // -----------------------------------------------------------------------

    /// Start all modules in watch (daemon) mode. Each module runs in its own
    /// task, periodically calling scan() and forwarding detected threats
    /// through a channel to the central event processing loop.
    ///
    /// Blocks until the `cancel` token is triggered (e.g. via SIGINT/SIGTERM).
    pub async fn run_daemon(&self, cancel: CancellationToken) -> Result<()> {
        output::print_banner();
        info!("Starting daemon mode");

        println!(
            "\n  {} Daemon is running. Modules will scan every 60 seconds.",
            "ACTIVE".green().bold()
        );
        println!("  Press Ctrl+C to stop.\n");

        {
            let mut state = self.state.write().await;
            state.daemon_running = true;
        }

        // Channel for modules to send threats to the central handler.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ThreatEvent>(512);

        // Spawn a watch task for each module. Modules with a real watch()
        // implementation (e.g. file_integrity with inotify) use native
        // watching; others fall back to a 60-second scan loop.
        let mut tasks = Vec::new();
        for module in &self.modules {
            let module = Arc::clone(module);
            let module_tx = tx.clone();
            let module_cancel = cancel.clone();
            let module_name = module.name().to_string();

            info!(module = %module_name, supports_watch = module.supports_watch(), "Starting watch task");

            if module.supports_watch() {
                // Use the module's native watch implementation.
                tasks.push(tokio::spawn(async move {
                    // Early exit if already cancelled (avoids lingering blocking tasks).
                    if module_cancel.is_cancelled() {
                        return;
                    }
                    info!(module = %module_name, "Using native watch mode");
                    if let Err(e) = module.watch(module_tx, module_cancel).await {
                        error!(module = %module_name, error = %e, "Watch task failed");
                    }
                }));
            } else {
                // Fallback: periodic scan loop.
                let scan_interval = std::time::Duration::from_secs(60);
                tasks.push(tokio::spawn(async move {
                    info!(module = %module_name, "Watch task started (60s scan loop)");
                    let mut interval = tokio::time::interval(scan_interval);

                    loop {
                        tokio::select! {
                            _ = module_cancel.cancelled() => {
                                info!(module = %module_name, "Watch task cancelled");
                                break;
                            }
                            _ = interval.tick() => {
                                info!(module = %module_name, "Running periodic scan");
                                match module.scan().await {
                                    Ok(threats) => {
                                        if !threats.is_empty() {
                                            info!(
                                                module = %module_name,
                                                count = threats.len(),
                                                "Daemon scan found {} threat(s)",
                                                threats.len()
                                            );
                                        }
                                        for threat in threats {
                                            if module_tx.send(threat).await.is_err() {
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            module = %module_name,
                                            error = %e,
                                            "Periodic scan failed"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }));
            }
        }

        // Drop the master sender so the channel closes when all tasks exit.
        drop(tx);

        // Central event processing loop with TTL-aware deduplication.
        let dedup_ttl = Scheduler::parse_duration(&self.config.general.dedup_ttl)
            .unwrap_or(std::time::Duration::from_secs(3600));
        let dedup_enabled = dedup_ttl.as_secs() > 0;
        let ttl_chrono =
            chrono::Duration::from_std(dedup_ttl).unwrap_or(chrono::Duration::hours(1));

        let mut seen = self.storage.load_seen_threats().unwrap_or_default();
        // Prune stale entries on startup.
        Storage::prune_seen_threats(&mut seen, std::time::Duration::from_secs(86400));
        let mut suppressed_since_last_log: usize = 0;
        let mut last_suppression_log = Instant::now();

        // Housekeeping timer: runs every 5 minutes to prune memory and expire blocks.
        let mut housekeeping_interval = tokio::time::interval(std::time::Duration::from_secs(300));
        // Don't fire immediately on startup.
        housekeeping_interval.tick().await;

        info!("Event processing loop started");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Daemon shutdown requested");
                    break;
                }
                _ = housekeeping_interval.tick() => {
                    // Cap in-memory threats
                    {
                        let mut state = self.state.write().await;
                        let evicted = state.cap_threats();
                        let expired = state.expire_blocks();
                        if evicted > 0 {
                            info!(evicted, "Housekeeping: trimmed in-memory threats");
                        }
                        if expired > 0 {
                            info!(expired, "Housekeeping: removed expired IP blocks");
                            if let Err(e) = self.storage.save_block_list(&state.blocked_ips) {
                                warn!(error = %e, "Failed to persist block list after expiry");
                            }
                        }

                        // v2.6.0 Bucket D: drift detection between the persisted
                        // block list and the live AEGIS_BLOCK firewall chain.
                        // Runs every 5 min (every housekeeping tick). The
                        // `reconcile_interval_minutes` config field is reserved
                        // for future dedicated scheduling; for now, 5 min gives
                        // us fast detection of manual tampering without much
                        // overhead (iptables -S subprocess completes in <100ms
                        // even for chains with thousands of rules).
                        let report = self.response_engine.reconcile_firewall_state(&mut state);
                        if !report.is_in_sync() {
                            warn!(
                                persisted = report.persisted_count,
                                firewall = report.firewall_count,
                                missing = report.missing_from_firewall.len(),
                                orphaned = report.orphaned_in_firewall.len(),
                                auto_reconciled = report.auto_reconciled,
                                "Housekeeping: firewall drift detected"
                            );
                            // If auto-reconcile fixed missing rules, persist the
                            // block list so restart is consistent.
                            if report.auto_reconciled {
                                if let Err(e) = self.storage.save_block_list(&state.blocked_ips) {
                                    warn!(error = %e, "Failed to persist block list after reconcile");
                                }
                            }
                        }
                    }
                    // Prune expired blocks from disk
                    if let Err(e) = self.storage.prune_expired_blocks() {
                        warn!(error = %e, "Failed to prune expired blocks from disk");
                    }
                    // Prune stale seen-threats
                    Storage::prune_seen_threats(&mut seen, std::time::Duration::from_secs(86400));
                    if let Err(e) = self.storage.save_seen_threats(&seen) {
                        warn!(error = %e, "Failed to persist seen threats during housekeeping");
                    }
                    // Prune and persist strike history
                    {
                        let mut state = self.state.write().await;
                        let window = Scheduler::parse_duration(&self.config.response.repeat_offender_window)
                            .map(|d| chrono::Duration::from_std(d).unwrap_or(chrono::Duration::days(30)))
                            .unwrap_or(chrono::Duration::days(30));
                        let pruned = state.prune_strikes(window, self.config.response.max_strike_records);
                        if pruned > 0 {
                            info!(pruned, "Housekeeping: pruned old strike records");
                        }
                        if let Err(e) = self.storage.save_strike_history(&state.strike_history) {
                            warn!(error = %e, "Failed to persist strike history during housekeeping");
                        }
                    }
                    info!("Housekeeping cycle complete");
                }
                maybe_threat = rx.recv() => {
                    match maybe_threat {
                        Some(threat) => {
                            let fingerprint = threat_fingerprint(&threat);
                            let now = Utc::now();

                            // TTL-aware dedup: suppress if seen within TTL window.
                            if dedup_enabled {
                                if let Some(entry) = seen.get(&fingerprint) {
                                    if entry.last_seen >= now - ttl_chrono {
                                        // Update count and skip processing.
                                        if let Some(entry) = seen.get_mut(&fingerprint) {
                                            entry.last_seen = now;
                                            entry.count += 1;
                                        }
                                        suppressed_since_last_log += 1;

                                        // Log a suppression summary every 60 seconds.
                                        if last_suppression_log.elapsed() >= std::time::Duration::from_secs(60) {
                                            info!(
                                                suppressed = suppressed_since_last_log,
                                                "Suppressed {} duplicate threat(s) in the last 60s",
                                                suppressed_since_last_log
                                            );
                                            suppressed_since_last_log = 0;
                                            last_suppression_log = Instant::now();
                                        }
                                        continue;
                                    }
                                }
                            }

                            // Record in seen map.
                            let entry = seen.entry(fingerprint).or_insert_with(|| SeenEntry {
                                first_seen: now,
                                last_seen: now,
                                count: 0,
                                responded: false,
                            });
                            entry.last_seen = now;
                            entry.count += 1;

                            self.handle_daemon_threat(threat).await;
                        }
                        None => {
                            warn!("All module senders closed; stopping event loop");
                            break;
                        }
                    }
                }
            }
        }

        // Wait for all watch tasks to finish, with a timeout to prevent
        // hanging on stuck tasks (e.g. inotify on NFS mount).
        for (i, task) in tasks.into_iter().enumerate() {
            match tokio::time::timeout(std::time::Duration::from_secs(5), task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(task = i, error = %e, "Watch task panicked during shutdown"),
                Err(_) => warn!(task = i, "Watch task did not exit within 5s, abandoning"),
            }
        }

        {
            let mut state = self.state.write().await;
            state.daemon_running = false;
        }

        // Persist seen-threats, block list, and strike history on shutdown.
        if let Err(e) = self.storage.save_seen_threats(&seen) {
            warn!(error = %e, "Failed to persist seen threats on shutdown");
        }
        self.persist_block_list().await;
        {
            let state = self.state.read().await;
            if let Err(e) = self.storage.save_strike_history(&state.strike_history) {
                warn!(error = %e, "Failed to persist strike history on shutdown");
            }
        }

        info!("Daemon shutdown complete");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Process a single threat event received during daemon mode.
    async fn handle_daemon_threat(&self, mut threat: ThreatEvent) {
        info!(
            id = %threat.id,
            threat_type = %threat.threat_type,
            severity = %threat.severity,
            "Received threat event in daemon loop"
        );

        // Print to terminal so the operator sees it in real time.
        output::print_threat(&threat);

        // Publish to the event bus for subscribers (alerting, logging, etc.).
        self.event_bus.try_publish(threat.clone());

        // Auto-respond if the response engine is enabled.
        if self.config.response.enabled {
            let action = self.response_engine.determine_action(&threat);
            if action != ResponseAction::Log {
                let mut state = self.state.write().await;
                match self.response_engine.respond(&threat, &mut state).await {
                    Ok(msg) => {
                        info!(action = %msg, "Auto-response executed");
                        threat.auto_responded = true;
                        threat
                            .details
                            .insert("response_action".to_string(), format!("{}", action));
                        println!("    {} {}", "RESPONSE:".green().bold(), msg);
                    }
                    Err(e) => error!(error = %e, "Auto-response failed"),
                }
            }
        }

        // Write threat to the JSONL log.
        if let Err(e) = self.storage.append_threat(&threat) {
            warn!(error = %e, "Failed to write threat to JSONL log");
        }

        // Send alerts (email, webhook, etc.).
        if let Err(e) = self.alert_manager.alert(&threat).await {
            warn!(error = %e, "Alert delivery failed");
        }

        // Store the threat in shared state and persist strike history.
        {
            let mut state = self.state.write().await;
            state.add_threat(threat);
            if let Err(e) = self.storage.save_strike_history(&state.strike_history) {
                warn!(error = %e, "Failed to persist strike history after auto-respond");
            }
        }
    }

    /// Run the response engine against each threat, mutating each threat's
    /// `auto_responded` flag when an action is taken.
    async fn auto_respond(&self, threats: &mut [ThreatEvent]) {
        let mut state = self.state.write().await;

        for threat in threats.iter_mut() {
            let action = self.response_engine.determine_action(threat);
            if action == ResponseAction::Log {
                continue;
            }

            match self.response_engine.respond(threat, &mut state).await {
                Ok(msg) => {
                    info!(
                        threat_id = %threat.id,
                        action = %msg,
                        "Auto-response executed"
                    );
                    threat.auto_responded = true;
                    threat
                        .details
                        .insert("response_action".to_string(), format!("{}", action));
                }
                Err(e) => {
                    error!(
                        threat_id = %threat.id,
                        error = %e,
                        "Auto-response failed"
                    );
                }
            }
        }
    }

    /// Save the current block list to disk.
    async fn persist_block_list(&self) {
        let state = self.state.read().await;
        if let Err(e) = self.storage.save_block_list(&state.blocked_ips) {
            warn!(error = %e, "Failed to persist block list to disk");
        } else if !state.blocked_ips.is_empty() {
            info!(count = state.blocked_ips.len(), "Block list saved to disk");
        }
    }
}

/// Compute a deduplication fingerprint for a threat event.
/// Format: "threat_type|source_ip|target"
fn threat_fingerprint(threat: &ThreatEvent) -> String {
    format!(
        "{}|{}|{}",
        threat.threat_type,
        threat
            .source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        threat.target.as_deref().unwrap_or("")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a config with an empty temp data dir so tests don't
    /// load real threat/block data from ~/.aegis.
    fn test_config() -> (AegisConfig, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = AegisConfig::default();
        config.general.data_dir = tmp.path().to_string_lossy().to_string();
        (config, tmp)
    }

    #[tokio::test]
    async fn test_engine_creation() {
        let (config, _tmp) = test_config();
        let engine = Engine::new(config);

        // Default config enables all 6 modules.
        assert!(!engine.modules.is_empty());

        let state = engine.state.read().await;
        assert_eq!(state.threats.len(), 0);
        assert!(!state.daemon_running);
    }

    #[tokio::test]
    async fn test_engine_scan_all_modules() {
        let (config, _tmp) = test_config();
        let engine = Engine::new(config);

        // Run scan without auto-respond, no filter (all modules).
        let threats = engine.run_scan(None, false).await.unwrap();

        // Modules now produce real results on a live system.
        let state = engine.state.read().await;
        assert!(!state.modules_run.is_empty());
        assert_eq!(state.stats.scans_run, 1);
        assert_eq!(state.stats.threats_found, threats.len() as u64);
    }

    #[tokio::test]
    async fn test_engine_scan_filtered() {
        let config = AegisConfig::default();
        let engine = Engine::new(config);

        let filter = Some(vec!["network".to_string()]);
        let threats = engine.run_scan(filter, false).await.unwrap();

        // Threats may or may not be empty depending on the live system state.
        let _ = threats;

        let state = engine.state.read().await;
        assert!(state.modules_run.contains("network"));
        // Other modules should not have been run.
        assert!(!state.modules_run.contains("auth"));
    }

    #[tokio::test]
    async fn test_engine_daemon_cancellation() {
        let config = AegisConfig::default();
        let engine = Engine::new(config);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Cancel immediately so the daemon exits right away.
        cancel_clone.cancel();

        let result = engine.run_daemon(cancel).await;
        assert!(result.is_ok());

        let state = engine.state.read().await;
        assert!(!state.daemon_running);
    }

    #[tokio::test]
    async fn test_register_module() {
        use crate::config::schema::NetworkConfig;
        use crate::modules::network::NetworkModule;

        let mut config = AegisConfig::default();
        config.general.modules.clear(); // Start with no modules
        let mut engine = Engine::new(config);
        assert!(engine.modules.is_empty());

        engine.register_module(Box::new(NetworkModule::new(NetworkConfig::default())));
        assert_eq!(engine.modules.len(), 1);
        assert_eq!(engine.modules[0].name(), "network");
    }

    #[tokio::test]
    async fn test_engine_state_sharing() {
        let config = AegisConfig::default();
        let engine = Engine::new(config);

        let state_handle = engine.state();
        {
            let mut state = state_handle.write().await;
            state.mark_module_run("test_module");
        }

        let state = engine.state.read().await;
        assert!(state.modules_run.contains("test_module"));
    }
}
