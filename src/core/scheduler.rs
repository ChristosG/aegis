use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// A periodic scheduler for daemon mode that runs tasks on configurable
/// intervals and supports graceful shutdown via a CancellationToken.
pub struct Scheduler {
    /// Maps module/task name to its scheduled interval.
    intervals: HashMap<String, Duration>,
    /// Token used to signal all spawned tasks to stop.
    cancel: CancellationToken,
}

impl Scheduler {
    /// Create a new scheduler with the given cancellation token.
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            intervals: HashMap::new(),
            cancel,
        }
    }

    /// Register a module with its scheduling interval.
    pub fn add_interval(&mut self, name: impl Into<String>, interval: Duration) {
        self.intervals.insert(name.into(), interval);
    }

    /// Get the configured interval for a module.
    pub fn get_interval(&self, name: &str) -> Option<Duration> {
        self.intervals.get(name).copied()
    }

    /// Get a clone of the cancellation token (for passing to spawned tasks).
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Run a single periodic task until cancelled. Spawns the task on the
    /// current Tokio runtime. Returns a JoinHandle for the background task.
    pub fn spawn_periodic<F, Fut>(
        &self,
        name: &str,
        interval: Duration,
        task: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let cancel = self.cancel.clone();
        let task_name = name.to_string();

        tokio::spawn(async move {
            info!(
                task = %task_name,
                interval_secs = interval.as_secs(),
                "Starting periodic task"
            );

            let mut ticker = time::interval(interval);
            // The first tick fires immediately; consume it so the first real
            // execution happens after one full interval.
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!(task = %task_name, "Periodic task cancelled, shutting down");
                        return;
                    }
                    _ = ticker.tick() => {
                        debug!(task = %task_name, "Running scheduled task");
                        if let Err(e) = task().await {
                            error!(task = %task_name, error = %e, "Scheduled task failed");
                        }
                    }
                }
            }
        })
    }

    /// Convenience: run all registered intervals, calling the provided
    /// dispatch function with the module name on each tick. Returns handles
    /// for all spawned tasks.
    pub fn run_all<F, Fut>(&self, dispatch: F) -> Vec<tokio::task::JoinHandle<()>>
    where
        F: Fn(String) -> Fut + Send + Clone + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let mut handles = Vec::new();

        for (name, interval) in &self.intervals {
            let cancel = self.cancel.clone();
            let task_name = name.clone();
            let interval = *interval;
            let dispatch = dispatch.clone();

            let handle = tokio::spawn(async move {
                info!(
                    task = %task_name,
                    interval_secs = interval.as_secs(),
                    "Starting scheduled module"
                );

                let mut ticker = time::interval(interval);
                ticker.tick().await; // consume immediate first tick

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            info!(task = %task_name, "Module scheduler cancelled");
                            return;
                        }
                        _ = ticker.tick() => {
                            debug!(task = %task_name, "Dispatching scheduled module");
                            if let Err(e) = dispatch(task_name.clone()).await {
                                error!(
                                    task = %task_name,
                                    error = %e,
                                    "Scheduled module execution failed"
                                );
                            }
                        }
                    }
                }
            });

            handles.push(handle);
        }

        if handles.is_empty() {
            warn!("No intervals registered; scheduler has nothing to run");
        }

        handles
    }

    /// Trigger graceful shutdown of all tasks managed by this scheduler.
    pub fn shutdown(&self) {
        info!("Scheduler shutdown requested");
        self.cancel.cancel();
    }

    /// Run a one-shot task as a static helper, useful for standalone scheduling
    /// without constructing a full Scheduler instance.
    pub async fn run_periodic_standalone<F, Fut>(
        name: &str,
        interval: Duration,
        cancel: CancellationToken,
        task: F,
    ) -> Result<()>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        info!(
            task = name,
            interval_secs = interval.as_secs(),
            "Starting periodic task (standalone)"
        );
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!(task = name, "Periodic task cancelled, shutting down");
                    return Ok(());
                }
                _ = ticker.tick() => {
                    debug!(task = name, "Running scheduled task");
                    if let Err(e) = task().await {
                        error!(task = name, error = %e, "Scheduled task failed");
                    }
                }
            }
        }
    }

    /// Parse a duration string like "6h", "30m", "300s", "1d" into a Duration.
    pub fn parse_duration(s: &str) -> Result<Duration> {
        let s = s.trim();
        if s.is_empty() {
            anyhow::bail!("Empty duration string");
        }

        let (num_str, unit) = if let Some(stripped) = s.strip_suffix('d') {
            (stripped, "d")
        } else if let Some(stripped) = s.strip_suffix('h') {
            (stripped, "h")
        } else if let Some(stripped) = s.strip_suffix('m') {
            (stripped, "m")
        } else if let Some(stripped) = s.strip_suffix('s') {
            (stripped, "s")
        } else {
            // Assume seconds if no unit
            (s, "s")
        };

        let num: u64 = num_str
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid duration number: '{}'", num_str))?;

        let secs = match unit {
            "d" => num * 86400,
            "h" => num * 3600,
            "m" => num * 60,
            "s" => num,
            _ => unreachable!(),
        };

        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(
            Scheduler::parse_duration("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            Scheduler::parse_duration("5m").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            Scheduler::parse_duration("2h").unwrap(),
            Duration::from_secs(7200)
        );
        assert_eq!(
            Scheduler::parse_duration("1d").unwrap(),
            Duration::from_secs(86400)
        );
        assert_eq!(
            Scheduler::parse_duration("300").unwrap(),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(Scheduler::parse_duration("").is_err());
        assert!(Scheduler::parse_duration("abc").is_err());
    }

    #[test]
    fn test_scheduler_intervals() {
        let cancel = CancellationToken::new();
        let mut sched = Scheduler::new(cancel);
        sched.add_interval("network", Duration::from_secs(30));
        sched.add_interval("process", Duration::from_secs(60));

        assert_eq!(sched.get_interval("network"), Some(Duration::from_secs(30)));
        assert_eq!(sched.get_interval("process"), Some(Duration::from_secs(60)));
        assert_eq!(sched.get_interval("nonexistent"), None);
    }

    #[tokio::test]
    async fn test_scheduler_shutdown() {
        let cancel = CancellationToken::new();
        let sched = Scheduler::new(cancel.clone());

        let handle =
            sched.spawn_periodic("test_task", Duration::from_secs(3600), || async { Ok(()) });

        // Shutdown should cause the task to complete
        sched.shutdown();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_run_all_empty() {
        let cancel = CancellationToken::new();
        let sched = Scheduler::new(cancel);
        let handles = sched.run_all(|_name: String| async { Ok(()) });
        assert!(handles.is_empty());
    }
}
