use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Tracks byte offsets for log files across scans so modules only process
/// new lines instead of re-reading the full history every time.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LogCursors {
    offsets: HashMap<String, u64>,
}

impl LogCursors {
    /// Load cursors from a JSON file. Returns default if file doesn't exist.
    pub fn load(path: &Path) -> Self {
        if path.exists() {
            fs::read_to_string(path)
                .ok()
                .and_then(|json| serde_json::from_str(&json).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Save cursors to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Read lines from a log file with incremental tracking.
    ///
    /// - First scan (no saved offset): reads last `tail_lines` lines, saves offset at EOF
    /// - Subsequent scans: reads only new lines added since last scan
    /// - Log rotation (file smaller than saved offset): reads from beginning
    pub fn read_lines(&mut self, file_path: &Path, tail_lines: usize) -> Result<Vec<String>> {
        let key = file_path.to_string_lossy().to_string();
        let file = fs::File::open(file_path)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        let file_len = file.metadata()?.len();

        if let Some(&saved_offset) = self.offsets.get(&key) {
            if saved_offset <= file_len && saved_offset > 0 {
                // Incremental read: only new lines since last scan
                let mut reader = BufReader::new(file);
                reader.seek(SeekFrom::Start(saved_offset))?;
                let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
                debug!(
                    path = %key,
                    new_lines = lines.len(),
                    "Incremental read: {} new line(s) since last scan",
                    lines.len()
                );
                self.offsets.insert(key, file_len);
                return Ok(lines);
            }
            // File rotated (smaller than saved offset) — read from beginning
            debug!(path = %key, "Log file rotated, reading from beginning");
        }

        // First scan or rotation: read last N lines, set cursor to EOF
        let reader = BufReader::new(file);
        let all_lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
        let start = all_lines.len().saturating_sub(tail_lines);
        debug!(
            path = %key,
            total_lines = all_lines.len(),
            reading_from = start,
            "Initial scan: reading last {} line(s)",
            all_lines.len() - start
        );
        self.offsets.insert(key, file_len);
        Ok(all_lines[start..].to_vec())
    }

    /// Derive the cursor file path for a given module name.
    /// Stored in `<data_dir>/cursor_{module}.json`.
    pub fn path_for_module(module_name: &str, data_dir: &Path) -> PathBuf {
        data_dir.join(format!("cursor_{}.json", module_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_read_gets_tail_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // Write 20 lines
        let mut content = String::new();
        for i in 0..20 {
            content.push_str(&format!("line {}\n", i));
        }
        std::fs::write(&log_path, &content).unwrap();

        let mut cursors = LogCursors::default();
        let lines = cursors.read_lines(&log_path, 5).unwrap();

        // Should get last 5 lines
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "line 15");
        assert_eq!(lines[4], "line 19");
    }

    #[test]
    fn test_incremental_read_gets_new_lines_only() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // Write initial content
        let mut content = String::new();
        for i in 0..10 {
            content.push_str(&format!("line {}\n", i));
        }
        std::fs::write(&log_path, &content).unwrap();

        let mut cursors = LogCursors::default();

        // First read
        let lines = cursors.read_lines(&log_path, 100).unwrap();
        assert_eq!(lines.len(), 10);

        // Append new lines
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        use std::io::Write;
        writeln!(file, "new line 1").unwrap();
        writeln!(file, "new line 2").unwrap();
        drop(file);

        // Second read — should only get the 2 new lines
        let lines = cursors.read_lines(&log_path, 100).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "new line 1");
        assert_eq!(lines[1], "new line 2");
    }

    #[test]
    fn test_log_rotation_resets_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        // Write large initial content
        let content: String = (0..100).map(|i| format!("line {}\n", i)).collect();
        std::fs::write(&log_path, &content).unwrap();

        let mut cursors = LogCursors::default();
        let _ = cursors.read_lines(&log_path, 100).unwrap();

        // Simulate log rotation: replace with smaller file
        std::fs::write(&log_path, "rotated line 1\nrotated line 2\n").unwrap();

        let lines = cursors.read_lines(&log_path, 100).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "rotated line 1");
    }

    #[test]
    fn test_save_and_load_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let cursor_path = dir.path().join("cursors.json");
        let log_path = dir.path().join("test.log");

        std::fs::write(&log_path, "line 1\nline 2\n").unwrap();

        let mut cursors = LogCursors::default();
        let _ = cursors.read_lines(&log_path, 100).unwrap();
        cursors.save(&cursor_path).unwrap();

        // Load from disk
        let loaded = LogCursors::load(&cursor_path);
        let key = log_path.to_string_lossy().to_string();
        assert!(loaded.offsets.contains_key(&key));
    }

    #[test]
    fn test_no_new_lines_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");

        std::fs::write(&log_path, "line 1\nline 2\n").unwrap();

        let mut cursors = LogCursors::default();
        let _ = cursors.read_lines(&log_path, 100).unwrap();

        // Read again with no changes — should get 0 lines
        let lines = cursors.read_lines(&log_path, 100).unwrap();
        assert_eq!(lines.len(), 0);
    }
}
