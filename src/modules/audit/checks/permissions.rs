use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::modules::audit::CisCheckResult;

/// Check critical file permissions according to CIS benchmarks.
pub fn check_permissions() -> Vec<CisCheckResult> {
    vec![
        check_file_perms("6.1.2", "/etc/passwd", 0o644),
        check_file_perms("6.1.3", "/etc/shadow", 0o640),
        check_file_perms("6.1.4", "/etc/group", 0o644),
        check_file_perms("6.1.5", "/etc/gshadow", 0o640),
        check_no_world_writable(),
    ]
}

fn check_file_perms(id: &str, path: &str, max_mode: u32) -> CisCheckResult {
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            let pass = mode <= max_mode;
            CisCheckResult {
                id: id.into(),
                title: format!("Permissions on {}", path),
                pass,
                details: format!("Current: {:o}, expected <= {:o}", mode, max_mode),
                remediation: format!("Run: chmod {:o} {}", max_mode, path),
            }
        }
        Err(e) => CisCheckResult {
            id: id.into(),
            title: format!("Permissions on {}", path),
            pass: false,
            details: format!("Cannot stat {}: {}", path, e),
            remediation: format!("Ensure {} exists with proper permissions", path),
        },
    }
}

fn check_no_world_writable() -> CisCheckResult {
    let dirs = ["/etc", "/usr/bin", "/usr/sbin"];
    let mut world_writable = Vec::new();

    for dir in &dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let mode = meta.permissions().mode();
                    if mode & 0o002 != 0 && !meta.is_dir() {
                        world_writable.push(entry.path().to_string_lossy().to_string());
                        if world_writable.len() >= 10 {
                            break;
                        }
                    }
                }
            }
        }
    }

    let pass = world_writable.is_empty();
    CisCheckResult {
        id: "6.1.9".into(),
        title: "No world-writable files in critical dirs".into(),
        pass,
        details: if pass {
            "No world-writable files found".into()
        } else {
            format!(
                "Found {} world-writable file(s): {}",
                world_writable.len(),
                world_writable.join(", ")
            )
        },
        remediation: "Remove world-writable permission: chmod o-w <file>".into(),
    }
}
