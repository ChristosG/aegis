use anyhow::{bail, Result};
use tracing::warn;

/// Check if the current process is running as root (UID 0).
pub fn check_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Query the Linux capabilities of the current process.
///
/// Reads from /proc/self/status and parses the CapEff (effective capabilities)
/// bitmask, returning a list of human-readable capability names that are set.
pub fn check_capabilities() -> Vec<String> {
    let mut caps = Vec::new();

    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return caps,
    };

    let cap_eff_hex = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1));

    let cap_eff = match cap_eff_hex {
        Some(hex) => match u64::from_str_radix(hex.trim(), 16) {
            Ok(v) => v,
            Err(_) => return caps,
        },
        None => return caps,
    };

    // Map of capability bit index -> name (Linux UAPI, up to kernel 6.x)
    let cap_names: &[(u32, &str)] = &[
        (0, "CAP_CHOWN"),
        (1, "CAP_DAC_OVERRIDE"),
        (2, "CAP_DAC_READ_SEARCH"),
        (3, "CAP_FOWNER"),
        (4, "CAP_FSETID"),
        (5, "CAP_KILL"),
        (6, "CAP_SETGID"),
        (7, "CAP_SETUID"),
        (8, "CAP_SETPCAP"),
        (9, "CAP_LINUX_IMMUTABLE"),
        (10, "CAP_NET_BIND_SERVICE"),
        (11, "CAP_NET_BROADCAST"),
        (12, "CAP_NET_ADMIN"),
        (13, "CAP_NET_RAW"),
        (14, "CAP_IPC_LOCK"),
        (15, "CAP_IPC_OWNER"),
        (16, "CAP_SYS_MODULE"),
        (17, "CAP_SYS_RAWIO"),
        (18, "CAP_SYS_CHROOT"),
        (19, "CAP_SYS_PTRACE"),
        (20, "CAP_SYS_PACCT"),
        (21, "CAP_SYS_ADMIN"),
        (22, "CAP_SYS_BOOT"),
        (23, "CAP_SYS_NICE"),
        (24, "CAP_SYS_RESOURCE"),
        (25, "CAP_SYS_TIME"),
        (26, "CAP_SYS_TTY_CONFIG"),
        (27, "CAP_MKNOD"),
        (28, "CAP_LEASE"),
        (29, "CAP_AUDIT_WRITE"),
        (30, "CAP_AUDIT_CONTROL"),
        (31, "CAP_SETFCAP"),
        (32, "CAP_MAC_OVERRIDE"),
        (33, "CAP_MAC_ADMIN"),
        (34, "CAP_SYSLOG"),
        (35, "CAP_WAKE_ALARM"),
        (36, "CAP_BLOCK_SUSPEND"),
        (37, "CAP_AUDIT_READ"),
        (38, "CAP_PERFMON"),
        (39, "CAP_BPF"),
        (40, "CAP_CHECKPOINT_RESTORE"),
    ];

    for &(bit, name) in cap_names {
        if cap_eff & (1u64 << bit) != 0 {
            caps.push(name.to_string());
        }
    }

    caps
}

/// Ensure the process has sufficient privileges to perform security monitoring.
///
/// Aegis needs root or at minimum CAP_NET_ADMIN + CAP_DAC_READ_SEARCH + CAP_KILL
/// to read /proc, manipulate iptables, and terminate malicious processes.
pub fn ensure_privileged() -> Result<()> {
    if check_root() {
        return Ok(());
    }

    let caps = check_capabilities();

    let required = ["CAP_NET_ADMIN", "CAP_DAC_READ_SEARCH"];
    let missing: Vec<&str> = required
        .iter()
        .filter(|&&cap| !caps.contains(&cap.to_string()))
        .copied()
        .collect();

    if missing.is_empty() {
        // Has sufficient capabilities even without root
        warn!(
            "Running without root; relying on capabilities: {}",
            caps.join(", ")
        );
        return Ok(());
    }

    bail!(
        "Insufficient privileges. Aegis requires root or the following capabilities: {}. \
         Missing: {}. Run with sudo or set capabilities with: \
         sudo setcap 'cap_net_admin,cap_dac_read_search,cap_kill+ep' /path/to/aegis",
        required.join(", "),
        missing.join(", ")
    )
}

/// Check if a specific capability is available.
pub fn has_capability(cap_name: &str) -> bool {
    if check_root() {
        return true;
    }
    check_capabilities().contains(&cap_name.to_string())
}

/// Warn if not running as root (many monitoring features need elevated privileges).
pub fn warn_if_not_root() {
    if !check_root() {
        warn!(
            "Aegis is not running as root. Some features (firewall control, \
             process inspection, reading auth logs) may be limited."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_root_returns_bool() {
        // Just ensure it doesn't panic; actual value depends on test runner
        let _is_root = check_root();
    }

    #[test]
    fn test_check_capabilities_returns_vec() {
        let caps = check_capabilities();
        // Should return a (possibly empty) vec without panicking
        for cap in &caps {
            assert!(cap.starts_with("CAP_"));
        }
    }

    #[test]
    fn test_has_capability() {
        // This just exercises the function; results depend on test environment
        let _has_admin = has_capability("CAP_NET_ADMIN");
    }
}
