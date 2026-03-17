use std::fs;

use crate::modules::audit::CisCheckResult;

/// Check SSH server hardening according to CIS benchmarks.
pub fn check_ssh_hardening() -> Vec<CisCheckResult> {
    let mut results = Vec::new();

    let sshd_config = fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();

    // 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
    results.push(check_sshd_config_perms());

    // 5.2.2 - Ensure SSH Protocol is set to 2 (obsolete check but still in some profiles)
    // Modern OpenSSH only supports protocol 2, so always pass
    results.push(CisCheckResult {
        id: "5.2.2".into(),
        title: "SSH Protocol version".into(),
        pass: true,
        details: "Modern OpenSSH only supports Protocol 2".into(),
        remediation: String::new(),
    });

    // 5.2.4 - Ensure SSH root login is disabled
    let root_login_disabled = sshd_config
        .lines()
        .any(|l| {
            let l = l.trim();
            !l.starts_with('#') && l.to_lowercase().contains("permitrootlogin")
                && (l.contains("no") || l.contains("prohibit-password")
                    || l.contains("forced-commands-only"))
        });
    results.push(CisCheckResult {
        id: "5.2.4".into(),
        title: "SSH root login disabled".into(),
        pass: root_login_disabled,
        details: if root_login_disabled {
            "PermitRootLogin is restricted".into()
        } else {
            "PermitRootLogin is not restricted".into()
        },
        remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config".into(),
    });

    // 5.2.5 - Ensure SSH MaxAuthTries is set to 4 or less
    let max_auth_ok = sshd_config.lines().any(|l| {
        let l = l.trim();
        if l.starts_with('#') {
            return false;
        }
        if let Some(rest) = l.strip_prefix("MaxAuthTries") {
            if let Ok(n) = rest.trim().parse::<u32>() {
                return n <= 4;
            }
        }
        false
    });
    results.push(CisCheckResult {
        id: "5.2.5".into(),
        title: "SSH MaxAuthTries <= 4".into(),
        pass: max_auth_ok,
        details: if max_auth_ok {
            "MaxAuthTries is properly configured".into()
        } else {
            "MaxAuthTries is not set or too high".into()
        },
        remediation: "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config".into(),
    });

    // 5.2.8 - Ensure SSH PermitEmptyPasswords is disabled
    let no_empty_pass = !sshd_config.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.to_lowercase().contains("permitemptypasswords")
            && l.to_lowercase().contains("yes")
    });
    results.push(CisCheckResult {
        id: "5.2.8".into(),
        title: "SSH empty passwords disabled".into(),
        pass: no_empty_pass,
        details: if no_empty_pass {
            "PermitEmptyPasswords is not enabled".into()
        } else {
            "PermitEmptyPasswords is enabled".into()
        },
        remediation: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config".into(),
    });

    results
}

fn check_sshd_config_perms() -> CisCheckResult {
    let path = "/etc/ssh/sshd_config";
    match fs::metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            let pass = mode <= 0o600;
            CisCheckResult {
                id: "5.2.1".into(),
                title: "sshd_config permissions".into(),
                pass,
                details: format!("Permissions: {:o} (expected <= 600)", mode),
                remediation: "Run: chmod 600 /etc/ssh/sshd_config".into(),
            }
        }
        Err(_) => CisCheckResult {
            id: "5.2.1".into(),
            title: "sshd_config permissions".into(),
            pass: false,
            details: "Cannot read /etc/ssh/sshd_config".into(),
            remediation: "Ensure sshd is installed and config exists".into(),
        },
    }
}
