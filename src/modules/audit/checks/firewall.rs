use std::process::Command;

use crate::modules::audit::CisCheckResult;

/// Check firewall configuration according to CIS benchmarks.
pub fn check_firewall() -> Vec<CisCheckResult> {
    let mut results = Vec::new();

    // 3.5.1 - Ensure a firewall is active
    let firewall_active = is_iptables_active() || is_nftables_active() || is_ufw_active();
    results.push(CisCheckResult {
        id: "3.5.1".into(),
        title: "Firewall is active".into(),
        pass: firewall_active,
        details: if firewall_active {
            "A firewall (iptables/nftables/ufw) is active".into()
        } else {
            "No active firewall detected".into()
        },
        remediation: "Enable a firewall: sudo ufw enable".into(),
    });

    // 3.5.2 - Ensure default deny policy
    let default_deny = check_default_deny_policy();
    results.push(CisCheckResult {
        id: "3.5.2".into(),
        title: "Firewall default deny policy".into(),
        pass: default_deny,
        details: if default_deny {
            "Default INPUT policy is DROP or REJECT".into()
        } else {
            "Default INPUT policy is ACCEPT or unknown".into()
        },
        remediation: "Set default policy: iptables -P INPUT DROP".into(),
    });

    results
}

fn is_iptables_active() -> bool {
    Command::new("iptables")
        .args(["-L", "-n"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

fn is_nftables_active() -> bool {
    Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .map(|o| o.status.success() && o.stdout.len() > 10)
        .unwrap_or(false)
}

fn is_ufw_active() -> bool {
    Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout).contains("Status: active")
        })
        .unwrap_or(false)
}

fn check_default_deny_policy() -> bool {
    if let Ok(output) = Command::new("iptables").args(["-L", "INPUT", "-n"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(first_line) = stdout.lines().next() {
            return first_line.contains("DROP") || first_line.contains("REJECT");
        }
    }
    false
}
