use std::fs;

use crate::modules::audit::CisCheckResult;

/// Check kernel security parameters according to CIS benchmarks.
pub fn check_kernel_params() -> Vec<CisCheckResult> {
    vec![
        check_sysctl("1.5.1", "ASLR enabled", "kernel.randomize_va_space", "2"),
        check_sysctl(
            "3.1.1",
            "IP forwarding disabled",
            "net.ipv4.ip_forward",
            "0",
        ),
        check_sysctl(
            "3.2.1",
            "Source routing disabled",
            "net.ipv4.conf.all.accept_source_route",
            "0",
        ),
        check_sysctl(
            "3.2.2",
            "ICMP redirects disabled",
            "net.ipv4.conf.all.accept_redirects",
            "0",
        ),
        check_sysctl(
            "3.2.4",
            "Log suspicious packets",
            "net.ipv4.conf.all.log_martians",
            "1",
        ),
        check_sysctl(
            "3.3.1",
            "TCP SYN cookies enabled",
            "net.ipv4.tcp_syncookies",
            "1",
        ),
        check_core_dumps_restricted(),
    ]
}

fn check_sysctl(id: &str, title: &str, param: &str, expected: &str) -> CisCheckResult {
    let proc_path = format!("/proc/sys/{}", param.replace('.', "/"));
    match fs::read_to_string(&proc_path) {
        Ok(value) => {
            let value = value.trim();
            let pass = value == expected;
            CisCheckResult {
                id: id.into(),
                title: title.into(),
                pass,
                details: format!("{} = {} (expected {})", param, value, expected),
                remediation: format!("Run: sysctl -w {}={}", param, expected),
            }
        }
        Err(_) => CisCheckResult {
            id: id.into(),
            title: title.into(),
            pass: false,
            details: format!("Cannot read {}", param),
            remediation: format!("Ensure {} is set to {}", param, expected),
        },
    }
}

fn check_core_dumps_restricted() -> CisCheckResult {
    // Check /etc/security/limits.conf for "* hard core 0"
    let limits_ok = fs::read_to_string("/etc/security/limits.conf")
        .unwrap_or_default()
        .lines()
        .any(|l| {
            let l = l.trim();
            !l.starts_with('#') && l.contains("hard") && l.contains("core") && l.contains('0')
        });

    // Also check sysctl
    let sysctl_ok = fs::read_to_string("/proc/sys/fs/suid_dumpable")
        .unwrap_or_default()
        .trim()
        == "0";

    let pass = limits_ok || sysctl_ok;
    CisCheckResult {
        id: "1.5.3".into(),
        title: "Core dumps restricted".into(),
        pass,
        details: if pass {
            "Core dumps are restricted".into()
        } else {
            "Core dumps are not restricted".into()
        },
        remediation: "Add '* hard core 0' to /etc/security/limits.conf and set fs.suid_dumpable=0"
            .into(),
    }
}
