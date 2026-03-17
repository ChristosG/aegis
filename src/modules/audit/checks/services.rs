use std::process::Command;

use crate::modules::audit::CisCheckResult;

/// Check for unnecessary or insecure services.
pub fn check_services(profile: &str) -> Vec<CisCheckResult> {
    let mut results = Vec::new();

    // 2.1.x - Ensure inetd services are not enabled
    let insecure_services = [
        ("2.1.1", "xinetd", "xinetd (legacy inetd)"),
        ("2.1.2", "telnet.socket", "Telnet server"),
        ("2.1.3", "rsh.socket", "RSH server"),
        ("2.1.4", "rlogin.socket", "rlogin server"),
    ];

    for (id, service, desc) in &insecure_services {
        let enabled = is_service_enabled(service);
        results.push(CisCheckResult {
            id: id.to_string(),
            title: format!("{} not enabled", desc),
            pass: !enabled,
            details: if enabled {
                format!("{} is enabled", service)
            } else {
                format!("{} is not enabled", service)
            },
            remediation: format!("Run: systemctl disable --now {}", service),
        });
    }

    // 2.2.x - Ensure specific services are appropriate for profile
    if profile == "server" {
        // On servers, check that X11 is not installed/running
        let x11_running = is_service_enabled("display-manager");
        results.push(CisCheckResult {
            id: "2.2.2".into(),
            title: "X Window System not installed (server)".into(),
            pass: !x11_running,
            details: if x11_running {
                "A display manager is enabled on a server profile".into()
            } else {
                "No display manager enabled".into()
            },
            remediation: "Run: systemctl disable display-manager".into(),
        });
    }

    // Check for NFS server on non-file-server systems
    let nfs_enabled = is_service_enabled("nfs-server");
    results.push(CisCheckResult {
        id: "2.2.7".into(),
        title: "NFS server not enabled (unless needed)".into(),
        pass: !nfs_enabled,
        details: if nfs_enabled {
            "NFS server is enabled".into()
        } else {
            "NFS server is not enabled".into()
        },
        remediation: "If not needed: systemctl disable --now nfs-server".into(),
    });

    results
}

fn is_service_enabled(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-enabled", service])
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim() == "enabled"
        })
        .unwrap_or(false)
}
