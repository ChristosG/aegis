use std::fs;

/// Information about a container a process is running in.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: Option<String>,
    pub runtime: String,
}

/// Detect if a process is running inside a container by reading its cgroup.
/// Returns `None` if the process is running on the host.
pub fn detect_container(pid: u32) -> Option<ContainerInfo> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = fs::read_to_string(&cgroup_path).ok()?;

    for line in content.lines() {
        // Docker format: "12:devices:/docker/<container_id>"
        if let Some(pos) = line.find("/docker/") {
            let id = &line[pos + 8..];
            if id.len() >= 12 {
                return Some(ContainerInfo {
                    id: id[..12].to_string(),
                    name: get_container_name_docker(id),
                    runtime: "docker".to_string(),
                });
            }
        }

        // containerd/k8s format: "12:devices:/kubepods/..." or
        // "0::/system.slice/containerd-<id>.scope"
        if line.contains("/kubepods/") || line.contains("/kubepods.slice/") {
            if let Some(id) = extract_container_id_from_cgroup(line) {
                return Some(ContainerInfo {
                    id,
                    name: None,
                    runtime: "containerd".to_string(),
                });
            }
        }

        // Podman format: "12:devices:/libpod-<container_id>"
        if let Some(pos) = line.find("/libpod-") {
            let id = &line[pos + 8..];
            if id.len() >= 12 {
                return Some(ContainerInfo {
                    id: id[..12].to_string(),
                    name: None,
                    runtime: "podman".to_string(),
                });
            }
        }

        // LXC format: "12:devices:/lxc/<name>"
        if let Some(pos) = line.find("/lxc/") {
            let name = &line[pos + 5..];
            if !name.is_empty() {
                return Some(ContainerInfo {
                    id: name.to_string(),
                    name: Some(name.to_string()),
                    runtime: "lxc".to_string(),
                });
            }
        }
    }

    // Note: we do NOT check /.dockerenv as a fallback because that would
    // detect Aegis's OWN container, not the target pid's. If Aegis itself
    // runs in Docker, every host process would be mislabeled as containerized.
    None
}

/// Check for signs of a container escape attempt.
/// Looks for processes that have elevated capabilities or access to host resources.
pub fn detect_escape_attempt(pid: u32, _container: &ContainerInfo) -> bool {
    // Check if the process has access to host namespaces
    let ns_path = format!("/proc/{}/ns", pid);
    let init_ns_path = "/proc/1/ns";

    // If container process shares network/pid namespace with init, it may be escaping
    for ns in &["net", "pid", "mnt"] {
        let proc_ns = format!("{}/{}", ns_path, ns);
        let init_ns = format!("{}/{}", init_ns_path, ns);

        if let (Ok(proc_link), Ok(init_link)) = (fs::read_link(&proc_ns), fs::read_link(&init_ns)) {
            if proc_link == init_link {
                // Process shares a namespace with host init - suspicious for a container
                return true;
            }
        }
    }

    // Check for nsenter or unshare in cmdline
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
        let cmd_lower = cmdline.to_lowercase();
        if cmd_lower.contains("nsenter") || cmd_lower.contains("unshare") {
            return true;
        }
    }

    // Check for CAP_SYS_ADMIN (dangerous in containers)
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(status) = fs::read_to_string(&status_path) {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                if let Some(hex) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(hex, 16) {
                        // CAP_SYS_ADMIN = bit 21
                        if caps & (1 << 21) != 0 {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Try to get the container name from Docker.
fn get_container_name_docker(container_id: &str) -> Option<String> {
    let short_id = &container_id[..12.min(container_id.len())];
    // Try reading from the Docker API socket
    let hostname_path = format!("/var/lib/docker/containers/{}/hostname", container_id);
    fs::read_to_string(&hostname_path)
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| Some(short_id.to_string()))
}

/// Extract container ID from a cgroup line.
fn extract_container_id_from_cgroup(line: &str) -> Option<String> {
    // Look for a 64-char hex string (container IDs are SHA-256)
    for segment in line.split('/') {
        let segment = segment.trim_end_matches(".scope");
        let segment = segment.strip_prefix("cri-containerd-").unwrap_or(segment);
        let segment = segment.strip_prefix("docker-").unwrap_or(segment);
        if segment.len() >= 12 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(segment[..12].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_container_id_docker() {
        let line =
            "12:devices:/docker/abc123def456789abcdef0123456789abcdef0123456789abcdef01234567";
        let id = extract_container_id_from_cgroup(line);
        assert_eq!(id, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_extract_container_id_containerd() {
        let line = "0::/kubepods.slice/kubepods-besteffort.slice/cri-containerd-abcdef123456.scope";
        let id = extract_container_id_from_cgroup(line);
        assert_eq!(id, Some("abcdef123456".to_string()));
    }

    #[test]
    fn test_detect_container_nonexistent_pid() {
        // PID 999999999 should not exist
        assert!(detect_container(999999999).is_none());
    }
}
