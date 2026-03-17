use std::fs;
use std::path::Path;

use anyhow::Result;

/// Capture process information from /proc/[pid]/.
pub fn capture_process_info(pid: u32, output_dir: &Path) -> Result<()> {
    let proc_dir = format!("/proc/{}", pid);

    let files_to_capture = [
        "status",
        "cmdline",
        "environ",
        "maps",
        "limits",
        "cgroup",
        "mountinfo",
    ];

    let proc_output = output_dir.join("process");
    fs::create_dir_all(&proc_output)?;

    for file in &files_to_capture {
        let src = format!("{}/{}", proc_dir, file);
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        if let Ok(content) = fs::read_to_string(&src) {
            let dst = proc_output.join(file);
            fs::write(&dst, &content)?;
        }
    }

    // Capture open file descriptors
    let fd_dir = format!("{}/fd", proc_dir);
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        let mut fd_list = Vec::new();
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                fd_list.push(format!(
                    "{} -> {}",
                    entry.file_name().to_string_lossy(),
                    target.display()
                ));
            }
        }
        fs::write(proc_output.join("fd_list"), fd_list.join("\n"))?;
    }

    Ok(())
}

/// Capture current network state.
pub fn capture_network_state(output_dir: &Path) -> Result<()> {
    let net_output = output_dir.join("network");
    fs::create_dir_all(&net_output)?;

    let net_files = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ];

    for file in &net_files {
        if let Ok(content) = fs::read_to_string(file) {
            let name = file.rsplit('/').next().unwrap_or("unknown");
            fs::write(net_output.join(name), &content)?;
        }
    }

    Ok(())
}

/// Capture the process tree.
pub fn capture_process_tree(output_dir: &Path) -> Result<()> {
    let mut tree = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.chars().all(|c| c.is_ascii_digit()) {
                let pid = name_str.to_string();
                let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let status =
                    fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();

                let ppid = status
                    .lines()
                    .find(|l| l.starts_with("PPid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("0")
                    .to_string();
                let uid = status
                    .lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("0")
                    .to_string();

                tree.push(format!("{}\t{}\t{}\t{}", pid, ppid, uid, comm));
            }
        }
    }

    tree.sort();
    fs::write(
        output_dir.join("process_tree.tsv"),
        format!("PID\tPPID\tUID\tCOMM\n{}", tree.join("\n")),
    )?;

    Ok(())
}
