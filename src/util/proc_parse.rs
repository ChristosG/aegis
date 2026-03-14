use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result};

/// Information about a running process, parsed from /proc.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub uid: u32,
}

/// Read the contents of a procfs file (or any text file) as a string.
///
/// Returns an error if the file does not exist or is not readable.
pub fn read_proc_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read proc file: {}", path.display()))
}

/// Parse a hex-encoded IP address as found in /proc/net/tcp and /proc/net/tcp6.
///
/// IPv4 addresses are 8 hex chars (4 bytes, little-endian on x86).
/// IPv6 addresses are 32 hex chars (16 bytes, little-endian per 4-byte group).
pub fn parse_hex_ip(hex: &str) -> Result<IpAddr> {
    let hex = hex.trim();
    match hex.len() {
        8 => {
            // IPv4: stored as a single 32-bit value in host byte order (little-endian on x86)
            let val = u32::from_str_radix(hex, 16)
                .with_context(|| format!("Invalid hex IPv4: '{}'", hex))?;
            // Convert from the printed host-order representation back to an IP.
            // The kernel prints the u32 in hex, and on LE systems bytes are reversed.
            let bytes = val.to_be_bytes();
            Ok(IpAddr::V4(Ipv4Addr::new(
                bytes[3], bytes[2], bytes[1], bytes[0],
            )))
        }
        32 => {
            // IPv6: stored as four 32-bit groups, each in host byte order
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let chunk = &hex[i * 8..(i + 1) * 8];
                let val = u32::from_str_radix(chunk, 16)
                    .with_context(|| format!("Invalid hex IPv6 chunk: '{}'", chunk))?;
                let be = val.to_be_bytes();
                octets[i * 4] = be[3];
                octets[i * 4 + 1] = be[2];
                octets[i * 4 + 2] = be[1];
                octets[i * 4 + 3] = be[0];
            }
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => {
            anyhow::bail!(
                "Invalid hex IP length {}: expected 8 (IPv4) or 32 (IPv6), got '{}'",
                hex.len(),
                hex
            );
        }
    }
}

/// Parse a hex-encoded port number as found in /proc/net/tcp.
///
/// Port numbers are stored as up to 4 hex chars in network byte order.
pub fn parse_hex_port(hex: &str) -> Result<u16> {
    let hex = hex.trim();
    u16::from_str_radix(hex, 16).with_context(|| format!("Invalid hex port: '{}'", hex))
}

/// Read basic process info from /proc/<pid>.
pub fn read_proc_info(pid: u32) -> Result<ProcInfo> {
    let proc_dir = Path::new("/proc").join(pid.to_string());

    let comm = std::fs::read_to_string(proc_dir.join("comm"))
        .unwrap_or_default()
        .trim()
        .to_string();

    let exe = std::fs::read_link(proc_dir.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    let cmdline_raw = std::fs::read_to_string(proc_dir.join("cmdline")).unwrap_or_default();
    let cmdline: Vec<String> = cmdline_raw
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let status = std::fs::read_to_string(proc_dir.join("status")).unwrap_or_default();
    let uid = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(ProcInfo {
        pid,
        name: comm,
        exe,
        cmdline,
        uid,
    })
}

/// List all numeric PIDs from /proc.
pub fn list_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

/// Parse a single line from /proc/net/tcp into (local_ip, local_port, remote_ip, remote_port, state).
///
/// Format: `sl local_address rem_address st ...`
/// where addresses are `HEXIP:HEXPORT`.
pub fn parse_tcp_line(line: &str) -> Result<(IpAddr, u16, IpAddr, u16, u8)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        anyhow::bail!("TCP line too short: '{}'", line);
    }

    let (local_ip, local_port) = parse_addr_field(parts[1])?;
    let (remote_ip, remote_port) = parse_addr_field(parts[2])?;
    let state = u8::from_str_radix(parts[3], 16)
        .with_context(|| format!("Invalid TCP state: '{}'", parts[3]))?;

    Ok((local_ip, local_port, remote_ip, remote_port, state))
}

/// Parse an address field like "0100007F:0050" into (IpAddr, u16).
fn parse_addr_field(field: &str) -> Result<(IpAddr, u16)> {
    let mut split = field.split(':');
    let ip_hex = split
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing IP in address field: '{}'", field))?;
    let port_hex = split
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing port in address field: '{}'", field))?;

    let ip = parse_hex_ip(ip_hex)?;
    let port = parse_hex_port(port_hex)?;
    Ok((ip, port))
}

/// Well-known TCP state codes from /proc/net/tcp.
pub mod tcp_state {
    pub const ESTABLISHED: u8 = 0x01;
    pub const SYN_SENT: u8 = 0x02;
    pub const SYN_RECV: u8 = 0x03;
    pub const FIN_WAIT1: u8 = 0x04;
    pub const FIN_WAIT2: u8 = 0x05;
    pub const TIME_WAIT: u8 = 0x06;
    pub const CLOSE: u8 = 0x07;
    pub const CLOSE_WAIT: u8 = 0x08;
    pub const LAST_ACK: u8 = 0x09;
    pub const LISTEN: u8 = 0x0A;
    pub const CLOSING: u8 = 0x0B;

    /// Return a human-readable name for a TCP state code.
    pub fn name(state: u8) -> &'static str {
        match state {
            ESTABLISHED => "ESTABLISHED",
            SYN_SENT => "SYN_SENT",
            SYN_RECV => "SYN_RECV",
            FIN_WAIT1 => "FIN_WAIT1",
            FIN_WAIT2 => "FIN_WAIT2",
            TIME_WAIT => "TIME_WAIT",
            CLOSE => "CLOSE",
            CLOSE_WAIT => "CLOSE_WAIT",
            LAST_ACK => "LAST_ACK",
            LISTEN => "LISTEN",
            CLOSING => "CLOSING",
            _ => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_ip_v4_loopback() {
        // 0100007F = 127.0.0.1 in little-endian
        let ip = parse_hex_ip("0100007F").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_parse_hex_ip_v4_zero() {
        let ip = parse_hex_ip("00000000").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_parse_hex_ip_v4_example() {
        // 192.168.1.100 stored little-endian: 0x6401A8C0
        let ip = parse_hex_ip("6401A8C0").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_parse_hex_port() {
        assert_eq!(parse_hex_port("0050").unwrap(), 80);
        assert_eq!(parse_hex_port("01BB").unwrap(), 443);
        assert_eq!(parse_hex_port("0016").unwrap(), 22);
        assert_eq!(parse_hex_port("0000").unwrap(), 0);
    }

    #[test]
    fn test_parse_hex_port_invalid() {
        assert!(parse_hex_port("ZZZZ").is_err());
    }

    #[test]
    fn test_parse_hex_ip_invalid_length() {
        assert!(parse_hex_ip("ABC").is_err());
        assert!(parse_hex_ip("").is_err());
    }

    #[test]
    fn test_parse_tcp_line() {
        let line = "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let (local_ip, local_port, remote_ip, remote_port, state) = parse_tcp_line(line).unwrap();
        assert_eq!(local_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(local_port, 80);
        assert_eq!(remote_ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(remote_port, 0);
        assert_eq!(state, tcp_state::LISTEN);
    }

    #[test]
    fn test_tcp_state_names() {
        assert_eq!(tcp_state::name(0x01), "ESTABLISHED");
        assert_eq!(tcp_state::name(0x0A), "LISTEN");
        assert_eq!(tcp_state::name(0x03), "SYN_RECV");
        assert_eq!(tcp_state::name(0xFF), "UNKNOWN");
    }

    #[test]
    fn test_read_proc_file_nonexistent() {
        let result = read_proc_file(Path::new("/proc/nonexistent_file_aegis_test"));
        assert!(result.is_err());
    }
}
