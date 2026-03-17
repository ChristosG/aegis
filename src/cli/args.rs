use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Whitelist management subcommands.
#[derive(Subcommand, Debug)]
pub enum WhitelistAction {
    /// List all whitelisted CIDR ranges.
    List,
    /// Add a CIDR range to the whitelist.
    Add {
        /// CIDR range to add (e.g. "10.0.0.0/8" or "203.0.113.5").
        cidr: String,
    },
    /// Remove a CIDR range from the whitelist.
    Remove {
        /// CIDR range to remove.
        cidr: String,
    },
}

/// Aegis -- Linux Security Monitoring & Response Tool
#[derive(Parser, Debug)]
#[command(
    name = "aegis",
    version,
    about = "Linux Security Monitoring & Response Tool",
    long_about = "Aegis monitors your Linux system for network intrusions, process anomalies,\n\
                  file integrity violations, authentication attacks, web application threats,\n\
                  and cross-references activity against curated threat intelligence feeds.\n\n\
                  Run `aegis init` to generate a default configuration file, then use\n\
                  `aegis scan` for one-shot analysis or `aegis watch` for continuous monitoring."
)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,

    /// Path to a custom configuration file.
    ///
    /// If omitted, Aegis searches ./aegis.toml, /etc/aegis/aegis.toml,
    /// and ~/.config/aegis/aegis.toml in that order.
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Enable verbose (debug-level) output.
    ///
    /// Overrides the `log_level` setting in the configuration file.
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

/// All available Aegis subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a one-shot security scan across enabled modules.
    ///
    /// By default all enabled modules are run. Use the flags below to restrict
    /// the scan to specific modules.
    Scan {
        /// Scan network connections for SYN floods, port scans, suspicious
        /// outbound traffic, and C2 beacon patterns.
        #[arg(long)]
        network: bool,

        /// Scan running processes for crypto miners, reverse shells, and
        /// binaries executing from suspicious directories.
        #[arg(long)]
        processes: bool,

        /// Check file integrity against the stored baseline.
        #[arg(long)]
        files: bool,

        /// Analyse authentication logs for brute-force attacks, root logins,
        /// and logins from new IP addresses.
        #[arg(long)]
        auth: bool,

        /// Analyse web-server access logs for DDoS, SQLi, path traversal,
        /// and scanner probes.
        #[arg(long)]
        web: bool,

        /// Cross-reference active connections against threat intelligence feeds.
        #[arg(long)]
        intel: bool,

        /// Scan DNS logs for DGA domains and tunneling.
        #[arg(long)]
        dns: bool,

        /// Run rootkit detection checks.
        #[arg(long)]
        rootkit: bool,

        /// Analyse SSH session commands for suspicious patterns.
        #[arg(long)]
        ssh_session: bool,

        /// Enable automatic response actions (block, kill) for detected threats.
        ///
        /// Without this flag threats are reported but no automated mitigation
        /// is performed.
        #[arg(long, help = "Enable auto-response actions")]
        auto_respond: bool,
    },

    /// Start continuous monitoring (daemon mode).
    ///
    /// All enabled modules run their watch loops, periodically rescanning and
    /// listening for real-time events (e.g. inotify for file changes).
    Watch {
        /// Run in the foreground instead of daemonizing.
        #[arg(long)]
        foreground: bool,
    },

    /// Display the current security posture and active module status.
    Status,

    /// List all active threat events detected in the current session.
    Threats,

    /// Manually block an IP address via the configured firewall backend.
    Block {
        /// IP address to block (IPv4 or IPv6).
        ip: String,

        /// How long to block the IP (e.g. "1h", "24h", "7d", "forever").
        #[arg(short, long, default_value = "24h")]
        duration: String,
    },

    /// Remove a manual or automatic block on an IP address.
    Unblock {
        /// IP address to unblock.
        ip: String,
    },

    /// Create or update the file integrity baseline.
    ///
    /// Walks all configured watch paths, computes SHA-256 hashes, and stores
    /// the result in the configured baseline file.
    Baseline,

    /// Generate a human-readable security report of all findings.
    Report {
        /// Output format: text, html, or pdf.
        #[arg(long, default_value = "text")]
        format: String,

        /// Output file path (prints to stdout if not specified).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Interactively configure SMTP credentials for email alerts.
    ///
    /// Prompts for SMTP host, port, username, password, and recipient addresses.
    /// Stores credentials securely in /etc/aegis/mail.env (mode 0600) and
    /// updates /etc/aegis/aegis.toml with the email settings.
    InitMail,

    /// Validate the current configuration file and report errors/warnings.
    Check,

    /// Manage the IP whitelist (IPs that are never blocked).
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },

    /// Check for updates or update Aegis to the latest version.
    Update {
        /// Only check if an update is available, don't install.
        #[arg(long)]
        check: bool,

        /// Force update even if already on latest version.
        #[arg(long)]
        force: bool,
    },

    /// Enable or disable file integrity monitoring.
    ///
    /// Updates aegis.toml and optionally generates a baseline when enabling.
    Fi {
        /// Turn file integrity on.
        #[arg(long, conflicts_with = "off")]
        on: bool,
        /// Turn file integrity off.
        #[arg(long, conflicts_with = "on")]
        off: bool,
    },

    /// Merge new config options into an existing aegis.toml.
    ///
    /// Adds any keys/sections from the default config that are missing in
    /// the user's config, without changing existing values. Called
    /// automatically by the .deb postinst on upgrades.
    #[command(name = "config-upgrade")]
    ConfigUpgrade,

    /// Run CIS benchmark compliance audit.
    Audit {
        /// Audit profile: "server" or "workstation".
        #[arg(long, default_value = "server")]
        profile: String,

        /// Output format: "text", "json", or "html".
        #[arg(long, default_value = "text")]
        format: String,

        /// Output file path (prints to stdout if not specified).
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Start gRPC aggregation server for fleet monitoring.
    #[cfg(feature = "server")]
    Server {
        /// gRPC bind address.
        #[arg(long, default_value = "0.0.0.0:50051")]
        bind: String,

        /// TLS certificate file.
        #[arg(long)]
        tls_cert: Option<String>,

        /// TLS key file.
        #[arg(long)]
        tls_key: Option<String>,
    },

    /// Full system hardening setup: config, sysctl, firewall, baseline,
    /// fail2ban, and systemd service installation.
    Init {
        /// Skip kernel hardening via sysctl.
        #[arg(long)]
        skip_sysctl: bool,

        /// Skip file integrity baseline generation.
        #[arg(long)]
        skip_baseline: bool,

        /// Skip systemd service installation.
        #[arg(long)]
        skip_service: bool,

        /// Skip AEGIS_BLOCK iptables dedup cleanup.
        #[arg(long)]
        skip_firewall_cleanup: bool,

        /// Skip fail2ban jail installation.
        #[arg(long)]
        skip_fail2ban: bool,

        /// Skip web dashboard setup prompt.
        #[arg(long)]
        skip_dashboard: bool,
    },
}

impl Commands {
    /// Return the list of module IDs that should be scanned, based on the flags
    /// passed to the `scan` subcommand. If no module-specific flag is set, all
    /// modules are included (i.e. returns `None` to mean "all").
    pub fn scan_module_filter(&self) -> Option<Vec<String>> {
        match self {
            Commands::Scan {
                network,
                processes,
                files,
                auth,
                web,
                intel,
                dns,
                rootkit,
                ssh_session,
                ..
            } => {
                // If no flag is set, run everything.
                if !network && !processes && !files && !auth && !web && !intel
                    && !dns && !rootkit && !ssh_session
                {
                    return None;
                }

                let mut modules = Vec::new();
                if *network {
                    modules.push("network".to_string());
                }
                if *processes {
                    modules.push("process".to_string());
                }
                if *files {
                    modules.push("file_integrity".to_string());
                }
                if *auth {
                    modules.push("auth".to_string());
                }
                if *web {
                    modules.push("web".to_string());
                }
                if *intel {
                    modules.push("threat_intel".to_string());
                }
                if *dns {
                    modules.push("dns".to_string());
                }
                if *rootkit {
                    modules.push("rootkit".to_string());
                }
                if *ssh_session {
                    modules.push("ssh_session".to_string());
                }
                Some(modules)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_scan_all() {
        let cli = Cli::parse_from(["aegis", "scan"]);
        assert!(matches!(cli.command, Commands::Scan { .. }));
        assert!(cli.command.scan_module_filter().is_none());
    }

    #[test]
    fn test_parse_scan_network_only() {
        let cli = Cli::parse_from(["aegis", "scan", "--network"]);
        let filter = cli.command.scan_module_filter().unwrap();
        assert_eq!(filter, vec!["network"]);
    }

    #[test]
    fn test_parse_scan_multiple_modules() {
        let cli = Cli::parse_from(["aegis", "scan", "--network", "--auth", "--web"]);
        let filter = cli.command.scan_module_filter().unwrap();
        assert!(filter.contains(&"network".to_string()));
        assert!(filter.contains(&"auth".to_string()));
        assert!(filter.contains(&"web".to_string()));
        assert!(!filter.contains(&"process".to_string()));
    }

    #[test]
    fn test_parse_block() {
        let cli = Cli::parse_from(["aegis", "block", "1.2.3.4", "-d", "12h"]);
        match cli.command {
            Commands::Block { ip, duration } => {
                assert_eq!(ip, "1.2.3.4");
                assert_eq!(duration, "12h");
            }
            _ => panic!("Expected Block command"),
        }
    }

    #[test]
    fn test_parse_block_default_duration() {
        let cli = Cli::parse_from(["aegis", "block", "10.0.0.1"]);
        match cli.command {
            Commands::Block { duration, .. } => {
                assert_eq!(duration, "24h");
            }
            _ => panic!("Expected Block command"),
        }
    }

    #[test]
    fn test_parse_watch_foreground() {
        let cli = Cli::parse_from(["aegis", "watch", "--foreground"]);
        match cli.command {
            Commands::Watch { foreground } => {
                assert!(foreground);
            }
            _ => panic!("Expected Watch command"),
        }
    }

    #[test]
    fn test_global_verbose() {
        let cli = Cli::parse_from(["aegis", "-v", "status"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_global_config() {
        let cli = Cli::parse_from(["aegis", "-c", "/tmp/aegis.toml", "scan"]);
        assert_eq!(cli.config.unwrap(), PathBuf::from("/tmp/aegis.toml"));
    }

    #[test]
    fn test_parse_scan_auto_respond() {
        let cli = Cli::parse_from(["aegis", "scan", "--auto-respond"]);
        match cli.command {
            Commands::Scan { auto_respond, .. } => {
                assert!(auto_respond);
            }
            _ => panic!("Expected Scan command"),
        }
    }
}
