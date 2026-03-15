use anyhow::{Context, Result};
use genpdf::{elements, style, Alignment, Element};

use crate::core::state::AppState;
use crate::core::threat::ThreatSeverity;

/// Generate a PDF security report and write it to the given path.
pub fn generate_pdf_report(state: &AppState, path: &str) -> Result<()> {
    // Use a built-in font (Helvetica) that doesn't require font files.
    let font_family =
        genpdf::fonts::from_files("/usr/share/fonts/truetype/dejavu", "DejaVuSans", None)
            .or_else(|_| {
                // Fallback: try Liberation fonts
                genpdf::fonts::from_files(
                    "/usr/share/fonts/truetype/liberation",
                    "LiberationSans",
                    None,
                )
            })
            .or_else(|_| {
                // Fallback: try another common location
                genpdf::fonts::from_files("/usr/share/fonts/TTF", "DejaVuSans", None)
            });

    let font_family = match font_family {
        Ok(f) => f,
        Err(_) => {
            // If no TrueType fonts are available, fall back to text report
            let text = super::report::generate_report(state)?;
            std::fs::write(path, &text)
                .with_context(|| format!("Failed to write report to {}", path))?;
            tracing::warn!("No TrueType fonts found; wrote plain text report instead of PDF");
            return Ok(());
        }
    };

    let mut doc = genpdf::Document::new(font_family);
    doc.set_title("Aegis Security Report");
    doc.set_minimal_conformance();

    // Decorators for page numbers
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Title
    doc.push(
        elements::Paragraph::new("AEGIS SECURITY REPORT")
            .aligned(Alignment::Center)
            .styled(style::Style::new().bold().with_font_size(18)),
    );
    doc.push(elements::Break::new(1));

    // Generation info
    let now = chrono::Utc::now();
    doc.push(elements::Paragraph::new(format!(
        "Generated: {}",
        now.format("%Y-%m-%d %H:%M:%S UTC")
    )));
    doc.push(elements::Paragraph::new(format!(
        "Security Posture: {}",
        state.posture
    )));
    doc.push(elements::Paragraph::new(format!(
        "Aegis Version: {}",
        env!("CARGO_PKG_VERSION")
    )));
    doc.push(elements::Break::new(1));

    // Executive Summary
    doc.push(
        elements::Paragraph::new("EXECUTIVE SUMMARY")
            .styled(style::Style::new().bold().with_font_size(14)),
    );
    doc.push(elements::Break::new(0.5));

    let counts = state.threat_counts();
    let total = state.threats.len();
    doc.push(elements::Paragraph::new(format!(
        "Total threats detected: {}",
        total
    )));

    for sev in &[
        ThreatSeverity::Critical,
        ThreatSeverity::High,
        ThreatSeverity::Medium,
        ThreatSeverity::Low,
        ThreatSeverity::Info,
    ] {
        let count = counts.get(sev).copied().unwrap_or(0);
        if count > 0 {
            doc.push(elements::Paragraph::new(format!("  {} : {}", sev, count)));
        }
    }

    doc.push(elements::Paragraph::new(format!(
        "Blocked IPs: {}",
        state.blocked_ips.len()
    )));
    doc.push(elements::Break::new(1));

    // Threats detail
    if !state.threats.is_empty() {
        doc.push(
            elements::Paragraph::new("THREAT DETAILS")
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        for (i, threat) in state.threats.iter().rev().take(50).enumerate() {
            let ip_str = threat
                .source_ip
                .map_or("N/A".to_string(), |ip| ip.to_string());
            doc.push(elements::Paragraph::new(format!(
                "{}. [{}] {} - {}",
                i + 1,
                threat.severity,
                threat.threat_type,
                threat.description
            )));
            doc.push(elements::Paragraph::new(format!(
                "   Source: {} | Module: {} | Time: {}",
                ip_str,
                threat.source_module,
                threat.timestamp.format("%Y-%m-%d %H:%M:%S")
            )));
        }

        if state.threats.len() > 50 {
            doc.push(elements::Paragraph::new(format!(
                "... and {} more threats",
                state.threats.len() - 50
            )));
        }
    }

    doc.push(elements::Break::new(1));

    // Blocked IPs
    if !state.blocked_ips.is_empty() {
        doc.push(
            elements::Paragraph::new("BLOCKED IP ADDRESSES")
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        for entry in state.blocked_ips.values() {
            let expires = entry
                .expires_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "permanent".to_string());
            doc.push(elements::Paragraph::new(format!(
                "{} - {} (expires: {})",
                entry.ip, entry.reason, expires
            )));
        }
    }

    // Render to file
    doc.render_to_file(path)
        .with_context(|| format!("Failed to render PDF to {}", path))?;

    Ok(())
}
