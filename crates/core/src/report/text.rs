//! Human-readable terminal reporter with severity coloring and rich finding details.

use std::io::IsTerminal;
use std::io::Write;

use crate::{MatchLocation, Severity, VerificationResult, VerifiedFinding};

use super::{ReportError, Reporter, WriterBackedReporter};

/// Human-readable text output with gradient banner and styled findings.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::TextReporter;
///
/// let reporter = TextReporter::with_color(Vec::new(), false);
/// let _ = reporter;
/// ```
pub struct TextReporter<W: Write + Send> {
    writer: W,
    count: usize,
    color: bool,
    live_count: usize,
    dead_count: usize,
}

impl<W: Write + Send> TextReporter<W> {
    /// Create a text reporter with ANSI colors enabled when stdout is a TTY.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::TextReporter;
    ///
    /// let reporter = TextReporter::new(Vec::new());
    /// let _ = reporter;
    /// ```
    pub fn new(writer: W) -> Self {
        Self::with_color(writer, std::io::stdout().is_terminal())
    }

    /// Create a text reporter with explicit ANSI color control.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::TextReporter;
    ///
    /// let reporter = TextReporter::with_color(Vec::new(), false);
    /// let _ = reporter;
    /// ```
    pub fn with_color(writer: W, color: bool) -> Self {
        Self {
            writer,
            count: 0,
            color,
            live_count: 0,
            dead_count: 0,
        }
    }

    fn print_header(&mut self) -> Result<(), ReportError> {
        Ok(())
    }
}

impl<W: Write + Send> Reporter for TextReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        if self.count == 0 {
            self.print_header()?;
        }
        self.count += 1;

        // Track verification stats
        match &finding.verification {
            VerificationResult::Live => self.live_count += 1,
            VerificationResult::Dead => self.dead_count += 1,
            _ => {}
        }

        let severity_str = format_severity(finding.severity, self.color);
        let verified = format_verification(&finding.verification, self.color);
        let location = format_location(&finding.location);
        let confidence_value = finding.confidence.unwrap_or(0.0);
        const BAR_WIDTH: usize = 6;
        let filled = (confidence_value * BAR_WIDTH as f64) as usize;
        let bar = format!(
            "{}{}",
            "■".repeat(filled.min(BAR_WIDTH)),
            "□".repeat(BAR_WIDTH.saturating_sub(filled.min(BAR_WIDTH)))
        );
        let confidence_tone = if confidence_value >= 0.8 {
            "31"
        } else if confidence_value >= 0.5 {
            "33"
        } else {
            "90"
        };
        let confidence = format!(
            "{} {}",
            colorize(&bar, confidence_tone, self.color),
            colorize(
                &format!("{:>3}%", (confidence_value * 100.0) as u32),
                "90",
                self.color,
            )
        );

        // Severity color for the box border
        let border_ansi = match finding.severity {
            Severity::Critical => "1;31",
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "90",
        };

        // Top border with severity and detector name
        writeln!(
            self.writer,
            "  {} {} {}",
            colorize("┌", border_ansi, self.color),
            severity_str,
            colorize(
                &format!("─── {}", finding.detector_name),
                border_ansi,
                self.color,
            ),
        )?;

        // Secret
        writeln!(
            self.writer,
            "  {} {} {}",
            colorize("│", border_ansi, self.color),
            dim("Secret:    ", self.color),
            highlight(&finding.credential_redacted, self.color),
        )?;

        // Location
        writeln!(
            self.writer,
            "  {} {} {}",
            colorize("│", border_ansi, self.color),
            dim("Location:  ", self.color),
            location,
        )?;

        // Confidence + verification
        let verify_suffix = if verified.is_empty() {
            String::new()
        } else {
            format!("  ({})", verified)
        };
        writeln!(
            self.writer,
            "  {} {} {}{}",
            colorize("│", border_ansi, self.color),
            dim("Confidence:", self.color),
            confidence,
            verify_suffix,
        )?;

        // Commit info
        if let Some(commit) = &finding.location.commit {
            writeln!(
                self.writer,
                "  {} {} {}",
                colorize("│", border_ansi, self.color),
                dim("Commit:    ", self.color),
                commit,
            )?;
        }

        if let Some(author) = &finding.location.author {
            writeln!(
                self.writer,
                "  {} {} {}",
                colorize("│", border_ansi, self.color),
                dim("Author:    ", self.color),
                author,
            )?;
        }

        if let Some(date) = &finding.location.date {
            writeln!(
                self.writer,
                "  {} {} {}",
                colorize("│", border_ansi, self.color),
                dim("Date:      ", self.color),
                date,
            )?;
        }

        // Extra metadata
        for (key, value) in &finding.metadata {
            writeln!(
                self.writer,
                "  {} {} {}",
                colorize("│", border_ansi, self.color),
                dim(&format!("{:<11}", format!("{}:", key)), self.color),
                value,
            )?;
        }

        if !finding.additional_locations.is_empty() {
            writeln!(
                self.writer,
                "  {} {} (+{} more locations)",
                colorize("│", border_ansi, self.color),
                dim("Extra:     ", self.color),
                finding.additional_locations.len(),
            )?;
        }

        // Remediation
        let remediation = match finding.severity {
            Severity::Critical | Severity::High => "Revoke immediately and rotate.",
            Severity::Medium => "Review usage and rotate if active.",
            _ => "Remove from codebase.",
        };
        writeln!(
            self.writer,
            "  {} {} {}",
            colorize("│", border_ansi, self.color),
            dim("Action:    ", self.color),
            colorize(remediation, "3;32", self.color),
        )?;

        // Bottom border
        writeln!(
            self.writer,
            "  {}\n",
            colorize(
                "└─────────────────────────────────────────────",
                border_ansi,
                self.color,
            ),
        )?;

        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        if self.count == 0 {
            self.print_header()?;
            writeln!(
                self.writer,
                "  {}\n",
                colorize("No secrets found. Your code is clean.", "1;32", self.color),
            )?;
        } else {
            let summary_border = colorize(
                "━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                "90",
                self.color,
            );
            writeln!(self.writer, "  {}", summary_border)?;

            let plural = if self.count == 1 { "" } else { "s" };

            let mut parts = vec![highlight(
                &format!("{} secret{plural} found", self.count),
                self.color,
            )];
            if self.live_count > 0 {
                parts.push(colorize(
                    &format!("{} live", self.live_count),
                    "1;31",
                    self.color,
                ));
            }
            if self.dead_count > 0 {
                parts.push(colorize(
                    &format!("{} dead", self.dead_count),
                    "32",
                    self.color,
                ));
            }
            let unverified = self.count - self.live_count - self.dead_count;
            if unverified > 0 {
                parts.push(colorize(
                    &format!("{unverified} unverified"),
                    "33",
                    self.color,
                ));
            }

            writeln!(self.writer, "  {}", parts.join(" · "))?;

            // Next steps
            writeln!(self.writer)?;
            writeln!(
                self.writer,
                "  {} Revoke active secrets in the provider's dashboard.",
                colorize("1.", "1;31", self.color),
            )?;
            writeln!(
                self.writer,
                "  {} Remove credentials from codebase and git history.",
                colorize("2.", "1;33", self.color),
            )?;
            writeln!(
                self.writer,
                "  {} Use a secure secret manager or environment variables.",
                colorize("3.", "1;32", self.color),
            )?;

            let end_border = colorize(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                "90",
                self.color,
            );
            writeln!(self.writer, "\n  {}\n", end_border)?;
        }
        self.flush_writer()
    }
}

impl<W: Write + Send> WriterBackedReporter for TextReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

fn format_severity(severity: Severity, color: bool) -> String {
    let (label, style) = match severity {
        Severity::Critical => ("CRITICAL", "1;31"),
        Severity::High => ("HIGH", "31"),
        Severity::Medium => ("MEDIUM", "33"),
        Severity::Low => ("LOW", "36"),
        Severity::Info => ("INFO", "90"),
    };
    colorize(&format!("{:>8}", label), style, color)
}

fn format_verification(result: &VerificationResult, color: bool) -> String {
    match result {
        VerificationResult::Live => colorize("LIVE", "1;31;43", color),
        VerificationResult::Revoked => colorize("revoked", "1;33", color),
        VerificationResult::Dead => colorize("dead", "32", color),
        VerificationResult::RateLimited => colorize("limited", "33", color),
        VerificationResult::Error(_) => colorize("error", "33", color),
        VerificationResult::Unverifiable | VerificationResult::Skipped => String::new(),
    }
}

fn format_location(location: &MatchLocation) -> String {
    match (&location.file_path, location.line) {
        (Some(path), Some(line)) => format!("{}:{}", path, line),
        (Some(path), None) => path.to_string(),
        _ => location.source.to_string(),
    }
}

fn highlight(text: &str, color: bool) -> String {
    colorize(text, "1", color)
}

fn dim(text: &str, color: bool) -> String {
    colorize(text, "90", color)
}

fn colorize(text: &str, ansi: &str, color: bool) -> String {
    if color {
        format!("\x1b[{ansi}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}
