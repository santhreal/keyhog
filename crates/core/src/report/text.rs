//! Human-readable terminal reporter with severity coloring and rich finding details.

use std::io::Write;

use crate::{MatchLocation, VerificationResult, VerifiedFinding};

use super::escape::sanitize_terminal;
use super::style as report_style;
use super::{impl_writer_backed, ReportError, Reporter, WriterBackedReporter};

/// Human-readable text output with gradient banner and styled findings.
///
/// # Examples
///
/// ```ignore
/// // Crate-internal reporter; public callers use `write_report`.
/// use keyhog_core::report::text::TextReporter;
///
/// let reporter = TextReporter::with_color(Vec::new(), false);
/// let _ = reporter;
/// ```
pub(crate) struct TextReporter<W: Write + Send> {
    writer: W,
    count: usize,
    color: bool,
    live_count: usize,
    dead_count: usize,
    /// Number of credentials matched and then suppressed as known
    /// examples/test/placeholder values. Surfaced in the empty-findings
    /// summary so "0 secrets" doesn't get conflated with "0 matches at
    /// all". Set by the caller before `finish()`; default 0 keeps the
    /// original behavior for callers that don't track it.
    example_suppressions: usize,
    /// True when the caller is running with `--dogfood`. The empty-findings
    /// line drops the "Pass --dogfood to see them" hint in that case, since the
    /// user has clearly already done so. Set by the caller before `finish()`;
    /// default false matches the historical behavior.
    dogfood_active: bool,
}

impl<W: Write + Send> TextReporter<W> {
    /// Create a text reporter with explicit ANSI color control.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Crate-internal reporter; public callers use `write_report`.
    /// use keyhog_core::report::text::TextReporter;
    ///
    /// let reporter = TextReporter::with_color(Vec::new(), false);
    /// let _ = reporter;
    /// ```
    pub(crate) fn with_color(writer: W, color: bool) -> Self {
        Self {
            writer,
            count: 0,
            color,
            live_count: 0,
            dead_count: 0,
            example_suppressions: 0,
            dogfood_active: false,
        }
    }

    /// Tell the reporter how many credentials were matched and silently
    /// suppressed as known example/test/placeholder values. The reporter
    /// uses this only to phrase the empty-findings summary honestly
    /// (e.g. demo-secret.env's `AKIAIOSFODNN7EXAMPLE` shouldn't render
    /// as "Your code is clean"). Idempotent; later calls replace.
    pub(crate) fn set_example_suppressions(&mut self, n: usize) {
        self.example_suppressions = n;
    }

    /// Tell the reporter that the caller is already running with `--dogfood`.
    /// Suppresses the "Pass --dogfood to see them" hint in the empty-findings
    /// line, since the user has clearly already passed it. Idempotent.
    pub(crate) fn set_dogfood_active(&mut self, active: bool) {
        self.dogfood_active = active;
    }
}

impl<W: Write + Send> Reporter for TextReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.count += 1;

        // Track verification stats. `Dead` and `Revoked` are both CONFIRMED-
        // INACTIVE outcomes of a real verification, so both count toward the
        // inactive (`dead`) tally. Folding `Revoked` here keeps the summary's
        // `unverified = count - live - dead` honest: a verified-revoked secret
        // was verified - it must not be reported as "unverified" (which means
        // "liveness unknown"). The per-finding line still shows `revoked`
        // precisely; only this coarse roll-up groups the two inactive states.
        match &finding.verification {
            VerificationResult::Live => self.live_count += 1,
            VerificationResult::Dead | VerificationResult::Revoked => self.dead_count += 1,
            VerificationResult::RateLimited
            | VerificationResult::Error(_)
            | VerificationResult::Unverifiable
            | VerificationResult::Skipped => {}
        }

        let severity_str = report_style::severity_label(finding.severity, self.color);
        let verified = report_style::verification_label(&finding.verification, self.color);
        let location = format_location(&finding.location);
        // `confidence` is a public field, so a library-constructed finding could
        // carry an out-of-range or NaN score. Sanitize ONCE into [0,1] and derive
        // both the bar fill and the percent from it, so they can never disagree
        // (e.g. a full bar rendered "150%", or a NaN percent). NaN -> 0, matching
        // the scanner's `finalize_confidence` (clamp alone does not sanitize NaN).
        let confidence_value = finding.confidence.unwrap_or(0.0); // LAW10: no confidence score -> empty bar; display only, finding still printed
        let display_conf = if confidence_value.is_finite() {
            confidence_value.clamp(0.0, 1.0)
        } else {
            0.0
        };
        const BAR_WIDTH: usize = 6;
        let filled = ((display_conf * BAR_WIDTH as f64) as usize).min(BAR_WIDTH);
        let bar = format!("{}{}", "■".repeat(filled), "□".repeat(BAR_WIDTH - filled));
        let confidence = format!(
            "{} {}",
            report_style::confidence_bar(&bar, display_conf, self.color),
            report_style::dim(
                &format!("{:>3}%", (display_conf * 100.0) as u32),
                self.color,
            )
        );

        // Severity color for the box border
        let border_ansi = report_style::severity_border_style(finding.severity);

        // Top border with severity and detector name
        writeln!(
            self.writer,
            "  {} {} {}",
            report_style::paint("┌", border_ansi, self.color),
            severity_str,
            report_style::paint(
                &format!("─── {}", finding.detector_name),
                border_ansi,
                self.color,
            ),
        )?;

        // Secret
        writeln!(
            self.writer,
            "  {} {} {}",
            report_style::paint("│", border_ansi, self.color),
            report_style::dim("Secret:    ", self.color),
            report_style::highlight(&sanitize_terminal(&finding.credential_redacted), self.color),
        )?;

        // Location
        writeln!(
            self.writer,
            "  {} {} {}",
            report_style::paint("│", border_ansi, self.color),
            report_style::dim("Location:  ", self.color),
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
            report_style::paint("│", border_ansi, self.color),
            report_style::dim("Confidence:", self.color),
            confidence,
            verify_suffix,
        )?;

        // Commit info
        if let Some(commit) = &finding.location.commit {
            writeln!(
                self.writer,
                "  {} {} {}",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim("Commit:    ", self.color),
                sanitize_terminal(commit),
            )?;
        }

        if let Some(author) = &finding.location.author {
            writeln!(
                self.writer,
                "  {} {} {}",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim("Author:    ", self.color),
                sanitize_terminal(author),
            )?;
        }

        if let Some(date) = &finding.location.date {
            writeln!(
                self.writer,
                "  {} {} {}",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim("Date:      ", self.color),
                sanitize_terminal(date),
            )?;
        }

        // Extra metadata. Sort HashMap-backed provider fields so text output is
        // byte-stable across processes and hash seeds.
        let mut metadata: Vec<_> = finding.metadata.iter().collect();
        metadata.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (key, value) in metadata {
            writeln!(
                self.writer,
                "  {} {} {}",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim(
                    &format!("{:<11}", format!("{}:", sanitize_terminal(key))),
                    self.color
                ),
                sanitize_terminal(value),
            )?;
        }

        if !finding.additional_locations.is_empty() {
            writeln!(
                self.writer,
                "  {} {} (+{} more locations)",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim("Extra:     ", self.color),
                finding.additional_locations.len(),
            )?;
        }

        // Remediation
        let remediation = crate::auto_fix::remediation_for(
            &finding.detector_id,
            &finding.service,
            finding.severity,
        );
        writeln!(
            self.writer,
            "  {} {} {}",
            report_style::paint("│", border_ansi, self.color),
            report_style::dim("Action:    ", self.color),
            report_style::remediation_action(&sanitize_terminal(&remediation.action), self.color),
        )?;
        if let Some(command) = &remediation.revoke_command {
            writeln!(
                self.writer,
                "  {} {} {}",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim("Command:   ", self.color),
                sanitize_terminal(command),
            )?;
        }
        if let Some(url) = remediation
            .revoke_url
            .as_ref()
            .or(remediation.docs_url.as_ref())
        {
            writeln!(
                self.writer,
                "  {} {} {}",
                report_style::paint("│", border_ansi, self.color),
                report_style::dim("Docs:      ", self.color),
                sanitize_terminal(url),
            )?;
        }

        // Bottom border
        writeln!(
            self.writer,
            "  {}\n",
            report_style::paint(
                "└─────────────────────────────────────────────",
                border_ansi,
                self.color,
            ),
        )?;

        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        if self.count == 0 {
            if self.example_suppressions > 0 {
                let plural = if self.example_suppressions == 1 {
                    ""
                } else {
                    "s"
                };
                let msg = if self.dogfood_active {
                    format!(
                        "No real secrets, but {} example/test key{} suppressed (see --dogfood output above for the full list).",
                        self.example_suppressions, plural
                    )
                } else {
                    format!(
                        "No real secrets, but {} example/test key{} suppressed. Pass --dogfood to see them.",
                        self.example_suppressions, plural
                    )
                };
                writeln!(
                    self.writer,
                    "  {}\n",
                    report_style::warning(&msg, self.color)
                )?;
            } else {
                // Never claim "clean": a scanner cannot prove the ABSENCE of
                // secrets (only their presence), and skipped/unreadable/binary
                // files were not covered at all. State only what is true — nothing
                // was detected in what was scanned. The end-of-scan skip summary
                // (stderr) reports what was NOT covered.
                writeln!(
                    self.writer,
                    "  {}\n",
                    report_style::success("No secrets detected in the scanned files.", self.color),
                )?;
            }
        } else {
            let summary_border = report_style::muted_border(
                "━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                self.color,
            );
            writeln!(self.writer, "  {}", summary_border)?;

            let plural = if self.count == 1 { "" } else { "s" };

            let mut parts = vec![report_style::highlight(
                &format!("{} secret{plural} found", self.count),
                self.color,
            )];
            if self.live_count > 0 {
                parts.push(report_style::danger(
                    &format!("{} live", self.live_count),
                    self.color,
                ));
            }
            if self.dead_count > 0 {
                parts.push(report_style::success(
                    &format!("{} dead", self.dead_count),
                    self.color,
                ));
            }
            let unverified = self.count - self.live_count - self.dead_count;
            if unverified > 0 {
                parts.push(report_style::warning(
                    &format!("{unverified} unverified"),
                    self.color,
                ));
            }

            writeln!(self.writer, "  {}", parts.join(" · "))?;

            // Next steps
            writeln!(self.writer)?;
            writeln!(
                self.writer,
                "  {} Revoke active secrets in the provider's dashboard.",
                report_style::danger("1.", self.color),
            )?;
            writeln!(
                self.writer,
                "  {} Remove credentials from codebase and git history.",
                report_style::warning("2.", self.color),
            )?;
            writeln!(
                self.writer,
                "  {} Use a secure secret manager or environment variables.",
                report_style::success("3.", self.color),
            )?;

            let end_border = report_style::muted_border(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                self.color,
            );
            writeln!(self.writer, "\n  {}\n", end_border)?;
        }
        self.flush_writer()
    }
}

impl_writer_backed!(TextReporter);

fn format_location(location: &MatchLocation) -> String {
    match (&location.file_path, location.line) {
        (Some(path), Some(line)) => {
            format!(
                "{}:{}",
                sanitize_terminal(crate::strip_windows_verbatim_prefix(path)),
                line
            )
        }
        (Some(path), None) => {
            sanitize_terminal(crate::strip_windows_verbatim_prefix(path)).into_owned()
        }
        _ => sanitize_terminal(&location.source).into_owned(),
    }
}
