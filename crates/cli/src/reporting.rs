//! Report formatting and delivery for the KeyHog CLI.

use crate::args::{OutputFormat, ScanArgs};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use keyhog_core::{ReportFormat, VerifiedFinding};
use std::io::{self, IsTerminal};

#[derive(Clone, Debug)]
pub(crate) struct ReportMetadata {
    scan_started_at: String,
    scan_finished_at: String,
}

impl ReportMetadata {
    pub(crate) fn from_scan_times(started_at: DateTime<Utc>, finished_at: DateTime<Utc>) -> Self {
        Self {
            scan_started_at: format_gitlab_time(started_at),
            scan_finished_at: format_gitlab_time(finished_at),
        }
    }

    fn generated_now() -> Self {
        let now = Utc::now();
        Self::from_scan_times(now, now)
    }
}

pub(crate) fn report_findings(findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()> {
    let metadata = ReportMetadata::generated_now();
    report_findings_with_metadata(findings, args, &metadata)
}

pub(crate) fn report_findings_with_metadata(
    findings: &[VerifiedFinding],
    args: &ScanArgs,
    metadata: &ReportMetadata,
) -> Result<()> {
    if let Some(ref path) = args.output {
        crate::atomic_file::write_with_file(path, |writer_handle| {
            let w = io::BufWriter::new(writer_handle);
            report_with(w, &args.format, false, findings, metadata)
                .map_err(|error| io::Error::other(format!("{error:#}")))
        })
        .with_context(|| format!("atomically writing report {}", path.display()))?;
        Ok(())
    } else {
        let w = io::BufWriter::new(io::stdout());
        report_with(
            w,
            &args.format,
            io::stdout().is_terminal(),
            findings,
            metadata,
        )
    }
}

fn report_with<W: std::io::Write + 'static + Send>(
    w: W,
    format: &OutputFormat,
    color: bool,
    findings: &[VerifiedFinding],
    metadata: &ReportMetadata,
) -> Result<()> {
    let format = match format {
        OutputFormat::Text => ReportFormat::Text {
            color,
            // Pass the example-suppression count so the empty-findings
            // summary distinguishes "no matches at all" from
            // "matched + suppressed N as known examples". Structured
            // formats (JSON/JSONL/SARIF) don't render prose, so the
            // count goes via --dogfood for those callers.
            example_suppressions: keyhog_scanner::telemetry::example_suppression_count(),
            dogfood_active: keyhog_scanner::telemetry::is_dogfood_enabled(),
        },
        OutputFormat::Json => ReportFormat::Json,
        OutputFormat::Jsonl => ReportFormat::Jsonl,
        OutputFormat::Sarif => ReportFormat::Sarif {
            skip_summary: sarif_skip_summary(),
        },
        OutputFormat::Csv => ReportFormat::Csv,
        OutputFormat::GithubAnnotations => ReportFormat::GithubAnnotations,
        OutputFormat::GitlabSast => ReportFormat::GitlabSast {
            scan_started_at: metadata.scan_started_at.clone(),
            scan_finished_at: metadata.scan_finished_at.clone(),
        },
        OutputFormat::Html => ReportFormat::Html,
        OutputFormat::Junit => ReportFormat::Junit,
    };
    keyhog_core::write_report(w, format, findings)?;
    Ok(())
}

fn format_gitlab_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// Build the SARIF coverage-gap summary from source and scanner counters. Each
/// non-zero category becomes one `(reason, count)` pair the SARIF reporter
/// surfaces as a tool-execution notification, so a consuming platform sees the
/// scan's coverage gaps (unreadable files especially — those are unknowns).
fn sarif_skip_summary() -> Vec<(String, usize)> {
    let c = keyhog_sources::skip_counts();
    let summary = vec![
        ("exceeded --max-file-size".to_string(), c.over_max_size),
        (
            "binary (extension or content sniff)".to_string(),
            c.binary,
        ),
        (
            "default-exclusion list (lock/minified/vendored)".to_string(),
            c.excluded,
        ),
        (
            "unreadable (permission denied or I/O error)".to_string(),
            c.unreadable,
        ),
        (
            "archive extraction truncated by decompression-bomb guard (remaining entries not scanned)".to_string(),
            c.archive_truncated,
        ),
        (
            "binary section name unresolved (corrupt section-name string table; section may be unscanned)".to_string(),
            c.binary_section_name_unresolved,
        ),
        (
            "source scan truncated by aggregate source cap (remaining input not scanned)".to_string(),
            c.source_truncated,
        ),
        (
            "structured source parse failed (raw text scanned; derived chunks not expanded)".to_string(),
            c.structured_source_parse_failures,
        ),
        (
            "scanner structured parse failed (raw text scanned; encoded structured values not decoded)".to_string(),
            keyhog_scanner::telemetry::structured_parse_failure_count(),
        ),
        (
            "scanner decode-through truncated by budget/cap (raw bytes scanned; deeper encoded layers not expanded)".to_string(),
            keyhog_scanner::telemetry::decode_truncation_count(),
        ),
        (
            "scanner pattern skipped by invalid detector index (scanner invariant violation; scan partial)".to_string(),
            keyhog_scanner::telemetry::invalid_detector_index_skip_count(),
        ),
        (
            "scanner pattern expansion skipped by invalid pattern index (scanner invariant violation; scan partial)".to_string(),
            keyhog_scanner::telemetry::invalid_pattern_index_skip_count(),
        ),
        (
            "scanner boundary reassembly skipped by chunk/result cardinality mismatch (scanner invariant violation; scan partial)".to_string(),
            keyhog_scanner::telemetry::boundary_result_cardinality_mismatch_count(),
        ),
    ];

    #[cfg(feature = "binary")]
    let summary = {
        let mut summary = summary;
        summary.push((
            "binary deep analysis degraded to strings-only (Ghidra failed or output too large)"
                .to_string(),
            keyhog_sources::binary_degraded_to_strings(),
        ));
        summary
    };

    summary.into_iter().filter(|(_, n)| *n > 0).collect()
}
