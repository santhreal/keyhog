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
        // Atomic-write the report file. A partial SARIF/JSON output
        // breaks downstream tooling (GitHub code scanning rejects
        // malformed SARIF; CI gates fail to parse JSON). Write to
        // a NamedTempFile in the target directory, let the reporter
        // flush + finish, then atomic-rename. If keyhog crashes
        // mid-report (panic, OOM, kill), the user's previous
        // report file is untouched and the tmp gets reaped by Drop.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating output parent dir {}", parent.display()))?;
        let tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating output tmp in {}", parent.display()))?;
        let writer_handle = tmp
            .reopen()
            .with_context(|| format!("reopening output tmp for write of {}", path.display()))?;
        let w = io::BufWriter::new(writer_handle);
        report_with(w, &args.format, false, findings, metadata)?;
        // BufWriter is dropped inside report_with's flush path;
        // sync the tempfile's backing file before atomic rename so
        // a crash between persist and the next fsync of the parent
        // dir doesn't lose data on filesystems with delayed
        // metadata writeback.
        tmp.as_file()
            .sync_all()
            .with_context(|| format!("fsyncing output tmp for {}", path.display()))?;
        tmp.persist(path)
            .map_err(|e| e.error)
            .with_context(|| format!("renaming output tmp onto {}", path.display()))?;
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

/// Build the SARIF skipped-file summary from the source-layer skip counters.
/// Each non-zero category becomes one `(reason, count)` pair the SARIF reporter
/// surfaces as a tool-execution notification, so a consuming platform sees the
/// scan's coverage gaps (unreadable files especially — those are unknowns).
fn sarif_skip_summary() -> Vec<(String, usize)> {
    let c = keyhog_sources::skip_counts();
    [
        ("exceeded --max-file-size", c.over_max_size),
        ("binary (extension or content sniff)", c.binary),
        (
            "default-exclusion list (lock/minified/vendored)",
            c.excluded,
        ),
        ("unreadable (permission denied or I/O error)", c.unreadable),
        (
            "archive extraction truncated by decompression-bomb guard (remaining entries not scanned)",
            c.archive_truncated,
        ),
        (
            "binary section name unresolved (corrupt section-name string table; section may be unscanned)",
            c.binary_section_name_unresolved,
        ),
        (
            "source scan truncated by aggregate source cap (remaining input not scanned)",
            c.source_truncated,
        ),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .map(|(reason, n)| (reason.to_string(), n))
    .collect()
}
