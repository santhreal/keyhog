//! Report formatting and delivery for the KeyHog CLI.

use crate::args::{OutputFormat, ScanArgs};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use keyhog_core::{HtmlScanMetadata, ReportFormat, VerifiedFinding};
use std::io::{self, IsTerminal};

#[derive(Clone, Debug)]
pub(crate) struct ReportMetadata {
    scan_started_at: String,
    scan_finished_at: String,
    duration_ms: u128,
    targets: Vec<String>,
    source_chunks_scanned: usize,
    detector_count: usize,
    keyhog_version: String,
}

impl ReportMetadata {
    pub(crate) fn from_scan_times(started_at: DateTime<Utc>, finished_at: DateTime<Utc>) -> Self {
        Self {
            scan_started_at: format_gitlab_time(started_at),
            scan_finished_at: format_gitlab_time(finished_at),
            duration_ms: 0,
            targets: Vec::new(),
            source_chunks_scanned: 0,
            detector_count: keyhog_core::embedded_detector_count(),
            keyhog_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub(crate) fn from_scan_run(
        args: &ScanArgs,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        duration_ms: u128,
        source_chunks_scanned: usize,
        detector_count: usize,
    ) -> Self {
        let mut metadata = Self::from_scan_times(started_at, finished_at);
        metadata.duration_ms = duration_ms;
        metadata.targets = scan_targets(args);
        metadata.source_chunks_scanned = source_chunks_scanned;
        metadata.detector_count = detector_count;
        metadata
    }

    fn generated_now() -> Self {
        let now = Utc::now();
        Self::from_scan_times(now, now)
    }

    fn html(&self) -> HtmlScanMetadata {
        HtmlScanMetadata {
            keyhog_version: self.keyhog_version.clone(),
            generated_at: self.scan_finished_at.clone(),
            scan_started_at: self.scan_started_at.clone(),
            scan_finished_at: self.scan_finished_at.clone(),
            duration_ms: self.duration_ms,
            targets: self.targets.clone(),
            source_chunks_scanned: self.source_chunks_scanned,
            detector_count: self.detector_count,
        }
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
            skip_summary: coverage_gap_summary(&CoverageCounts::current()),
        },
        OutputFormat::Csv => ReportFormat::Csv,
        OutputFormat::GithubAnnotations => ReportFormat::GithubAnnotations,
        OutputFormat::GitlabSast => ReportFormat::GitlabSast {
            scan_started_at: metadata.scan_started_at.clone(),
            scan_finished_at: metadata.scan_finished_at.clone(),
        },
        OutputFormat::Html => ReportFormat::Html {
            skip_summary: coverage_gap_summary(&CoverageCounts::current()),
            metadata: Some(metadata.html()),
        },
        OutputFormat::Junit => ReportFormat::Junit,
    };
    keyhog_core::write_report(w, format, findings)?;
    Ok(())
}

fn format_gitlab_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// One end-of-scan snapshot of every coverage-gap counter the reporters read.
///
/// The counters live in process-global atomics across two crates (source-side
/// [`keyhog_sources::skip_counts`] plus the scanner's telemetry) and are read
/// exactly once, at end of scan, by [`CoverageCounts::current`]. Threading a
/// snapshot through [`coverage_gap_summary`] instead of reading the globals
/// inside it makes that function pure — every category can be exercised
/// directly in a unit test — and keeps the "where do the numbers come from"
/// answer in one place.
#[derive(Debug, Clone, Default)]
pub(crate) struct CoverageCounts {
    /// Source-walker skip counters (files not scanned or only partially scanned).
    pub(crate) skip: keyhog_sources::SkipCounts,
    /// Source rows that surfaced as errors (requested input not fully scanned).
    pub(crate) source_errors: usize,
    /// Scanner structured parse failed (raw text scanned; encoded values not decoded).
    pub(crate) scanner_structured_parse_failures: usize,
    /// Structured decode-through file matched but exceeded the parse size cap.
    pub(crate) scanner_structured_oversize_skips: usize,
    /// Decode-through hit a budget/size cap; deeper encoded layers not expanded.
    pub(crate) scanner_decode_truncations: usize,
    /// Pattern expansion skipped by an invalid pattern index (invariant violation).
    pub(crate) scanner_invalid_pattern_index_skips: usize,
    /// Boundary reassembly skipped by chunk/result cardinality drift (invariant).
    pub(crate) scanner_boundary_cardinality_mismatches: usize,
    /// Multiline attribution used a fallback source offset (approximate lines).
    pub(crate) scanner_line_offset_mismatches: usize,
    /// Binaries whose deep analysis degraded to strings-only (0 without `binary`).
    pub(crate) binary_degraded: usize,
    /// Binaries dropped as unreadable (0 without the `binary` feature).
    pub(crate) binary_unreadable: usize,
}

impl CoverageCounts {
    /// Read every coverage-gap counter once, at end of scan. This is the ONLY
    /// place the process-global counters are read; everything downstream is a
    /// pure function of the returned snapshot.
    pub(crate) fn current() -> Self {
        use keyhog_scanner::telemetry;
        CoverageCounts {
            skip: keyhog_sources::skip_counts(),
            source_errors: crate::SOURCE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
            scanner_structured_parse_failures: telemetry::structured_parse_failure_count(),
            scanner_structured_oversize_skips: telemetry::structured_oversize_skip_count(),
            scanner_decode_truncations: telemetry::decode_truncation_count(),
            scanner_invalid_pattern_index_skips: telemetry::invalid_pattern_index_skip_count(),
            scanner_boundary_cardinality_mismatches:
                telemetry::boundary_result_cardinality_mismatch_count(),
            scanner_line_offset_mismatches: telemetry::line_offset_mapping_mismatch_count(),
            binary_degraded: binary_degraded_count(),
            binary_unreadable: binary_unreadable_count(),
        }
    }
}

/// Ghidra-degraded binary count, or 0 when the `binary` source is not compiled.
fn binary_degraded_count() -> usize {
    #[cfg(feature = "binary")]
    {
        keyhog_sources::binary_degraded_to_strings()
    }
    #[cfg(not(feature = "binary"))]
    {
        0
    }
}

/// Unreadable-binary count, or 0 when the `binary` source is not compiled.
fn binary_unreadable_count() -> usize {
    #[cfg(feature = "binary")]
    {
        keyhog_sources::binary_unreadable()
    }
    #[cfg(not(feature = "binary"))]
    {
        0
    }
}

/// Build the SARIF/HTML coverage-gap summary from a [`CoverageCounts`] snapshot.
/// Each non-zero category becomes one `(reason, count)` pair the reporter
/// surfaces as a tool-execution notification, so a consuming platform sees the
/// scan's coverage gaps (unreadable files especially — those are unknowns).
///
/// Every category the human end-of-scan summary can print MUST appear here too:
/// the structured (SARIF/HTML/JSON) surface silently under-reporting a gap the
/// human sees is a false-clean (Law 10). This previously drifted — the SARIF
/// path omitted unreadable *binaries* and the structured decode-through
/// oversize skip — so both are explicit entries below.
fn coverage_gap_summary(counts: &CoverageCounts) -> Vec<(String, usize)> {
    let c = &counts.skip;
    // Unreadable binaries are reported as their OWN category below, so the
    // generic unreadable count excludes them — otherwise the same dropped file
    // is counted twice across the two categories.
    let non_binary_unreadable = c.unreadable.saturating_sub(counts.binary_unreadable);
    let summary = vec![
        (
            "source emitted error rows (requested input was not fully scanned)".to_string(),
            counts.source_errors,
        ),
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
            non_binary_unreadable,
        ),
        (
            "Git object unreadable or wrong object kind (referenced commit/tree/blob not scanned)"
                .to_string(),
            c.git_object_unreadable,
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
            "archive duplicate-entry detection unavailable (zip64 or malformed central directory; shadow entries may be missed)".to_string(),
            c.archive_duplicate_scan_unavailable,
        ),
        (
            "Git-LFS pointer (pointer text scanned; referenced blob is in LFS storage, not on disk — run `git lfs pull` then rescan)".to_string(),
            c.git_lfs_pointer,
        ),
        (
            "scanner structured parse failed (raw text scanned; encoded structured values not decoded)".to_string(),
            counts.scanner_structured_parse_failures,
        ),
        (
            "scanner structured decode-through skipped by size cap (structured file matched but exceeded the parse cap; encoded values e.g. a k8s data block were not decoded)".to_string(),
            counts.scanner_structured_oversize_skips,
        ),
        (
            "scanner decode-through truncated by budget/cap (raw bytes scanned; deeper encoded layers not expanded)".to_string(),
            counts.scanner_decode_truncations,
        ),
        (
            "scanner pattern expansion skipped by invalid pattern index (scanner invariant violation; scan partial)".to_string(),
            counts.scanner_invalid_pattern_index_skips,
        ),
        (
            "scanner boundary reassembly skipped by chunk/result cardinality mismatch (scanner invariant violation; scan partial)".to_string(),
            counts.scanner_boundary_cardinality_mismatches,
        ),
        (
            "scanner multiline attribution used fallback source offsets (line-offset metadata mismatch; scan partial)".to_string(),
            counts.scanner_line_offset_mismatches,
        ),
        (
            "binary deep analysis degraded to strings-only (Ghidra failed or output too large)"
                .to_string(),
            counts.binary_degraded,
        ),
        (
            "binary unreadable (permission denied or I/O error; binary NOT scanned)".to_string(),
            counts.binary_unreadable,
        ),
    ];

    summary.into_iter().filter(|(_, n)| *n > 0).collect()
}

#[cfg(test)]
mod coverage_gap_tests;

fn scan_targets(args: &ScanArgs) -> Vec<String> {
    let mut targets = Vec::new();
    // Every filesystem root the run actually scans, deduplicated by
    // `scan_roots` (which also absorbs the orchestrator's internal
    // `input -> path` promotion), so the header lists each root once whether the
    // invocation was `--path`, a single positional, or `keyhog scan a/ b/ c/`.
    for root in args.scan_roots() {
        push_path_target(&mut targets, "path", Some(&root));
    }
    if args.stdin {
        targets.push("stdin".to_string());
    }

    #[cfg(feature = "git")]
    {
        push_path_target(&mut targets, "git-blobs", args.git_blobs.as_ref());
        if let Some(base) = &args.git_diff {
            let repo = match args.git_diff_path.as_ref() {
                Some(path) => path.display().to_string(),
                None => ".".to_string(),
            };
            targets.push(format!("git-diff:{repo}@{base}"));
        }
        push_path_target(&mut targets, "git-history", args.git_history.as_ref());
        if args.git_staged {
            targets.push("git-staged".to_string());
        }
    }

    #[cfg(feature = "github")]
    if let Some(org) = &args.github_org {
        targets.push(format!("github-org:{org}"));
    }
    #[cfg(feature = "gitlab")]
    if let Some(group) = &args.gitlab_group {
        targets.push(format!("gitlab-group:{group}"));
    }
    #[cfg(feature = "bitbucket")]
    if let Some(workspace) = &args.bitbucket_workspace {
        targets.push(format!("bitbucket-workspace:{workspace}"));
    }
    #[cfg(feature = "s3")]
    if let Some(bucket) = &args.s3_bucket {
        targets.push(match &args.s3_prefix {
            Some(prefix) => format!("s3:{bucket}/{prefix}"),
            None => format!("s3:{bucket}"),
        });
    }
    #[cfg(feature = "gcs")]
    if let Some(bucket) = &args.gcs_bucket {
        targets.push(match &args.gcs_prefix {
            Some(prefix) => format!("gcs:{bucket}/{prefix}"),
            None => format!("gcs:{bucket}"),
        });
    }
    #[cfg(feature = "azure")]
    if let Some(url) = &args.azure_container_url {
        targets.push(format!("azure:{}", redact_url_target(url)));
    }
    #[cfg(feature = "docker")]
    if let Some(image) = &args.docker_image {
        targets.push(format!("docker:{image}"));
    }
    #[cfg(feature = "web")]
    if let Some(urls) = &args.url {
        targets.extend(
            urls.iter()
                .map(|url| format!("url:{}", redact_url_target(url))),
        );
    }
    if let Some(custom) = &args.source {
        targets.extend(custom.iter().map(|name| format!("source:{name}")));
    }

    targets.sort();
    targets.dedup();
    targets
}

fn push_path_target(targets: &mut Vec<String>, kind: &str, path: Option<&std::path::PathBuf>) {
    if let Some(path) = path {
        targets.push(format!("{kind}:{}", path.display()));
    }
}

// `pub(crate)` so the relocated unit test reaches it through the `crate::testing`
// facade (the `reporting_no_inline_tests` gate forbids inline test modules here).
pub(crate) fn redact_url_target(raw: &str) -> String {
    let without_fragment = raw.split_once('#').map_or(raw, |(head, _)| head);
    match without_fragment.split_once('?') {
        Some((head, _)) => format!("{head}?<redacted>"),
        None => without_fragment.to_string(),
    }
}
