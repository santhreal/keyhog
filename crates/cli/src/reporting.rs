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
            skip_summary: coverage_gap_summary(),
        },
        OutputFormat::Csv => ReportFormat::Csv,
        OutputFormat::GithubAnnotations => ReportFormat::GithubAnnotations,
        OutputFormat::GitlabSast => ReportFormat::GitlabSast {
            scan_started_at: metadata.scan_started_at.clone(),
            scan_finished_at: metadata.scan_finished_at.clone(),
        },
        OutputFormat::Html => ReportFormat::Html {
            skip_summary: coverage_gap_summary(),
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

/// Build the SARIF coverage-gap summary from source and scanner counters. Each
/// non-zero category becomes one `(reason, count)` pair the SARIF reporter
/// surfaces as a tool-execution notification, so a consuming platform sees the
/// scan's coverage gaps (unreadable files especially — those are unknowns).
fn coverage_gap_summary() -> Vec<(String, usize)> {
    let c = keyhog_sources::skip_counts();
    let source_errors = crate::SOURCE_ERRORS.load(std::sync::atomic::Ordering::Relaxed);
    let summary = vec![
        (
            "source emitted error rows (requested input was not fully scanned)".to_string(),
            source_errors,
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
            c.unreadable,
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
            "scanner structured parse failed (raw text scanned; encoded structured values not decoded)".to_string(),
            keyhog_scanner::telemetry::structured_parse_failure_count(),
        ),
        (
            "scanner decode-through truncated by budget/cap (raw bytes scanned; deeper encoded layers not expanded)".to_string(),
            keyhog_scanner::telemetry::decode_truncation_count(),
        ),
        (
            "scanner pattern expansion skipped by invalid pattern index (scanner invariant violation; scan partial)".to_string(),
            keyhog_scanner::telemetry::invalid_pattern_index_skip_count(),
        ),
        (
            "scanner boundary reassembly skipped by chunk/result cardinality mismatch (scanner invariant violation; scan partial)".to_string(),
            keyhog_scanner::telemetry::boundary_result_cardinality_mismatch_count(),
        ),
        (
            "scanner multiline attribution used fallback source offsets (line-offset metadata mismatch; scan partial)".to_string(),
            keyhog_scanner::telemetry::line_offset_mapping_mismatch_count(),
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
