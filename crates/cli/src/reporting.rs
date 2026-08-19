//! Report formatting and delivery for the KeyHog CLI.

use crate::args::{OutputFormat, ScanArgs};
use crate::stable_hash::StableHasher;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use keyhog_core::{
    AccessTargetReport, CorrelatedCredential, ReportFormat, ResolvedScanManifest,
    ScanCompletionStatus, ScanReport, ScanReportMetadata, StaticRecoveryMetrics, VerifiedFinding,
    STATIC_RECOVERY_METRICS_SCHEMA_VERSION,
};
use keyhog_profile::Stage;
use std::collections::BTreeMap;
use std::io::{self, BufWriter, IsTerminal, Write};

/// Default buffer capacity in bytes for streaming report writers.
const REPORT_BUFFER_CAPACITY: usize = 64 * 1024;

/// Wrap a writer in a standard buffered writer sized for report streaming.
fn buffered_report_writer<W: Write>(writer: W) -> BufWriter<W> {
    BufWriter::with_capacity(REPORT_BUFFER_CAPACITY, writer)
}
pub(crate) fn report_findings(findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()> {
    let metadata = generated_report_metadata();
    report_findings_with_metadata(findings, args, &metadata)
}

pub(crate) fn report_findings_with_metadata(
    findings: &[VerifiedFinding],
    args: &ScanArgs,
    metadata: &ScanReportMetadata,
) -> Result<()> {
    // Correlation reads the final reported findings, so it sees exactly what
    // the report will publish regardless of which source backend produced them.
    // Skipping the join entirely when the flag is off keeps the default path at
    // zero added work and its output byte-identical.
    let correlations = if args.correlate {
        let _correlate = keyhog_profile::span(Stage::Reporting);
        keyhog_core::correlate_findings(findings)
    } else {
        Vec::new()
    };
    // Access-target association reads the same final finding set. It re-reads
    // file context from disk, which is real work, so it only happens when the
    // operator asked: with the flag off the pass is never constructed and the
    // envelope has no `access_targets` key at all.
    let access_targets = if args.access_targets {
        let _doors = keyhog_profile::span(Stage::Reporting);
        Some(keyhog_core::associate_access_targets(findings))
    } else {
        None
    };
    if let Some(path) = &args.output {
        crate::atomic_file::write_with_file(path, |writer_handle| {
            let w = buffered_report_writer(writer_handle);
            report_with(
                w,
                &args.format,
                false,
                findings,
                metadata,
                &correlations,
                access_targets.as_ref(),
            )
            .map_err(|error| io::Error::other(format!("{error:#}")))
        })
        .with_context(|| format!("atomically writing report {}", path.display()))?;
        Ok(())
    } else {
        let w = buffered_report_writer(io::stdout());
        // Color when stdout is a TTY and the operator did not force plain output
        // via `--no-color`. (The `NO_COLOR` env convention is honored in the
        // orchestrator, which sets the flag-equivalent before reporting.)
        let color = io::stdout().is_terminal() && !args.no_color;
        report_with(
            w,
            &args.format,
            color,
            findings,
            metadata,
            &correlations,
            access_targets.as_ref(),
        )
    }
}

fn report_with<W: std::io::Write + 'static + Send>(
    w: W,
    format: &OutputFormat,
    color: bool,
    findings: &[VerifiedFinding],
    metadata: &ScanReportMetadata,
    correlations: &[CorrelatedCredential],
    access_targets: Option<&AccessTargetReport>,
) -> Result<()> {
    // One match owns every format. CSV uses write_csv_coverage_report (coverage
    // columns + gap summary); other formats go through write_scan_report.
    let report = {
        // Report finalization/assembly is Reporting-stage work.
        let _assembly = keyhog_profile::span(Stage::Reporting);
        ScanReport::new(findings)
            .with_metadata(metadata)
            .with_correlations(correlations)
    };
    let report = match access_targets {
        Some(targets) => report.with_access_targets(targets),
        None => report,
    };
    match format {
        OutputFormat::Csv => {
            // Per-format encoder span covers this format's write and flush.
            let _encoder = keyhog_profile::span(Stage::Reporting);
            let coverage_gap_summary = coverage_gap_summary(&CoverageCounts::current());
            keyhog_core::write_csv_coverage_report(w, report, &coverage_gap_summary)?;
            Ok(())
        }
        OutputFormat::Text => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            // Pass the example-suppression count so the empty-findings summary
            // distinguishes "no matches at all" from "matched + suppressed N as
            // known examples". Structured formats don't render prose, so the
            // count goes via --dogfood for those callers.
            let coverage = CoverageCounts::current();
            keyhog_core::write_scan_report(
                w,
                ReportFormat::Text {
                    color,
                    example_suppressions: keyhog_scanner::telemetry::example_suppression_count(),
                    dogfood_active: keyhog_scanner::telemetry::is_dogfood_enabled(),
                    // One snapshot for both, so stdout prose and the stderr
                    // coverage summary cannot disagree about what this scan
                    // looked at or what it threw away.
                    covered_nothing: coverage.covered_nothing(),
                    path_policy_suppressions: coverage.vendored_path_suppressions,
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::Json => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            if metadata.scan_status == ScanCompletionStatus::Failed && findings.is_empty() {
                return Ok(());
            }
            keyhog_core::write_scan_report(w, ReportFormat::Json, report)?;
            Ok(())
        }
        OutputFormat::JsonEnvelope => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::JsonEnvelope {
                    coverage_gap_summary: coverage_gap_summary(&CoverageCounts::current()),
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::Jsonl => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(w, ReportFormat::Jsonl, report)?;
            Ok(())
        }
        OutputFormat::JsonlEnvelope => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::JsonlEnvelope {
                    coverage_gap_summary: coverage_gap_summary(&CoverageCounts::current()),
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::Sarif => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::Sarif {
                    skip_summary: coverage_gap_summary(&CoverageCounts::current()),
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::GithubAnnotations => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::GithubAnnotationsCoverage {
                    skip_summary: coverage_gap_summary(&CoverageCounts::current()),
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::GitlabSast => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::GitlabSastCoverage {
                    scan_started_at: metadata.scan_started_at.clone(),
                    scan_finished_at: metadata.scan_finished_at.clone(),
                    skip_summary: coverage_gap_summary(&CoverageCounts::current()),
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::Html => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::Html {
                    skip_summary: coverage_gap_summary(&CoverageCounts::current()),
                    metadata: None,
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::Junit => {
            let _encoder = keyhog_profile::span(Stage::Reporting);
            keyhog_core::write_scan_report(
                w,
                ReportFormat::JunitCoverage {
                    skip_summary: coverage_gap_summary(&CoverageCounts::current()),
                },
                report,
            )?;
            Ok(())
        }
    }
}

/// Build the minimal metadata used when a caller reports findings outside a
/// full scan run (for example a direct `scan --format` invocation).
fn generated_report_metadata() -> ScanReportMetadata {
    let now = Utc::now();
    report_metadata_from_times(now, now, None)
}

/// Construct report metadata for scan paths whose corpus is fixed by their
/// existing protocol (for example the embedded-only daemon route).
pub(crate) fn report_metadata_from_scan_run(
    args: &ScanArgs,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    duration_ms: u128,
    source_chunks_scanned: usize,
    source_bytes_scanned: u64,
    detector_count: usize,
    config_digest: Option<u64>,
) -> ScanReportMetadata {
    report_metadata_from_scan_run_inner(
        args,
        started_at,
        finished_at,
        duration_ms,
        source_chunks_scanned,
        source_bytes_scanned,
        detector_count,
        None,
        config_digest,
    )
}

/// Construct scan metadata with the effective detector-corpus identity that the
/// in-process orchestrator loaded and compiled.
pub(crate) fn report_metadata_from_scan_run_with_corpus(
    args: &ScanArgs,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    duration_ms: u128,
    source_chunks_scanned: usize,
    source_bytes_scanned: u64,
    detector_count: usize,
    effective_detector_digest: &str,
    detector_provenance: &crate::orchestrator_config::DetectorCorpusProvenance,
    config_digest: Option<u64>,
) -> ScanReportMetadata {
    report_metadata_from_scan_run_inner(
        args,
        started_at,
        finished_at,
        duration_ms,
        source_chunks_scanned,
        source_bytes_scanned,
        detector_count,
        Some((effective_detector_digest, detector_provenance)),
        config_digest,
    )
}

fn report_metadata_from_scan_run_inner(
    args: &ScanArgs,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    duration_ms: u128,
    source_chunks_scanned: usize,
    source_bytes_scanned: u64,
    detector_count: usize,
    detector_corpus: Option<(&str, &crate::orchestrator_config::DetectorCorpusProvenance)>,
    config_digest: Option<u64>,
) -> ScanReportMetadata {
    let mut metadata = report_metadata_from_times(started_at, finished_at, config_digest);
    metadata.duration_ms = duration_ms;
    metadata.targets = scan_targets(args);
    metadata.source_chunks_scanned = source_chunks_scanned;
    metadata.source_bytes_scanned = source_bytes_scanned;
    metadata.detector_count = detector_count;
    metadata.backend_recoveries = crate::backend_recovery_summaries();
    metadata.static_recovery = Some(current_static_recovery_metrics());
    let scanner = crate::orchestrator_config::build_scanner_config(args);
    let mut resolved_scan = resolved_scan_manifest(args, &scanner);
    if let Some((effective_detector_digest, detector_provenance)) = detector_corpus {
        resolved_scan.effective.insert(
            "detector_corpus_mode".to_string(),
            detector_provenance.mode.to_string(),
        );
        resolved_scan.effective.insert(
            "detector_corpus_source".to_string(),
            detector_provenance.source.clone(),
        );
        resolved_scan.effective.insert(
            "detector_corpus_digest".to_string(),
            effective_detector_digest.to_string(),
        );
        resolved_scan.effective.insert(
            "detector_corpus_embedded_count".to_string(),
            detector_provenance.embedded_count.to_string(),
        );
        resolved_scan.effective.insert(
            "detector_corpus_custom_count".to_string(),
            detector_provenance.custom_count.to_string(),
        );
    }
    metadata.resolved_scan = Some(resolved_scan);
    let scan_failed = crate::FAILED_SOURCES.load(std::sync::atomic::Ordering::Relaxed) > 0;
    let scan_incomplete = crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed)
        || !coverage_gap_summary(&CoverageCounts::current_with_scanned_bytes(
            source_bytes_scanned,
        ))
        .is_empty();
    metadata.scan_status = if scan_failed {
        ScanCompletionStatus::Failed
    } else if scan_incomplete {
        ScanCompletionStatus::Partial
    } else if crate::BACKEND_RECOVERY_EVENTS.load(std::sync::atomic::Ordering::Relaxed) > 0 {
        ScanCompletionStatus::CompleteAfterRecovery
    } else {
        ScanCompletionStatus::Success
    };
    metadata.scan_id = scan_report_id(&metadata);
    metadata
}

fn report_metadata_from_times(
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    config_digest: Option<u64>,
) -> ScanReportMetadata {
    let mut metadata = ScanReportMetadata {
        scan_id: String::new(),
        scan_status: ScanCompletionStatus::Success,
        backend_recoveries: Vec::new(),
        static_recovery: Some(current_static_recovery_metrics()),
        keyhog_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: keyhog_core::git_hash().to_string(),
        detector_digest: keyhog_core::detector_digest().to_string(),
        config_digest: config_digest.map(|digest| format!("{digest:016x}")),
        resolved_scan: None,
        generated_at: format_gitlab_time(finished_at),
        scan_started_at: format_gitlab_time(started_at),
        scan_finished_at: format_gitlab_time(finished_at),
        duration_ms: 0,
        targets: Vec::new(),
        source_chunks_scanned: 0,
        source_bytes_scanned: 0,
        detector_count: keyhog_core::embedded_detector_count(),
    };
    metadata.scan_id = scan_report_id(&metadata);
    metadata
}

fn current_static_recovery_metrics() -> StaticRecoveryMetrics {
    let status = keyhog_scanner::telemetry::static_recovery_status();
    StaticRecoveryMetrics {
        schema_version: STATIC_RECOVERY_METRICS_SCHEMA_VERSION.to_string(),
        supported: status.supported,
        unsupported: status.unsupported,
        erroneous: status.erroneous,
        reasons: keyhog_scanner::telemetry::static_recovery_rejection_counts(),
    }
}

/// Build the one report-visible description of the preset and every effective
/// detection knob. The scanner config has already passed the normal merge and
/// sanitisation path, so this cannot describe a policy different from the one
/// the engine received. Values are strings by contract to keep the manifest
/// extensible without floating-point equality or schema churn.
fn resolved_scan_manifest(
    args: &ScanArgs,
    scanner: &keyhog_scanner::ScannerConfig,
) -> ResolvedScanManifest {
    let (preset, base) = if args.fast {
        ("fast", keyhog_scanner::ScannerConfig::fast())
    } else if args.deep {
        ("deep", keyhog_scanner::ScannerConfig::thorough())
    } else if args.precision {
        ("precision", keyhog_scanner::ScannerConfig::high_precision())
    } else {
        ("default", keyhog_scanner::ScannerConfig::default())
    };
    let effective = scanner_manifest_values(scanner);
    let base_values = scanner_manifest_values(&base);
    let overrides = effective
        .keys()
        .filter(|key| effective.get(*key) != base_values.get(*key))
        .cloned()
        .collect();
    ResolvedScanManifest {
        schema_version: 1,
        preset: preset.to_string(),
        effective,
        overrides,
    }
}

fn scanner_manifest_values(scanner: &keyhog_scanner::ScannerConfig) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    values.insert(
        "max_decode_depth".to_string(),
        scanner.max_decode_depth.to_string(),
    );
    values.insert(
        "max_decode_bytes".to_string(),
        scanner.max_decode_bytes.to_string(),
    );
    values.insert(
        "entropy_enabled".to_string(),
        scanner.entropy_enabled.to_string(),
    );
    values.insert(
        "entropy_in_source_files".to_string(),
        scanner.entropy_in_source_files.to_string(),
    );
    values.insert(
        "entropy_ml_authoritative".to_string(),
        scanner.entropy_ml_authoritative.to_string(),
    );
    values.insert(
        "generic_keyword_low_entropy".to_string(),
        scanner.generic_keyword_low_entropy.to_string(),
    );
    values.insert(
        "entropy_threshold".to_string(),
        scanner.entropy_threshold.to_string(),
    );
    values.insert(
        "entropy_bpe_max_bytes_per_token".to_string(),
        scanner.entropy_bpe_max_bytes_per_token.to_string(),
    );
    values.insert(
        "entropy_bpe_override".to_string(),
        scanner
            .entropy_bpe_max_bytes_per_token_override
            .map_or_else(|| "unset".to_string(), |value| value.to_string()),
    );
    values.insert(
        "min_secret_len".to_string(),
        scanner.min_secret_len.to_string(),
    );
    values.insert(
        "min_confidence".to_string(),
        scanner.min_confidence.to_string(),
    );
    values.insert("ml_enabled".to_string(), scanner.ml_enabled.to_string());
    values.insert(
        "ml_weight".to_string(),
        scanner.ml_weight_override.map_or_else(
            || "detector-policy".to_string(),
            |weight| weight.to_string(),
        ),
    );
    values.insert(
        "unicode_normalization".to_string(),
        scanner.unicode_normalization.to_string(),
    );
    values.insert(
        "validate_decode".to_string(),
        scanner.validate_decode.to_string(),
    );
    values.insert(
        "max_matches_per_chunk".to_string(),
        scanner.max_matches_per_chunk.to_string(),
    );
    values.insert(
        "scan_comments".to_string(),
        scanner.scan_comments.to_string(),
    );
    values.insert(
        "penalize_test_paths".to_string(),
        scanner.penalize_test_paths.to_string(),
    );
    values.insert(
        "known_prefixes_digest".to_string(),
        digest_strings("known-prefixes", &scanner.known_prefixes),
    );
    values.insert(
        "secret_keywords_digest".to_string(),
        digest_strings("secret-keywords", &scanner.secret_keywords),
    );
    values.insert(
        "test_keywords_digest".to_string(),
        digest_strings("test-keywords", &scanner.test_keywords),
    );
    values.insert(
        "placeholder_keywords_digest".to_string(),
        digest_strings("placeholder-keywords", &scanner.placeholder_keywords),
    );
    values
}

fn digest_strings(domain: &str, values: &[String]) -> String {
    let mut hasher = StableHasher::new(domain);
    for value in values {
        hasher.field_str("value", value);
    }
    hasher
        .finish_256()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Derive the artifact join key from non-secret scan identity and workload
/// fields. Targets are already redacted by `scan_targets`; length-prefixed
/// fields prevent ambiguous concatenation and the versioned domain keeps this
/// identifier independent from autoroute/config digests.
fn scan_report_id(metadata: &ScanReportMetadata) -> String {
    let mut hasher = StableHasher::new("scan-report-id-v1");
    hasher
        .field_str("keyhog_version", &metadata.keyhog_version)
        .field_str("git_hash", &metadata.git_hash)
        .field_str("detector_digest", &metadata.detector_digest)
        .field_option_str("config_digest", metadata.config_digest.as_deref())
        .field_str("scan_started_at", &metadata.scan_started_at)
        .field_str("scan_finished_at", &metadata.scan_finished_at)
        .field_bytes("duration_ms", &metadata.duration_ms.to_le_bytes())
        .field_usize("source_chunks_scanned", metadata.source_chunks_scanned)
        .field_u64("source_bytes_scanned", metadata.source_bytes_scanned)
        .field_usize("detector_count", metadata.detector_count);
    if let Some(resolved_scan) = &metadata.resolved_scan {
        hasher
            .field_u64("resolved_scan_schema", resolved_scan.schema_version as u64)
            .field_str("resolved_scan_preset", &resolved_scan.preset);
        for (key, value) in &resolved_scan.effective {
            hasher.field_str("resolved_scan_key", key);
            hasher.field_str("resolved_scan_value", value);
        }
        for override_key in &resolved_scan.overrides {
            hasher.field_str("resolved_scan_override", override_key);
        }
    }
    for target in &metadata.targets {
        hasher.field_str("target", target);
    }
    let digest = hasher.finish_256();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn format_gitlab_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S").to_string()
}

#[cfg(test)]
#[path = "../tests/unit/report_identity.rs"]
mod report_identity_tests;

/// One end-of-scan snapshot of every coverage-gap counter the reporters read.
///
/// The counters live in process-global atomics across two crates (source-side
/// [`keyhog_sources::skip_counts`] plus the scanner's telemetry) and are read
/// exactly once, at end of scan, by [`CoverageCounts::current`]. Threading a
/// snapshot through [`coverage_gap_summary`] instead of reading the globals
/// inside it makes that function pure, every category can be exercised
/// directly in a unit test, and keeps the "where do the numbers come from"
/// answer in one place.
#[derive(Debug, Clone, Default)]
pub(crate) struct CoverageCounts {
    /// Source-walker skip counters (files not scanned or only partially scanned).
    pub(crate) skip: keyhog_sources::SkipCounts,
    /// Source rows that surfaced as errors (requested input not fully scanned).
    pub(crate) source_errors: usize,
    /// Scan batches that could not be routed to any backend and were therefore
    /// never scanned at all. Distinct from `source_errors`: no source errored,
    /// the bytes arrived and then had nowhere to go.
    pub(crate) batches_not_routed: usize,
    /// Scanner structured parse failed (raw text scanned; encoded values not decoded).
    pub(crate) scanner_structured_parse_failures: usize,
    /// Structured decode-through file matched but exceeded the parse size cap.
    pub(crate) scanner_structured_oversize_skips: usize,
    /// Decode-through hit a budget/size cap; deeper encoded layers not expanded.
    pub(crate) scanner_decode_truncations: usize,
    /// Chunks larger than `--decode-size-limit`: decode-through never ran on
    /// them, so encoded secrets inside them were never recovered.
    pub(crate) scanner_decode_oversize_skips: usize,
    /// Pattern expansion skipped by an invalid pattern index (invariant violation).
    pub(crate) scanner_invalid_pattern_index_skips: usize,
    /// Boundary reassembly skipped by chunk/result cardinality drift (invariant).
    pub(crate) scanner_boundary_cardinality_mismatches: usize,
    /// Boundary reassembly context was truncated to MAX_BOUNDARY_SEAM_BYTES (128 KiB).
    pub(crate) scanner_boundary_seam_truncations: usize,
    /// Multiline attribution used a fallback source offset (approximate lines).
    pub(crate) scanner_line_offset_mismatches: usize,
    /// Chunks whose per-chunk deadline elapsed mid-scan: detection and/or
    /// post-processing stopped early and the chunk's remaining bytes were
    /// never matched, so its empty/short result is not a clean bill.
    pub(crate) scanner_chunk_deadline_aborts: usize,
    /// Named-detector matches the scanner MATCHED on a binary-derived chunk
    /// (ELF/PE/Mach-O strings, an archive member, a container layer) and then
    /// dropped because the match carried no structural proof. Like the
    /// vendored/minified row this is a FINDING-coverage gap, not a byte one:
    /// the bytes were read and a detector did fire.
    pub(crate) scanner_binary_strings_named_exclusions: usize,
    /// Binaries whose deep analysis degraded to strings-only (0 without `binary`).
    pub(crate) binary_degraded: usize,
    /// Binaries dropped as unreadable (0 without the `binary` feature).
    pub(crate) binary_unreadable: usize,
    /// Findings the scanner MATCHED and then dropped because their path is a
    /// vendored/minified bundle. Not a byte-coverage gap: the bytes were read.
    /// It is a FINDING-coverage gap, and an uncounted one used to be the only
    /// way a `sk_live_` key inlined into `app.min.js` could reach the report
    /// as "No secrets detected".
    pub(crate) vendored_path_suppressions: usize,
    /// The scan read ZERO source bytes and the walker found NOTHING to read:
    /// an empty directory, a directory holding only symlinks (never followed),
    /// or a CI matrix partition whose slice has no scannable files.
    ///
    /// Every other category answers "what did this scan miss"; this pair
    /// answers "did this scan look at anything at all". Production sets at most
    /// one of the two; the split exists because the remedies differ, and
    /// "policy hid everything" is far more likely to be a misconfiguration than
    /// "there was nothing there".
    pub(crate) nothing_scanned_no_input: bool,
    /// The scan read ZERO source bytes and the walker DID find candidates, then
    /// skipped every one of them. A `.keyhogignore` of `path:**`, an
    /// `--exclude-paths '**'`, or a tree that is entirely vendored used to
    /// produce exit 0, status success, an empty gap summary, and "No secrets
    /// detected" - a clean bill of health for a scan that examined nothing.
    pub(crate) nothing_scanned_all_skipped: bool,
}

impl CoverageCounts {
    /// Read every coverage-gap counter once, at end of scan. This is the ONLY
    /// place the process-global counters are read; everything downstream is a
    /// pure function of the returned snapshot.
    pub(crate) fn current() -> Self {
        Self::current_with_scanned_bytes(
            crate::SCANNED_BYTES.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    fn current_with_scanned_bytes(source_bytes_scanned: u64) -> Self {
        use keyhog_scanner::telemetry;
        let skip = keyhog_sources::skip_counts();
        // A trusted Merkle hit is completed incremental coverage, not an
        // exclusion. Clean files are cached only after a complete scan, while
        // finding-bearing files are forgotten before publication. Therefore a
        // warm all-unchanged run examined its requested content through the
        // persisted proof even though zero bytes reached the scanner.
        let covered_nothing =
            source_bytes_scanned == 0 && crate::orchestrator::merkle_skipped_unchanged() == 0;
        // "Policy hid everything" and "there was nothing there" are different
        // operator problems with different fixes, so they are different rows.
        // Any skip at all proves the walker found candidates and dropped them.
        let anything_skipped =
            skip.total() > 0 || skip.git_lfs_pointer > 0 || skip.git_object_unreadable > 0;
        CoverageCounts {
            skip,
            source_errors: crate::SOURCE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
            batches_not_routed: crate::BATCHES_NOT_ROUTED
                .load(std::sync::atomic::Ordering::Relaxed),
            scanner_structured_parse_failures: telemetry::structured_parse_failure_count(),
            scanner_structured_oversize_skips: telemetry::structured_oversize_skip_count(),
            scanner_decode_truncations: telemetry::decode_truncation_count(),
            scanner_decode_oversize_skips: telemetry::decode_oversize_skip_count(),
            scanner_invalid_pattern_index_skips: telemetry::invalid_pattern_index_skip_count(),
            scanner_boundary_cardinality_mismatches:
                telemetry::boundary_result_cardinality_mismatch_count(),
            scanner_boundary_seam_truncations: telemetry::boundary_seam_truncation_count(),
            scanner_line_offset_mismatches: telemetry::line_offset_mapping_mismatch_count(),
            scanner_chunk_deadline_aborts: telemetry::chunk_deadline_abort_count(),
            scanner_binary_strings_named_exclusions:
                telemetry::binary_strings_named_exclusion_count(),
            binary_degraded: binary_degraded_count(),
            binary_unreadable: binary_unreadable_count(),
            vendored_path_suppressions: telemetry::vendored_path_suppression_count(),
            nothing_scanned_no_input: covered_nothing && !anything_skipped,
            nothing_scanned_all_skipped: covered_nothing && anything_skipped,
        }
    }

    /// True when this scan read zero source bytes, whatever the cause. The
    /// text reporter's empty-findings prose asks this instead of duplicating
    /// the byte check, so the stdout line and the gap rows always agree.
    pub(crate) fn covered_nothing(&self) -> bool {
        self.nothing_scanned_no_input || self.nothing_scanned_all_skipped
    }

    /// Sum of every FAIL-class [`CoverageGapKind`] count (KH-1410). Incomplete
    /// exit 13 and baseline refuse use this single sum so they cannot drift
    /// from the severity table.
    pub(crate) fn fail_class_total(&self) -> usize {
        CoverageGapKind::fail_class_kinds()
            .map(|kind| kind.count(self))
            .sum()
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

/// Terminal severity for a coverage gap in the human end-of-scan summary.
/// `Fail` (red) means the scan genuinely did NOT cover some requested bytes, so
/// a "no secrets found" result is not a clean bill of health. `Warn` (yellow) is
/// an advisory/deliberate skip (size cap, binary, exclusion) or a partial
/// decode-through the raw scan still covered. SARIF notifications carry every
/// gap regardless of severity; only the terminal renderer colours by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverageSeverity {
    Fail,
    Warn,
}

/// The single canonical set of scan coverage-gap categories. Both the human
/// end-of-scan summary ([`crate::orchestrator::reporting::report_skip_summary`])
/// and the structured SARIF/HTML report ([`coverage_gap_summary`]) iterate
/// [`CoverageGapKind::ALL`], so a category can never exist on one surface and not
/// the other, a gap visible on the terminal but absent from SARIF is a
/// structured false-clean (Law 10). The per-surface *wording* legitimately
/// differs (terse machine reason for SARIF, verbose reason-plus-remedy for the
/// operator), but the *set* of categories and their severity live here once.
/// Adding a variant is a compile error until every `match` below handles it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverageGapKind {
    NothingScannedNoInput,
    NothingScannedAllSkipped,
    ScannerStructuredParseFailure,
    ScannerStructuredOversizeSkip,
    ScannerDecodeTruncation,
    ScannerDecodeOversizeSkip,
    ScannerInvalidPatternIndexSkip,
    ScannerBoundaryCardinalityMismatch,
    ScannerBoundarySeamTruncation,
    ScannerLineOffsetMismatch,
    ScannerChunkDeadlineAbort,
    ScannerBinaryStringsNamedExclusion,
    VendoredPathSuppressed,
    SourceError,
    BatchNotRouted,
    OverMaxSize,
    Binary,
    Excluded,
    NonBinaryUnreadable,
    GitObjectUnreadable,
    ArchiveTruncated,
    BinarySectionNameUnresolved,
    SourceTruncated,
    StructuredSourceParseFailure,
    ArchiveDuplicateScanUnavailable,
    GitLfsPointer,
    BinaryDegraded,
    BinaryUnreadable,
}

impl CoverageGapKind {
    /// Canonical emission order: the whole-scan "did we look at anything" row
    /// first, then scanner-engine gaps, then source-walker gaps, then
    /// binary-source gaps. Both surfaces emit non-zero categories in this order.
    pub(crate) const ALL: [CoverageGapKind; 28] = [
        Self::NothingScannedNoInput,
        Self::NothingScannedAllSkipped,
        Self::ScannerStructuredParseFailure,
        Self::ScannerStructuredOversizeSkip,
        Self::ScannerDecodeTruncation,
        Self::ScannerDecodeOversizeSkip,
        Self::ScannerInvalidPatternIndexSkip,
        Self::ScannerBoundaryCardinalityMismatch,
        Self::ScannerBoundarySeamTruncation,
        Self::ScannerLineOffsetMismatch,
        Self::ScannerChunkDeadlineAbort,
        Self::ScannerBinaryStringsNamedExclusion,
        Self::VendoredPathSuppressed,
        Self::SourceError,
        Self::BatchNotRouted,
        Self::OverMaxSize,
        Self::Binary,
        Self::Excluded,
        Self::NonBinaryUnreadable,
        Self::GitObjectUnreadable,
        Self::ArchiveTruncated,
        Self::BinarySectionNameUnresolved,
        Self::SourceTruncated,
        Self::StructuredSourceParseFailure,
        Self::ArchiveDuplicateScanUnavailable,
        Self::GitLfsPointer,
        Self::BinaryDegraded,
        Self::BinaryUnreadable,
    ];

    /// FAIL-class kinds only (KH-1410). Incomplete exit 13, baseline refuse,
    /// and `SourceCoverageGaps::fail_class_total` must agree with this set.
    pub(crate) fn fail_class_kinds() -> impl Iterator<Item = CoverageGapKind> {
        Self::ALL
            .into_iter()
            .filter(|k| k.severity() == CoverageSeverity::Fail)
    }

    /// This category's count from a snapshot. `NonBinaryUnreadable` excludes
    /// unreadable binaries (their own category) so the same dropped file is never
    /// counted twice across the two surfaces.
    pub(crate) fn count(self, counts: &CoverageCounts) -> usize {
        let c = &counts.skip;
        match self {
            Self::NothingScannedNoInput => usize::from(counts.nothing_scanned_no_input),
            Self::NothingScannedAllSkipped => usize::from(counts.nothing_scanned_all_skipped),
            Self::ScannerStructuredParseFailure => counts.scanner_structured_parse_failures,
            Self::ScannerStructuredOversizeSkip => counts.scanner_structured_oversize_skips,
            Self::ScannerDecodeTruncation => counts.scanner_decode_truncations,
            Self::ScannerDecodeOversizeSkip => counts.scanner_decode_oversize_skips,
            Self::ScannerInvalidPatternIndexSkip => counts.scanner_invalid_pattern_index_skips,
            Self::ScannerBoundaryCardinalityMismatch => {
                counts.scanner_boundary_cardinality_mismatches
            }
            Self::ScannerBoundarySeamTruncation => counts.scanner_boundary_seam_truncations,
            Self::ScannerLineOffsetMismatch => counts.scanner_line_offset_mismatches,
            Self::ScannerChunkDeadlineAbort => counts.scanner_chunk_deadline_aborts,
            Self::ScannerBinaryStringsNamedExclusion => {
                counts.scanner_binary_strings_named_exclusions
            }
            Self::VendoredPathSuppressed => counts.vendored_path_suppressions,
            Self::SourceError => counts.source_errors,
            Self::BatchNotRouted => counts.batches_not_routed,
            Self::OverMaxSize => c.over_max_size,
            Self::Binary => c.binary,
            Self::Excluded => c.excluded,
            Self::NonBinaryUnreadable => c.unreadable.saturating_sub(counts.binary_unreadable),
            Self::GitObjectUnreadable => c.git_object_unreadable,
            Self::ArchiveTruncated => c.archive_truncated,
            Self::BinarySectionNameUnresolved => c.binary_section_name_unresolved,
            Self::SourceTruncated => c.source_truncated,
            Self::StructuredSourceParseFailure => c.structured_source_parse_failures,
            Self::ArchiveDuplicateScanUnavailable => c.archive_duplicate_scan_unavailable,
            Self::GitLfsPointer => c.git_lfs_pointer,
            Self::BinaryDegraded => counts.binary_degraded,
            Self::BinaryUnreadable => counts.binary_unreadable,
        }
    }

    /// Terminal severity for the human summary. SARIF ignores this, it reports
    /// every non-zero gap identically.
    pub(crate) fn severity(self) -> CoverageSeverity {
        match self {
            // Deliberate skips and bounded decode-through gaps whose raw bytes
            // remain fully covered render as advisory WARN.
            Self::OverMaxSize
            | Self::Binary
            | Self::Excluded
            // Findings dropped by the vendored/minified path policy are a
            // precision trade the operator can reverse with
            // `--no-default-excludes`, and a `node_modules` tree can produce
            // thousands. WARN keeps a normal repo scan at exit 0 while still
            // printing the count and the flag that recovers them.
            | Self::VendoredPathSuppressed
            // Same class one layer down: a named detector matched inside a
            // binary's printable runs and the match could not prove it was a
            // whole token rather than a fragment of surrounding identifier
            // soup. The bytes are fully covered and the trade is a precision
            // one, so WARN keeps a binary-heavy tree at exit 0 while printing
            // the count and how to see the matches.
            | Self::ScannerBinaryStringsNamedExclusion
            | Self::ScannerStructuredOversizeSkip
            | Self::ScannerDecodeTruncation
            | Self::ScannerDecodeOversizeSkip
            | Self::ScannerInvalidPatternIndexSkip
            | Self::ScannerBoundaryCardinalityMismatch
            | Self::ScannerBoundarySeamTruncation => CoverageSeverity::Warn,
            // Genuine "these bytes were NOT covered" (or line identity is wrong)
            // → red FAIL: a clean bill is unsafe while any of these is non-zero.
            // Line-offset mismatch is FAIL so incomplete exit 13 and SARIF
            // consumers share one FAIL set (KH-1347).
            // Structured parse failure loses encoded-value coverage and must
            // fail closed rather than bless the raw-only scan as complete.
            // Zero bytes read is the strongest FAIL there is: nothing was
            // examined, so "no secrets detected" states nothing at all.
            Self::NothingScannedNoInput
            | Self::NothingScannedAllSkipped
            | Self::ScannerStructuredParseFailure
            | Self::SourceError
            | Self::BatchNotRouted
            | Self::NonBinaryUnreadable
            | Self::GitObjectUnreadable
            | Self::ArchiveTruncated
            | Self::BinarySectionNameUnresolved
            | Self::SourceTruncated
            | Self::StructuredSourceParseFailure
            | Self::ArchiveDuplicateScanUnavailable
            | Self::GitLfsPointer
            | Self::BinaryDegraded
            | Self::BinaryUnreadable
            | Self::ScannerChunkDeadlineAbort
            | Self::ScannerLineOffsetMismatch => CoverageSeverity::Fail,
        }
    }

    /// Terse, stable machine reason for a SARIF `toolExecutionNotifications`
    /// entry (the count is a separate field, so this string is count-free).
    pub(crate) fn sarif_reason(self) -> &'static str {
        match self {
            Self::NothingScannedNoInput => {
                "scan covered nothing (zero source bytes reached the scanner and no skip was counted; nothing was examined, so this result is not a clean bill of health)"
            }
            Self::NothingScannedAllSkipped => {
                "scan covered nothing (zero source bytes read; every candidate was skipped by exclusion or skip policy, so nothing was examined)"
            }
            Self::ScannerStructuredParseFailure => {
                "scanner structured parse failed (raw text scanned; encoded structured values not decoded)"
            }
            Self::ScannerStructuredOversizeSkip => {
                "scanner structured decode-through skipped by size cap (structured file matched but exceeded the parse cap; encoded values e.g. a k8s data block were not decoded)"
            }
            Self::ScannerDecodeTruncation => {
                "scanner decode-through truncated by budget/cap (raw bytes scanned; deeper encoded layers not expanded)"
            }
            Self::ScannerDecodeOversizeSkip => {
                "scanner decode-through declined by --decode-size-limit (chunk larger than the limit; raw bytes scanned, nothing encoded inside it was recovered)"
            }
            Self::ScannerInvalidPatternIndexSkip => {
                "scanner pattern expansion skipped by invalid pattern index (scanner invariant violation; scan partial)"
            }
            Self::ScannerBoundaryCardinalityMismatch => {
                "scanner boundary reassembly skipped by chunk/result cardinality mismatch (scanner invariant violation; scan partial)"
            }
            Self::ScannerBoundarySeamTruncation => {
                "scanner boundary reassembly context truncated by seam size cap (raw chunk bytes scanned; unbounded match straddling a seam wider than the cap was not reassembled)"
            }
            Self::ScannerLineOffsetMismatch => {
                "scanner multiline attribution used fallback source offsets (line-offset metadata mismatch; scan partial)"
            }
            Self::ScannerChunkDeadlineAbort => {
                "scanner chunk abandoned at its per-chunk deadline (detection and/or post-processing stopped early; the chunk's remaining bytes were not matched)"
            }
            Self::ScannerBinaryStringsNamedExclusion => {
                "named-detector matches dropped by the binary-strings noise gate (the match was inside a compiled artifact's printable runs and did not span a whole token; rerun with --dogfood to see them)"
            }
            Self::VendoredPathSuppressed => {
                "matches dropped by the vendored/minified path policy (credentials matched in .min.js/.bundle.js/.min.css or a vendored tree and were not reported; rerun with --no-default-excludes to report them)"
            }
            Self::SourceError => {
                "source emitted error rows (requested input was not fully scanned)"
            }
            Self::BatchNotRouted => {
                "scan batches could not be routed to any backend and were never scanned"
            }
            // One counter, many caps: `SourceSkipEvent::OverMaxSize` is raised by
            // --max-file-size AND by every --limit-*-bytes cap (stdin, git blob,
            // docker tar entry / image config, s3 / gcs / azure object, archive
            // per-entry, windowed-mmap sanity). Naming only --max-file-size sent
            // operators to raise a cap that had not fired: with
            // `--limit-git-blob-bytes 64B` the warning said "exceeded
            // --max-file-size", so raising that flag left the blobs skipped. The
            // per-cap warnings above the summary name the exact flag; this label
            // must not contradict them.
            Self::OverMaxSize => {
                "exceeded a configured size cap (--max-file-size or the matching --limit-*-bytes)"
            }
            Self::Binary => "binary (extension or content sniff)",
            Self::Excluded => {
                "default exclusion policy (lock files, minified/bundled assets, vendored and build-output trees). User `.keyhogignore` / --exclude-paths removals are not counted here"
            }
            Self::NonBinaryUnreadable => "unreadable (permission denied or I/O error)",
            Self::GitObjectUnreadable => {
                "Git object unreadable or wrong object kind (referenced commit/tree/blob not scanned)"
            }
            Self::ArchiveTruncated => {
                "archive or container extraction truncated by an unpack budget (remaining entries not scanned; the warnings above name the exact cap)"
            }
            Self::BinarySectionNameUnresolved => {
                "binary section name unresolved (corrupt section-name string table; section may be unscanned)"
            }
            Self::SourceTruncated => {
                "source scan truncated by aggregate source cap (remaining input not scanned)"
            }
            Self::StructuredSourceParseFailure => {
                "structured source parse failed (raw text scanned; derived chunks not expanded)"
            }
            Self::ArchiveDuplicateScanUnavailable => {
                "archive duplicate-entry detection unavailable (zip64 or malformed central directory; shadow entries may be missed)"
            }
            Self::GitLfsPointer => {
                "Git-LFS pointer (pointer text scanned; referenced blob is in LFS storage, not on disk; run `git lfs pull` then rescan)"
            }
            Self::BinaryDegraded => {
                "binary deep analysis degraded to strings-only (Ghidra failed or output too large)"
            }
            Self::BinaryUnreadable => {
                "binary unreadable (permission denied or I/O error; binary NOT scanned)"
            }
        }
    }

    /// Verbose operator reason WITH the remedy, for the human stderr summary.
    /// `n` is this category's count (always > 0 at the call site).
    pub(crate) fn human_reason(self, n: usize) -> String {
        match self {
            // `n` is always 1 here (a scan either read bytes or did not), so
            // these two read as statements of fact rather than counts.
            Self::NothingScannedNoInput => format!(
                "This scan read ZERO bytes: nothing under the requested target(s) reached \
                 the scanner and no skip was counted. Nothing was examined, so an empty \
                 result says nothing about whether secrets are present. Check the target \
                 path and your `.keyhogignore` / `--exclude-paths` patterns (`path:**` or \
                 `**` removes every file), and note that symlinks are never followed and an \
                 empty directory contributes nothing. ({n} scan.)"
            ),
            Self::NothingScannedAllSkipped => format!(
                "This scan read ZERO bytes: the walker found candidates and skipped every \
                 one of them (see the other rows for which policy). Nothing was examined, so \
                 an empty result says nothing about whether secrets are present. Narrow your \
                 `.keyhogignore` / `--exclude-paths`, or pass `--no-default-excludes`, then \
                 re-scan. ({n} scan.)"
            ),
            Self::ScannerStructuredParseFailure => format!(
                "{n} file(s) matched a structured format (k8s Secret / Terraform state / \
                 Jupyter notebook / docker-compose) but FAILED to parse: secrets ENCODED \
                 inside them (e.g. base64 in a k8s `data:` block) were NOT decoded. The raw \
                 text was still scanned. Fix the file syntax to scan their encoded contents."
            ),
            Self::ScannerStructuredOversizeSkip => format!(
                "{n} file(s) matched a structured decode-through format (k8s Secret / \
                 Terraform state / Jupyter notebook / docker-compose) but EXCEEDED the \
                 structured-parse size cap: base64-encoded values (e.g. a k8s `data:` block) \
                 were NOT decoded. The raw text was still scanned. Split the file or scan the \
                 encoded blob directly to prove its decoded coverage."
            ),
            Self::ScannerDecodeTruncation => format!(
                "{n} decode root(s) hit a decode-through budget/cap: raw bytes were scanned, \
                 but deeper encoded layers may not have been expanded. Re-scan the affected \
                 corpus with a narrower target or tuned decode limits to prove encoded coverage."
            ),
            Self::ScannerDecodeOversizeSkip => format!(
                "{n} chunk(s) were larger than the decode-through limit \
                 (`--decode-size-limit`, `decode_size_limit`), so decode-through did NOT run \
                 on them at all: the raw bytes were scanned, but nothing base64/hex/URL-encoded \
                 inside them was recovered. Raise `--decode-size-limit` above the largest \
                 affected input, or scan the encoded blobs directly, to prove decoded coverage."
            ),
            Self::ScannerInvalidPatternIndexSkip => format!(
                "{n} scanner pattern expansion edge(s) were NOT applied: compiled pattern-index \
                 side data referenced patterns outside the trigger bitmap. This is a scanner \
                 invariant violation; treat the scan as partial."
            ),
            Self::ScannerBoundaryCardinalityMismatch => format!(
                "{n} boundary reassembly pass(es) were NOT applied: chunk/result cardinality \
                 drift made cross-chunk findings unsafe to append. This is a scanner invariant \
                 violation; treat the scan as partial."
            ),
            Self::ScannerBoundarySeamTruncation => format!(
                "{n} boundary reassembly pass(es) were TRUNCATED to the seam size cap: \
                 raw chunk bytes were scanned, but an unbounded pattern match wider than \
                 the cap straddling a seam was not reassembled. Split chunks or scan as a continuous stream \
                 to prove cross-seam coverage."
            ),
            Self::ScannerLineOffsetMismatch => format!(
                "{n} multiline attribution mapping(s) used a fallback source offset because \
                 line-offset metadata was inconsistent. Findings were still emitted, but \
                 reported locations may be approximate; treat the scan as partial."
            ),
            Self::ScannerChunkDeadlineAbort => format!(
                "{n} chunk scan(s) STOPPED at the per-chunk deadline: detection and/or \
                 post-processing did not finish, so those chunks' remaining bytes were NOT \
                 checked for secrets and an empty result for them is not a clean bill. \
                 Raise or clear the per-chunk deadline and re-scan the affected input."
            ),
            Self::ScannerBinaryStringsNamedExclusion => format!(
                "{n} named-detector match(es) were MATCHED inside a compiled artifact's \
                 printable runs and then DROPPED because the match did not span a whole \
                 token: it began or ended mid-identifier, which in a binary usually means \
                 a mangled symbol or a concatenated string table rather than a credential \
                 the program holds. Re-scan with `--dogfood` to see each excluded match \
                 and its detector."
            ),
            Self::VendoredPathSuppressed => format!(
                "{n} credential match(es) were DROPPED before the report because their file \
                 is a minified or vendored bundle (`.min.js`, `.bundle.js`, `.min.css`, \
                 `node_modules/`, `site-packages/`, `wp-includes/`, `dist/assets/`, and \
                 similar). One credential can be matched by more than one detector, so this \
                 counts drops, not distinct secrets. Build tooling routinely inlines real \
                 API keys into those bundles, so this is a precision trade, not proof they \
                 are noise. Re-scan with `--no-default-excludes` to report them."
            ),
            Self::SourceError => format!(
                "{n} source error row(s) emitted: requested input was NOT fully scanned. \
                 Inspect the source errors above and rerun affected inputs."
            ),
            Self::BatchNotRouted => format!(
                "{n} scan batch(es) could not be routed to a backend and were NEVER SCANNED: \
                 their bytes reached the scanner and had nowhere to go, so any secret in them \
                 is unreported. Rerun `keyhog calibrate-autoroute` for this workload, or pass \
                 an explicit `--backend`, then rerun the scan."
            ),
            Self::OverMaxSize => format!(
                "{n} file(s) skipped: exceeded a configured size cap (--max-file-size or the \
                 matching --limit-*-bytes). Raise the cap named in the warnings above and re-scan."
            ),
            Self::Binary => format!(
                "{n} file(s) skipped: detected as binary (extension or content sniff) and not \
                 scanned as text."
            ),
            Self::Excluded => format!(
                "{n} path(s) skipped by the DEFAULT exclusion policy (lock files, \
                 minified/bundled assets, vendored and build-output trees). \
                 Default-excluded directories are pruned during discovery and counted \
                 once each; nested files under them are not enumerated. Pass \
                 `--no-default-excludes` to scan them. Files removed by your own \
                 `.keyhogignore` or `--exclude-paths` are not counted in this number."
            ),
            Self::NonBinaryUnreadable => format!(
                "{n} file(s) NOT scanned: unreadable (permission denied or I/O error). These \
                 were NOT checked for secrets."
            ),
            Self::GitObjectUnreadable => format!(
                "{n} Git object(s) NOT scanned: referenced commit/tree/blob data was unreadable \
                 or not the expected object kind."
            ),
            Self::ArchiveTruncated => format!(
                "{n} archive(s) or container image(s) only PARTIALLY scanned: extraction \
                 stopped at an unpack budget. Remaining entries were NOT checked for \
                 secrets. Several caps raise this one counter (the filesystem \
                 decompression-bomb guard at 4x `--max-file-size`, the Docker/OCI image \
                 and per-tar budgets, the tar entry-count cap), so raise the cap named in \
                 the warnings above and re-scan."
            ),
            Self::BinarySectionNameUnresolved => format!(
                "{n} binary section(s) NOT scanned: their name could not be resolved \
                 (corrupt/truncated section-name string table). A secret-bearing section may \
                 have been skipped."
            ),
            Self::SourceTruncated => format!(
                "{n} source scan(s) only PARTIALLY scanned: a source-level aggregate cap was \
                 reached before all input was exhausted."
            ),
            Self::StructuredSourceParseFailure => format!(
                "{n} structured source file(s) only PARTIALLY scanned: format-specific \
                 expansion failed, so raw text was scanned but derived request/response/body \
                 chunks were not expanded."
            ),
            Self::ArchiveDuplicateScanUnavailable => format!(
                "{n} archive(s) scanned WITHOUT duplicate-entry detection: a zip64 or malformed \
                 central directory prevented it, so a duplicated/shadow entry hiding a secret \
                 may have been missed."
            ),
            Self::GitLfsPointer => format!(
                "{n} Git-LFS pointer(s) scanned WITHOUT their referenced content: the real blob \
                 lives in LFS storage and was not on disk. Run `git lfs pull` to materialise \
                 the blobs, then rescan."
            ),
            Self::BinaryDegraded => format!(
                "{n} binary(ies) only SHALLOWLY scanned: Ghidra deep decompiler analysis failed \
                 or was too large, so only strings-mode extraction ran. Encoded/split secrets \
                 may have been missed."
            ),
            Self::BinaryUnreadable => format!(
                "{n} binary(ies) NOT scanned: unreadable (permission denied or I/O error). \
                 These were NOT checked for secrets."
            ),
        }
    }
}

/// Build the SARIF/HTML coverage-gap summary from a [`CoverageCounts`] snapshot.
/// Each non-zero category becomes one `(reason, count)` pair the reporter
/// surfaces as a tool-execution notification, so a consuming platform sees the
/// scan's coverage gaps (unreadable files especially (those are unknowns)).
///
/// Every category the human end-of-scan summary can print MUST appear here too:
/// the structured (SARIF/HTML/JSON) surface silently under-reporting a gap the
/// human sees is a false-clean (Law 10). This previously drifted, the SARIF
/// path omitted unreadable *binaries* and the structured decode-through
/// oversize skip (so both are explicit entries below).
pub(crate) fn coverage_gap_summary(counts: &CoverageCounts) -> Vec<(String, usize)> {
    let summary: Vec<(String, usize)> = CoverageGapKind::ALL
        .iter()
        .map(|kind| (kind.sarif_reason().to_string(), kind.count(counts)))
        .filter(|(_, n)| *n > 0)
        .collect();
    // One event per detection pass that found at least one gap.
    if !summary.is_empty() {
        keyhog_profile::record_event(keyhog_profile::EventId::CoverageGap, 1);
    }
    summary
}

#[cfg(test)]
mod coverage_gap_tests;
#[cfg(test)]
mod scan_target_tests;

fn scan_targets(args: &ScanArgs) -> Vec<String> {
    let mut targets = Vec::new();
    // Every filesystem root the run actually scans, deduplicated by
    // `scan_roots` (which also absorbs the orchestrator's internal
    // `input -> path` promotion), so the header lists each root once whether the
    // invocation was `--path`, a single positional, or `keyhog scan a/ b/ c/`.
    #[cfg(feature = "git")]
    let scans_worktree = !args.git_staged;
    #[cfg(not(feature = "git"))]
    let scans_worktree = true;
    if scans_worktree {
        for root in args.scan_roots() {
            push_path_target(&mut targets, "path", Some(&root));
        }
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
            push_path_target(&mut targets, "git-staged", args.scan_roots().first());
        }
    }

    #[cfg(feature = "github")]
    if let Some(org) = &args.github_org {
        targets.push(format!("github-org:{org}"));
    }
    #[cfg(feature = "github")]
    if let Some(repository) = &args.github_collaboration {
        let mut surfaces = Vec::new();
        if args.github_all || args.github_issues {
            surfaces.push("issues");
        }
        if args.github_all || args.github_pull_requests {
            surfaces.push("pull-requests");
        }
        if args.github_all || args.github_discussions {
            surfaces.push("discussions");
        }
        if args.github_all || args.github_wiki {
            surfaces.push("wiki");
        }
        if args.github_all || args.github_gists {
            surfaces.push("gists");
        }
        targets.push(format!(
            "github-collaboration:{repository}[{}]",
            surfaces.join(",")
        ));
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
