//! Report formatting and delivery for the KeyHog CLI.

use crate::args::{OutputFormat, ScanArgs};
use crate::stable_hash::StableHasher;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use keyhog_core::{
    ReportFormat, ResolvedScanManifest, ScanCompletionStatus, ScanReport, ScanReportMetadata,
    VerifiedFinding,
};
use std::collections::BTreeMap;
use std::io::{self, IsTerminal};

pub(crate) fn report_findings(findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()> {
    let metadata = generated_report_metadata();
    report_findings_with_metadata(findings, args, &metadata)
}

pub(crate) fn report_findings_with_metadata(
    findings: &[VerifiedFinding],
    args: &ScanArgs,
    metadata: &ScanReportMetadata,
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
        // Color when stdout is a TTY and the operator did not force plain output
        // via `--no-color`. (The `NO_COLOR` env convention is honored in the
        // orchestrator, which sets the flag-equivalent before reporting.)
        let color = io::stdout().is_terminal() && !args.no_color;
        report_with(w, &args.format, color, findings, metadata)
    }
}

fn report_with<W: std::io::Write + 'static + Send>(
    w: W,
    format: &OutputFormat,
    color: bool,
    findings: &[VerifiedFinding],
    metadata: &ScanReportMetadata,
) -> Result<()> {
    // One match owns every format. CSV uses write_csv_coverage_report (coverage
    // columns + gap summary); other formats go through write_scan_report.
    let report = ScanReport::new(findings).with_metadata(metadata);
    match format {
        OutputFormat::Csv => {
            let coverage_gap_summary = coverage_gap_summary(&CoverageCounts::current());
            keyhog_core::write_csv_coverage_report(w, report, &coverage_gap_summary)?;
            Ok(())
        }
        OutputFormat::Text => {
            // Pass the example-suppression count so the empty-findings summary
            // distinguishes "no matches at all" from "matched + suppressed N as
            // known examples". Structured formats don't render prose, so the
            // count goes via --dogfood for those callers.
            keyhog_core::write_scan_report(
                w,
                ReportFormat::Text {
                    color,
                    example_suppressions: keyhog_scanner::telemetry::example_suppression_count(),
                    dogfood_active: keyhog_scanner::telemetry::is_dogfood_enabled(),
                },
                report,
            )?;
            Ok(())
        }
        OutputFormat::Json => {
            keyhog_core::write_scan_report(w, ReportFormat::Json, report)?;
            Ok(())
        }
        OutputFormat::JsonEnvelope => {
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
            keyhog_core::write_scan_report(w, ReportFormat::Jsonl, report)?;
            Ok(())
        }
        OutputFormat::JsonlEnvelope => {
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

/// Construct the single core-owned report metadata model for a scan run.
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
    let mut metadata = report_metadata_from_times(started_at, finished_at, config_digest);
    metadata.duration_ms = duration_ms;
    metadata.targets = scan_targets(args);
    metadata.source_chunks_scanned = source_chunks_scanned;
    metadata.source_bytes_scanned = source_bytes_scanned;
    metadata.detector_count = detector_count;
    metadata.backend_recoveries = crate::backend_recovery_summaries();
    let scanner = crate::orchestrator_config::build_scanner_config(args);
    metadata.resolved_scan = Some(resolved_scan_manifest(args, &scanner));
    let has_coverage_gaps = !coverage_gap_summary(&CoverageCounts::current()).is_empty();
    metadata.scan_status = if has_coverage_gaps {
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
mod tests {
    use super::{resolved_scan_manifest, scan_report_id, ScanReportMetadata};
    use crate::args::ScanArgs;
    use clap::Parser;
    use keyhog_core::{ResolvedScanManifest, ScanCompletionStatus};
    use std::collections::BTreeMap;

    fn metadata() -> ScanReportMetadata {
        ScanReportMetadata {
            scan_id: String::new(),
            scan_status: ScanCompletionStatus::Success,
            backend_recoveries: Vec::new(),
            keyhog_version: env!("CARGO_PKG_VERSION").to_string(),
            git_hash: "test-git".to_string(),
            detector_digest: "test-detectors".to_string(),
            config_digest: Some("0000000000000001".to_string()),
            resolved_scan: None,
            generated_at: "2026-07-14T00:00:01".to_string(),
            scan_started_at: "2026-07-14T00:00:00".to_string(),
            scan_finished_at: "2026-07-14T00:00:01".to_string(),
            duration_ms: 1_000,
            targets: vec!["path:repo".to_string()],
            source_chunks_scanned: 2,
            source_bytes_scanned: 128,
            detector_count: 922,
        }
    }

    #[test]
    fn scan_report_id_is_stable_and_identity_bound() {
        let base = metadata();
        assert_eq!(scan_report_id(&base), scan_report_id(&base));
        assert_eq!(scan_report_id(&base).len(), 32);
        assert!(scan_report_id(&base)
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));

        let mut changed_config = base.clone();
        changed_config.config_digest = Some("0000000000000002".to_string());
        assert_ne!(scan_report_id(&base), scan_report_id(&changed_config));

        let mut changed_target = base;
        changed_target.targets = vec!["path:other-repo".to_string()];
        assert_ne!(
            scan_report_id(&changed_target),
            scan_report_id(&changed_config)
        );

        let mut changed_mode = changed_config.clone();
        changed_mode.resolved_scan = Some(ResolvedScanManifest {
            schema_version: 1,
            preset: "deep".to_string(),
            effective: BTreeMap::new(),
            overrides: Vec::new(),
        });
        assert_ne!(
            scan_report_id(&changed_mode),
            scan_report_id(&changed_config)
        );
    }

    #[test]
    fn resolved_scan_manifest_is_diffable_across_presets_and_overrides(
    ) -> Result<(), serde_json::Error> {
        let default_args = ScanArgs::parse_from(["keyhog"]);
        let deep_args = ScanArgs::parse_from(["keyhog", "--deep", "--decode-depth", "3"]);
        let default_manifest =
            resolved_scan_manifest(&default_args, &keyhog_scanner::ScannerConfig::default());
        let deep_manifest = resolved_scan_manifest(
            &deep_args,
            &crate::orchestrator_config::build_scanner_config(&deep_args),
        );

        assert_eq!(default_manifest.schema_version, 1);
        assert_eq!(default_manifest.preset, "default");
        assert_eq!(deep_manifest.preset, "deep");
        assert_ne!(default_manifest, deep_manifest);
        assert_eq!(deep_manifest.effective["max_decode_depth"], "3");
        assert!(deep_manifest
            .overrides
            .iter()
            .any(|key| key == "max_decode_depth"));

        let encoded = serde_json::to_string(&deep_manifest)?;
        assert!(encoded.contains("\"preset\":\"deep\""));
        assert!(encoded.contains("\"max_decode_depth\":\"3\""));
        Ok(())
    }
}

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
    ScannerStructuredParseFailure,
    ScannerStructuredOversizeSkip,
    ScannerDecodeTruncation,
    ScannerInvalidPatternIndexSkip,
    ScannerBoundaryCardinalityMismatch,
    ScannerLineOffsetMismatch,
    SourceError,
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
    /// Canonical emission order: scanner-engine gaps first, then source-walker
    /// gaps, then binary-source gaps. Both surfaces emit non-zero categories in
    /// this order.
    pub(crate) const ALL: [CoverageGapKind; 20] = [
        Self::ScannerStructuredParseFailure,
        Self::ScannerStructuredOversizeSkip,
        Self::ScannerDecodeTruncation,
        Self::ScannerInvalidPatternIndexSkip,
        Self::ScannerBoundaryCardinalityMismatch,
        Self::ScannerLineOffsetMismatch,
        Self::SourceError,
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
            Self::ScannerStructuredParseFailure => counts.scanner_structured_parse_failures,
            Self::ScannerStructuredOversizeSkip => counts.scanner_structured_oversize_skips,
            Self::ScannerDecodeTruncation => counts.scanner_decode_truncations,
            Self::ScannerInvalidPatternIndexSkip => counts.scanner_invalid_pattern_index_skips,
            Self::ScannerBoundaryCardinalityMismatch => {
                counts.scanner_boundary_cardinality_mismatches
            }
            Self::ScannerLineOffsetMismatch => counts.scanner_line_offset_mismatches,
            Self::SourceError => counts.source_errors,
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
            | Self::ScannerStructuredOversizeSkip
            | Self::ScannerDecodeTruncation
            | Self::ScannerInvalidPatternIndexSkip
            | Self::ScannerBoundaryCardinalityMismatch => CoverageSeverity::Warn,
            // Genuine "these bytes were NOT covered" (or line identity is wrong)
            // → red FAIL: a clean bill is unsafe while any of these is non-zero.
            // Line-offset mismatch is FAIL so incomplete exit 13 and SARIF
            // consumers share one FAIL set (KH-1347).
            // Structured parse failure loses encoded-value coverage and must
            // fail closed rather than bless the raw-only scan as complete.
            Self::ScannerStructuredParseFailure
            | Self::SourceError
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
            | Self::ScannerLineOffsetMismatch => CoverageSeverity::Fail,
        }
    }

    /// Terse, stable machine reason for a SARIF `toolExecutionNotifications`
    /// entry (the count is a separate field, so this string is count-free).
    pub(crate) fn sarif_reason(self) -> &'static str {
        match self {
            Self::ScannerStructuredParseFailure => {
                "scanner structured parse failed (raw text scanned; encoded structured values not decoded)"
            }
            Self::ScannerStructuredOversizeSkip => {
                "scanner structured decode-through skipped by size cap (structured file matched but exceeded the parse cap; encoded values e.g. a k8s data block were not decoded)"
            }
            Self::ScannerDecodeTruncation => {
                "scanner decode-through truncated by budget/cap (raw bytes scanned; deeper encoded layers not expanded)"
            }
            Self::ScannerInvalidPatternIndexSkip => {
                "scanner pattern expansion skipped by invalid pattern index (scanner invariant violation; scan partial)"
            }
            Self::ScannerBoundaryCardinalityMismatch => {
                "scanner boundary reassembly skipped by chunk/result cardinality mismatch (scanner invariant violation; scan partial)"
            }
            Self::ScannerLineOffsetMismatch => {
                "scanner multiline attribution used fallback source offsets (line-offset metadata mismatch; scan partial)"
            }
            Self::SourceError => {
                "source emitted error rows (requested input was not fully scanned)"
            }
            Self::OverMaxSize => "exceeded --max-file-size",
            Self::Binary => "binary (extension or content sniff)",
            Self::Excluded => {
                "exclusion policy (.keyhogignore, --exclude-paths, or lock/minified/vendored defaults)"
            }
            Self::NonBinaryUnreadable => "unreadable (permission denied or I/O error)",
            Self::GitObjectUnreadable => {
                "Git object unreadable or wrong object kind (referenced commit/tree/blob not scanned)"
            }
            Self::ArchiveTruncated => {
                "archive extraction truncated by decompression-bomb guard (remaining entries not scanned)"
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
            Self::ScannerLineOffsetMismatch => format!(
                "{n} multiline attribution mapping(s) used a fallback source offset because \
                 line-offset metadata was inconsistent. Findings were still emitted, but \
                 reported locations may be approximate; treat the scan as partial."
            ),
            Self::SourceError => format!(
                "{n} source error row(s) emitted: requested input was NOT fully scanned. \
                 Inspect the source errors above and rerun affected inputs."
            ),
            Self::OverMaxSize => format!(
                "{n} file(s) skipped: exceeded --max-file-size. Re-scan with a larger cap to \
                 include them."
            ),
            Self::Binary => format!(
                "{n} file(s) skipped: detected as binary (extension or content sniff) and not \
                 scanned as text."
            ),
            Self::Excluded => format!(
                "{n} file(s) skipped by exclusion policy (.keyhogignore, --exclude-paths, or lock/minified/vendored defaults)."
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
                "{n} archive(s) only PARTIALLY scanned: extraction was truncated by the \
                 decompression-bomb guard (uncompressed size exceeded 4x --max-file-size). \
                 Remaining entries were NOT checked for secrets."
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
    CoverageGapKind::ALL
        .iter()
        .map(|kind| (kind.sarif_reason().to_string(), kind.count(counts)))
        .filter(|(_, n)| *n > 0)
        .collect()
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
        if args.github_issues {
            surfaces.push("issues");
        }
        if args.github_pull_requests {
            surfaces.push("pull-requests");
        }
        if args.github_discussions {
            surfaces.push("discussions");
        }
        if args.github_wiki {
            surfaces.push("wiki");
        }
        if args.github_gists {
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
