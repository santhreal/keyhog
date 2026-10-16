//! Scan report metadata, manifest construction, and deterministic report ID derivation.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use keyhog_core::{
    ResolvedScanManifest, ScanCompletionStatus, ScanReportMetadata, StaticRecoveryMetrics,
    STATIC_RECOVERY_METRICS_SCHEMA_VERSION,
};
use crate::args::ScanArgs;
use crate::stable_hash::StableHasher;
use super::{scan_targets, CoverageCounts};

/// Build the minimal metadata used when a caller reports findings outside a
/// full scan run (for example a direct `scan --format` invocation).
pub(super) fn generated_report_metadata() -> ScanReportMetadata {
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
pub(super) fn scan_report_id(metadata: &ScanReportMetadata) -> String {
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

pub(super) fn format_gitlab_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S").to_string()
}

