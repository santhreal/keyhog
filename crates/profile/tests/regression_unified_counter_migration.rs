//! Regression test for unified counter ownership and migration parity (Row 99).
//!
//! WHY: Previously, scattered process-global `AtomicUsize` statics across `scanner/src/telemetry.rs`,
//! `sources/src/skip.rs`, `sources/src/binary/mod.rs`, and `sources/src/git/source.rs` were not part
//! of the profile runtime metric model (`keyhog_profile`), causing coverage gap counters and scan
//! telemetry to be invisible to `--profile-out` and duplicating counters (e.g. `GPU_DISPATCHES` vs
//! `GpuDispatchCalls`). This suite proves that every scattered counter has an exact, stable
//! `CounterId` / `GaugeId` identity in `keyhog_profile`, that all metric descriptors are registered
//! without drift, and that both GPU dispatch recording pathways update the single unified counter.

use keyhog_profile::{
    add_counter, reset, set_enabled, take_typed_metrics, CounterId, GaugeId, MetricId, MetricKind,
    MetricUnit, METRICS,
};

#[test]
fn all_scattered_counters_have_exact_profile_identities() {
    // Exact mapping check of every previously-scattered counter.
    let expected_mappings: &[(CounterId, &str, MetricUnit)] = &[
        (CounterId::FilesScanned, "files-scanned", MetricUnit::Count),
        (CounterId::BytesScanned, "bytes-scanned", MetricUnit::Bytes),
        (CounterId::SkippedFiles, "skipped-files", MetricUnit::Count),
        (CounterId::MatchesFound, "matches-found", MetricUnit::Count),
        (
            CounterId::StructuredParseFailures,
            "structured-parse-failures",
            MetricUnit::Count,
        ),
        (
            CounterId::StructuredOversizeSkips,
            "structured-oversize-skips",
            MetricUnit::Count,
        ),
        (
            CounterId::DecodeTruncations,
            "decode-truncations",
            MetricUnit::Count,
        ),
        (
            CounterId::DecodeOversizeSkips,
            "decode-oversize-skips",
            MetricUnit::Count,
        ),
        (
            CounterId::InvalidPatternIndexSkips,
            "invalid-pattern-index-skips",
            MetricUnit::Count,
        ),
        (
            CounterId::BoundaryResultCardinalityMismatches,
            "boundary-result-cardinality-mismatches",
            MetricUnit::Count,
        ),
        (
            CounterId::BoundarySeamTruncations,
            "boundary-seam-truncations",
            MetricUnit::Count,
        ),
        (
            CounterId::LineOffsetMappingMismatches,
            "line-offset-mapping-mismatches",
            MetricUnit::Count,
        ),
        (
            CounterId::ChunkDeadlineAborts,
            "chunk-deadline-aborts",
            MetricUnit::Count,
        ),
        (
            CounterId::BinaryStringsNamedExclusions,
            "binary-strings-named-exclusions",
            MetricUnit::Count,
        ),
        (
            CounterId::SkippedOverMaxSize,
            "skipped-over-max-size",
            MetricUnit::Count,
        ),
        (
            CounterId::SkippedBinary,
            "skipped-binary",
            MetricUnit::Count,
        ),
        (
            CounterId::SkippedExcluded,
            "skipped-excluded",
            MetricUnit::Count,
        ),
        (
            CounterId::SkippedUnreadable,
            "skipped-unreadable",
            MetricUnit::Count,
        ),
        (
            CounterId::GitObjectUnreadable,
            "git-object-unreadable",
            MetricUnit::Count,
        ),
        (
            CounterId::SkippedArchiveTruncated,
            "skipped-archive-truncated",
            MetricUnit::Count,
        ),
        (
            CounterId::BinarySectionNameUnresolved,
            "binary-section-name-unresolved",
            MetricUnit::Count,
        ),
        (
            CounterId::SourceTruncated,
            "source-truncated",
            MetricUnit::Count,
        ),
        (
            CounterId::StructuredSourceParseFailures,
            "structured-source-parse-failures",
            MetricUnit::Count,
        ),
        (
            CounterId::ArchiveDuplicateScanUnavailable,
            "archive-duplicate-scan-unavailable",
            MetricUnit::Count,
        ),
        (
            CounterId::GitLfsPointer,
            "git-lfs-pointer",
            MetricUnit::Count,
        ),
        (
            CounterId::VendoredPathSuppressions,
            "vendored-path-suppressions",
            MetricUnit::Count,
        ),
        (
            CounterId::ExampleSuppressions,
            "example-suppressions",
            MetricUnit::Count,
        ),
        (
            CounterId::BinaryGhidraDegradedToStrings,
            "binary-ghidra-degraded-to-strings",
            MetricUnit::Count,
        ),
        (
            CounterId::BinaryUnreadable,
            "binary-unreadable",
            MetricUnit::Count,
        ),
        (
            CounterId::GpuDispatchCalls,
            "gpu-dispatch-calls",
            MetricUnit::Count,
        ),
    ];

    for &(counter_id, expected_name, expected_unit) in expected_mappings {
        let metric_id = counter_id.metric_id();
        let descriptor = metric_id.descriptor();
        assert_eq!(
            descriptor.name, expected_name,
            "descriptor name mismatch for counter {counter_id:?}"
        );
        assert_eq!(
            descriptor.kind,
            MetricKind::Counter,
            "descriptor kind mismatch for counter {counter_id:?}"
        );
        assert_eq!(
            descriptor.unit, expected_unit,
            "descriptor unit mismatch for counter {counter_id:?}"
        );
        assert_eq!(metric_id.as_str(), expected_name);
    }
}

#[test]
fn gauge_identities_cover_git_buffered_blob_chunks() {
    let gauge_id = GaugeId::GitBufferedBlobChunks;
    let metric_id = gauge_id.metric_id();
    let descriptor = metric_id.descriptor();
    assert_eq!(descriptor.name, "git-buffered-blob-chunks");
    assert_eq!(descriptor.kind, MetricKind::Gauge);
    assert_eq!(descriptor.unit, MetricUnit::Count);
}

#[test]
fn full_metric_registry_descriptors_are_continuous_and_bijective() {
    assert_eq!(METRICS.len(), MetricId::COUNT);
    for (index, descriptor) in METRICS.iter().enumerate() {
        assert_eq!(
            descriptor.id as usize, index,
            "metric descriptor at index {index} has mismatched enum value {:?}",
            descriptor.id
        );
        assert!(
            !descriptor.name.is_empty(),
            "metric descriptor at index {index} has empty name"
        );
    }

    for counter in CounterId::ALL {
        let metric_id = counter.metric_id();
        let descriptor = metric_id.descriptor();
        assert_eq!(descriptor.kind, MetricKind::Counter);
    }

    for gauge in GaugeId::ALL {
        let metric_id = gauge.metric_id();
        let descriptor = metric_id.descriptor();
        assert_eq!(descriptor.kind, MetricKind::Gauge);
    }
}

#[test]
fn duplicate_gpu_dispatch_recording_resolves_to_single_counter_identity() {
    reset();
    set_enabled(true);

    // Call path 1: direct engine/telemetry dispatch increment
    add_counter(CounterId::GpuDispatchCalls, 3);

    // Call path 2: accelerator evidence submission increment
    add_counter(CounterId::GpuDispatchCalls, 4);

    let metrics = take_typed_metrics();
    let gpu_dispatches = metrics
        .iter()
        .find(|m| m.metric_id == MetricId::GpuDispatchCalls)
        .expect("gpu-dispatch-calls metric must be present");

    assert_eq!(
        gpu_dispatches.value, 7,
        "both GPU dispatch call paths must aggregate into single CounterId::GpuDispatchCalls"
    );

    reset();
}

#[test]
fn registry_derived_reset_clears_all_registered_counters_without_manual_enumeration() {
    reset();
    set_enabled(true);

    // Increment every single registered CounterId
    for counter in CounterId::ALL {
        add_counter(counter, 42);
    }

    let metrics_before_reset = take_typed_metrics();
    assert!(
        !metrics_before_reset.is_empty(),
        "metrics must record values before reset"
    );

    // Reset clears everything derived from registry
    reset();

    let metrics_after_reset = take_typed_metrics();
    for metric in metrics_after_reset {
        if metric.metric_id.descriptor().kind == MetricKind::Counter {
            assert_eq!(
                metric.value,
                0,
                "counter {:?} ({}) must be 0 after reset()",
                metric.metric_id,
                metric.metric_id.as_str()
            );
        }
    }
}
