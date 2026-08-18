use keyhog_profile::{MacroStageId, MetricId, MetricKind, MetricUnit, Stage, METRICS};
use std::collections::HashSet;

/// Registry indices and wire names must remain unique because profiles persist numeric and textual metric identity.
#[test]
fn registry_has_unique_ids_and_names_in_discriminant_order() {
    assert_eq!(METRICS.len(), MetricId::COUNT);
    let mut names = HashSet::with_capacity(METRICS.len());
    for (index, descriptor) in METRICS.iter().enumerate() {
        assert_eq!(descriptor.id as usize, index);
        assert!(names.insert(descriptor.name), "duplicate metric name");
        assert!(!descriptor.name.is_empty());
    }
}

/// Every hot-path stage must resolve directly to static nanosecond duration metadata without hashing or allocation.
#[test]
fn stages_resolve_to_static_duration_descriptors() {
    for stage in Stage::ALL {
        let descriptor = stage.metric_id().descriptor();
        assert_eq!(descriptor.id, stage.metric_id());
        assert_eq!(descriptor.name, stage.as_str());
        assert_eq!(descriptor.kind, MetricKind::Duration);
        assert_eq!(descriptor.unit, MetricUnit::Nanoseconds);
        assert!(std::ptr::eq(descriptor, stage.metric_id().descriptor()));
    }
}

/// Counter and gauge metadata must use physical units so analysis cannot interpret bytes as counts or milliseconds.
#[test]
fn non_stage_metrics_have_exact_kinds_and_units() {
    let expected = [
        (MetricId::InputBytes, MetricKind::Counter, MetricUnit::Bytes),
        (MetricId::InputUnits, MetricKind::Counter, MetricUnit::Count),
        (
            MetricId::WallTime,
            MetricKind::Duration,
            MetricUnit::Nanoseconds,
        ),
        (
            MetricId::ProcessCpuTime,
            MetricKind::Counter,
            MetricUnit::Milliseconds,
        ),
        (
            MetricId::ResidentMemory,
            MetricKind::Gauge,
            MetricUnit::Bytes,
        ),
        (
            MetricId::VirtualMemory,
            MetricKind::Gauge,
            MetricUnit::Bytes,
        ),
        (
            MetricId::ProcessThreads,
            MetricKind::Gauge,
            MetricUnit::Count,
        ),
    ];

    for (id, kind, unit) in expected {
        assert_eq!(id.descriptor().kind, kind);
        assert_eq!(id.descriptor().unit, unit);
    }
}

/// Metric identifiers must retain stable kebab-case JSON names across serialization round trips.
#[test]
fn metric_identifiers_have_stable_wire_names() {
    for descriptor in METRICS {
        let json = serde_json::to_string(&descriptor.id).expect("serialize metric id");
        assert_eq!(json, format!("\"{}\"", descriptor.name));
        let decoded: MetricId = serde_json::from_str(&json).expect("deserialize metric id");
        assert_eq!(decoded, descriptor.id);
    }
}

/// Every micro-function must map to one stable macro owner so profiles can aggregate without names.
#[test]
fn micro_functions_have_exact_macro_stage_ownership() {
    let expected = [
        (Stage::SourceAcquire, MacroStageId::Acquire),
        (Stage::SourceWalk, MacroStageId::Acquire),
        (Stage::SourceRead, MacroStageId::Acquire),
        (Stage::SourceQueueWait, MacroStageId::Acquire),
        (Stage::Preprocess, MacroStageId::Scan),
        (Stage::Phase1Triggers, MacroStageId::Scan),
        (Stage::BackendDispatch, MacroStageId::Scan),
        (Stage::HotPatterns, MacroStageId::Scan),
        (Stage::ConfirmedPatterns, MacroStageId::Scan),
        (Stage::Phase2Prefilter, MacroStageId::Scan),
        (Stage::Phase2KeywordAc, MacroStageId::Scan),
        (Stage::Phase2SharedAc, MacroStageId::Scan),
        (Stage::Phase2AnchoredVerify, MacroStageId::Scan),
        (Stage::Phase2WholeChunk, MacroStageId::Scan),
        (Stage::GenericDetection, MacroStageId::Scan),
        (Stage::Entropy, MacroStageId::Scan),
        (Stage::MachineLearning, MacroStageId::Scan),
        (Stage::Decode, MacroStageId::Scan),
        (Stage::IncrementalLookup, MacroStageId::Scan),
        (Stage::BackendSelect, MacroStageId::Scan),
        (Stage::ScannerQueueWait, MacroStageId::Scan),
        (Stage::AutorouteCalibration, MacroStageId::Scan),
        (Stage::BoundaryScan, MacroStageId::Scan),
        (Stage::DetectorLoad, MacroStageId::Scan),
        (Stage::DetectorValidate, MacroStageId::Scan),
        (Stage::ExecutionPackSelect, MacroStageId::Scan),
        (Stage::ExecutionPackMap, MacroStageId::Scan),
        (Stage::BackendAcquire, MacroStageId::Scan),
        (Stage::BackendInit, MacroStageId::Scan),
        (Stage::Teardown, MacroStageId::Scan),
        (Stage::ScanPipeline, MacroStageId::Scan),
        (Stage::ScannerCompile, MacroStageId::Scan),
        (Stage::Suppression, MacroStageId::Resolve),
        (Stage::ResultMerge, MacroStageId::Resolve),
        (Stage::LiveVerification, MacroStageId::Verify),
        (Stage::Reporting, MacroStageId::Report),
    ];
    assert_eq!(expected.len(), Stage::ALL.len());
    for (stage, macro_stage) in expected {
        assert_eq!(stage.macro_stage_id(), macro_stage, "{stage:?}");
    }
}

/// Macro identifiers must retain numeric order and kebab-case wire names across JSON round trips.
#[test]
fn macro_stage_identifiers_are_stable_and_round_trip() {
    let expected_names = ["acquire", "scan", "resolve", "verify", "report"];
    for (index, (macro_stage, expected_name)) in MacroStageId::ALL
        .into_iter()
        .zip(expected_names)
        .enumerate()
    {
        assert_eq!(macro_stage as usize, index);
        assert_eq!(macro_stage.as_str(), expected_name);
        let json = serde_json::to_string(&macro_stage).expect("serialize macro stage");
        assert_eq!(json, format!("\"{expected_name}\""));
        let decoded: MacroStageId = serde_json::from_str(&json).expect("deserialize macro stage");
        assert_eq!(decoded, macro_stage);
    }
}
