//! Cross-platform backend shape, schema compatibility, and registry additions.

use keyhog_profile::{
    Evidence, EvidenceGap, MetricId, MetricKind, MetricUnit, RunIdentity, RunState, Session, Stage,
    METRICS,
};

fn session(name: &str) -> Session {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        name,
        "test",
        "cpu-simd",
    ))
    .expect("start profile")
}

/// Span records written before span hardware existed must decode with an
/// explicit legacy gap rather than a deserialization error.
#[test]
fn span_record_without_hardware_decodes_as_legacy_gap() {
    let session = session("span-hardware-compat");
    let runtime = session.runtime();
    drop(keyhog_profile::span(Stage::SourceRead));
    let (spans, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0);
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].version, 3);
    let mut json = serde_json::to_value(&spans[0]).expect("serialize span");
    json.as_object_mut()
        .expect("span object")
        .remove("hardware");
    let decoded: keyhog_profile::SpanRecordV2 =
        serde_json::from_value(json).expect("decode legacy span");
    assert_eq!(
        decoded.hardware,
        Evidence::unavailable(EvidenceGap::LegacyV1NotRecorded)
    );
    let _ = session.finish(RunState::Completed);
}

/// A causal profile written before run hardware evidence existed must decode
/// with an explicit legacy gap on the hardware field.
#[test]
fn causal_profile_without_hardware_decodes_as_legacy_gap() {
    let profile = session("causal-hardware-compat").finish(RunState::Completed);
    let causal = keyhog_profile::CausalProfileV2::from_v1(profile);
    let mut json = serde_json::to_value(&causal).expect("serialize causal profile");
    json.as_object_mut()
        .expect("causal object")
        .remove("hardware");
    let decoded: keyhog_profile::CausalProfileV2 =
        serde_json::from_value(json).expect("decode legacy causal profile");
    assert_eq!(
        decoded.hardware,
        Evidence::unavailable(EvidenceGap::LegacyV1NotRecorded)
    );
}

/// GPU and CPU registry additions must carry exact names, kinds, and units in
/// numeric MetricId order so the wire registry stays stable.
#[test]
fn registry_additions_have_exact_descriptors() {
    assert_eq!(METRICS.len(), MetricId::COUNT);
    let hardware = MetricId::HardwareCycles.descriptor();
    assert_eq!(hardware.name, "hardware-cycles");
    assert_eq!(hardware.kind, MetricKind::Counter);
    assert_eq!(hardware.unit, MetricUnit::Count);
    let delay = MetricId::SchedulerDelayNs.descriptor();
    assert_eq!(delay.name, "scheduler-delay-ns");
    assert_eq!(delay.unit, MetricUnit::Nanoseconds);
    let upload = MetricId::GpuUploadNs.descriptor();
    assert_eq!(upload.name, "gpu-upload-ns");
    assert_eq!(upload.kind, MetricKind::Counter);
    assert_eq!(upload.unit, MetricUnit::Nanoseconds);
    let resident = MetricId::GpuResidentBytes.descriptor();
    assert_eq!(resident.name, "gpu-resident-bytes");
    assert_eq!(resident.kind, MetricKind::Gauge);
    assert_eq!(resident.unit, MetricUnit::Bytes);
    assert_eq!(
        keyhog_profile::CounterId::GpuKernelNs.metric_id(),
        MetricId::GpuKernelNs
    );
    assert_eq!(
        keyhog_profile::GaugeId::GpuPeakResidentBytes.metric_id(),
        MetricId::GpuPeakResidentBytes
    );
    assert_eq!(keyhog_profile::EventId::COUNT, 8);
    assert_eq!(keyhog_profile::CounterId::ALL.len(), 132);
    assert_eq!(keyhog_profile::GaugeId::ALL.len(), 11);
}
