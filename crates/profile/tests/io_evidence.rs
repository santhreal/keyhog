//! Caller-reported IO evidence: filesystem latency distributions, explicit
//! page-cache states, retained-buffer high water, decode expansion ratios,
//! and network counters with retry aggregation at drain.

use keyhog_profile::{
    add_derived_decoder_bytes, add_input_bytes, record_annotation,
    record_fs_metadata_latency_ns, record_fs_open_latency_ns, record_fs_read_latency_ns,
    record_io_cache_state, record_network_bytes, record_network_latency_ns,
    record_network_request, record_retained_buffer_bytes, take_metric_distributions,
    take_typed_metrics, AnnotationId, Evidence, EvidenceGap, IoCacheStateV2, MetricId, MetricKind,
    RunIdentity, RunState, Session,
};

fn session(name: &str) -> Session {
    Session::start(RunIdentity::new(
        "0.5.49",
        "detectors",
        "config",
        name,
        "test",
        "auto",
    ))
    .expect("start profile")
}

fn distributions() -> Vec<keyhog_profile::MetricDistributionV2> {
    take_metric_distributions()
}

fn find_distribution(
    records: &[keyhog_profile::MetricDistributionV2],
    metric: MetricId,
) -> &keyhog_profile::MetricDistributionV2 {
    records
        .iter()
        .find(|record| record.metric_id == metric)
        .expect("distribution drained")
}

/// Filesystem latency recordings must land in exact logarithmic buckets with
/// exact min, max, and call counts, since cache-state analysis reads these
/// distributions.
#[test]
fn fs_latency_distributions_have_exact_buckets() {
    let session = session("io-latency");
    for value in [100_u64, 100, 5_000, 9_000_000] {
        record_fs_read_latency_ns(value);
    }
    record_fs_open_latency_ns(250);
    record_fs_open_latency_ns(250);
    record_fs_metadata_latency_ns(1_000_000);
    record_network_latency_ns(42_000_000);

    let records = distributions();
    let reads = find_distribution(&records, MetricId::FsReadLatencyNs);
    assert_eq!(reads.call_count, 4);
    assert_eq!(reads.minimum, 100);
    assert_eq!(reads.maximum, 9_000_000);
    let bucket_count = |lower: u64| {
        reads
            .buckets
            .iter()
            .find(|bucket| bucket.lower_bound == lower)
            .map(|bucket| bucket.count)
            .unwrap_or(0)
    };
    // Buckets double at powers of two: 100 lands in [64,127], 5000 in
    // [4096,8191], 9000000 in [2^23,2^24-1].
    assert_eq!(bucket_count(64), 2);
    assert_eq!(bucket_count(4_096), 1);
    assert_eq!(bucket_count(1 << 23), 1);

    let opens = find_distribution(&records, MetricId::FsOpenLatencyNs);
    assert_eq!(opens.call_count, 2);
    assert_eq!(opens.minimum, 250);
    assert_eq!(opens.maximum, 250);
    assert_eq!(opens.buckets.len(), 1);
    assert_eq!(opens.buckets[0].count, 2);

    let metadata = find_distribution(&records, MetricId::FsMetadataLatencyNs);
    assert_eq!(metadata.call_count, 1);
    assert_eq!(metadata.minimum, 1_000_000);

    let network = find_distribution(&records, MetricId::NetworkLatencyNs);
    assert_eq!(network.call_count, 1);
    assert_eq!(network.minimum, 42_000_000);
    // A second drain must be empty; distributions are take-once.
    assert!(take_metric_distributions().is_empty());
    let _ = session.finish(RunState::Completed);
}

/// Explicit cache-state recordings must aggregate into exact typed counters
/// and annotation values, and the state enum must reject unknown values
/// instead of coercing them.
#[test]
fn cache_states_record_explicit_counters_and_annotations() {
    let session = session("io-cache-state");
    let runtime = session.runtime();
    record_io_cache_state(IoCacheStateV2::Cold);
    record_io_cache_state(IoCacheStateV2::Warm);
    record_io_cache_state(IoCacheStateV2::Cold);
    record_io_cache_state(IoCacheStateV2::Direct);

    assert_eq!(IoCacheStateV2::from_value(1), Some(IoCacheStateV2::Cold));
    assert_eq!(IoCacheStateV2::from_value(2), Some(IoCacheStateV2::Warm));
    assert_eq!(IoCacheStateV2::from_value(3), Some(IoCacheStateV2::Direct));
    assert_eq!(IoCacheStateV2::from_value(0), None);
    assert_eq!(IoCacheStateV2::from_value(9), None);

    let typed = runtime.take_session_typed_metrics();
    let find = |metric: MetricId| {
        typed
            .iter()
            .find(|record| record.metric_id == metric)
            .map(|record| record.value)
    };
    assert_eq!(find(MetricId::PageCacheColdObservations), Some(2));
    assert_eq!(find(MetricId::PageCacheWarmObservations), Some(1));
    assert_eq!(find(MetricId::PageCacheDirectObservations), Some(1));

    let (_events, annotations, loss) = runtime.take_session_typed_events();
    let states: Vec<u64> = annotations
        .iter()
        .filter(|annotation| annotation.annotation_id == AnnotationId::IoCacheState)
        .map(|annotation| annotation.value)
        .collect();
    assert_eq!(states, vec![1, 2, 1, 3]);
    assert_eq!(loss.annotations, 0);
    let _ = session.finish(RunState::Completed);
}

/// Retained-buffer recordings must keep the latest level and the exact
/// running high water in both the drained gauges and the session evidence.
#[test]
fn retained_buffers_track_latest_and_exact_peak() {
    let session = session("retained-buffers");
    let runtime = session.runtime();
    record_retained_buffer_bytes(100);
    record_retained_buffer_bytes(300);
    record_retained_buffer_bytes(200);
    let profile = session.finish(RunState::Completed);

    let system = match &profile.system {
        Evidence::Recorded { value } => value,
        other => panic!("system evidence must be recorded: {other:?}"),
    };
    assert_eq!(system.decode.retained_bytes, Evidence::recorded(200));
    assert_eq!(system.decode.retained_peak_bytes, Evidence::recorded(300));

    let typed = runtime.take_session_typed_metrics();
    let find = |metric: MetricId| {
        typed
            .iter()
            .find(|record| record.metric_id == metric)
            .map(|record| (record.kind, record.value))
    };
    assert_eq!(
        find(MetricId::RetainedBufferBytes),
        Some((MetricKind::Gauge, 200))
    );
    assert_eq!(
        find(MetricId::RetainedBufferPeakBytes),
        Some((MetricKind::Gauge, 300))
    );
}

/// The decode expansion ratio must equal derived bytes over input bytes in
/// exact thousandths, and must gap explicitly when no input was measured.
#[test]
fn decode_expansion_ratio_is_exact() {
    let recorded = session("decode-ratio");
    add_input_bytes(2_000);
    add_derived_decoder_bytes(5_000);
    let profile = recorded.finish(RunState::Completed);
    let system = match &profile.system {
        Evidence::Recorded { value } => value,
        other => panic!("system evidence must be recorded: {other:?}"),
    };
    assert_eq!(
        system.decode.expansion_ratio_milli,
        Evidence::recorded(2_500)
    );

    let empty = session("decode-ratio-empty").finish(RunState::Completed);
    let empty_system = match &empty.system {
        Evidence::Recorded { value } => value,
        other => panic!("system evidence must be recorded: {other:?}"),
    };
    assert_eq!(
        empty_system.decode.expansion_ratio_milli,
        Evidence::unavailable(EvidenceGap::Unavailable)
    );
    assert_eq!(
        empty_system.decode.retained_bytes,
        Evidence::unavailable(EvidenceGap::Unavailable)
    );
}

/// Caller-reported network bytes and requests must drain as exact typed
/// counters, and retry annotations must aggregate into the retry counter and
/// the session network evidence at finish.
#[test]
fn network_counters_and_retry_aggregation_are_exact() {
    let session = session("network-counters");
    let runtime = session.runtime();
    record_network_bytes(1_000, 2_000);
    record_network_bytes(500, 0);
    record_network_request();
    record_network_request();
    record_network_request();
    record_annotation(AnnotationId::RetryAttempt, 1);
    record_annotation(AnnotationId::RetryAttempt, 2);
    let profile = session.finish(RunState::Completed);

    let system = match &profile.system {
        Evidence::Recorded { value } => value,
        other => panic!("system evidence must be recorded: {other:?}"),
    };
    assert_eq!(system.network.retry_annotations, 2);

    let typed = runtime.take_session_typed_metrics();
    let find = |metric: MetricId| {
        typed
            .iter()
            .find(|record| record.metric_id == metric)
            .map(|record| record.value)
    };
    assert_eq!(find(MetricId::NetworkBytesRead), Some(1_500));
    assert_eq!(find(MetricId::NetworkBytesWritten), Some(2_000));
    assert_eq!(find(MetricId::NetworkRequests), Some(3));
    assert_eq!(find(MetricId::NetworkRetries), Some(2));

    let (_events, annotations, _loss) = runtime.take_session_typed_events();
    let retries: Vec<u64> = annotations
        .iter()
        .filter(|annotation| annotation.annotation_id == AnnotationId::RetryAttempt)
        .map(|annotation| annotation.value)
        .collect();
    assert_eq!(retries, vec![1, 2]);
    let _ = take_typed_metrics();
}
