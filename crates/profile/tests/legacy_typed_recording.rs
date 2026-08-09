//! Legacy standalone-runtime typed recording and scanner registry additions.

use keyhog_profile::{
    add_counter, add_input_bytes, add_input_units, record_distribution, reset, set_enabled,
    take_metric_distributions, take_typed_metrics, CounterId, MetricId, MetricKind, MetricUnit,
    METRICS, METRIC_REGISTRY_VERSION,
};

/// The standalone set_enabled runtime must record typed counters exactly so
/// perf-trace style exact counts flow through keyhog-profile storage.
#[test]
fn legacy_runtime_records_typed_counters_exactly() {
    set_enabled(true);
    add_counter(CounterId::MlBatchCalls, 3);
    add_counter(CounterId::MlBatchCalls, 4);
    add_counter(CounterId::GenericEmits, 5);
    add_counter(CounterId::GenericPrefilterNs, 1_250);
    let metrics = take_typed_metrics();
    assert_eq!(metrics.len(), 3);
    assert_eq!(metrics[0].metric_id, MetricId::GenericEmits);
    assert_eq!(metrics[0].kind, MetricKind::Counter);
    assert_eq!(metrics[0].value, 5);
    assert_eq!(metrics[1].metric_id, MetricId::MlBatchCalls);
    assert_eq!(metrics[1].value, 7);
    assert_eq!(metrics[2].metric_id, MetricId::GenericPrefilterNs);
    assert_eq!(metrics[2].value, 1_250);
    // Drain empties the store.
    assert!(take_typed_metrics().is_empty());
    set_enabled(false);
}

/// Legacy input accounting must mirror into typed counters so input truth is
/// identical on the standalone path.
#[test]
fn legacy_input_totals_mirror_into_typed_counters() {
    set_enabled(true);
    add_input_bytes(100);
    add_input_bytes(28);
    add_input_units(3);
    let metrics = take_typed_metrics();
    assert_eq!(metrics.len(), 2);
    assert_eq!(metrics[0].metric_id, MetricId::InputBytes);
    assert_eq!(metrics[0].value, 128);
    assert_eq!(metrics[1].metric_id, MetricId::InputUnits);
    assert_eq!(metrics[1].value, 3);
    reset();
    assert!(take_typed_metrics().is_empty());
    set_enabled(false);
}

/// The scanner mark-stats invariant (gate skips + hyperscan served + regexset
/// served == calls) must hold exactly through the typed counters.
#[test]
fn mark_stats_invariant_flows_through_typed_counters() {
    set_enabled(true);
    add_counter(CounterId::Phase2PrefilterGateSkips, 11);
    add_counter(CounterId::Phase2PrefilterHsServed, 20);
    add_counter(CounterId::Phase2PrefilterRegexsetServed, 9);
    add_counter(CounterId::Phase2PrefilterMarkCalls, 40);
    let metrics = take_typed_metrics();
    let value_of = |id: MetricId| {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .expect("mark-stats counter")
            .value
    };
    assert_eq!(metrics.len(), 4);
    assert_eq!(
        value_of(MetricId::Phase2PrefilterGateSkips)
            + value_of(MetricId::Phase2PrefilterHsServed)
            + value_of(MetricId::Phase2PrefilterRegexsetServed),
        value_of(MetricId::Phase2PrefilterMarkCalls)
    );
    set_enabled(false);
}

/// record_distribution must bucket observed values into exact logarithmic
/// bounds with exact min, max, and call count.
#[test]
fn value_distribution_buckets_exact_observations() {
    set_enabled(true);
    record_distribution(MetricId::MlBatchSize, 1);
    record_distribution(MetricId::MlBatchSize, 5);
    record_distribution(MetricId::MlBatchSize, 5);
    record_distribution(MetricId::MlBatchSize, 300);

    let distributions = take_metric_distributions();
    assert_eq!(distributions.len(), 1);
    let distribution = &distributions[0];
    assert_eq!(distribution.version, 1);
    assert_eq!(distribution.metric_id, MetricId::MlBatchSize);
    assert_eq!(distribution.call_count, 4);
    assert_eq!(distribution.minimum, 1);
    assert_eq!(distribution.maximum, 300);
    assert_eq!(distribution.buckets.len(), 3);
    assert_eq!(
        (
            distribution.buckets[0].lower_bound,
            distribution.buckets[0].upper_bound
        ),
        (1, 1)
    );
    assert_eq!(distribution.buckets[0].count, 1);
    assert_eq!(
        (
            distribution.buckets[1].lower_bound,
            distribution.buckets[1].upper_bound
        ),
        (4, 7)
    );
    assert_eq!(distribution.buckets[1].count, 2);
    assert_eq!(
        (
            distribution.buckets[2].lower_bound,
            distribution.buckets[2].upper_bound
        ),
        (256, 511)
    );
    assert_eq!(distribution.buckets[2].count, 1);
    assert!(take_metric_distributions().is_empty());
    set_enabled(false);
}

/// The registry additions must keep existing variant numeric values stable,
/// declare correct kinds and units, and bump the registry version once.
#[test]
fn scanner_registry_variants_have_stable_descriptors() {
    assert_eq!(METRIC_REGISTRY_VERSION, 6);
    assert_eq!(MetricId::InputBytes as usize, 25);
    assert_eq!(MetricId::ProcessThreads as usize, 31);
    assert_eq!(MetricId::Phase2PrefilterMarkCalls as usize, 32);
    assert_eq!(METRICS.len(), MetricId::COUNT);
    let descriptor = MetricId::DecodeExtractNs.descriptor();
    assert_eq!(descriptor.name, "decode-extract-ns");
    assert_eq!(descriptor.kind, MetricKind::Counter);
    assert_eq!(descriptor.unit, MetricUnit::Nanoseconds);
    let descriptor = MetricId::DecodeExtractBytes.descriptor();
    assert_eq!(descriptor.kind, MetricKind::Counter);
    assert_eq!(descriptor.unit, MetricUnit::Bytes);
    let descriptor = MetricId::MlBatchSize.descriptor();
    assert_eq!(descriptor.kind, MetricKind::Distribution);
    assert_eq!(descriptor.unit, MetricUnit::Count);
    let descriptor = MetricId::Phase2PrefilterDroppedHostNs.descriptor();
    assert_eq!(descriptor.name, "phase2-prefilter-dropped-host-ns");
    assert_eq!(descriptor.unit, MetricUnit::Nanoseconds);
    let descriptor = MetricId::DecodeDerivedBytes.descriptor();
    assert_eq!(descriptor.name, "decode-derived-bytes");
    assert_eq!(descriptor.kind, MetricKind::Counter);
    assert_eq!(descriptor.unit, MetricUnit::Bytes);
    assert_eq!(MetricId::DecodeDerivedBytes as usize, 57);
}

/// Accepted derived decode bytes must record through the legacy runtime as an
/// exact typed counter, which add_derived_decoder_bytes never provided.
#[test]
fn decode_derived_bytes_records_exactly_on_legacy_runtime() {
    set_enabled(true);
    add_counter(CounterId::DecodeDerivedBytes, 4_096);
    add_counter(CounterId::DecodeDerivedBytes, 1_024);
    let metrics = take_typed_metrics();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].metric_id, MetricId::DecodeDerivedBytes);
    assert_eq!(metrics[0].kind, MetricKind::Counter);
    assert_eq!(metrics[0].value, 5_120);
    set_enabled(false);
}

/// reset() must clear legacy typed counters and distributions so a reused
/// standalone runtime starts from an exact empty baseline.
#[test]
fn reset_clears_legacy_typed_counters_and_distributions() {
    set_enabled(true);
    add_counter(CounterId::MlBatchCalls, 9);
    add_counter(CounterId::DecodeDerivedBytes, 100);
    record_distribution(MetricId::MlBatchSize, 64);
    reset();
    assert!(take_typed_metrics().is_empty());
    assert!(take_metric_distributions().is_empty());
    set_enabled(false);
}
