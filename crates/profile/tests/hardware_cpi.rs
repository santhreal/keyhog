//! CPI and ratio math on known counter pairs, plus span aggregation joins.

use keyhog_profile::{
    aggregate_span_hardware, milli_ratio, Evidence, EvidenceGap, HardwareCounterSampleV2,
    HardwareCounterSetV2, HardwareFieldSourceV2, MetricId, SourcedEvidenceV2, SpanHardwareV2,
    SpanRecordV2, WorkOrigin, HARDWARE_EVIDENCE_V2_VERSION, SPAN_HARDWARE_V2_VERSION,
};

fn recorded_pair(begin: u64, end: u64) -> (Evidence<u64>, Evidence<u64>) {
    (Evidence::recorded(begin), Evidence::recorded(end))
}

fn span_hardware(cycles: (u64, u64), instructions: (u64, u64)) -> Evidence<SpanHardwareV2> {
    let (cycles_begin, cycles_end) = recorded_pair(cycles.0, cycles.1);
    let (instructions_begin, instructions_end) = recorded_pair(instructions.0, instructions.1);
    Evidence::recorded(SpanHardwareV2 {
        version: SPAN_HARDWARE_V2_VERSION,
        cycles_begin,
        cycles_end,
        instructions_begin,
        instructions_end,
    })
}

fn span_record(
    span_id: u64,
    metric_id: MetricId,
    thread_id: u64,
    hardware: Evidence<SpanHardwareV2>,
) -> SpanRecordV2 {
    SpanRecordV2 {
        version: 3,
        span_id,
        parent_span_id: Evidence::unavailable(EvidenceGap::Unavailable),
        metric_id,
        start_ns: 0,
        inclusive_ns: 1,
        exclusive_ns: 1,
        thread_id,
        task_id: Evidence::unavailable(EvidenceGap::Unavailable),
        worker_id: Evidence::unavailable(EvidenceGap::Unavailable),
        work_origin: WorkOrigin::Root,
        hardware,
    }
}

/// Integer milli-ratios must be exact for known pairs and refuse division by
/// zero, since CPI and miss ratios are derived from this one primitive.
#[test]
fn milli_ratio_is_exact_on_known_pairs() {
    assert_eq!(milli_ratio(3, 2), Some(1_500));
    assert_eq!(milli_ratio(1, 3), Some(333));
    assert_eq!(milli_ratio(0, 7), Some(0));
    assert_eq!(milli_ratio(7, 1), Some(7_000));
    assert_eq!(milli_ratio(5, 0), None);
    assert_eq!(milli_ratio(u64::MAX, u64::MAX), Some(1_000));
    assert_eq!(milli_ratio(u64::MAX, 1), Some(u64::MAX));
}

/// Per-span CPI must equal the cycle delta over the instruction delta for a
/// known counter pair, and a missing pair must surface as a gap.
#[test]
fn span_cpi_computes_from_known_counter_pair() {
    let hardware = span_hardware((1_000, 4_000), (500, 1_500));
    let Evidence::Recorded { value: hardware } = hardware else {
        panic!("hardware recorded")
    };
    assert_eq!(hardware.cycles(), Evidence::recorded(3_000));
    assert_eq!(hardware.instructions(), Evidence::recorded(1_000));
    assert_eq!(hardware.cpi_milli(), Evidence::recorded(3_000));

    let mut gapped = hardware;
    gapped.instructions_begin = Evidence::unavailable(EvidenceGap::Unsupported);
    gapped.instructions_end = Evidence::unavailable(EvidenceGap::Unsupported);
    assert_eq!(
        gapped.instructions(),
        Evidence::unavailable(EvidenceGap::Unsupported)
    );
    assert_eq!(
        gapped.cpi_milli(),
        Evidence::unavailable(EvidenceGap::Unsupported)
    );
}

/// Run-level deltas must subtract exact known samples and derive exact cache
/// miss and branch misprediction ratios, propagating gaps from either side.
#[test]
fn counter_set_between_computes_exact_ratios() {
    let source = HardwareFieldSourceV2::PerfEventOpen;
    let sample = |cycles: u64,
                  instructions: u64,
                  cache_refs: u64,
                  cache_misses: u64,
                  branches: u64,
                  branch_misses: u64| {
        HardwareCounterSampleV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            elapsed_ns: 0,
            cycles: SourcedEvidenceV2::recorded(cycles, source),
            instructions: SourcedEvidenceV2::recorded(instructions, source),
            cache_references: SourcedEvidenceV2::recorded(cache_refs, source),
            cache_misses: SourcedEvidenceV2::recorded(cache_misses, source),
            branch_instructions: SourcedEvidenceV2::recorded(branches, source),
            branch_misses: SourcedEvidenceV2::recorded(branch_misses, source),
            stalled_cycles_frontend: SourcedEvidenceV2::gapped(source, EvidenceGap::Unsupported),
            stalled_cycles_backend: SourcedEvidenceV2::gapped(source, EvidenceGap::Unsupported),
            stalled_cycles_memory: SourcedEvidenceV2::gapped(source, EvidenceGap::Unsupported),
        }
    };
    let start = sample(1_000, 2_000, 500, 100, 800, 40);
    let end = sample(5_000, 4_000, 1_500, 300, 2_800, 120);
    let set = HardwareCounterSetV2::between(&start, &end);
    assert_eq!(set.cycles.value, Evidence::recorded(4_000));
    assert_eq!(set.instructions.value, Evidence::recorded(2_000));
    assert_eq!(set.cpi_milli, Evidence::recorded(2_000));
    assert_eq!(set.cache_references.value, Evidence::recorded(1_000));
    assert_eq!(set.cache_misses.value, Evidence::recorded(200));
    assert_eq!(set.cache_miss_ratio_milli, Evidence::recorded(200));
    assert_eq!(set.branch_instructions.value, Evidence::recorded(2_000));
    assert_eq!(set.branch_misses.value, Evidence::recorded(80));
    assert_eq!(set.branch_miss_ratio_milli, Evidence::recorded(40));
    assert_eq!(
        set.stalled_cycles_frontend.value,
        Evidence::unavailable(EvidenceGap::Unsupported)
    );

    let mut denied_end = sample(5_000, 4_000, 1_500, 300, 2_800, 120);
    denied_end.cycles = SourcedEvidenceV2::gapped(source, EvidenceGap::PermissionDenied);
    let gapped = HardwareCounterSetV2::between(&start, &denied_end);
    assert_eq!(
        gapped.cycles.value,
        Evidence::unavailable(EvidenceGap::PermissionDenied)
    );
    assert_eq!(
        gapped.cpi_milli,
        Evidence::unavailable(EvidenceGap::PermissionDenied)
    );
}

/// Aggregation over drained spans must join exact per-stage, per-thread, and
/// per-run CPI, skipping spans that carry no counter readings.
#[test]
fn aggregation_joins_stage_thread_and_run_cpi() {
    let spans = vec![
        span_record(
            1,
            MetricId::SourceRead,
            7,
            span_hardware((0, 900), (0, 300)),
        ),
        span_record(
            2,
            MetricId::SourceRead,
            7,
            span_hardware((900, 2_100), (300, 900)),
        ),
        span_record(3, MetricId::Decode, 9, span_hardware((0, 400), (0, 800))),
        span_record(
            4,
            MetricId::Reporting,
            9,
            Evidence::unavailable(EvidenceGap::Unavailable),
        ),
    ];
    let aggregation = aggregate_span_hardware(&spans);
    assert_eq!(aggregation.version, HARDWARE_EVIDENCE_V2_VERSION);

    assert_eq!(aggregation.run.span_count, 4);
    assert_eq!(aggregation.run.spans_with_counters, 3);
    assert_eq!(aggregation.run.cycles, 900 + 1_200 + 400);
    assert_eq!(aggregation.run.instructions, 300 + 600 + 800);
    assert_eq!(aggregation.run.cpi_milli, Evidence::recorded(1_470));

    assert_eq!(aggregation.stages.len(), 2);
    assert_eq!(aggregation.stages[0].metric_id, MetricId::SourceRead);
    assert_eq!(aggregation.stages[0].span_count, 2);
    assert_eq!(aggregation.stages[0].cycles, 2_100);
    assert_eq!(aggregation.stages[0].instructions, 900);
    assert_eq!(aggregation.stages[0].cpi_milli, Evidence::recorded(2_333));
    assert_eq!(aggregation.stages[1].metric_id, MetricId::Decode);
    assert_eq!(aggregation.stages[1].span_count, 1);
    assert_eq!(aggregation.stages[1].cycles, 400);
    assert_eq!(aggregation.stages[1].instructions, 800);
    assert_eq!(aggregation.stages[1].cpi_milli, Evidence::recorded(500));

    assert_eq!(aggregation.threads.len(), 2);
    assert_eq!(aggregation.threads[0].thread_id, 7);
    assert_eq!(aggregation.threads[0].span_count, 2);
    assert_eq!(aggregation.threads[0].cycles, 2_100);
    assert_eq!(aggregation.threads[0].cpi_milli, Evidence::recorded(2_333));
    assert_eq!(aggregation.threads[1].thread_id, 9);
    assert_eq!(aggregation.threads[1].span_count, 1);
    assert_eq!(aggregation.threads[1].cycles, 400);
    assert_eq!(aggregation.threads[1].cpi_milli, Evidence::recorded(500));
}

/// An empty span set must aggregate to zeros with a CPI gap, never a panic or
/// a fabricated zero-over-zero ratio.
#[test]
fn aggregation_of_empty_spans_is_zero_with_gap() {
    let aggregation = aggregate_span_hardware(&[]);
    assert_eq!(aggregation.run.span_count, 0);
    assert_eq!(aggregation.run.spans_with_counters, 0);
    assert_eq!(aggregation.run.cycles, 0);
    assert_eq!(aggregation.run.instructions, 0);
    assert_eq!(
        aggregation.run.cpi_milli,
        Evidence::unavailable(EvidenceGap::Unavailable)
    );
    assert!(aggregation.stages.is_empty());
    assert!(aggregation.threads.is_empty());
}
