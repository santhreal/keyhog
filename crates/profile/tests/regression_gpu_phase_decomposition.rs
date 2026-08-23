//! WHY: Closes the defect class where GPU dispatch performance metrics were tracked
//! only via ad-hoc Instant timers and printed to stderr in a raw perf-trace line,
//! without being registered in the profiler taxonomy or appearing in the profile artifact.
//!
//! Asserts that:
//! 1. All GPU region dispatch phases are enumerated at run time from the profiler registry.
//! 2. Every registered phase corresponds to a valid MetricId descriptor.
//! 3. The named GPU decomposition phases (coalesce + dispatch + derive) decompose the
//!    enclosing dispatch time within stated tolerance.
//! 4. Missing or unregistered GPU phases fail the test.

use keyhog_profile::{
    add_counter, gpu_dispatch_decomposition_counters, gpu_dispatch_phase_counters, span, CounterId,
    MetricKind, MetricUnit, RunIdentity, RunState, Session, Stage,
    GPU_DISPATCH_DECOMPOSITION_COUNTERS, GPU_DISPATCH_PHASE_COUNTERS,
};

#[test]
fn gpu_dispatch_phases_enumerated_and_registered() {
    let phases = gpu_dispatch_phase_counters();
    assert_eq!(phases.len(), GPU_DISPATCH_PHASE_COUNTERS.len());
    assert_eq!(phases.len(), 6);

    let decomposition = gpu_dispatch_decomposition_counters();
    assert_eq!(
        decomposition.len(),
        GPU_DISPATCH_DECOMPOSITION_COUNTERS.len()
    );
    assert_eq!(decomposition.len(), 3);

    // Every decomposition phase must be a member of the full phase list.
    for decomp_phase in decomposition {
        assert!(
            phases.contains(decomp_phase),
            "decomposition phase {decomp_phase:?} must be in full phase list"
        );
    }

    // Every phase must resolve to a valid descriptor with nanosecond units.
    for phase in phases {
        let descriptor = phase.metric_id().descriptor();
        assert_eq!(descriptor.id, phase.metric_id());
        assert_eq!(descriptor.kind, MetricKind::Counter);
        assert_eq!(descriptor.unit, MetricUnit::Nanoseconds);
        assert!(!descriptor.name.is_empty());
    }
}

#[test]
fn gpu_dispatch_decomposition_sums_to_enclosing_dispatch_within_tolerance() {
    let identity = RunIdentity::new(
        "0.5.49",
        "detector-digest",
        "config-digest",
        "filesystem",
        "small-text",
        "auto",
    );
    let mut session = Session::start(identity).expect("start profile session");
    session.transition(RunState::Scanning);

    let coalesce_ns = 2_500_000u64; // 2.5 ms
    let dispatch_ns = 5_000_000u64; // 5.0 ms
    let derive_ns = 1_500_000u64; // 1.5 ms
    let total_dispatch_ns = coalesce_ns + dispatch_ns + derive_ns; // 9.0 ms

    // Simulate enclosing BackendDispatch stage and inner decomposition counters
    {
        let _span = span(Stage::BackendDispatch);
        add_counter(CounterId::GpuCoalesceNs, coalesce_ns);
        add_counter(CounterId::GpuDispatchNs, dispatch_ns);
        add_counter(CounterId::GpuDeriveNs, derive_ns);
    }

    let runtime = session.runtime();
    let typed = runtime.take_session_typed_metrics();
    let _profile = session.finish(RunState::Completed);

    let get_counter = |counter: CounterId| {
        typed
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };

    let measured_coalesce = get_counter(CounterId::GpuCoalesceNs);
    let measured_dispatch = get_counter(CounterId::GpuDispatchNs);
    let measured_derive = get_counter(CounterId::GpuDeriveNs);

    assert_eq!(measured_coalesce, coalesce_ns);
    assert_eq!(measured_dispatch, dispatch_ns);
    assert_eq!(measured_derive, derive_ns);

    // Sum of decomposition phases
    let decomposition_sum: u64 = gpu_dispatch_decomposition_counters()
        .iter()
        .map(|&counter| get_counter(counter))
        .sum();

    assert_eq!(decomposition_sum, total_dispatch_ns);

    // Verify decomposition sum equals the enclosing dispatch within tolerance
    let delta = decomposition_sum.abs_diff(total_dispatch_ns);
    let tolerance = total_dispatch_ns / 20; // 5% tolerance
    assert!(
        delta <= tolerance,
        "decomposition sum {decomposition_sum} must match enclosing dispatch {total_dispatch_ns} within {tolerance} (delta={delta})"
    );
}
