//! Hardware counter collection, capability reporting, and typed recording.

use keyhog_profile::{
    CollectorAvailability, CollectorId, Evidence, EvidenceGap, RunIdentity, RunState, Session,
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

fn collector(profile: &keyhog_profile::RunProfile, id: CollectorId) -> &keyhog_profile::CollectorCapability {
    profile
        .collectors
        .iter()
        .find(|capability| capability.collector == id)
        .expect("collector capability present")
}

/// With the feature off every hardware collector must report Disabled with the
/// exact remediation, and the run evidence must be an explicit gap, never a
/// silently absent or fabricated measurement.
#[cfg(not(feature = "hardware-counters"))]
#[test]
fn disabled_feature_reports_disabled_collectors_and_gap() {
    let profile = session("hw-disabled").finish(RunState::Completed);
    for id in [
        CollectorId::HardwareCounters,
        CollectorId::SchedulerActivity,
        CollectorId::ThreadUtilization,
        CollectorId::CpuTopology,
    ] {
        let capability = collector(&profile, id);
        assert_eq!(capability.availability, CollectorAvailability::Disabled);
        assert_eq!(
            capability.detail.as_deref(),
            Some("enable the keyhog-profile hardware-counters feature")
        );
    }
    assert_eq!(
        profile.hardware,
        Evidence::unavailable(EvidenceGap::CollectorDisabled)
    );
}

#[cfg(all(feature = "hardware-counters", target_os = "linux"))]
mod linux {
    use keyhog_profile::{
        CounterId, HardwareCounterCollector, HardwareFieldSourceV2, MetricId,
        SchedulerCollector, SnapshotCollector,
    };

    use super::*;

    /// perf_event_open must either produce real per-thread cycle and
    /// instruction counters or an explicit permission gap naming the paranoid
    /// level; both outcomes are honest capability reports.
    #[test]
    fn perf_counters_collect_or_report_permission_gap() {
        let mut collector = HardwareCounterCollector::new();
        let capability = collector.capability();
        assert_eq!(capability.collector, CollectorId::HardwareCounters);
        let begin = collector.sample();
        let mut sink = 0_u64;
        for index in 0..1_000_000_u64 {
            sink = sink.wrapping_add(index).wrapping_mul(2_654_435_761);
        }
        std::hint::black_box(sink);
        let end = collector.sample();
        match capability.availability {
            CollectorAvailability::Available => {
                let begin_cycles = match &begin.cycles.value {
                    Evidence::Recorded { value } => *value,
                    other => panic!("cycles must be recorded when available: {other:?}"),
                };
                let end_cycles = match &end.cycles.value {
                    Evidence::Recorded { value } => *value,
                    other => panic!("cycles must be recorded when available: {other:?}"),
                };
                assert!(end_cycles > begin_cycles);
                let begin_instructions = match &begin.instructions.value {
                    Evidence::Recorded { value } => *value,
                    other => panic!("instructions must be recorded when available: {other:?}"),
                };
                let end_instructions = match &end.instructions.value {
                    Evidence::Recorded { value } => *value,
                    other => panic!("instructions must be recorded when available: {other:?}"),
                };
                assert!(end_instructions > begin_instructions);
                assert_eq!(begin.cycles.source, HardwareFieldSourceV2::PerfEventOpen);
                assert_eq!(
                    begin.instructions.source,
                    HardwareFieldSourceV2::PerfEventOpen
                );
            }
            CollectorAvailability::PermissionDenied => {
                let detail = capability.detail.expect("denial must explain itself");
                assert!(
                    detail.contains("perf_event_paranoid"),
                    "denial must name the paranoid level: {detail}"
                );
                assert_eq!(
                    begin.cycles.value,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                assert_eq!(
                    begin.instructions.value,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                assert_eq!(
                    begin.cache_references.value,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                assert_eq!(
                    begin.branch_misses.value,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                // Frontend and backend stalls come from the same perf
                // facility, so a denied host must gap them with the same
                // explicit reason rather than fabricating zeros.
                assert_eq!(
                    begin.stalled_cycles_frontend.value,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                assert_eq!(
                    begin.stalled_cycles_backend.value,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                let set = keyhog_profile::HardwareCounterSetV2::between(&begin, &end);
                assert_eq!(
                    set.cpi_milli,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                assert_eq!(
                    set.cache_miss_ratio_milli,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
                assert_eq!(
                    set.branch_miss_ratio_milli,
                    Evidence::unavailable(EvidenceGap::PermissionDenied)
                );
            }
            other => panic!("unexpected hardware counter availability: {other:?}"),
        }
        // Generic memory stalls have no perf event on any CPU; the gap must be
        // explicit regardless of permission level.
        assert_eq!(
            begin.stalled_cycles_memory.value,
            Evidence::unavailable(EvidenceGap::Unsupported)
        );
        assert_eq!(
            begin.stalled_cycles_memory.source,
            HardwareFieldSourceV2::PerfEventOpen
        );
    }

    /// Scheduler sampling must record context switches from /proc/self/sched
    /// and runqueue delay from /proc/self/schedstat, each with its source,
    /// and a sleep must register as at least one voluntary switch.
    #[test]
    fn scheduler_records_switches_and_delay_with_sources() {
        let mut collector = SchedulerCollector::new();
        assert_eq!(
            collector.capability().availability,
            CollectorAvailability::Available
        );
        let begin = collector.sample();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let end = collector.sample();
        let delta = keyhog_profile::SchedulerEvidenceV2::between(&begin, &end);
        let voluntary = match &delta.voluntary_context_switches.value {
            Evidence::Recorded { value } => *value,
            other => panic!("voluntary switches must be recorded on Linux: {other:?}"),
        };
        assert!(voluntary >= 1, "a 2ms sleep must switch voluntarily");
        assert_eq!(
            delta.voluntary_context_switches.source,
            HardwareFieldSourceV2::ProcSelfSched
        );
        assert_eq!(
            delta.involuntary_context_switches.source,
            HardwareFieldSourceV2::ProcSelfSched
        );
        assert!(
            matches!(
                delta.involuntary_context_switches.value,
                Evidence::Recorded { .. }
            ),
            "involuntary switches must be recorded on Linux"
        );
        assert_eq!(
            delta.scheduler_delay_ns.source,
            HardwareFieldSourceV2::ProcSelfSchedstat
        );
        assert!(
            matches!(
                delta.scheduler_delay_ns.value,
                Evidence::Recorded { .. }
            ),
            "schedstat runqueue delay must be recorded on this kernel"
        );
        assert_eq!(
            delta.timeslices.source,
            HardwareFieldSourceV2::ProcSelfSchedstat
        );
        // Migrations come only from perf software events; the field must say so.
        assert_eq!(
            delta.cpu_migrations.source,
            HardwareFieldSourceV2::PerfEventOpen
        );
    }

    /// The total context-switch field must equal voluntary plus involuntary
    /// on a real sample pair, and the absolute counts must match an
    /// independent read of /proc/thread-self/sched.
    #[test]
    fn scheduler_total_matches_independent_procfs_read() {
        fn independent_switches() -> (u64, u64) {
            let sched = std::fs::read_to_string("/proc/thread-self/sched").expect("thread sched");
            let mut voluntary = None;
            let mut involuntary = None;
            for line in sched.lines() {
                if let Some(value) = line.strip_prefix("nr_voluntary_switches") {
                    voluntary = value.split(':').nth(1).and_then(|v| v.trim().parse().ok());
                } else if let Some(value) = line.strip_prefix("nr_involuntary_switches") {
                    involuntary = value.split(':').nth(1).and_then(|v| v.trim().parse().ok());
                }
            }
            (voluntary.expect("voluntary field"), involuntary.expect("involuntary field"))
        }

        let mut collector = SchedulerCollector::new();
        let begin = collector.sample();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let end = collector.sample();
        let (end_voluntary, end_involuntary) = independent_switches();
        let recorded_voluntary = match &end.voluntary_context_switches.value {
            Evidence::Recorded { value } => *value,
            other => panic!("voluntary switches must be recorded: {other:?}"),
        };
        let recorded_involuntary = match &end.involuntary_context_switches.value {
            Evidence::Recorded { value } => *value,
            other => panic!("involuntary switches must be recorded: {other:?}"),
        };
        // The independent read trails the collector by microseconds; only a
        // handful of switches can land between the two reads of the same file.
        assert!(end_voluntary >= recorded_voluntary);
        assert!(end_voluntary - recorded_voluntary <= 4);
        assert!(end_involuntary >= recorded_involuntary);
        assert!(end_involuntary - recorded_involuntary <= 4);
        let delta = keyhog_profile::SchedulerEvidenceV2::between(&begin, &end);
        let voluntary = match &delta.voluntary_context_switches.value {
            Evidence::Recorded { value } => *value,
            other => panic!("voluntary delta must be recorded: {other:?}"),
        };
        let involuntary = match &delta.involuntary_context_switches.value {
            Evidence::Recorded { value } => *value,
            other => panic!("involuntary delta must be recorded: {other:?}"),
        };
        assert_eq!(
            delta.total_context_switches.value,
            Evidence::recorded(voluntary + involuntary)
        );
    }

    /// A finished session must expose run evidence whose scheduler totals are
    /// also recorded as exact typed counters on the session runtime.
    #[test]
    fn session_records_scheduler_totals_as_typed_counters() {
        let session = session("hw-typed-scheduler");
        let runtime = session.runtime();
        std::thread::sleep(std::time::Duration::from_millis(2));
        drop(keyhog_profile::span(Stage::SourceRead));
        let profile = session.finish(RunState::Completed);

        let evidence = match &profile.hardware {
            Evidence::Recorded { value } => value,
            other => panic!("hardware evidence must be recorded with the feature on: {other:?}"),
        };
        let voluntary = match &evidence.scheduler.voluntary_context_switches.value {
            Evidence::Recorded { value } => *value,
            other => panic!("session voluntary switches must be recorded: {other:?}"),
        };
        assert!(voluntary >= 1);

        let typed = runtime.take_session_typed_metrics();
        let typed_voluntary = typed
            .iter()
            .find(|record| record.metric_id == MetricId::SchedulerVoluntaryContextSwitches)
            .expect("typed voluntary context switches recorded");
        assert_eq!(typed_voluntary.value, voluntary);
        let typed_counter = CounterId::SchedulerVoluntaryContextSwitches;
        assert_eq!(typed_counter.metric_id(), MetricId::SchedulerVoluntaryContextSwitches);
        // Perf is denied on hosts with perf_event_paranoid above 2; the run
        // counter fields must then carry the same explicit gap.
        let capability = collector(&profile, CollectorId::HardwareCounters);
        if capability.availability == CollectorAvailability::PermissionDenied {
            assert_eq!(
                evidence.counters.cycles.value,
                Evidence::unavailable(EvidenceGap::PermissionDenied)
            );
            assert!(!typed
                .iter()
                .any(|record| record.metric_id == MetricId::HardwareCycles));
        }
    }
}
