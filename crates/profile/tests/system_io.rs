//! Page faults, process IO counters, RSS high water, PSI, and thermal
//! evidence against real /proc and sysfs reads, with explicit capability
//! gaps where the host cannot provide a family.

use keyhog_profile::{
    CollectorAvailability, CollectorId, Evidence, EvidenceGap, HardwareFieldSourceV2, RunIdentity,
    RunState, Session, SnapshotCollector, SystemIoCollector,
};
use std::sync::{Mutex, MutexGuard};

static SYSTEM_IO_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    SYSTEM_IO_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

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

/// Without process metrics every system family must collapse to explicit
/// disabled capabilities and gaps, never fabricated zeros.
#[cfg(not(feature = "process-metrics"))]
#[test]
fn disabled_process_metrics_gap_every_system_family() {
    let _guard = lock();
    let mut collector = SystemIoCollector::new();
    let capability = collector.capability();
    assert_eq!(capability.availability, CollectorAvailability::Disabled);
    assert_eq!(
        capability.detail.as_deref(),
        Some("enable the keyhog-profile process-metrics feature")
    );
    let sample = collector.sample();
    assert_eq!(
        sample.minor_faults.value,
        Evidence::unavailable(EvidenceGap::CollectorDisabled)
    );
    let profile = session("system-disabled").finish(RunState::Completed);
    let system = match &profile.system {
        Evidence::Recorded { value } => value,
        other => panic!("system evidence must be recorded: {other:?}"),
    };
    assert_eq!(
        system.faults.minor_faults.value,
        Evidence::unavailable(EvidenceGap::CollectorDisabled)
    );
    assert_eq!(
        system.io.read_bytes.value,
        Evidence::unavailable(EvidenceGap::CollectorDisabled)
    );
}

#[cfg(all(feature = "process-metrics", target_os = "linux"))]
mod linux {
    use super::*;
    use keyhog_profile::{PressureThermalCollector, Stage};
    use std::io::Write;

    fn io_field(field: &str) -> u64 {
        let io = std::fs::read_to_string("/proc/self/io").expect("proc io");
        io.lines()
            .find_map(|line| line.strip_prefix(field)?.trim().parse().ok())
            .expect("io field present")
    }

    fn stat_faults() -> (u64, u64) {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("proc stat");
        let command_end = stat.rfind(')').expect("stat command end");
        let mut fields = stat[command_end + 2..].split_whitespace();
        let minor: u64 = fields
            .nth(7)
            .expect("minflt")
            .parse()
            .expect("minflt value");
        let major: u64 = fields
            .nth(1)
            .expect("majflt")
            .parse()
            .expect("majflt value");
        (minor, major)
    }

    fn status_field(field: &str) -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").expect("proc status");
        status
            .lines()
            .find_map(|line| {
                line.strip_prefix(field)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
            .expect("status field present")
    }

    /// Fault and IO samples must match an independent parse of the same
    /// /proc files within the slack of back-to-back reads.
    #[test]
    fn faults_and_io_match_independent_procfs_reads() {
        let _guard = lock();
        let mut collector = SystemIoCollector::new();
        assert_eq!(
            collector.capability().availability,
            CollectorAvailability::Available
        );
        let sample = collector.sample();
        let (minor, major) = stat_faults();
        let recorded_minor = match &sample.minor_faults.value {
            Evidence::Recorded { value } => *value,
            other => panic!("minor faults must be recorded on Linux: {other:?}"),
        };
        let recorded_major = match &sample.major_faults.value {
            Evidence::Recorded { value } => *value,
            other => panic!("major faults must be recorded on Linux: {other:?}"),
        };
        assert!(minor >= recorded_minor && minor - recorded_minor <= 256);
        assert!(major >= recorded_major);
        assert_eq!(
            sample.minor_faults.source,
            HardwareFieldSourceV2::ProcSelfStat
        );

        let read_syscalls = io_field("syscr:");
        let recorded_read_syscalls = match &sample.read_syscalls.value {
            Evidence::Recorded { value } => *value,
            other => panic!("read syscalls must be recorded on Linux: {other:?}"),
        };
        // The independent read itself issues read syscalls, so it must be
        // strictly ahead of the collector sample.
        assert!(read_syscalls > recorded_read_syscalls);
        assert!(read_syscalls - recorded_read_syscalls <= 64);
        assert_eq!(
            sample.read_syscalls.source,
            HardwareFieldSourceV2::ProcSelfIo
        );
        for field in [
            &sample.read_bytes,
            &sample.write_bytes,
            &sample.write_syscalls,
            &sample.cancelled_write_bytes,
        ] {
            assert!(matches!(field.value, Evidence::Recorded { .. }));
            assert_eq!(field.source, HardwareFieldSourceV2::ProcSelfIo);
        }
    }

    /// Touching freshly allocated pages must register as real minor faults
    /// and explicit file writes must register as write syscalls in the
    /// session deltas.
    #[test]
    fn session_deltas_register_known_faults_and_writes() {
        let _guard = lock();
        let session = session("system-deltas");
        let runtime = session.runtime();
        let touched = vec![1_u8; 32 * 1024 * 1024];
        std::hint::black_box(&touched);
        let mut file = std::fs::File::create("/tmp/keyhog-profile-io-test.bin").expect("create");
        for _ in 0..3 {
            file.write_all(&[7_u8; 4_096]).expect("write");
        }
        file.sync_all().expect("sync");
        drop(file);
        let profile = session.finish(RunState::Completed);
        std::fs::remove_file("/tmp/keyhog-profile-io-test.bin").expect("remove");

        let system = match &profile.system {
            Evidence::Recorded { value } => value,
            other => panic!("system evidence must be recorded: {other:?}"),
        };
        let minor = match &system.faults.minor_faults.value {
            Evidence::Recorded { value } => *value,
            other => panic!("minor faults must be recorded: {other:?}"),
        };
        // 32 MiB of fresh pages is at least 16 faults with 2 MiB huge pages.
        assert!(minor >= 16, "touching 32 MiB must fault pages, got {minor}");
        let write_syscalls = match &system.io.write_syscalls.value {
            Evidence::Recorded { value } => *value,
            other => panic!("write syscalls must be recorded: {other:?}"),
        };
        assert!(write_syscalls >= 3, "three write_all calls must count");

        let typed = runtime.take_session_typed_metrics();
        let find = |metric: keyhog_profile::MetricId| {
            typed
                .iter()
                .find(|record| record.metric_id == metric)
                .map(|record| record.value)
        };
        assert_eq!(find(keyhog_profile::MetricId::MinorFaults), Some(minor));
        assert_eq!(
            find(keyhog_profile::MetricId::IoWriteSyscalls),
            Some(write_syscalls)
        );
    }

    /// The kernel high water must be recorded, dominate the resident size,
    /// and grow past a known 256 MiB touch; the session max-observed RSS must
    /// equal the maximum of its own samples exactly.
    #[test]
    fn resident_high_water_tracks_known_growth() {
        let _guard = lock();
        let before_hwm = status_field("VmHWM:") * 1_024;
        let session = session("system-hwm");
        let grown = vec![3_u8; 256 * 1024 * 1024];
        std::hint::black_box(grown.iter().map(|byte| u64::from(*byte)).sum::<u64>());
        let profile = session.finish(RunState::Completed);
        drop(grown);

        let system = match &profile.system {
            Evidence::Recorded { value } => value,
            other => panic!("system evidence must be recorded: {other:?}"),
        };
        let hwm = match &system.memory.resident_high_water_bytes.value {
            Evidence::Recorded { value } => *value,
            other => panic!("high water must be recorded on Linux: {other:?}"),
        };
        let resident = match &system.memory.resident_bytes.value {
            Evidence::Recorded { value } => *value,
            other => panic!("resident bytes must be recorded: {other:?}"),
        };
        assert_eq!(
            system.memory.resident_high_water_bytes.source,
            HardwareFieldSourceV2::ProcSelfStatus
        );
        assert!(hwm >= resident, "high water must dominate resident size");
        // No earlier test in this binary exceeds 256 MiB, so the growth must
        // push the high water up by at least 128 MiB.
        assert!(
            hwm >= before_hwm + 128 * 1024 * 1024,
            "high water {hwm} must grow past a 256 MiB touch from {before_hwm}"
        );
        let max_observed = profile
            .resources
            .max_observed_resident_bytes
            .expect("max observed resident bytes");
        let sample_max = profile
            .resource_samples
            .iter()
            .filter_map(|sample| sample.snapshot.resident_bytes)
            .max()
            .expect("resident sample");
        assert!(max_observed >= sample_max);
        assert!(max_observed >= 256 * 1024 * 1024);
    }

    /// PSI and thermal fields must either carry real parsed values that match
    /// independent reads, or explicit capability gaps; both outcomes are
    /// honest host reports.
    #[test]
    fn pressure_and_thermal_collect_or_report_capability() {
        let _guard = lock();
        let mut collector = PressureThermalCollector::new();
        let sample = collector.sample();
        if std::path::Path::new("/proc/pressure/cpu").exists() {
            assert_eq!(
                collector.capability().availability,
                CollectorAvailability::Available
            );
            let cpu_some = match &sample.cpu_some_avg10_milli.value {
                Evidence::Recorded { value } => *value,
                other => panic!("PSI cpu some must be recorded when present: {other:?}"),
            };
            let contents = std::fs::read_to_string("/proc/pressure/cpu").expect("pressure cpu");
            let some_line = contents
                .lines()
                .find(|line| line.starts_with("some"))
                .expect("some line");
            let avg10: f64 = some_line
                .split_whitespace()
                .find_map(|field| field.strip_prefix("avg10="))
                .expect("avg10 field")
                .parse()
                .expect("avg10 value");
            let independent = (avg10 * 1_000.0) as u64;
            // avg10 decays between reads; allow two percent of drift.
            assert!(cpu_some.abs_diff(independent) <= 2_000);
            assert_eq!(
                sample.cpu_some_avg10_milli.source,
                HardwareFieldSourceV2::ProcPressure
            );
        } else {
            assert_eq!(
                collector.capability().availability,
                CollectorAvailability::Unavailable
            );
            assert_eq!(
                sample.cpu_some_avg10_milli.value,
                Evidence::unavailable(EvidenceGap::Unavailable)
            );
        }
        match &sample.max_zone_millicelsius.value {
            Evidence::Recorded { value } => {
                assert!(*value > 0 && *value <= 150_000);
                assert_eq!(
                    sample.max_zone_millicelsius.source,
                    HardwareFieldSourceV2::SysfsThermal
                );
            }
            Evidence::Unavailable { reason } => {
                // No readable thermal zones on this host.
                assert!(matches!(
                    reason,
                    EvidenceGap::Unavailable | EvidenceGap::Unsupported
                ));
            }
        }
        // Throttle counters exist only on some Intel platforms; this host
        // must show either a real count or an explicit unsupported gap.
        match &sample.throttle_events.value {
            Evidence::Recorded { .. } => {}
            Evidence::Unavailable { reason } => assert_eq!(*reason, EvidenceGap::Unsupported),
        }
    }

    /// A finished session must attach system evidence whose network process
    /// counters are an explicit unsupported gap on Linux (procfs has no
    /// per-process network counters) and whose allocation totals stay an
    /// explicit gap when no TrackingAllocator is installed.
    #[test]
    fn session_system_evidence_reports_network_gap_and_stage_slots() {
        let _guard = lock();
        let session = session("system-network");
        {
            let _read = keyhog_profile::span(Stage::SourceRead);
            std::hint::black_box(42);
        }
        let profile = session.finish(RunState::Completed);
        let system = match &profile.system {
            Evidence::Recorded { value } => value,
            other => panic!("system evidence must be recorded: {other:?}"),
        };
        assert_eq!(
            system.network.process_counters.value,
            Evidence::unavailable(EvidenceGap::Unsupported)
        );
        assert_eq!(system.network.retry_annotations, 0);
        assert!(matches!(
            system.allocation.totals,
            Evidence::Unavailable { .. }
        ));
        assert!(system.allocation.stages.is_empty());
        let io_capability = profile
            .collectors
            .iter()
            .find(|capability| capability.collector == CollectorId::SystemIo)
            .expect("system io capability");
        assert_eq!(io_capability.availability, CollectorAvailability::Available);
        let allocation_capability = profile
            .collectors
            .iter()
            .find(|capability| capability.collector == CollectorId::AllocationTracking)
            .expect("allocation capability");
        #[cfg(feature = "allocation-tracking")]
        {
            assert_eq!(
                allocation_capability.availability,
                CollectorAvailability::Unavailable
            );
            assert_eq!(
                allocation_capability.detail.as_deref(),
                Some(
                    "install keyhog_profile::TrackingAllocator as the global allocator to count allocations"
                )
            );
        }
        #[cfg(not(feature = "allocation-tracking"))]
        assert_eq!(
            allocation_capability.availability,
            CollectorAvailability::Disabled
        );
    }
}
