//! Per-thread CPU utilization and effective parallelism from task stats.

use keyhog_profile::{Evidence, EvidenceGap, RunIdentity, RunState, Session};

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

/// With the feature off utilization must be an explicit disabled gap.
#[cfg(not(feature = "hardware-counters"))]
#[test]
fn disabled_feature_gaps_utilization() {
    let profile = session("utilization-disabled").finish(RunState::Completed);
    assert_eq!(
        profile.hardware,
        Evidence::unavailable(EvidenceGap::CollectorDisabled)
    );
}

#[cfg(all(feature = "hardware-counters", target_os = "linux"))]
mod linux {
    use keyhog_profile::{HardwareFieldSourceV2, SnapshotCollector, ThreadUtilizationCollector};

    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    fn process_cpu_ns() -> u64 {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("proc stat");
        let command_end = stat.rfind(')').expect("stat command end");
        let mut fields = stat[command_end + 2..].split_whitespace();
        let user_ticks: u64 = fields.nth(11).expect("utime").parse().expect("utime value");
        let system_ticks: u64 = fields.next().expect("stime").parse().expect("stime value");
        (user_ticks + system_ticks) * 10_000_000
    }

    fn task_cpu_ns() -> Vec<(u64, u64)> {
        let mut tasks: Vec<(u64, u64)> = std::fs::read_dir("/proc/self/task")
            .expect("task directory")
            .flatten()
            .filter_map(|entry| {
                let tid = entry.file_name().to_string_lossy().parse::<u64>().ok()?;
                let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
                let command_end = stat.rfind(')')?;
                let mut fields = stat[command_end + 2..].split_whitespace();
                let user_ticks: u64 = fields.nth(11)?.parse().ok()?;
                let system_ticks: u64 = fields.next()?.parse().ok()?;
                Some((tid, (user_ticks + system_ticks) * 10_000_000))
            })
            .collect();
        tasks.sort_unstable();
        tasks
    }

    /// Per-thread utilization deltas must add up to the process CPU delta read
    /// independently from /proc/self/stat while every worker is parked, so the
    /// sums cannot drift between the two reads.
    #[test]
    fn per_thread_utilization_adds_up_to_process_cpu() {
        let spin = Arc::new(AtomicBool::new(false));
        let park = Arc::new(AtomicBool::new(false));
        let parked = Arc::new(AtomicU64::new(0));
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let spin = Arc::clone(&spin);
                let park = Arc::clone(&park);
                let parked = Arc::clone(&parked);
                std::thread::spawn(move || {
                    while !spin.load(Ordering::Relaxed) {
                        std::thread::yield_now();
                    }
                    let start = std::time::Instant::now();
                    let mut sink = 0_u64;
                    while start.elapsed() < std::time::Duration::from_millis(30) {
                        sink = sink.wrapping_mul(2_654_435_761).wrapping_add(1);
                    }
                    std::hint::black_box(sink);
                    parked.fetch_add(1, Ordering::Relaxed);
                    while !park.load(Ordering::Relaxed) {
                        std::thread::park();
                    }
                })
            })
            .collect();

        let process_start = process_cpu_ns();
        let tasks_start = task_cpu_ns();
        let mut collector = ThreadUtilizationCollector::new();
        let first = collector.sample();
        spin.store(true, Ordering::Relaxed);
        while parked.load(Ordering::Relaxed) < 3 {
            std::thread::yield_now();
        }
        let last = collector.sample();
        let process_end = process_cpu_ns();
        let tasks_end = task_cpu_ns();
        park.store(true, Ordering::Relaxed);
        for worker in workers {
            worker.thread().unpark();
            worker.join().expect("join worker");
        }

        let first_by_id: std::collections::BTreeMap<u64, u64> = first
            .threads
            .iter()
            .map(|thread| (thread.thread_id, thread.cpu_time_ns))
            .collect();
        let collector_total: u64 = last
            .threads
            .iter()
            .filter_map(|thread| {
                first_by_id
                    .get(&thread.thread_id)
                    .map(|start| thread.cpu_time_ns.saturating_sub(*start))
            })
            .sum();
        assert!(
            collector_total >= 30_000_000,
            "three spinning workers must accrue CPU"
        );

        let start_by_id: std::collections::BTreeMap<u64, u64> =
            tasks_start.iter().copied().collect();
        let independent_total: u64 = tasks_end
            .iter()
            .filter_map(|(tid, end)| start_by_id.get(tid).map(|start| end.saturating_sub(*start)))
            .sum();
        // Both totals come from the same tick counters nanoseconds apart while
        // workers are parked; they may differ only by main-thread bookkeeping.
        let drift = independent_total.abs_diff(collector_total);
        assert!(
            drift <= 20_000_000,
            "collector total {collector_total} must match independent total {independent_total}"
        );

        let process_delta = process_end - process_start;
        assert!(
            process_delta >= collector_total.saturating_sub(20_000_000),
            "process cpu delta {process_delta} must cover per-thread total {collector_total}"
        );
        assert!(first.dropped_threads == 0 && last.dropped_threads == 0);
        assert!(!first.threads.is_empty());
    }

    /// A session must report effective parallelism that rises with real
    /// parallel work and stays inside wall capacity. Workers start before the
    /// session and stay alive through finish so both boundary samples see
    /// them; threads absent from either sample are excluded by design.
    #[test]
    fn session_reports_effective_parallelism_inside_capacity() {
        let stop = Arc::new(AtomicBool::new(false));
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut sink = 0_u64;
                    while !stop.load(Ordering::Relaxed) {
                        sink = sink.wrapping_mul(2_654_435_761).wrapping_add(1);
                    }
                    std::hint::black_box(sink);
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let session = session("utilization-parallelism");
        std::thread::sleep(std::time::Duration::from_millis(40));
        let profile = session.finish(RunState::Completed);
        stop.store(true, Ordering::Relaxed);
        for worker in workers {
            worker.join().expect("join worker");
        }
        let evidence = match &profile.hardware {
            Evidence::Recorded { value } => value,
            other => panic!("hardware evidence must be recorded: {other:?}"),
        };
        let utilization = &evidence.utilization;
        let logical = u64::from(utilization.logical_cpus);
        assert!(logical >= 1);
        assert!(utilization.wall_ns > 0);
        assert!(utilization.total_thread_cpu_ns > 0);
        let parallelism = match &utilization.effective_parallelism_milli {
            Evidence::Recorded { value } => *value,
            other => panic!("parallelism must be recorded: {other:?}"),
        };
        assert!(
            parallelism > 500,
            "three spinning workers must exceed half a CPU of parallelism, got {parallelism}"
        );
        assert!(
            parallelism <= logical * 1_000,
            "parallelism {parallelism} cannot exceed {logical} CPUs"
        );
        let capacity = match &utilization.capacity_utilization_milli {
            Evidence::Recorded { value } => *value,
            other => panic!("capacity utilization must be recorded: {other:?}"),
        };
        assert!(capacity <= 1_000);
        let thread_sum: u64 = utilization
            .threads
            .iter()
            .map(|thread| thread.cpu_time_ns)
            .sum();
        assert_eq!(thread_sum, utilization.total_thread_cpu_ns);
        assert_eq!(utilization.dropped_samples, 0);
    }

    /// Utilization sampling must stay bounded: more transitions than
    /// MAX_UTILIZATION_SAMPLES must drop with an exact count, never grow the
    /// retained series.
    #[test]
    fn utilization_samples_are_bounded_with_exact_loss() {
        let mut session = session("utilization-bounded");
        for _ in 0..keyhog_profile::MAX_UTILIZATION_SAMPLES + 7 {
            session.transition(RunState::Scanning);
        }
        let profile = session.finish(RunState::Completed);
        let evidence = match &profile.hardware {
            Evidence::Recorded { value } => value,
            other => panic!("hardware evidence must be recorded: {other:?}"),
        };
        let utilization = &evidence.utilization;
        assert_eq!(
            utilization.samples_retained,
            keyhog_profile::MAX_UTILIZATION_SAMPLES as u64
        );
        // Pushes: start, one per loop transition, finish's transition, and
        // finish's final sample; retained plus dropped must account for all.
        let pushes = 1 + (keyhog_profile::MAX_UTILIZATION_SAMPLES + 7) + 1 + 1;
        assert_eq!(
            utilization.samples_retained + utilization.dropped_samples,
            pushes as u64
        );
        assert_eq!(utilization.dropped_samples, 10);
        assert!(utilization.frequency_samples.len() <= keyhog_profile::MAX_UTILIZATION_SAMPLES);
    }

    /// Threads that exit mid-session and threads that join mid-session must
    /// be counted explicitly, and only threads alive at both boundaries
    /// contribute CPU to the totals.
    #[test]
    fn exited_and_joined_threads_are_counted_explicitly() {
        let early = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(5));
        });
        let session = session("utilization-lifecycle");
        early.join().expect("join early thread");
        let stop = Arc::new(AtomicBool::new(false));
        let late = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::yield_now();
                }
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        let profile = session.finish(RunState::Completed);
        stop.store(true, Ordering::Relaxed);
        late.join().expect("join late thread");
        let evidence = match &profile.hardware {
            Evidence::Recorded { value } => value,
            other => panic!("hardware evidence must be recorded: {other:?}"),
        };
        let utilization = &evidence.utilization;
        assert!(
            utilization.exited_threads >= 1,
            "the early thread must exit mid-session"
        );
        assert!(
            utilization.joined_threads >= 1,
            "the late thread must join mid-session"
        );
        for thread in &utilization.threads {
            assert_ne!(thread.thread_id, 0);
        }
    }
}
