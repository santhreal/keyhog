//! CPU topology, affinity, NUMA, frequency, and cgroup evidence from real sysfs.

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

/// With the feature off the topology evidence must collapse to one explicit
/// disabled gap rather than a half-populated record.
#[cfg(not(feature = "hardware-counters"))]
#[test]
fn disabled_feature_gaps_topology() {
    let profile = session("topology-disabled").finish(RunState::Completed);
    assert_eq!(
        profile.hardware,
        Evidence::unavailable(EvidenceGap::CollectorDisabled)
    );
}

#[cfg(all(feature = "hardware-counters", target_os = "linux"))]
mod linux {
    use keyhog_profile::{
        CollectorAvailability, HardwareFieldSourceV2, SnapshotCollector, TopologyCollector,
    };

    use super::*;

    fn sysfs_cpu_indices() -> Vec<u32> {
        let mut indices: Vec<u32> = std::fs::read_dir("/sys/devices/system/cpu")
            .expect("sysfs cpu directory")
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .strip_prefix("cpu")
                    .and_then(|rest| rest.parse::<u32>().ok())
                    .map(|index| index)
            })
            .collect();
        indices.sort_unstable();
        indices
    }

    fn read_u32(path: &str) -> Option<u32> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// Topology must be populated from real sysfs: physical cores and packages
    /// recomputed independently by the test must match the collector exactly.
    #[test]
    fn topology_matches_independent_sysfs_parse() {
        let mut collector = TopologyCollector::new();
        assert_eq!(
            collector.capability().availability,
            CollectorAvailability::Available
        );
        let topology = collector.sample();
        let expected_logical = std::thread::available_parallelism()
            .expect("available parallelism")
            .get() as u32;
        assert_eq!(topology.logical_cpus, expected_logical);

        let cpus = sysfs_cpu_indices();
        assert!(!cpus.is_empty());
        let mut cores = std::collections::BTreeSet::new();
        let mut packages = std::collections::BTreeSet::new();
        for cpu in &cpus {
            let base = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
            let package =
                read_u32(&format!("{base}/physical_package_id")).expect("physical package id");
            let core = read_u32(&format!("{base}/core_id")).expect("core id");
            packages.insert(package);
            cores.insert((package, core));
        }
        assert_eq!(
            topology.physical_cores.value,
            Evidence::recorded(cores.len() as u32)
        );
        assert_eq!(
            topology.physical_cores.source,
            HardwareFieldSourceV2::SysfsCpu
        );
        assert_eq!(
            topology.packages.value,
            Evidence::recorded(packages.len() as u32)
        );
        assert!(cores.len() as u32 <= expected_logical);

        let expected_numa = std::fs::read_dir("/sys/devices/system/node")
            .expect("sysfs node directory")
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .strip_prefix("node")
                    .is_some_and(|rest| rest.parse::<u32>().is_ok())
            })
            .count() as u32;
        assert_eq!(topology.numa_nodes.value, Evidence::recorded(expected_numa));
        assert_eq!(topology.numa_nodes.source, HardwareFieldSourceV2::SysfsCpu);
    }

    /// Affinity must equal the process Cpus_allowed_list count parsed
    /// independently from /proc/self/status, and the cgroup quota field must
    /// agree with the actual cgroup files (recorded when limited, gap when
    /// unbounded).
    #[test]
    fn affinity_and_quota_match_procfs_and_cgroup() {
        let mut collector = TopologyCollector::new();
        let topology = collector.sample();
        let status = std::fs::read_to_string("/proc/self/status").expect("proc status");
        let allowed = status
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
            .expect("cpus allowed list")
            .trim();
        let expected_count: u32 = allowed
            .split(',')
            .map(|part| {
                if let Some((start, end)) = part.split_once('-') {
                    end.parse::<u32>().expect("range end")
                        - start.parse::<u32>().expect("range start")
                        + 1
                } else {
                    1
                }
            })
            .sum();
        assert_eq!(
            topology.affinity_cpus.value,
            Evidence::recorded(expected_count)
        );
        assert_eq!(
            topology.affinity_cpus.source,
            HardwareFieldSourceV2::SystemCall
        );

        let quota_v2 = std::fs::read_to_string("/sys/fs/cgroup/cpu.max").ok();
        let quota_v1 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").ok();
        match (&quota_v2, &quota_v1) {
            (Some(contents), _) if !contents.starts_with("max") => {
                let mut fields = contents.split_whitespace();
                let quota: u64 = fields.next().expect("quota").parse().expect("quota value");
                let period: u64 = fields
                    .next()
                    .expect("period")
                    .parse()
                    .expect("period value");
                assert_eq!(
                    topology.cpu_quota_milli.value,
                    Evidence::recorded(quota * 1_000 / period)
                );
            }
            (None, Some(_)) | (None, None) | (Some(_), _) => {
                // Unbounded (v2 "max"), v1-unlimited, or no cgroup controller:
                // the field must be an explicit gap, never a fabricated limit.
                assert!(matches!(
                    topology.cpu_quota_milli.value,
                    Evidence::Unavailable { .. }
                ));
            }
        }
        assert_eq!(
            topology.cpu_quota_milli.source,
            HardwareFieldSourceV2::SysfsCgroup
        );
    }

    /// A session must sample CPU frequency through sysfs cpufreq with exact
    /// min/mean/max consistency whenever the host exposes scaling_cur_freq.
    #[test]
    fn session_samples_frequency_consistent_with_sysfs() {
        let profile = session("topology-frequency").finish(RunState::Completed);
        let evidence = match &profile.hardware {
            Evidence::Recorded { value } => value,
            other => panic!("hardware evidence must be recorded: {other:?}"),
        };
        let cpufreq_cpus = sysfs_cpu_indices()
            .into_iter()
            .filter(|cpu| {
                std::path::Path::new(&format!(
                    "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq"
                ))
                .exists()
            })
            .count() as u32;
        if cpufreq_cpus == 0 {
            assert!(evidence.utilization.frequency_samples.is_empty());
            assert!(matches!(
                evidence.utilization.frequency_availability,
                Evidence::Unavailable { .. }
            ));
            return;
        }
        assert_eq!(
            evidence.utilization.frequency_availability,
            Evidence::recorded(HardwareFieldSourceV2::SysfsCpu)
        );
        assert!(!evidence.utilization.frequency_samples.is_empty());
        for sample in &evidence.utilization.frequency_samples {
            assert!(sample.min_khz <= sample.mean_khz);
            assert!(sample.mean_khz <= sample.max_khz);
            assert!(sample.cpu_count > 0);
            assert!(sample.cpu_count <= cpufreq_cpus);
            assert!(sample.min_khz > 0);
        }
    }
}
