use crate::collector::{
    CollectorAvailability, CollectorCapability, CollectorId, SnapshotCollector,
};
use crate::schema::{
    ResourceSample, ResourceSnapshot, ResourceUsage, StateMeasurement, StateTransition,
};
use std::time::Duration;
#[cfg(all(feature = "process-metrics", not(target_os = "linux")))]
use sysinfo::{Pid, ProcessesToUpdate, System};

pub(crate) struct ProcessResourceCollector {
    capability: CollectorCapability,
    #[cfg(all(feature = "process-metrics", not(target_os = "linux")))]
    system: System,
    #[cfg(all(feature = "process-metrics", not(target_os = "linux")))]
    pid: Option<Pid>,
}

impl ProcessResourceCollector {
    pub(crate) fn new() -> Self {
        #[cfg(not(feature = "process-metrics"))]
        {
            Self {
                capability: CollectorCapability::unavailable(
                    CollectorId::ProcessResources,
                    CollectorAvailability::Disabled,
                    "enable the keyhog-profile process-metrics feature",
                ),
            }
        }
        #[cfg(all(feature = "process-metrics", target_os = "linux"))]
        {
            Self {
                capability: linux_process_resource_capability(),
            }
        }
        #[cfg(all(feature = "process-metrics", not(target_os = "linux")))]
        {
            let pid = sysinfo::get_current_pid().ok();
            let capability = if pid.is_some() {
                CollectorCapability::available(CollectorId::ProcessResources)
            } else {
                CollectorCapability::unavailable(
                    CollectorId::ProcessResources,
                    CollectorAvailability::Unavailable,
                    "the current process identity is unavailable",
                )
            };
            Self {
                capability,
                system: System::new(),
                pid,
            }
        }
    }
}

impl SnapshotCollector for ProcessResourceCollector {
    type Snapshot = ResourceSnapshot;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        #[cfg(not(feature = "process-metrics"))]
        {
            ResourceSnapshot::default()
        }
        #[cfg(all(feature = "process-metrics", target_os = "linux"))]
        {
            linux_process_resources()
        }
        #[cfg(all(feature = "process-metrics", not(target_os = "linux")))]
        {
            let Some(pid) = self.pid else {
                return ResourceSnapshot::default();
            };
            let pids = [pid];
            self.system
                .refresh_processes(ProcessesToUpdate::Some(&pids), true);
            let Some(process) = self.system.process(pid) else {
                return ResourceSnapshot::default();
            };
            ResourceSnapshot {
                version: crate::schema::RESOURCE_SNAPSHOT_VERSION,
                cpu_time_ms: Some(process.accumulated_cpu_time()),
                resident_bytes: Some(process.memory()),
                virtual_bytes: Some(process.virtual_memory()),
                thread_count: process.tasks().map(|tasks| tasks.len() as u64),
                resident_high_water_bytes: None,
                swap_bytes: None,
            }
        }
    }
}

#[cfg(all(feature = "process-metrics", target_os = "linux"))]
fn linux_process_resource_capability() -> CollectorCapability {
    for path in ["/proc/self/status", "/proc/self/stat"] {
        if let Err(error) = std::fs::File::open(path) {
            let availability = if error.kind() == std::io::ErrorKind::PermissionDenied {
                CollectorAvailability::PermissionDenied
            } else {
                CollectorAvailability::Unavailable
            };
            return CollectorCapability::unavailable(
                CollectorId::ProcessResources,
                availability,
                "Linux process metrics require readable /proc/self/status and /proc/self/stat",
            );
        }
    }
    CollectorCapability::available(CollectorId::ProcessResources)
}

#[cfg(all(feature = "process-metrics", target_os = "linux"))]
fn linux_process_resources() -> ResourceSnapshot {
    fn status_value(status: &str, field: &str, scale: u64) -> Option<u64> {
        status.lines().find_map(|line| {
            let value = line.strip_prefix(field)?.split_whitespace().next()?;
            value.parse::<u64>().ok()?.checked_mul(scale)
        })
    }

    fn cpu_time_ms() -> Option<u64> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let command_end = stat.rfind(')')?;
        let mut fields = stat.get(command_end + 2..)?.split_whitespace();
        let user_ticks = fields.nth(11)?.parse::<u64>().ok()?;
        let system_ticks = fields.next()?.parse::<u64>().ok()?;
        // SAFETY: sysconf reads a process constant and receives no pointer.
        let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks_per_second <= 0 {
            return None;
        }
        let milliseconds =
            (u128::from(user_ticks) + u128::from(system_ticks)) * 1_000 / ticks_per_second as u128;
        u64::try_from(milliseconds).ok()
    }

    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    ResourceSnapshot {
        version: crate::schema::RESOURCE_SNAPSHOT_VERSION,
        cpu_time_ms: cpu_time_ms(),
        resident_bytes: status_value(&status, "VmRSS:", 1024),
        virtual_bytes: status_value(&status, "VmSize:", 1024),
        thread_count: status_value(&status, "Threads:", 1),
        resident_high_water_bytes: status_value(&status, "VmHWM:", 1024),
        swap_bytes: status_value(&status, "VmSwap:", 1024),
    }
}

fn max_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

fn cpu_percent(
    start_cpu_ms: Option<u64>,
    finish_cpu_ms: Option<u64>,
    elapsed_ns: u64,
) -> Option<f64> {
    start_cpu_ms
        .zip(finish_cpu_ms)
        .filter(|(start, finish)| finish >= start)
        .and_then(|(start, finish)| {
            let wall_ms = elapsed_ns as f64 / 1_000_000.0;
            (wall_ms > 0.0).then_some((finish - start) as f64 * 100.0 / wall_ms)
        })
}

fn cpu_milli_percent(
    start_cpu_ms: Option<u64>,
    finish_cpu_ms: Option<u64>,
    elapsed_ns: u64,
) -> Option<u64> {
    if elapsed_ns == 0 {
        return None;
    }
    let (start, finish) = start_cpu_ms
        .zip(finish_cpu_ms)
        .filter(|(start, finish)| finish >= start)?;
    let numerator = u128::from(finish - start) * 100_000_000_000_u128;
    Some(u64::try_from(numerator / u128::from(elapsed_ns)).unwrap_or(u64::MAX))
}

pub(crate) fn resource_usage(
    start: ResourceSnapshot,
    finish: ResourceSnapshot,
    wall: Duration,
    samples: &[ResourceSample],
) -> ResourceUsage {
    let aggregate_cpu_percent = cpu_percent(
        start.cpu_time_ms,
        finish.cpu_time_ms,
        u64::try_from(wall.as_nanos()).unwrap_or(u64::MAX),
    );
    let max_observed_resident_bytes = samples
        .iter()
        .filter_map(|sample| sample.snapshot.resident_bytes)
        .fold(
            max_option(start.resident_bytes, finish.resident_bytes),
            |maximum, value| max_option(maximum, Some(value)),
        );
    let max_observed_threads = samples
        .iter()
        .filter_map(|sample| sample.snapshot.thread_count)
        .fold(
            max_option(start.thread_count, finish.thread_count),
            |maximum, value| max_option(maximum, Some(value)),
        );
    ResourceUsage {
        version: crate::schema::RESOURCE_USAGE_VERSION,
        max_observed_resident_bytes,
        max_observed_threads,
        start,
        finish,
        aggregate_cpu_percent,
    }
}

pub(crate) fn state_measurements(
    transitions: &[StateTransition],
    samples: &[ResourceSample],
) -> Vec<StateMeasurement> {
    transitions
        .windows(2)
        .zip(samples.windows(2))
        .filter_map(|(transition, sample)| {
            let elapsed_ns = transition[1]
                .elapsed_ns
                .checked_sub(transition[0].elapsed_ns)?;
            let start = sample[0].snapshot;
            let finish = sample[1].snapshot;
            let cpu_time_ms = start
                .cpu_time_ms
                .zip(finish.cpu_time_ms)
                .filter(|(start, finish)| finish >= start)
                .map(|(start, finish)| finish - start);
            Some(StateMeasurement {
                version: crate::schema::STATE_MEASUREMENT_VERSION,
                state: transition[0].state,
                elapsed_ns,
                cpu_time_ms,
                aggregate_cpu_milli_percent: cpu_milli_percent(
                    start.cpu_time_ms,
                    finish.cpu_time_ms,
                    elapsed_ns,
                ),
                resident_start_bytes: start.resident_bytes,
                resident_end_bytes: finish.resident_bytes,
                threads_start: start.thread_count,
                threads_end: finish.thread_count,
            })
        })
        .collect()
}
