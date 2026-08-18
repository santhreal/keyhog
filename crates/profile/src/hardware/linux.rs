//! Linux hardware evidence: perf_event_open counters, procfs scheduler and
//! per-thread CPU reads, and sysfs topology, frequency, and cgroup limits.

use super::{
    CpuFrequencySampleV2, HardwareCounterSampleV2, HardwareFieldSourceV2, SchedulerSampleV2,
    SourcedEvidenceV2, SpanCounterReading, ThreadCpuV2, TopologyEvidenceV2,
    HARDWARE_EVIDENCE_V2_VERSION,
};
use crate::collector::{CollectorAvailability, CollectorCapability, CollectorId};
use crate::schema_v2::{Evidence, EvidenceGap};
use std::cell::RefCell;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};

pub(super) const COUNTER_SOURCE: HardwareFieldSourceV2 = HardwareFieldSourceV2::PerfEventOpen;
pub(super) const MEMORY_STALL_GAP: EvidenceGap = EvidenceGap::Unsupported;

const PERF_STATE_UNTRIED: u8 = 0;
const PERF_STATE_READY: u8 = 1;
const PERF_STATE_DENIED: u8 = 2;
const PERF_STATE_ABSENT: u8 = 3;

// perf_event_attr ABI (first 112 bytes, zero-padded to 128); stable since 2.6.31.
#[repr(C)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
    __reserved_3: [u64; 2],
}

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;
const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;

fn perf_event_open(attr: &PerfEventAttr) -> std::io::Result<OwnedFd> {
    // SAFETY: attr references a live PerfEventAttr; pid 0/cpu -1 scopes to the
    // calling thread, and the returned fd is wrapped exactly once.
    let fd = unsafe { libc::syscall(libc::SYS_perf_event_open, attr, 0, -1, -1, 0) } as RawFd;
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn open_counter(type_: u32, config: u64) -> std::io::Result<OwnedFd> {
    // SAFETY: PerfEventAttr is a POD C struct safely initialized with all zero bytes.
    let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
    attr.type_ = type_;
    attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
    attr.config = config;
    perf_event_open(&attr)
}

fn open_hardware_counter(config: u64) -> std::io::Result<OwnedFd> {
    open_counter(PERF_TYPE_HARDWARE, config)
}

fn open_software_counter(config: u64) -> std::io::Result<OwnedFd> {
    open_counter(PERF_TYPE_SOFTWARE, config)
}

static PERF_STATE: AtomicU8 = AtomicU8::new(PERF_STATE_UNTRIED);

fn read_counter(fd: RawFd) -> Option<u64> {
    let mut value = 0_u64;
    // SAFETY: value pointer is valid memory for size_of::<u64>() bytes.
    let read = unsafe {
        libc::pread(
            fd,
            std::ptr::addr_of_mut!(value).cast(),
            std::mem::size_of::<u64>(),
            0,
        )
    };
    (read == std::mem::size_of::<u64>() as isize).then_some(value)
}

fn perf_paranoid() -> Option<i64> {
    std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn perf_gap_detail() -> String {
    match perf_paranoid() {
        Some(level) => format!(
            "perf_event_open denied for per-thread counters: /proc/sys/kernel/perf_event_paranoid={level}; lower it to 2 or below, or grant CAP_PERFMON"
        ),
        None => "perf_event_open denied for per-thread counters".to_owned(),
    }
}

/// Probe perf once per process; the state machine never retries a denial.
fn perf_state() -> u8 {
    let state = PERF_STATE.load(Ordering::Relaxed);
    if state != PERF_STATE_UNTRIED {
        return state;
    }
    let probed = match open_hardware_counter(PERF_COUNT_HW_CPU_CYCLES) {
        Ok(_) => PERF_STATE_READY,
        Err(error) => match error.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => PERF_STATE_DENIED,
            Some(libc::ENOSYS) => PERF_STATE_ABSENT,
            _ => PERF_STATE_ABSENT,
        },
    };
    PERF_STATE.store(probed, Ordering::Relaxed);
    probed
}

fn counter_capability() -> CollectorCapability {
    match perf_state() {
        PERF_STATE_READY => CollectorCapability::available(CollectorId::HardwareCounters),
        PERF_STATE_DENIED => CollectorCapability::unavailable(
            CollectorId::HardwareCounters,
            CollectorAvailability::PermissionDenied,
            perf_gap_detail(),
        ),
        _ => CollectorCapability::unavailable(
            CollectorId::HardwareCounters,
            CollectorAvailability::Unavailable,
            "perf_event_open is not implemented by this kernel",
        ),
    }
}

pub(super) struct CounterState {
    cycles: Option<OwnedFd>,
    instructions: Option<OwnedFd>,
    cache_references: Option<OwnedFd>,
    cache_misses: Option<OwnedFd>,
    branch_instructions: Option<OwnedFd>,
    branch_misses: Option<OwnedFd>,
    stalled_frontend: Result<Option<OwnedFd>, EvidenceGap>,
    stalled_backend: Result<Option<OwnedFd>, EvidenceGap>,
}

pub(super) struct SchedulerState {
    migrations: Option<OwnedFd>,
}

pub(super) struct PlatformCollectors {
    pub counter_capability: CollectorCapability,
    pub scheduler_capability: CollectorCapability,
    pub utilization_capability: CollectorCapability,
    pub topology_capability: CollectorCapability,
    pub counters: CounterState,
    pub scheduler: SchedulerState,
}

fn unsupported_stall(reason: &'static str) -> Result<Option<OwnedFd>, EvidenceGap> {
    let _ = reason;
    Err(EvidenceGap::Unsupported)
}

fn open_stall(config: u64) -> Result<Option<OwnedFd>, EvidenceGap> {
    match open_hardware_counter(config) {
        Ok(fd) => Ok(Some(fd)),
        Err(error) => match error.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => {
                unsupported_stall("CPU exposes no generic stall counter")
            }
            _ => Err(EvidenceGap::Unavailable),
        },
    }
}

pub(super) fn platform_collectors() -> PlatformCollectors {
    let counter_capability = counter_capability();
    let available = counter_capability.availability == CollectorAvailability::Available;
    let open = |config: u64| {
        available
            .then(|| open_hardware_counter(config).ok())
            .flatten()
    };
    let counters = CounterState {
        cycles: open(PERF_COUNT_HW_CPU_CYCLES),
        instructions: open(PERF_COUNT_HW_INSTRUCTIONS),
        cache_references: open(PERF_COUNT_HW_CACHE_REFERENCES),
        cache_misses: open(PERF_COUNT_HW_CACHE_MISSES),
        branch_instructions: open(PERF_COUNT_HW_BRANCH_INSTRUCTIONS),
        branch_misses: open(PERF_COUNT_HW_BRANCH_MISSES),
        stalled_frontend: if available {
            open_stall(PERF_COUNT_HW_STALLED_CYCLES_FRONTEND)
        } else {
            Err(EvidenceGap::PermissionDenied)
        },
        stalled_backend: if available {
            open_stall(PERF_COUNT_HW_STALLED_CYCLES_BACKEND)
        } else {
            Err(EvidenceGap::PermissionDenied)
        },
    };
    let scheduler = SchedulerState {
        migrations: available
            .then(|| open_software_counter(PERF_COUNT_SW_CPU_MIGRATIONS).ok())
            .flatten(),
    };
    let scheduler_capability = if std::path::Path::new("/proc/thread-self/sched").exists() {
        CollectorCapability::available(CollectorId::SchedulerActivity)
    } else {
        CollectorCapability::unavailable(
            CollectorId::SchedulerActivity,
            CollectorAvailability::Unavailable,
            "/proc/thread-self/sched is not readable on this host",
        )
    };
    let utilization_capability = if std::path::Path::new("/proc/self/task").exists() {
        CollectorCapability::available(CollectorId::ThreadUtilization)
    } else {
        CollectorCapability::unavailable(
            CollectorId::ThreadUtilization,
            CollectorAvailability::Unavailable,
            "/proc/self/task is not readable on this host",
        )
    };
    let topology_capability = if std::path::Path::new("/sys/devices/system/cpu").exists() {
        CollectorCapability::available(CollectorId::CpuTopology)
    } else {
        CollectorCapability::unavailable(
            CollectorId::CpuTopology,
            CollectorAvailability::Unavailable,
            "sysfs CPU topology is not mounted on this host",
        )
    };
    PlatformCollectors {
        counter_capability,
        scheduler_capability,
        utilization_capability,
        topology_capability,
        counters,
        scheduler,
    }
}

fn perf_field(fd: &Option<OwnedFd>, denied_reason: EvidenceGap) -> SourcedEvidenceV2<u64> {
    match fd {
        Some(fd) => read_counter(fd.as_raw_fd())
            .map(|value| SourcedEvidenceV2::recorded(value, HardwareFieldSourceV2::PerfEventOpen))
            .unwrap_or_else(|| {
                SourcedEvidenceV2::gapped(
                    HardwareFieldSourceV2::PerfEventOpen,
                    EvidenceGap::Unavailable,
                )
            }),
        None => SourcedEvidenceV2::gapped(HardwareFieldSourceV2::PerfEventOpen, denied_reason),
    }
}

impl CounterState {
    fn perf_reason(&self) -> EvidenceGap {
        match perf_state() {
            PERF_STATE_DENIED => EvidenceGap::PermissionDenied,
            PERF_STATE_READY => EvidenceGap::Unavailable,
            _ => EvidenceGap::Unavailable,
        }
    }
}

pub(super) fn sample_counters(
    state: &mut CounterState,
    elapsed_ns: u64,
) -> HardwareCounterSampleV2 {
    let reason = state.perf_reason();
    let stall_field = |fd: &Result<Option<OwnedFd>, EvidenceGap>| -> SourcedEvidenceV2<u64> {
        match fd {
            Ok(Some(fd)) => read_counter(fd.as_raw_fd())
                .map(|value| {
                    SourcedEvidenceV2::recorded(value, HardwareFieldSourceV2::PerfEventOpen)
                })
                .unwrap_or_else(|| {
                    SourcedEvidenceV2::gapped(
                        HardwareFieldSourceV2::PerfEventOpen,
                        EvidenceGap::Unavailable,
                    )
                }),
            Ok(None) => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::PerfEventOpen,
                EvidenceGap::Unsupported,
            ),
            Err(gap_reason) => {
                SourcedEvidenceV2::gapped(HardwareFieldSourceV2::PerfEventOpen, *gap_reason)
            }
        }
    };
    HardwareCounterSampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        elapsed_ns,
        cycles: perf_field(&state.cycles, reason),
        instructions: perf_field(&state.instructions, reason),
        cache_references: perf_field(&state.cache_references, reason),
        cache_misses: perf_field(&state.cache_misses, reason),
        branch_instructions: perf_field(&state.branch_instructions, reason),
        branch_misses: perf_field(&state.branch_misses, reason),
        stalled_cycles_frontend: stall_field(&state.stalled_frontend),
        stalled_cycles_backend: stall_field(&state.stalled_backend),
        stalled_cycles_memory: SourcedEvidenceV2::gapped(
            HardwareFieldSourceV2::PerfEventOpen,
            EvidenceGap::Unsupported,
        ),
    }
}

fn parse_proc_sched() -> Option<(u64, u64)> {
    // thread-self scopes the read to the calling thread; /proc/self/sched
    // always names the main thread and misses worker-thread switches.
    let sched = std::fs::read_to_string("/proc/thread-self/sched").ok()?;
    let mut voluntary = None;
    let mut involuntary = None;
    for line in sched.lines() {
        if let Some(value) = line.strip_prefix("nr_voluntary_switches") {
            voluntary = value.split(':').nth(1)?.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("nr_involuntary_switches") {
            involuntary = value.split(':').nth(1)?.trim().parse().ok();
        }
    }
    Some((voluntary?, involuntary?))
}

fn parse_proc_schedstat() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").ok()?;
    let mut fields = stat.split_whitespace();
    let _runtime_ns: u64 = fields.next()?.parse().ok()?;
    let runqueue_delay_ns: u64 = fields.next()?.parse().ok()?;
    let timeslices: u64 = fields.next()?.parse().ok()?;
    Some((runqueue_delay_ns, timeslices))
}

pub(super) fn empty_scheduler_sample() -> SchedulerSampleV2 {
    sample_scheduler(&mut SchedulerState { migrations: None })
}

pub(super) fn sample_scheduler(state: &mut SchedulerState) -> SchedulerSampleV2 {
    let (voluntary, involuntary) = parse_proc_sched()
        .map(|(v, i)| {
            (
                SourcedEvidenceV2::recorded(v, HardwareFieldSourceV2::ProcSelfSched),
                SourcedEvidenceV2::recorded(i, HardwareFieldSourceV2::ProcSelfSched),
            )
        })
        .unwrap_or_else(|| {
            (
                SourcedEvidenceV2::gapped(
                    HardwareFieldSourceV2::ProcSelfSched,
                    EvidenceGap::Unavailable,
                ),
                SourcedEvidenceV2::gapped(
                    HardwareFieldSourceV2::ProcSelfSched,
                    EvidenceGap::Unavailable,
                ),
            )
        });
    let total = match (&voluntary.value, &involuntary.value) {
        (Evidence::Recorded { value: v }, Evidence::Recorded { value: i }) => {
            SourcedEvidenceV2::recorded(v.saturating_add(*i), HardwareFieldSourceV2::ProcSelfSched)
        }
        _ => SourcedEvidenceV2::gapped(
            HardwareFieldSourceV2::ProcSelfSched,
            EvidenceGap::Unavailable,
        ),
    };
    let migrations = match &state.migrations {
        Some(fd) => read_counter(fd.as_raw_fd())
            .map(|value| SourcedEvidenceV2::recorded(value, HardwareFieldSourceV2::PerfEventOpen))
            .unwrap_or_else(|| {
                SourcedEvidenceV2::gapped(
                    HardwareFieldSourceV2::PerfEventOpen,
                    EvidenceGap::Unavailable,
                )
            }),
        None => SourcedEvidenceV2::gapped(
            HardwareFieldSourceV2::PerfEventOpen,
            match perf_state() {
                PERF_STATE_DENIED => EvidenceGap::PermissionDenied,
                _ => EvidenceGap::Unavailable,
            },
        ),
    };
    let (runqueue_delay_ns, timeslices) = parse_proc_schedstat()
        .map(|(delay, slices)| {
            (
                SourcedEvidenceV2::recorded(delay, HardwareFieldSourceV2::ProcSelfSchedstat),
                SourcedEvidenceV2::recorded(slices, HardwareFieldSourceV2::ProcSelfSchedstat),
            )
        })
        .unwrap_or_else(|| {
            (
                SourcedEvidenceV2::gapped(
                    HardwareFieldSourceV2::ProcSelfSchedstat,
                    EvidenceGap::Unavailable,
                ),
                SourcedEvidenceV2::gapped(
                    HardwareFieldSourceV2::ProcSelfSchedstat,
                    EvidenceGap::Unavailable,
                ),
            )
        });
    SchedulerSampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        voluntary_context_switches: voluntary,
        involuntary_context_switches: involuntary,
        total_context_switches: total,
        cpu_migrations: migrations,
        runqueue_delay_ns,
        timeslices,
    }
}

fn clock_ticks_per_second() -> u64 {
    // SAFETY: sysconf reads a process constant and receives no pointer.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks).unwrap_or(100).max(1)
}

fn task_cpu_ns(tid: u64, ticks_per_second: u64) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    let command_end = stat.rfind(')')?;
    let mut fields = stat.get(command_end + 2..)?.split_whitespace();
    let user_ticks = fields.nth(11)?.parse::<u64>().ok()?;
    let system_ticks = fields.next()?.parse::<u64>().ok()?;
    Some(
        u64::try_from(
            (u128::from(user_ticks) + u128::from(system_ticks)) * 1_000_000_000
                / u128::from(ticks_per_second),
        )
        .unwrap_or(u64::MAX),
    )
}

pub(super) fn sample_thread_utilization() -> (Vec<ThreadCpuV2>, u64) {
    let ticks_per_second = clock_ticks_per_second();
    let mut threads = Vec::new();
    let mut dropped = 0_u64;
    let entries = match std::fs::read_dir("/proc/self/task") {
        Ok(entries) => entries,
        Err(_) => return (threads, 0),
    };
    for entry in entries.flatten() {
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<u64>() else {
            continue;
        };
        match task_cpu_ns(tid, ticks_per_second) {
            Some(cpu_time_ns) => threads.push(ThreadCpuV2 {
                version: HARDWARE_EVIDENCE_V2_VERSION,
                thread_id: tid,
                cpu_time_ns,
            }),
            None => dropped = dropped.saturating_add(1),
        }
    }
    threads.sort_unstable_by_key(|thread| thread.thread_id);
    (threads, dropped)
}

pub(super) fn sample_frequency(elapsed_ns: u64) -> Option<CpuFrequencySampleV2> {
    let mut minimum = u64::MAX;
    let mut maximum = 0_u64;
    let mut total = 0_u128;
    let mut count = 0_u32;
    for cpu in cpu_indices() {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq");
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(khz) = content.trim().parse::<u64>() else {
            continue;
        };
        minimum = minimum.min(khz);
        maximum = maximum.max(khz);
        total += u128::from(khz);
        count += 1;
    }
    (count > 0).then(|| CpuFrequencySampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        elapsed_ns,
        min_khz: minimum,
        max_khz: maximum,
        mean_khz: u64::try_from(total / u128::from(count)).unwrap_or(u64::MAX),
        cpu_count: count,
    })
}

pub(super) fn frequency_availability() -> Evidence<HardwareFieldSourceV2> {
    if cpu_indices().into_iter().any(|cpu| {
        std::path::Path::new(&format!(
            "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq"
        ))
        .exists()
    }) {
        Evidence::recorded(HardwareFieldSourceV2::SysfsCpu)
    } else {
        Evidence::unavailable(EvidenceGap::Unsupported)
    }
}

fn cpu_indices() -> Vec<u32> {
    let mut indices = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") else {
        return indices;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(index) = name
            .to_string_lossy()
            .strip_prefix("cpu")
            .and_then(|rest| rest.parse::<u32>().ok())
        else {
            continue;
        };
        indices.push(index);
    }
    indices.sort_unstable();
    indices
}

fn read_u32_file(path: &str) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn cgroup_quota_milli() -> Option<u64> {
    // cgroup v2: "MAX period" or "quota period" in microseconds.
    if let Ok(cpu_max) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        let mut fields = cpu_max.split_whitespace();
        let quota = fields.next()?;
        let period: u64 = fields.next()?.trim().parse().ok()?;
        if quota != "max" && period > 0 {
            let quota: u64 = quota.parse().ok()?;
            return Some(u64::try_from(u128::from(quota) * 1_000 / u128::from(period)).ok()?);
        }
        return None;
    }
    // cgroup v1: cfs quota over period in microseconds.
    let quota: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let period: u64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if quota <= 0 || period == 0 {
        return None;
    }
    u64::try_from(u128::from(quota as u64) * 1_000 / u128::from(period)).ok()
}

fn affinity_cpu_count() -> Option<u32> {
    // SAFETY: cpu_set_t is a POD C struct safely initialized with all zero bytes.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: set points to a valid zeroed cpu_set_t of the given size.
    let result =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if result != 0 {
        return None;
    }
    // SAFETY: set was fully initialized by the successful sched_getaffinity.
    Some(unsafe { libc::CPU_COUNT(&set) } as u32)
}

pub(super) fn capture_topology() -> TopologyEvidenceV2 {
    let cpus = cpu_indices();
    let logical_cpus = crate::host_parallelism::logical_cpus();
    let mut cores = std::collections::BTreeSet::new();
    let mut packages = std::collections::BTreeSet::new();
    let mut topology_readable = false;
    for cpu in &cpus {
        let base = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
        match (
            read_u32_file(&format!("{base}/physical_package_id")),
            read_u32_file(&format!("{base}/core_id")),
        ) {
            (Some(package), Some(core)) => {
                topology_readable = true;
                packages.insert(package);
                cores.insert((package, core));
            }
            _ => continue,
        }
    }
    let sourced_u32 = |value: Option<u32>| match value {
        Some(value) => SourcedEvidenceV2::recorded(value, HardwareFieldSourceV2::SysfsCpu),
        None => {
            SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SysfsCpu, EvidenceGap::Unavailable)
        }
    };
    let numa_nodes = std::fs::read_dir("/sys/devices/system/node")
        .ok()
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name.strip_prefix("node")
                        .is_some_and(|rest| rest.parse::<u32>().is_ok())
                })
                .count() as u32
        });
    TopologyEvidenceV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        logical_cpus,
        physical_cores: if topology_readable && !cores.is_empty() {
            sourced_u32(Some(cores.len() as u32))
        } else {
            sourced_u32(None)
        },
        packages: if topology_readable && !packages.is_empty() {
            sourced_u32(Some(packages.len() as u32))
        } else {
            sourced_u32(None)
        },
        numa_nodes: sourced_u32(numa_nodes.filter(|nodes| *nodes > 0)),
        affinity_cpus: match affinity_cpu_count() {
            Some(count) => SourcedEvidenceV2::recorded(count, HardwareFieldSourceV2::SystemCall),
            None => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::SystemCall,
                EvidenceGap::Unavailable,
            ),
        },
        cpu_quota_milli: match cgroup_quota_milli() {
            Some(quota) => SourcedEvidenceV2::recorded(quota, HardwareFieldSourceV2::SysfsCgroup),
            None => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::SysfsCgroup,
                EvidenceGap::Unavailable,
            ),
        },
    }
}

struct SpanCounterFds {
    cycles: OwnedFd,
    instructions: OwnedFd,
}

thread_local! {
    static SPAN_COUNTERS: RefCell<Option<SpanCounterFds>> = const { RefCell::new(None) };
}

fn with_span_fds<T>(read: impl FnOnce(&SpanCounterFds) -> T) -> Option<T> {
    SPAN_COUNTERS.with(|slot| slot.borrow().as_ref().map(read))
}

/// Per-thread lazy counter pair; denial is latched process-wide in PERF_STATE.
pub(crate) fn span_counter_reading() -> Option<SpanCounterReading> {
    if perf_state() != PERF_STATE_READY {
        return None;
    }
    if with_span_fds(|_| ()).is_none() {
        let cycles = open_hardware_counter(PERF_COUNT_HW_CPU_CYCLES).ok()?;
        let instructions = open_hardware_counter(PERF_COUNT_HW_INSTRUCTIONS).ok()?;
        SPAN_COUNTERS.with(|slot| {
            *slot.borrow_mut() = Some(SpanCounterFds {
                cycles,
                instructions,
            });
        });
    }
    with_span_fds(|fds| SpanCounterReading {
        cycles: read_counter(fds.cycles.as_raw_fd()),
        instructions: read_counter(fds.instructions.as_raw_fd()),
    })
}
