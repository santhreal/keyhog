//! macOS hardware evidence: thread CPU and task context switches through mach
//! task_info/thread_info; PMU counters have no public API and report gaps.

use super::{
    CpuFrequencySampleV2, HardwareCounterSampleV2, HardwareFieldSourceV2, SchedulerSampleV2,
    SourcedEvidenceV2, SpanCounterReading, ThreadCpuV2, TopologyEvidenceV2,
    HARDWARE_EVIDENCE_V2_VERSION,
};
use crate::collector::{CollectorAvailability, CollectorCapability, CollectorId};
use crate::schema_v2::{Evidence, EvidenceGap};
use std::ffi::{c_char, c_int, c_void};

pub(super) const COUNTER_SOURCE: HardwareFieldSourceV2 = HardwareFieldSourceV2::MacOsApi;
pub(super) const MEMORY_STALL_GAP: EvidenceGap = EvidenceGap::Unsupported;

const TASK_EVENTS_INFO: c_int = 2;
const TASK_EVENTS_INFO_COUNT: u32 = 8;
const THREAD_BASIC_INFO: c_int = 3;
const THREAD_BASIC_INFO_COUNT: u32 = 10;
const KERN_SUCCESS: c_int = 0;

type MachPort = u32;

extern "C" {
    fn mach_task_self() -> MachPort;
    fn task_info(task: MachPort, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
    fn task_threads(task: MachPort, threads: *mut *mut MachPort, count: *mut u32) -> c_int;
    fn thread_info(thread: MachPort, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
    fn vm_deallocate(task: MachPort, address: usize, size: usize) -> c_int;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> c_int;
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> c_int;
}

/// task_events_info layout: faults, pageins, cow_faults, messages_sent,
/// messages_received, syscalls_mach, syscalls_unix, csw.
fn task_context_switches() -> Option<u64> {
    let mut info: [c_int; TASK_EVENTS_INFO_COUNT as usize] = [0; TASK_EVENTS_INFO_COUNT as usize];
    let mut count = TASK_EVENTS_INFO_COUNT;
    // SAFETY: info has TASK_EVENTS_INFO_COUNT ints; task is the self port.
    let result = unsafe {
        task_info(
            mach_task_self(),
            TASK_EVENTS_INFO,
            info.as_mut_ptr(),
            &mut count,
        )
    };
    (result == KERN_SUCCESS).then(|| info[7] as u64)
}

/// thread_basic_info layout: user_time (2), system_time (2), cpu_usage,
/// policy, run_state, flags, suspend_count, sleep_time.
fn thread_cpu_ns(port: MachPort) -> Option<u64> {
    let mut info: [c_int; THREAD_BASIC_INFO_COUNT as usize] = [0; THREAD_BASIC_INFO_COUNT as usize];
    let mut count = THREAD_BASIC_INFO_COUNT;
    // SAFETY: info has THREAD_BASIC_INFO_COUNT ints; port names a live thread.
    let result = unsafe { thread_info(port, THREAD_BASIC_INFO, info.as_mut_ptr(), &mut count) };
    if result != KERN_SUCCESS {
        return None;
    }
    let user_ns = (info[0] as u64) * 1_000_000_000 + (info[1] as u64) * 1_000;
    let system_ns = (info[2] as u64) * 1_000_000_000 + (info[3] as u64) * 1_000;
    Some(user_ns.saturating_add(system_ns))
}

fn sysctl_u64(name: &'static [u8]) -> Option<u64> {
    let mut value = 0_u64;
    let mut size = std::mem::size_of::<u64>();
    // SAFETY: name is NUL-terminated static; value and size are live locals.
    let result = unsafe {
        sysctlbyname(
            name.as_ptr().cast(),
            std::ptr::addr_of_mut!(value).cast(),
            &mut size,
            std::ptr::null(),
            0,
        )
    };
    (result == 0).then_some(value)
}

fn unsupported(detail: &'static str, collector: CollectorId) -> CollectorCapability {
    CollectorCapability::unavailable(collector, CollectorAvailability::Unsupported, detail)
}

pub(super) struct CounterState;
pub(super) struct SchedulerState;

pub(super) struct PlatformCollectors {
    pub counter_capability: CollectorCapability,
    pub scheduler_capability: CollectorCapability,
    pub utilization_capability: CollectorCapability,
    pub topology_capability: CollectorCapability,
    pub counters: CounterState,
    pub scheduler: SchedulerState,
}

pub(super) fn platform_collectors() -> PlatformCollectors {
    PlatformCollectors {
        counter_capability: unsupported(
            "macOS exposes no public per-thread PMU counters; kpc is a private framework",
            CollectorId::HardwareCounters,
        ),
        scheduler_capability: if task_context_switches().is_some() {
            let mut capability = CollectorCapability::available(CollectorId::SchedulerActivity);
            capability.detail = Some(
                "total context switches via task_info(TASK_EVENTS_INFO); voluntary split, migrations, and runqueue delay are not exposed by macOS"
                    .to_owned(),
            );
            capability
        } else {
            CollectorCapability::unavailable(
                CollectorId::SchedulerActivity,
                CollectorAvailability::Unavailable,
                "task_info(TASK_EVENTS_INFO) failed for the current task",
            )
        },
        utilization_capability: CollectorCapability::available(CollectorId::ThreadUtilization),
        topology_capability: CollectorCapability::available(CollectorId::CpuTopology),
        counters: CounterState,
        scheduler: SchedulerState,
    }
}

fn pmu_gap() -> SourcedEvidenceV2<u64> {
    SourcedEvidenceV2::gapped(HardwareFieldSourceV2::MacOsApi, EvidenceGap::Unsupported)
}

pub(super) fn sample_counters(
    _state: &mut CounterState,
    elapsed_ns: u64,
) -> HardwareCounterSampleV2 {
    HardwareCounterSampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        elapsed_ns,
        cycles: pmu_gap(),
        instructions: pmu_gap(),
        cache_references: pmu_gap(),
        cache_misses: pmu_gap(),
        branch_instructions: pmu_gap(),
        branch_misses: pmu_gap(),
        stalled_cycles_frontend: pmu_gap(),
        stalled_cycles_backend: pmu_gap(),
        stalled_cycles_memory: pmu_gap(),
    }
}

pub(super) fn empty_scheduler_sample() -> SchedulerSampleV2 {
    sample_scheduler(&mut SchedulerState)
}

pub(super) fn sample_scheduler(_state: &mut SchedulerState) -> SchedulerSampleV2 {
    let mach_gap =
        || SourcedEvidenceV2::gapped(HardwareFieldSourceV2::MacOsApi, EvidenceGap::Unsupported);
    SchedulerSampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        voluntary_context_switches: mach_gap(),
        involuntary_context_switches: mach_gap(),
        total_context_switches: match task_context_switches() {
            Some(switches) => {
                SourcedEvidenceV2::recorded(switches, HardwareFieldSourceV2::MacOsApi)
            }
            None => {
                SourcedEvidenceV2::gapped(HardwareFieldSourceV2::MacOsApi, EvidenceGap::Unavailable)
            }
        },
        cpu_migrations: mach_gap(),
        runqueue_delay_ns: mach_gap(),
        timeslices: mach_gap(),
    }
}

pub(super) fn sample_thread_utilization() -> (Vec<ThreadCpuV2>, u64) {
    let mut threads = Vec::new();
    let mut dropped = 0_u64;
    let mut ports: *mut MachPort = std::ptr::null_mut();
    let mut count = 0_u32;
    // SAFETY: task is the self port; ports/count are live locals.
    let result = unsafe { task_threads(mach_task_self(), &mut ports, &mut count) };
    if result != KERN_SUCCESS || ports.is_null() {
        return (threads, dropped);
    }
    for index in 0..count as usize {
        // SAFETY: ports holds count valid mach port entries.
        let port = unsafe { *ports.add(index) };
        match thread_cpu_ns(port) {
            Some(cpu_time_ns) => threads.push(ThreadCpuV2 {
                version: HARDWARE_EVIDENCE_V2_VERSION,
                thread_id: u64::from(port),
                cpu_time_ns,
            }),
            None => dropped = dropped.saturating_add(1),
        }
        // task_threads returns owned send rights; vm_deallocate only frees the
        // array storage. Drop each port or repeated samples leak Mach rights.
        // SAFETY: port came from task_threads; deallocate regardless of
        // thread_info outcome.
        unsafe {
            mach_port_deallocate(mach_task_self(), port);
        }
    }
    // SAFETY: ports was allocated by task_threads with count entries.
    unsafe {
        vm_deallocate(
            mach_task_self(),
            ports as usize,
            count as usize * std::mem::size_of::<MachPort>(),
        );
    }
    threads.sort_unstable_by_key(|thread| thread.thread_id);
    (threads, dropped)
}

pub(super) fn sample_frequency(_elapsed_ns: u64) -> Option<CpuFrequencySampleV2> {
    None
}

pub(super) fn frequency_availability() -> Evidence<HardwareFieldSourceV2> {
    Evidence::unavailable(EvidenceGap::Unsupported)
}

pub(super) fn capture_topology() -> TopologyEvidenceV2 {
    let logical_cpus = sysctl_u64(b"hw.ncpu\0")
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .map(|count| count.get() as u32)
        })
        .unwrap_or(1);
    let sysctl_u32 = |name: &'static [u8]| {
        sysctl_u64(name)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
    };
    let sourced = |value: Option<u32>| match value {
        Some(value) => SourcedEvidenceV2::recorded(value, HardwareFieldSourceV2::MacOsApi),
        None => {
            SourcedEvidenceV2::gapped(HardwareFieldSourceV2::MacOsApi, EvidenceGap::Unsupported)
        }
    };
    TopologyEvidenceV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        logical_cpus,
        physical_cores: sourced(sysctl_u32(b"hw.physicalcpu\0")),
        packages: sourced(sysctl_u32(b"hw.packages\0")),
        numa_nodes: sourced(None),
        affinity_cpus: sourced(None),
        cpu_quota_milli: SourcedEvidenceV2::gapped(
            HardwareFieldSourceV2::MacOsApi,
            EvidenceGap::Unsupported,
        ),
    }
}

/// macOS exposes no public per-span cycle counter; spans stay hardware-free.
pub(crate) fn span_counter_reading() -> Option<SpanCounterReading> {
    None
}
