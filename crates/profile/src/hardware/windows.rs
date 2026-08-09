//! Windows hardware evidence: cycle time and thread CPU through process APIs,
//! with explicit capability gaps for everything Windows does not expose.

use super::{
    CpuFrequencySampleV2, HardwareCounterSampleV2, HardwareFieldSourceV2, SchedulerSampleV2,
    SourcedEvidenceV2, SpanCounterReading, ThreadCpuV2, TopologyEvidenceV2,
    HARDWARE_EVIDENCE_V2_VERSION,
};
use crate::collector::{CollectorAvailability, CollectorCapability, CollectorId};
use crate::schema_v2::{Evidence, EvidenceGap};

pub(super) const COUNTER_SOURCE: HardwareFieldSourceV2 = HardwareFieldSourceV2::WindowsApi;
pub(super) const MEMORY_STALL_GAP: EvidenceGap = EvidenceGap::Unsupported;

#[allow(non_snake_case)]
#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

impl FileTime {
    fn as_u64(&self) -> u64 {
        (u64::from(self.high) << 32) | u64::from(self.low)
    }
}

#[allow(non_snake_case)]
#[repr(C)]
struct SystemInfo {
    oem_id: u32,
    page_size: u32,
    minimum_application_address: usize,
    maximum_application_address: usize,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

#[allow(non_snake_case)]
#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

type Handle = usize;

const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const INVALID_HANDLE: Handle = usize::MAX;

extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> Handle;
    fn GetProcessTimes(
        process: Handle,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn GetThreadTimes(
        thread: Handle,
        creation: *mut FileTime,
        exit: *mut FileTime,
        kernel: *mut FileTime,
        user: *mut FileTime,
    ) -> i32;
    fn QueryThreadCycleTime(thread: Handle, cycles: *mut u64) -> i32;
    fn GetSystemInfo(info: *mut SystemInfo);
    fn GetNumaHighestNodeNumber(highest: *mut u32) -> i32;
    fn GetProcessAffinityMask(
        process: Handle,
        process_mask: *mut usize,
        system_mask: *mut usize,
    ) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
}

fn thread_cycle_time() -> Option<u64> {
    let mut cycles = 0_u64;
    // SAFETY: GetCurrentThread returns a pseudo-handle; cycles is valid memory.
    let ok = unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut cycles) };
    (ok != 0).then_some(cycles)
}

fn process_cpu_ns() -> Option<u64> {
    let mut creation = FileTime { low: 0, high: 0 };
    let mut exit = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    // SAFETY: all output pointers reference live stack values.
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    // FILETIME ticks are 100 ns.
    (ok != 0).then(|| kernel.as_u64().saturating_add(user.as_u64()) * 100)
}

fn thread_ids() -> Vec<u32> {
    let mut ids = Vec::new();
    // SAFETY: snapshot of all threads; entries are valid while the handle lives.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == 0 || snapshot == INVALID_HANDLE {
        return ids;
    }
    let owner = unsafe { GetCurrentProcessId() };
    let mut entry = ThreadEntry32 {
        size: std::mem::size_of::<ThreadEntry32>() as u32,
        usage: 0,
        thread_id: 0,
        owner_process_id: 0,
        base_priority: 0,
        delta_priority: 0,
        flags: 0,
    };
    let mut ok = unsafe { Thread32First(snapshot, &mut entry) };
    while ok != 0 {
        if entry.owner_process_id == owner {
            ids.push(entry.thread_id);
        }
        ok = unsafe { Thread32Next(snapshot, &mut entry) };
    }
    unsafe {
        CloseHandle(snapshot);
    }
    ids
}

fn thread_cpu_ns(thread_id: u32) -> Option<u64> {
    // SAFETY: OpenThread borrows no memory; the handle is closed below.
    let handle = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, thread_id) };
    if handle == 0 {
        return None;
    }
    let mut creation = FileTime { low: 0, high: 0 };
    let mut exit = FileTime { low: 0, high: 0 };
    let mut kernel = FileTime { low: 0, high: 0 };
    let mut user = FileTime { low: 0, high: 0 };
    let ok = unsafe { GetThreadTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    unsafe {
        CloseHandle(handle);
    }
    (ok != 0).then(|| kernel.as_u64().saturating_add(user.as_u64()) * 100)
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
    let counter_capability = if thread_cycle_time().is_some() {
        let mut capability = CollectorCapability::available(CollectorId::HardwareCounters);
        capability.detail = Some(
            "cycles via QueryThreadCycleTime; instructions, cache, and branch counters require a PMU driver and are reported Unsupported per field"
                .to_owned(),
        );
        capability
    } else {
        CollectorCapability::unavailable(
            CollectorId::HardwareCounters,
            CollectorAvailability::Unavailable,
            "QueryThreadCycleTime failed for the current thread",
        )
    };
    PlatformCollectors {
        counter_capability,
        scheduler_capability: unsupported(
            "Windows per-process context-switch, migration, and runqueue-delay counts require ETW kernel tracing; process APIs do not expose them",
            CollectorId::SchedulerActivity,
        ),
        utilization_capability: CollectorCapability::available(CollectorId::ThreadUtilization),
        topology_capability: CollectorCapability::available(CollectorId::CpuTopology),
        counters: CounterState,
        scheduler: SchedulerState,
    }
}

fn pmu_gap() -> SourcedEvidenceV2<u64> {
    SourcedEvidenceV2::gapped(HardwareFieldSourceV2::WindowsApi, EvidenceGap::Unsupported)
}

pub(super) fn sample_counters(
    _state: &mut CounterState,
    elapsed_ns: u64,
) -> HardwareCounterSampleV2 {
    HardwareCounterSampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        elapsed_ns,
        cycles: match thread_cycle_time() {
            Some(cycles) => SourcedEvidenceV2::recorded(cycles, HardwareFieldSourceV2::WindowsApi),
            None => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::WindowsApi,
                EvidenceGap::Unavailable,
            ),
        },
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
    let etw_gap =
        || SourcedEvidenceV2::gapped(HardwareFieldSourceV2::WindowsApi, EvidenceGap::Unsupported);
    SchedulerSampleV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        voluntary_context_switches: etw_gap(),
        involuntary_context_switches: etw_gap(),
        total_context_switches: etw_gap(),
        cpu_migrations: etw_gap(),
        runqueue_delay_ns: etw_gap(),
        timeslices: etw_gap(),
    }
}

pub(super) fn sample_thread_utilization() -> (Vec<ThreadCpuV2>, u64) {
    let mut threads = Vec::new();
    let mut dropped = 0_u64;
    for tid in thread_ids() {
        match thread_cpu_ns(tid) {
            Some(cpu_time_ns) => threads.push(ThreadCpuV2 {
                version: HARDWARE_EVIDENCE_V2_VERSION,
                thread_id: u64::from(tid),
                cpu_time_ns,
            }),
            None => dropped = dropped.saturating_add(1),
        }
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
    let mut info: SystemInfo = unsafe { std::mem::zeroed() };
    // SAFETY: info references a live stack value of the right size.
    unsafe { GetSystemInfo(&mut info) };
    let logical_cpus = info.number_of_processors.max(1);
    let numa_nodes = {
        let mut highest = 0_u32;
        // SAFETY: highest references a live stack value.
        let ok = unsafe { GetNumaHighestNodeNumber(&mut highest) };
        (ok != 0).then_some(highest.saturating_add(1))
    };
    let affinity = {
        let mut process_mask = 0_usize;
        let mut system_mask = 0_usize;
        // SAFETY: both masks reference live stack values.
        let ok = unsafe {
            GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask)
        };
        (ok != 0).then(|| process_mask.count_ones())
    };
    let processor_info_gap =
        || SourcedEvidenceV2::gapped(HardwareFieldSourceV2::WindowsApi, EvidenceGap::Unsupported);
    TopologyEvidenceV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        logical_cpus,
        physical_cores: processor_info_gap(),
        packages: processor_info_gap(),
        numa_nodes: match numa_nodes {
            Some(nodes) => SourcedEvidenceV2::recorded(nodes, HardwareFieldSourceV2::WindowsApi),
            None => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::WindowsApi,
                EvidenceGap::Unavailable,
            ),
        },
        affinity_cpus: match affinity {
            Some(count) => SourcedEvidenceV2::recorded(count, HardwareFieldSourceV2::WindowsApi),
            None => SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::WindowsApi,
                EvidenceGap::Unavailable,
            ),
        },
        cpu_quota_milli: SourcedEvidenceV2::gapped(
            HardwareFieldSourceV2::WindowsApi,
            EvidenceGap::Unsupported,
        ),
    }
}

/// Per-span cycle readings through QueryThreadCycleTime; instructions stay a gap.
pub(crate) fn span_counter_reading() -> Option<SpanCounterReading> {
    Some(SpanCounterReading {
        cycles: thread_cycle_time(),
        instructions: None,
    })
}

/// Process CPU time in nanoseconds, used by session-level utilization checks.
#[allow(dead_code)]
pub(crate) fn process_cpu_time_ns() -> Option<u64> {
    process_cpu_ns()
}
