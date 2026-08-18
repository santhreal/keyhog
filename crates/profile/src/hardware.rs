//! CPU hardware evidence: perf counters, scheduler activity, per-thread
//! utilization, and CPU topology, each with explicit capability gaps.
//!
//! Every collector follows the [`SnapshotCollector`] + [`CollectorCapability`]
//! pattern. A field that cannot be measured on this host records an
//! [`Evidence`] gap with its attempted [`HardwareFieldSourceV2`]; nothing is
//! fabricated. The span hot path stores only raw `u64` counter readings in
//! fixed slots; all joins and ratios run cold at drain time.

use crate::collector::{CollectorAvailability, CollectorCapability, SnapshotCollector};
use crate::schema_v2::{Evidence, EvidenceGap, SpanRecordV2};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "hardware-counters", target_os = "linux"))]
mod linux;
#[cfg(all(feature = "hardware-counters", target_os = "macos"))]
mod macos;
#[cfg(all(feature = "hardware-counters", windows))]
mod windows;

#[cfg(all(feature = "hardware-counters", target_os = "linux"))]
use linux as platform;
#[cfg(all(feature = "hardware-counters", target_os = "macos"))]
use macos as platform;
#[cfg(any(
    not(feature = "hardware-counters"),
    all(
        feature = "hardware-counters",
        not(any(target_os = "linux", target_os = "macos", windows))
    )
))]
use stubs as platform;
#[cfg(all(feature = "hardware-counters", windows))]
use windows as platform;

pub const HARDWARE_EVIDENCE_V2_VERSION: u16 = 1;
pub const SPAN_HARDWARE_V2_VERSION: u16 = 1;
/// Maximum retained utilization samples per session; excess is counted, never stored.
pub const MAX_UTILIZATION_SAMPLES: usize = 256;
/// Maximum retained threads per utilization sample; excess is counted.
pub const MAX_SAMPLE_THREADS: usize = 1024;

fn gap<T>(reason: EvidenceGap) -> Evidence<T> {
    Evidence::unavailable(reason)
}

const fn legacy_component_version() -> u16 {
    1
}

/// Exact host facility that produced (or was asked for) one hardware field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareFieldSourceV2 {
    PerfEventOpen,
    ProcSelfSched,
    ProcSelfSchedstat,
    ProcSelfTaskStat,
    ProcSelfStatus,
    ProcSelfStat,
    ProcSelfIo,
    ProcPressure,
    SysfsCpu,
    SysfsCgroup,
    SysfsThermal,
    SystemCall,
    WindowsApi,
    MacOsApi,
}

/// One measured field plus the facility that produced or was asked for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourcedEvidenceV2<T> {
    pub value: Evidence<T>,
    pub source: HardwareFieldSourceV2,
}

impl<T> SourcedEvidenceV2<T> {
    pub fn recorded(value: T, source: HardwareFieldSourceV2) -> Self {
        Self {
            value: Evidence::recorded(value),
            source,
        }
    }

    pub const fn gapped(source: HardwareFieldSourceV2, reason: EvidenceGap) -> Self {
        Self {
            value: Evidence::unavailable(reason),
            source,
        }
    }
}

pub(crate) fn sourced_delta(
    end: &SourcedEvidenceV2<u64>,
    start: &SourcedEvidenceV2<u64>,
) -> SourcedEvidenceV2<u64> {
    match (&end.value, &start.value) {
        (Evidence::Recorded { value: end_value }, Evidence::Recorded { value: start_value }) => {
            SourcedEvidenceV2::recorded(end_value.saturating_sub(*start_value), end.source)
        }
        (Evidence::Unavailable { reason }, _) => SourcedEvidenceV2::gapped(end.source, *reason),
        (_, Evidence::Unavailable { reason }) => SourcedEvidenceV2::gapped(end.source, *reason),
    }
}

/// Exact integer ratio in thousandths; `None` when the denominator is zero.
pub fn milli_ratio(numerator: u64, denominator: u64) -> Option<u64> {
    if denominator == 0 {
        return None;
    }
    Some(u64::try_from(u128::from(numerator) * 1_000 / u128::from(denominator)).unwrap_or(u64::MAX))
}

fn milli_ratio_evidence(numerator: &Evidence<u64>, denominator: &Evidence<u64>) -> Evidence<u64> {
    match (numerator, denominator) {
        (Evidence::Recorded { value: top }, Evidence::Recorded { value: bottom }) => {
            milli_ratio(*top, *bottom)
                .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded)
        }
        (Evidence::Unavailable { reason }, _) => gap(*reason),
        (_, Evidence::Unavailable { reason }) => gap(*reason),
    }
}

/// Raw per-span cycle and instruction readings attached at span begin and end.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpanHardwareV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub cycles_begin: Evidence<u64>,
    pub cycles_end: Evidence<u64>,
    pub instructions_begin: Evidence<u64>,
    pub instructions_end: Evidence<u64>,
}

impl SpanHardwareV2 {
    /// Retired cycles inside this span, including nested children.
    pub fn cycles(&self) -> Evidence<u64> {
        match (&self.cycles_end, &self.cycles_begin) {
            (Evidence::Recorded { value: end }, Evidence::Recorded { value: begin }) => {
                Evidence::recorded(end.saturating_sub(*begin))
            }
            (Evidence::Unavailable { reason }, _) => gap(*reason),
            (_, Evidence::Unavailable { reason }) => gap(*reason),
        }
    }

    /// Retired instructions inside this span, including nested children.
    pub fn instructions(&self) -> Evidence<u64> {
        match (&self.instructions_end, &self.instructions_begin) {
            (Evidence::Recorded { value: end }, Evidence::Recorded { value: begin }) => {
                Evidence::recorded(end.saturating_sub(*begin))
            }
            (Evidence::Unavailable { reason }, _) => gap(*reason),
            (_, Evidence::Unavailable { reason }) => gap(*reason),
        }
    }

    /// Cycles per instruction in thousandths for this span.
    pub fn cpi_milli(&self) -> Evidence<u64> {
        milli_ratio_evidence(&self.cycles(), &self.instructions())
    }
}

/// One absolute hardware-counter reading taken by [`HardwareCounterCollector`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HardwareCounterSampleV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub elapsed_ns: u64,
    pub cycles: SourcedEvidenceV2<u64>,
    pub instructions: SourcedEvidenceV2<u64>,
    pub cache_references: SourcedEvidenceV2<u64>,
    pub cache_misses: SourcedEvidenceV2<u64>,
    pub branch_instructions: SourcedEvidenceV2<u64>,
    pub branch_misses: SourcedEvidenceV2<u64>,
    pub stalled_cycles_frontend: SourcedEvidenceV2<u64>,
    pub stalled_cycles_backend: SourcedEvidenceV2<u64>,
    pub stalled_cycles_memory: SourcedEvidenceV2<u64>,
}

/// Counter deltas and derived ratios across one run (session-thread scope).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HardwareCounterSetV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub cycles: SourcedEvidenceV2<u64>,
    pub instructions: SourcedEvidenceV2<u64>,
    pub cache_references: SourcedEvidenceV2<u64>,
    pub cache_misses: SourcedEvidenceV2<u64>,
    pub branch_instructions: SourcedEvidenceV2<u64>,
    pub branch_misses: SourcedEvidenceV2<u64>,
    pub stalled_cycles_frontend: SourcedEvidenceV2<u64>,
    pub stalled_cycles_backend: SourcedEvidenceV2<u64>,
    pub stalled_cycles_memory: SourcedEvidenceV2<u64>,
    /// Cycles per instruction in thousandths.
    pub cpi_milli: Evidence<u64>,
    /// Cache misses per reference in thousandths.
    pub cache_miss_ratio_milli: Evidence<u64>,
    /// Branch mispredictions per branch instruction in thousandths.
    pub branch_miss_ratio_milli: Evidence<u64>,
}

impl HardwareCounterSetV2 {
    /// Delta between two absolute samples; gaps propagate from either side.
    pub fn between(start: &HardwareCounterSampleV2, end: &HardwareCounterSampleV2) -> Self {
        let counters = Self {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            cycles: sourced_delta(&end.cycles, &start.cycles),
            instructions: sourced_delta(&end.instructions, &start.instructions),
            cache_references: sourced_delta(&end.cache_references, &start.cache_references),
            cache_misses: sourced_delta(&end.cache_misses, &start.cache_misses),
            branch_instructions: sourced_delta(
                &end.branch_instructions,
                &start.branch_instructions,
            ),
            branch_misses: sourced_delta(&end.branch_misses, &start.branch_misses),
            stalled_cycles_frontend: sourced_delta(
                &end.stalled_cycles_frontend,
                &start.stalled_cycles_frontend,
            ),
            stalled_cycles_backend: sourced_delta(
                &end.stalled_cycles_backend,
                &start.stalled_cycles_backend,
            ),
            stalled_cycles_memory: sourced_delta(
                &end.stalled_cycles_memory,
                &start.stalled_cycles_memory,
            ),
            cpi_milli: gap(EvidenceGap::Unavailable),
            cache_miss_ratio_milli: gap(EvidenceGap::Unavailable),
            branch_miss_ratio_milli: gap(EvidenceGap::Unavailable),
        };
        Self {
            cpi_milli: milli_ratio_evidence(&counters.cycles.value, &counters.instructions.value),
            cache_miss_ratio_milli: milli_ratio_evidence(
                &counters.cache_misses.value,
                &counters.cache_references.value,
            ),
            branch_miss_ratio_milli: milli_ratio_evidence(
                &counters.branch_misses.value,
                &counters.branch_instructions.value,
            ),
            ..counters
        }
    }

    fn all_gapped(reason: EvidenceGap) -> Self {
        let source = platform::COUNTER_SOURCE;
        Self {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            cycles: SourcedEvidenceV2::gapped(source, reason),
            instructions: SourcedEvidenceV2::gapped(source, reason),
            cache_references: SourcedEvidenceV2::gapped(source, reason),
            cache_misses: SourcedEvidenceV2::gapped(source, reason),
            branch_instructions: SourcedEvidenceV2::gapped(source, reason),
            branch_misses: SourcedEvidenceV2::gapped(source, reason),
            stalled_cycles_frontend: SourcedEvidenceV2::gapped(source, reason),
            stalled_cycles_backend: SourcedEvidenceV2::gapped(source, reason),
            stalled_cycles_memory: SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::PerfEventOpen,
                memory_stall_gap(),
            ),
            cpi_milli: gap(reason),
            cache_miss_ratio_milli: gap(reason),
            branch_miss_ratio_milli: gap(reason),
        }
    }
}

fn memory_stall_gap() -> EvidenceGap {
    platform::MEMORY_STALL_GAP
}

/// One absolute scheduler-activity reading from procfs and perf software events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchedulerSampleV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub voluntary_context_switches: SourcedEvidenceV2<u64>,
    pub involuntary_context_switches: SourcedEvidenceV2<u64>,
    pub total_context_switches: SourcedEvidenceV2<u64>,
    pub cpu_migrations: SourcedEvidenceV2<u64>,
    pub runqueue_delay_ns: SourcedEvidenceV2<u64>,
    pub timeslices: SourcedEvidenceV2<u64>,
}

/// Scheduler activity deltas across one run with an explicit source per field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchedulerEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub voluntary_context_switches: SourcedEvidenceV2<u64>,
    pub involuntary_context_switches: SourcedEvidenceV2<u64>,
    pub total_context_switches: SourcedEvidenceV2<u64>,
    pub cpu_migrations: SourcedEvidenceV2<u64>,
    pub scheduler_delay_ns: SourcedEvidenceV2<u64>,
    pub timeslices: SourcedEvidenceV2<u64>,
}

impl SchedulerEvidenceV2 {
    /// Delta between two absolute scheduler samples; gaps propagate.
    pub fn between(start: &SchedulerSampleV2, end: &SchedulerSampleV2) -> Self {
        Self {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            voluntary_context_switches: sourced_delta(
                &end.voluntary_context_switches,
                &start.voluntary_context_switches,
            ),
            involuntary_context_switches: sourced_delta(
                &end.involuntary_context_switches,
                &start.involuntary_context_switches,
            ),
            total_context_switches: sourced_delta(
                &end.total_context_switches,
                &start.total_context_switches,
            ),
            cpu_migrations: sourced_delta(&end.cpu_migrations, &start.cpu_migrations),
            scheduler_delay_ns: sourced_delta(&end.runqueue_delay_ns, &start.runqueue_delay_ns),
            timeslices: sourced_delta(&end.timeslices, &start.timeslices),
        }
    }
}

/// One thread's cumulative CPU consumption at a sample instant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadCpuV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    /// Operating-system thread identity (Linux tid, Windows tid, mach port).
    pub thread_id: u64,
    pub cpu_time_ns: u64,
}

/// Per-thread CPU census at one instant, bounded with explicit loss.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadUtilizationSampleV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub elapsed_ns: u64,
    pub threads: Vec<ThreadCpuV2>,
    pub dropped_threads: u64,
}

/// Per-thread CPU consumption and utilization across one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadUtilizationV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub thread_id: u64,
    pub cpu_time_ns: u64,
    /// Share of wall time this thread ran, in thousandths of one CPU.
    pub utilization_milli: Evidence<u64>,
}

/// Aggregate CPU frequency across all CPUs at one sample instant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CpuFrequencySampleV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub elapsed_ns: u64,
    pub min_khz: u64,
    pub max_khz: u64,
    pub mean_khz: u64,
    pub cpu_count: u32,
}

/// Per-thread utilization, effective parallelism, and frequency series.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UtilizationEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub wall_ns: u64,
    pub logical_cpus: u32,
    /// Sum of per-thread CPU deltas for threads alive at both session ends.
    pub total_thread_cpu_ns: u64,
    /// Average concurrent CPUs: total thread CPU over wall time, in thousandths.
    pub effective_parallelism_milli: Evidence<u64>,
    /// Total thread CPU over wall CPU capacity (wall times logical CPUs), in thousandths.
    pub capacity_utilization_milli: Evidence<u64>,
    pub threads: Vec<ThreadUtilizationV2>,
    /// Threads present at session start but gone at finish; their CPU is excluded.
    pub exited_threads: u64,
    /// Threads created after the first sample; only their sampled work counts.
    pub joined_threads: u64,
    pub samples_retained: u64,
    pub dropped_samples: u64,
    pub frequency_samples: Vec<CpuFrequencySampleV2>,
    /// Where frequency came from, or why it could not be sampled.
    pub frequency_availability: Evidence<HardwareFieldSourceV2>,
    pub dropped_frequency_samples: u64,
}

/// Static CPU topology, affinity, NUMA, and cgroup CPU limits for one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopologyEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub logical_cpus: u32,
    pub physical_cores: SourcedEvidenceV2<u32>,
    pub packages: SourcedEvidenceV2<u32>,
    pub numa_nodes: SourcedEvidenceV2<u32>,
    /// CPUs the process is allowed to run on.
    pub affinity_cpus: SourcedEvidenceV2<u32>,
    /// Cgroup CPU quota in thousandths of one CPU; unavailable means unbounded.
    pub cpu_quota_milli: SourcedEvidenceV2<u64>,
}

/// Per-stage cycle and instruction totals joined from span records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageHardwareV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub metric_id: crate::MetricId,
    /// Spans of this stage that carried hardware readings.
    pub span_count: u64,
    pub cycles: u64,
    pub instructions: u64,
    /// Cycles per instruction in thousandths.
    pub cpi_milli: Evidence<u64>,
}

/// Per-thread cycle and instruction totals joined from span records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadHardwareV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub thread_id: u64,
    pub span_count: u64,
    pub cycles: u64,
    pub instructions: u64,
    pub cpi_milli: Evidence<u64>,
}

/// Run-level cycle and instruction totals joined from span records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunSpanHardwareV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub span_count: u64,
    pub spans_with_counters: u64,
    pub cycles: u64,
    pub instructions: u64,
    pub cpi_milli: Evidence<u64>,
}

/// Cold-path CPI aggregation over one drained span set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpanHardwareAggregationV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub run: RunSpanHardwareV2,
    pub stages: Vec<StageHardwareV2>,
    pub threads: Vec<ThreadHardwareV2>,
}

#[derive(Default)]
struct HardwareSum {
    spans: u64,
    cycles: u64,
    instructions: u64,
}

impl HardwareSum {
    fn add(&mut self, hardware: &SpanHardwareV2) {
        let mut counted = false;
        if let Evidence::Recorded { value } = hardware.cycles() {
            self.cycles = self.cycles.saturating_add(value);
            counted = true;
        }
        if let Evidence::Recorded { value } = hardware.instructions() {
            self.instructions = self.instructions.saturating_add(value);
            counted = true;
        }
        if counted {
            self.spans = self.spans.saturating_add(1);
        }
    }

    fn cpi_milli(&self) -> Evidence<u64> {
        milli_ratio(self.cycles, self.instructions)
            .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded)
    }
}

/// Join span-attached counter readings into per-stage, per-thread, and run CPI.
///
/// Nested spans contribute inclusive readings, so stage sums double count
/// nesting exactly as inclusive stage time does; compare like with like.
pub fn aggregate_span_hardware(spans: &[SpanRecordV2]) -> SpanHardwareAggregationV2 {
    let mut stages: std::collections::BTreeMap<crate::MetricId, HardwareSum> =
        std::collections::BTreeMap::new();
    let mut threads: std::collections::BTreeMap<u64, HardwareSum> =
        std::collections::BTreeMap::new();
    let mut run = HardwareSum::default();
    for span in spans {
        let Evidence::Recorded { value: hardware } = &span.hardware else {
            continue;
        };
        stages.entry(span.metric_id).or_default().add(hardware);
        threads.entry(span.thread_id).or_default().add(hardware);
        run.add(hardware);
    }
    SpanHardwareAggregationV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        run: RunSpanHardwareV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            span_count: spans.len() as u64,
            spans_with_counters: run.spans,
            cycles: run.cycles,
            instructions: run.instructions,
            cpi_milli: run.cpi_milli(),
        },
        stages: stages
            .into_iter()
            .map(|(metric_id, sum)| StageHardwareV2 {
                version: HARDWARE_EVIDENCE_V2_VERSION,
                metric_id,
                span_count: sum.spans,
                cycles: sum.cycles,
                instructions: sum.instructions,
                cpi_milli: sum.cpi_milli(),
            })
            .collect(),
        threads: threads
            .into_iter()
            .map(|(thread_id, sum)| ThreadHardwareV2 {
                version: HARDWARE_EVIDENCE_V2_VERSION,
                thread_id,
                span_count: sum.spans,
                cycles: sum.cycles,
                instructions: sum.instructions,
                cpi_milli: sum.cpi_milli(),
            })
            .collect(),
    }
}

/// Complete CPU hardware evidence for one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HardwareRunEvidenceV2 {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    /// Session-thread counter totals; other threads are covered per span.
    pub counters: HardwareCounterSetV2,
    pub scheduler: SchedulerEvidenceV2,
    pub utilization: UtilizationEvidenceV2,
    pub topology: TopologyEvidenceV2,
    /// CPI joined from drained span records; attach via [`Self::with_span_aggregation`].
    pub span_aggregation: Evidence<SpanHardwareAggregationV2>,
}

impl HardwareRunEvidenceV2 {
    /// Attach CPI aggregation computed from the session's drained span records.
    pub fn with_span_aggregation(mut self, spans: &[SpanRecordV2]) -> Self {
        self.span_aggregation = Evidence::recorded(aggregate_span_hardware(spans));
        self
    }
}

/// Linux perf, Windows cycle-time, or stub collector for hardware counters.
pub struct HardwareCounterCollector {
    capability: CollectorCapability,
    state: platform::CounterState,
    started: std::time::Instant,
}

impl HardwareCounterCollector {
    pub fn new() -> Self {
        let platform = platform::platform_collectors();
        Self {
            capability: platform.counter_capability,
            state: platform.counters,
            started: std::time::Instant::now(),
        }
    }
}

impl Default for HardwareCounterCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotCollector for HardwareCounterCollector {
    type Snapshot = HardwareCounterSampleV2;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        let elapsed_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        platform::sample_counters(&mut self.state, elapsed_ns)
    }
}

/// Context-switch, migration, and runqueue-delay collector.
pub struct SchedulerCollector {
    capability: CollectorCapability,
    state: platform::SchedulerState,
}

impl SchedulerCollector {
    pub fn new() -> Self {
        let platform = platform::platform_collectors();
        Self {
            capability: platform.scheduler_capability,
            state: platform.scheduler,
        }
    }
}

impl Default for SchedulerCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotCollector for SchedulerCollector {
    type Snapshot = SchedulerSampleV2;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        platform::sample_scheduler(&mut self.state)
    }
}

/// Per-thread CPU utilization and frequency sampler.
pub struct ThreadUtilizationCollector {
    capability: CollectorCapability,
    started: std::time::Instant,
}

impl ThreadUtilizationCollector {
    pub fn new() -> Self {
        let platform = platform::platform_collectors();
        Self {
            capability: platform.utilization_capability,
            started: std::time::Instant::now(),
        }
    }
}

impl Default for ThreadUtilizationCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotCollector for ThreadUtilizationCollector {
    type Snapshot = ThreadUtilizationSampleV2;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        let elapsed_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let (threads, dropped) = platform::sample_thread_utilization();
        let dropped_threads =
            dropped.saturating_add(threads.len().saturating_sub(MAX_SAMPLE_THREADS) as u64);
        ThreadUtilizationSampleV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            elapsed_ns,
            threads: threads.into_iter().take(MAX_SAMPLE_THREADS).collect(),
            dropped_threads,
        }
    }
}

/// Static CPU topology, affinity, NUMA, and cgroup limit collector.
pub struct TopologyCollector {
    capability: CollectorCapability,
}

impl TopologyCollector {
    pub fn new() -> Self {
        let platform = platform::platform_collectors();
        Self {
            capability: platform.topology_capability,
        }
    }
}

impl Default for TopologyCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotCollector for TopologyCollector {
    type Snapshot = TopologyEvidenceV2;

    fn capability(&self) -> CollectorCapability {
        self.capability.clone()
    }

    fn sample(&mut self) -> Self::Snapshot {
        platform::capture_topology()
    }
}

/// Raw per-span counter reading captured on the span hot path.
#[derive(Clone, Copy, Default)]
pub(crate) struct SpanCounterReading {
    pub cycles: Option<u64>,
    pub instructions: Option<u64>,
}

/// Read this thread's raw counters for one span edge; `None` when unsupported.
///
/// Costs one relaxed atomic load when the feature is disabled or perf is
/// restricted, and two counter reads per edge otherwise. Never allocates.
#[inline]
pub(crate) fn span_counter_reading() -> Option<SpanCounterReading> {
    platform::span_counter_reading()
}

/// Session-scoped hardware sampling state owned by `Session`.
pub(crate) struct HardwareSession {
    counter_collector: HardwareCounterCollector,
    scheduler_collector: SchedulerCollector,
    utilization_collector: ThreadUtilizationCollector,
    topology_collector: TopologyCollector,
    counters_start: Option<HardwareCounterSampleV2>,
    scheduler_start: Option<SchedulerSampleV2>,
    utilization_samples: Vec<ThreadUtilizationSampleV2>,
    dropped_utilization_samples: u64,
    frequency_samples: Vec<CpuFrequencySampleV2>,
    dropped_frequency_samples: u64,
    topology: Option<TopologyEvidenceV2>,
    disabled_reason: Option<EvidenceGap>,
}

impl HardwareSession {
    pub(crate) fn new() -> Self {
        let mut counter_collector = HardwareCounterCollector::new();
        let mut scheduler_collector = SchedulerCollector::new();
        let utilization_collector = ThreadUtilizationCollector::new();
        let mut topology_collector = TopologyCollector::new();
        let disabled_reason = match counter_collector.capability.availability {
            CollectorAvailability::Disabled => Some(EvidenceGap::CollectorDisabled),
            _ => None,
        };
        let counters_start = (disabled_reason.is_none()).then(|| counter_collector.sample());
        let scheduler_start = (disabled_reason.is_none()).then(|| scheduler_collector.sample());
        let topology = (disabled_reason.is_none()).then(|| topology_collector.sample());
        let mut session = Self {
            counter_collector,
            scheduler_collector,
            utilization_collector,
            topology_collector,
            counters_start,
            scheduler_start,
            utilization_samples: Vec::new(),
            dropped_utilization_samples: 0,
            frequency_samples: Vec::new(),
            dropped_frequency_samples: 0,
            topology,
            disabled_reason,
        };
        if session.disabled_reason.is_none() {
            session.transition_sample();
        }
        session
    }

    /// Sample per-thread CPU and frequency at one macro-state boundary.
    pub(crate) fn transition_sample(&mut self) {
        if self.disabled_reason.is_some() {
            return;
        }
        if self.utilization_samples.len() == MAX_UTILIZATION_SAMPLES {
            self.dropped_utilization_samples = self.dropped_utilization_samples.saturating_add(1);
        } else {
            self.utilization_samples
                .push(self.utilization_collector.sample());
        }
        if self.frequency_samples.len() == MAX_UTILIZATION_SAMPLES {
            self.dropped_frequency_samples = self.dropped_frequency_samples.saturating_add(1);
        } else if let Some(sample) = platform::sample_frequency(self.utilization_elapsed_ns()) {
            self.frequency_samples.push(sample);
        }
    }

    fn utilization_elapsed_ns(&self) -> u64 {
        self.utilization_samples
            .last()
            .map_or(0, |sample| sample.elapsed_ns)
    }

    pub(crate) fn capabilities(&self) -> Vec<CollectorCapability> {
        vec![
            self.counter_collector.capability(),
            self.scheduler_collector.capability(),
            self.utilization_collector.capability(),
            self.topology_collector.capability(),
        ]
    }

    /// Compute final evidence, recording run totals as typed session counters.
    pub(crate) fn finish_evidence(
        mut self,
        wall_ns: u64,
        runtime: &crate::Runtime,
    ) -> Evidence<HardwareRunEvidenceV2> {
        if let Some(reason) = self.disabled_reason {
            return Evidence::unavailable(reason);
        }
        self.transition_sample();
        let counters = match &self.counters_start {
            Some(start) => {
                let end = self.counter_collector.sample();
                HardwareCounterSetV2::between(start, &end)
            }
            None => HardwareCounterSetV2::all_gapped(EvidenceGap::Unavailable),
        };
        let scheduler = match &self.scheduler_start {
            Some(start) => {
                let end = self.scheduler_collector.sample();
                SchedulerEvidenceV2::between(start, &end)
            }
            None => SchedulerEvidenceV2::between(
                &platform::empty_scheduler_sample(),
                &platform::empty_scheduler_sample(),
            ),
        };
        let utilization = compute_utilization(
            &self.utilization_samples,
            self.dropped_utilization_samples,
            wall_ns,
            self.topology.as_ref().map_or_else(
                crate::host_parallelism::logical_cpus,
                |t| t.logical_cpus,
            ),
            std::mem::take(&mut self.frequency_samples),
            self.dropped_frequency_samples,
        );
        record_hardware_counters(runtime, &counters, &scheduler);
        Evidence::recorded(HardwareRunEvidenceV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            counters,
            scheduler,
            utilization,
            topology: self
                .topology
                .take()
                .unwrap_or_else(platform::capture_topology),
            span_aggregation: gap(EvidenceGap::Unavailable),
        })
    }
}

fn record_hardware_counters(
    runtime: &crate::Runtime,
    counters: &HardwareCounterSetV2,
    scheduler: &SchedulerEvidenceV2,
) {
    let pairs: [(&SourcedEvidenceV2<u64>, crate::CounterId); 12] = [
        (&counters.cycles, crate::CounterId::HardwareCycles),
        (
            &counters.instructions,
            crate::CounterId::HardwareInstructions,
        ),
        (
            &counters.cache_references,
            crate::CounterId::HardwareCacheReferences,
        ),
        (
            &counters.cache_misses,
            crate::CounterId::HardwareCacheMisses,
        ),
        (
            &counters.branch_instructions,
            crate::CounterId::HardwareBranchInstructions,
        ),
        (
            &counters.branch_misses,
            crate::CounterId::HardwareBranchMisses,
        ),
        (
            &counters.stalled_cycles_frontend,
            crate::CounterId::HardwareStalledCyclesFrontend,
        ),
        (
            &counters.stalled_cycles_backend,
            crate::CounterId::HardwareStalledCyclesBackend,
        ),
        (
            &scheduler.voluntary_context_switches,
            crate::CounterId::SchedulerVoluntaryContextSwitches,
        ),
        (
            &scheduler.involuntary_context_switches,
            crate::CounterId::SchedulerInvoluntaryContextSwitches,
        ),
        (
            &scheduler.cpu_migrations,
            crate::CounterId::SchedulerCpuMigrations,
        ),
        (
            &scheduler.scheduler_delay_ns,
            crate::CounterId::SchedulerDelayNs,
        ),
    ];
    for (field, counter) in pairs {
        if let Evidence::Recorded { value } = field.value {
            if value > 0 {
                runtime.add_counter(counter, value);
            }
        }
    }
}

fn compute_utilization(
    samples: &[ThreadUtilizationSampleV2],
    dropped_samples: u64,
    wall_ns: u64,
    logical_cpus: u32,
    frequency_samples: Vec<CpuFrequencySampleV2>,
    dropped_frequency_samples: u64,
) -> UtilizationEvidenceV2 {
    let frequency_availability = platform::frequency_availability();
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return UtilizationEvidenceV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            wall_ns,
            logical_cpus,
            total_thread_cpu_ns: 0,
            effective_parallelism_milli: gap(EvidenceGap::Unavailable),
            capacity_utilization_milli: gap(EvidenceGap::Unavailable),
            threads: Vec::new(),
            exited_threads: 0,
            joined_threads: 0,
            samples_retained: samples.len() as u64,
            dropped_samples,
            frequency_samples,
            frequency_availability,
            dropped_frequency_samples,
        };
    };
    let last_by_id: std::collections::BTreeMap<u64, u64> = last
        .threads
        .iter()
        .map(|thread| (thread.thread_id, thread.cpu_time_ns))
        .collect();
    let first_ids: std::collections::BTreeSet<u64> = first
        .threads
        .iter()
        .map(|thread| thread.thread_id)
        .collect();
    let mut threads = Vec::new();
    let mut exited_threads = 0_u64;
    let mut total = 0_u64;
    for thread in &first.threads {
        match last_by_id.get(&thread.thread_id) {
            Some(end) => {
                let cpu_time_ns = end.saturating_sub(thread.cpu_time_ns);
                total = total.saturating_add(cpu_time_ns);
                threads.push(ThreadUtilizationV2 {
                    version: HARDWARE_EVIDENCE_V2_VERSION,
                    thread_id: thread.thread_id,
                    cpu_time_ns,
                    utilization_milli: milli_ratio(cpu_time_ns, wall_ns)
                        .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded),
                });
            }
            None => exited_threads = exited_threads.saturating_add(1),
        }
    }
    let joined_threads = last
        .threads
        .iter()
        .filter(|thread| !first_ids.contains(&thread.thread_id))
        .count() as u64;
    let capacity_ns = u128::from(wall_ns).saturating_mul(u128::from(logical_cpus));
    UtilizationEvidenceV2 {
        version: HARDWARE_EVIDENCE_V2_VERSION,
        wall_ns,
        logical_cpus,
        total_thread_cpu_ns: total,
        effective_parallelism_milli: milli_ratio(total, wall_ns)
            .map_or_else(|| gap(EvidenceGap::Unavailable), Evidence::recorded),
        capacity_utilization_milli: if capacity_ns == 0 {
            gap(EvidenceGap::Unavailable)
        } else {
            Evidence::recorded(
                u64::try_from(u128::from(total) * 1_000 / capacity_ns).unwrap_or(u64::MAX),
            )
        },
        threads,
        exited_threads,
        joined_threads,
        samples_retained: samples.len() as u64,
        dropped_samples,
        frequency_samples,
        frequency_availability,
        dropped_frequency_samples,
    }
}

/// Stubs for builds without `hardware-counters` or on unhandled platforms:
/// every collector reports Disabled (feature off) or Unsupported (platform).
#[cfg(any(
    not(feature = "hardware-counters"),
    all(
        feature = "hardware-counters",
        not(any(target_os = "linux", target_os = "macos", windows))
    )
))]
mod stubs {
    use super::*;
    use crate::collector::CollectorId;

    pub(super) const COUNTER_SOURCE: HardwareFieldSourceV2 = HardwareFieldSourceV2::SystemCall;
    pub(super) const MEMORY_STALL_GAP: EvidenceGap = EvidenceGap::Unsupported;

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

    fn stub_availability() -> (CollectorAvailability, &'static str) {
        #[cfg(not(feature = "hardware-counters"))]
        {
            (
                CollectorAvailability::Disabled,
                "enable the keyhog-profile hardware-counters feature",
            )
        }
        #[cfg(feature = "hardware-counters")]
        {
            (
                CollectorAvailability::Unsupported,
                "CPU hardware evidence is implemented for Linux, Windows, and macOS only",
            )
        }
    }

    pub(super) fn platform_collectors() -> PlatformCollectors {
        let (availability, detail) = stub_availability();
        let capability = |collector: CollectorId| {
            CollectorCapability::unavailable(collector, availability, detail)
        };
        PlatformCollectors {
            counter_capability: capability(CollectorId::HardwareCounters),
            scheduler_capability: capability(CollectorId::SchedulerActivity),
            utilization_capability: capability(CollectorId::ThreadUtilization),
            topology_capability: capability(CollectorId::CpuTopology),
            counters: CounterState,
            scheduler: SchedulerState,
        }
    }

    fn gap_sample(reason: EvidenceGap) -> SourcedEvidenceV2<u64> {
        SourcedEvidenceV2::gapped(COUNTER_SOURCE, reason)
    }

    fn stub_reason() -> EvidenceGap {
        #[cfg(not(feature = "hardware-counters"))]
        {
            EvidenceGap::CollectorDisabled
        }
        #[cfg(feature = "hardware-counters")]
        {
            EvidenceGap::Unsupported
        }
    }

    pub(super) fn sample_counters(
        _state: &mut CounterState,
        elapsed_ns: u64,
    ) -> HardwareCounterSampleV2 {
        let reason = stub_reason();
        HardwareCounterSampleV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            elapsed_ns,
            cycles: gap_sample(reason),
            instructions: gap_sample(reason),
            cache_references: gap_sample(reason),
            cache_misses: gap_sample(reason),
            branch_instructions: gap_sample(reason),
            branch_misses: gap_sample(reason),
            stalled_cycles_frontend: gap_sample(reason),
            stalled_cycles_backend: gap_sample(reason),
            stalled_cycles_memory: SourcedEvidenceV2::gapped(
                HardwareFieldSourceV2::PerfEventOpen,
                EvidenceGap::Unsupported,
            ),
        }
    }

    pub(super) fn empty_scheduler_sample() -> SchedulerSampleV2 {
        let reason = stub_reason();
        SchedulerSampleV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            voluntary_context_switches: gap_sample(reason),
            involuntary_context_switches: gap_sample(reason),
            total_context_switches: gap_sample(reason),
            cpu_migrations: gap_sample(reason),
            runqueue_delay_ns: gap_sample(reason),
            timeslices: gap_sample(reason),
        }
    }

    pub(super) fn sample_scheduler(_state: &mut SchedulerState) -> SchedulerSampleV2 {
        empty_scheduler_sample()
    }

    pub(super) fn sample_thread_utilization() -> (Vec<ThreadCpuV2>, u64) {
        (Vec::new(), 0)
    }

    pub(super) fn sample_frequency(_elapsed_ns: u64) -> Option<CpuFrequencySampleV2> {
        None
    }

    pub(super) fn frequency_availability() -> Evidence<HardwareFieldSourceV2> {
        Evidence::unavailable(stub_reason())
    }

    pub(super) fn capture_topology() -> TopologyEvidenceV2 {
        let reason = stub_reason();
        let logical_cpus = crate::host_parallelism::logical_cpus();
        TopologyEvidenceV2 {
            version: HARDWARE_EVIDENCE_V2_VERSION,
            logical_cpus,
            physical_cores: SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SysfsCpu, reason),
            packages: SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SysfsCpu, reason),
            numa_nodes: SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SysfsCpu, reason),
            affinity_cpus: SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SystemCall, reason),
            cpu_quota_milli: SourcedEvidenceV2::gapped(HardwareFieldSourceV2::SysfsCgroup, reason),
        }
    }

    #[inline]
    pub(crate) fn span_counter_reading() -> Option<SpanCounterReading> {
        None
    }
}
