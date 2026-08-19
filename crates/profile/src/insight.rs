//! Turn one recorded profile into the answers an operator asked for.
//!
//! The measurement layers record spans, counters, resources, and allocator
//! ownership. This module reads one finished [`crate::CausalProfileV2`] and
//! derives the six questions a slow scan actually raises: where the wall time
//! went, how much of it was serial, how much of the machine was used, how much
//! memory the run cost and why, what a byte and a file cost, and which caches
//! paid off.
//!
//! Every derived number is an integer. Ratios are thousandths (`_milli`) or
//! parts per million (`_ppm`), so two runs diff exactly and a diff never shows
//! float noise.
//!
//! ```
//! use keyhog_profile::{CausalProfileV2, RunIdentity, RunState, Session};
//!
//! let identity = RunIdentity::new("0.5.49", "d", "c", "filesystem", "small-text", "auto");
//! let session = Session::start(identity).expect("start profile");
//! let profile = session.finish(RunState::Completed);
//! let causal = CausalProfileV2::from_v1(profile);
//! let insight = keyhog_profile::RunInsightV2::derive(&causal);
//! assert!(insight.render_summary().starts_with("bottleneck "));
//! ```

use crate::metrics::{MacroStageId, MetricId};
use crate::schema::{RunState, StateMeasurement};
use crate::schema_v2::{
    CacheEffectivenessV2, CausalProfileV2, CompileSurfaceRecordV2, Evidence, QueueDepthV2,
    RetryRecordV2,
};
use serde::{Deserialize, Serialize};

pub const RUN_INSIGHT_V2_VERSION: u16 = 1;

/// A stage is treated as serial when its average worker count stays under this.
const SERIAL_CONCURRENCY_MILLI: u64 = 1_500;
/// A phase must hold at least this share of wall time to be worth naming.
const MATERIAL_SHARE_PPM: u64 = 50_000;
/// A serial region below this share of wall time is noise, not a finding.
const SERIAL_REPORT_SHARE_PPM: u64 = 10_000;
/// Amplification is only meaningful once the input is a real workload.
const AMPLIFICATION_FLOOR_BYTES: u64 = 1024 * 1024;
/// Below this average worker count a region is sparse, not serial: it spans a
/// long window without occupying it.
const SERIAL_FLOOR_MILLI: u64 = 700;
/// A region must own most of the work recorded during its window to be a
/// barrier rather than a wrapper around parallel children.
const SERIAL_EXCLUSIVITY_PPM: u64 = 600_000;
/// Peak resident above this, with input far below it, is a fixed memory floor.
const MEMORY_FLOOR_BYTES: u64 = 64 * 1024 * 1024;
/// Peak resident this many times the input is amplification worth naming.
const AMPLIFICATION_MILLI: u64 = 2_000;

fn ppm(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    u64::try_from((u128::from(part) * 1_000_000) / u128::from(whole)).unwrap_or(u64::MAX)
}

fn milli(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        return 0;
    }
    u64::try_from((u128::from(part) * 1_000) / u128::from(whole)).unwrap_or(u64::MAX)
}

fn per_second_milli(count: u64, elapsed_ns: u64) -> u64 {
    if elapsed_ns == 0 {
        return 0;
    }
    u64::try_from((u128::from(count) * 1_000_000_000_000) / u128::from(elapsed_ns))
        .unwrap_or(u64::MAX)
}

fn mib_per_second_milli(bytes: u64, elapsed_ns: u64) -> u64 {
    if elapsed_ns == 0 {
        return 0;
    }
    u64::try_from((u128::from(bytes) * 1_000_000_000_000) / (u128::from(elapsed_ns) * 1_048_576))
        .unwrap_or(u64::MAX)
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
        ("B", 1),
    ];
    for (label, scale) in UNITS {
        if bytes >= scale {
            return format!("{:.1} {label}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes} B")
}

fn format_ms(nanoseconds: u64) -> String {
    format!("{:.3} ms", nanoseconds as f64 / 1_000_000.0)
}

fn format_ratio(value_milli: u64) -> String {
    format!("{:.2}x", value_milli as f64 / 1_000.0)
}

fn format_percent_ppm(value_ppm: u64) -> String {
    format!("{:.1}%", value_ppm as f64 / 10_000.0)
}

/// What limited this run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BottleneckKindV2 {
    /// A phase held the wall clock while the worker pool sat idle.
    SerialPhase,
    /// Workers were available but the achieved speedup stayed far below them.
    ParallelStarvation,
    /// Workers spent their time blocked waiting for a queue to deliver work.
    QueueStarvation,
    /// One micro-function dominated an otherwise parallel run.
    StageBound,
    /// Resident memory is dominated by a fixed cost the input did not cause.
    MemoryFloor,
    /// Resident memory scales as a large multiple of the input.
    MemoryAmplification,
    /// A reuse cache missed often enough to pay for the recomputation twice.
    CacheMiss,
    /// Work had to be attempted again, so a failure was not designed out.
    RetriedWork,
    /// Wall time went to work outside scanning: startup, config, reporting.
    FixedOverhead,
    /// Nothing measured is large enough to name a bottleneck honestly.
    Insufficient,
}

impl BottleneckKindV2 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SerialPhase => "serial-phase",
            Self::ParallelStarvation => "parallel-starvation",
            Self::QueueStarvation => "queue-starvation",
            Self::StageBound => "stage-bound",
            Self::MemoryFloor => "memory-floor",
            Self::MemoryAmplification => "memory-amplification",
            Self::CacheMiss => "cache-miss",
            Self::RetriedWork => "retried-work",
            Self::FixedOverhead => "fixed-overhead",
            Self::Insufficient => "insufficient-evidence",
        }
    }
}

/// One ranked conclusion with the measurement that supports it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingV2 {
    pub version: u16,
    pub kind: BottleneckKindV2,
    /// Zero is informational, three is the run's limiting factor.
    pub severity: u8,
    /// Wall time this finding accounts for. Zero when the finding is not timed.
    pub impact_ns: u64,
    pub impact_share_ppm: u64,
    /// Phase, micro-function, or cache the finding is about.
    pub subject: String,
    /// One sentence stating the conclusion and the number behind it.
    pub statement: String,
}

/// Wall time, CPU time, and memory for one macro phase.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhaseInsightV2 {
    pub version: u16,
    pub state: RunState,
    pub wall_ns: u64,
    pub share_ppm: u64,
    pub cpu_ns: u64,
    /// `cpu_ns / wall_ns` in thousandths: the workers this phase actually used.
    pub speedup_milli: u64,
    /// True when the phase ran at roughly one worker while a pool existed.
    pub serial: bool,
    pub mib_per_second_milli: u64,
    pub units_per_second_milli: u64,
    pub resident_start_bytes: u64,
    pub resident_end_bytes: u64,
    pub threads_start: u64,
    pub threads_end: u64,
}

/// Overall and per-phase rates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThroughputInsightV2 {
    pub version: u16,
    pub wall_ns: u64,
    pub input_bytes: u64,
    pub input_units: u64,
    /// MiB per second times one thousand.
    pub mib_per_second_milli: u64,
    /// Input units per second times one thousand.
    pub units_per_second_milli: u64,
    pub ns_per_unit: u64,
    /// Nanoseconds per input byte times one thousand.
    pub ns_per_byte_milli: u64,
    /// CPU nanoseconds per input byte times one thousand.
    pub cpu_ns_per_byte_milli: u64,
    pub phases: Vec<PhaseInsightV2>,
}

/// Allocation ownership for one micro-function.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageMemoryV2 {
    pub version: u16,
    /// `None` is the root slot: allocations made outside any recorded span.
    pub metric_id: Option<MetricId>,
    pub allocations: u64,
    pub allocated_bytes: u64,
    pub live_bytes: u64,
    pub peak_live_bytes: u64,
}

/// Where resident memory went and what caused it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryInsightV2 {
    pub version: u16,
    /// Exact kernel high water when available, otherwise the sampled maximum.
    pub peak_resident_bytes: u64,
    /// `kernel-vmhwm`, `boundary-samples`, or `unavailable`.
    pub peak_source: String,
    /// Resident memory at the first recorded boundary of the run.
    pub baseline_resident_bytes: u64,
    /// Resident memory on entry to scanning: the cost of standing the engine up.
    pub engine_init_resident_bytes: u64,
    /// Peak minus the engine-init floor: the part the input actually caused.
    pub input_driven_resident_bytes: u64,
    pub input_bytes: u64,
    /// Peak resident per input byte in thousandths.
    pub amplification_milli: u64,
    pub scanner_threads: u64,
    /// Peak resident divided by scanner threads; compare across thread counts
    /// to read the per-thread scratch slope.
    pub resident_per_scanner_thread_bytes: u64,
    /// Input-driven resident divided by scanner threads.
    pub input_driven_per_scanner_thread_bytes: u64,
    pub allocations: u64,
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    pub allocation_peak_live_bytes: u64,
    /// Bytes allocated per input byte in thousandths.
    pub allocated_per_input_byte_milli: u64,
    /// Allocation owners sorted by attributed bytes, largest first.
    pub stages: Vec<StageMemoryV2>,
}

/// Per-worker time and how much of the machine the run reached.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParallelismInsightV2 {
    pub version: u16,
    pub logical_cpus: u64,
    pub scanner_threads: u64,
    pub wall_ns: u64,
    pub process_cpu_ns: u64,
    /// `process_cpu_ns / wall_ns` in thousandths: the speedup actually achieved.
    pub achieved_speedup_milli: u64,
    /// Achieved speedup over logical CPUs, in parts per million.
    pub parallel_efficiency_ppm: u64,
    /// Amdahl ceiling implied by the measured serial share, in thousandths.
    pub speedup_ceiling_milli: u64,
    pub worker_count: u64,
    pub active_worker_count: u64,
    /// Summed outermost-span time across workers.
    pub instrumented_busy_ns: u64,
    /// Summed outermost blocked-wait time across workers.
    pub instrumented_blocked_ns: u64,
    /// `wall_ns * worker_count`: the time the pool could have spent working.
    pub worker_capacity_ns: u64,
    pub idle_ns: u64,
    pub idle_share_ppm: u64,
    pub busiest_busy_ns: u64,
    pub median_busy_ns: u64,
    /// Busiest minus median over busiest, in parts per million.
    pub imbalance_ppm: u64,
    /// Time inside outermost spans that was not on CPU. Threads sitting in an
    /// instrumented region while runnable-but-not-running show up here, which
    /// is where a large worker pool loses its speedup without ever going idle.
    pub busy_off_cpu_ns: u64,
    pub source_blocked_ns: u64,
    pub scanner_blocked_ns: u64,
    pub queues: Vec<QueueDepthV2>,
}

/// Scope a serial region was observed at.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SerialScopeV2 {
    /// A macro run state such as acquiring or scanning.
    Phase,
    /// One micro-function.
    Stage,
}

/// One region that held the wall clock without using the pool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SerialRegionV2 {
    pub version: u16,
    pub scope: SerialScopeV2,
    pub subject: String,
    pub wall_ns: u64,
    pub share_ppm: u64,
    /// Average workers inside the region, in thousandths.
    pub concurrency_milli: u64,
    pub worker_count: u64,
    /// Share of the work recorded during this window that belongs to this
    /// region, in parts per million. An inclusive wrapper span scores low
    /// because its children run inside it; a real barrier scores near one.
    pub exclusivity_ppm: u64,
    /// True when a caller declared the region serial with `serial_span`.
    pub declared: bool,
}

/// What one micro-function cost per call, per file, per byte.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageAttributionV2 {
    pub version: u16,
    pub metric_id: MetricId,
    pub macro_stage_id: MacroStageId,
    pub calls: u64,
    pub elapsed_ns: u64,
    pub share_of_recorded_ppm: u64,
    pub ns_per_call: u64,
    pub ns_per_input_unit: u64,
    /// Nanoseconds per input byte times one thousand.
    pub ns_per_input_byte_milli: u64,
    /// Bytes the caller attributed to this micro-function.
    pub bytes: u64,
    pub mib_per_second_milli: u64,
    pub concurrency_milli: u64,
    pub worker_count: u64,
}

/// What one backend was asked to do.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendAttributionV2 {
    pub version: u16,
    pub backend: String,
    pub batches: u64,
    pub recovered_batches: u64,
    pub share_ppm: u64,
}

/// Which measurements were available, so a missing number reads as a gap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InsightCoverageV2 {
    pub version: u16,
    pub process_metrics: bool,
    pub allocation_tracking: bool,
    pub stage_concurrency: bool,
    pub worker_occupancy: bool,
    pub dropped_span_events: u64,
    /// Plain sentences naming each gap that weakens a conclusion above.
    pub notes: Vec<String>,
}

/// Every derived answer for one run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunInsightV2 {
    pub version: u16,
    /// Ranked conclusions; the first is the run's limiting factor.
    pub findings: Vec<FindingV2>,
    pub throughput: ThroughputInsightV2,
    pub memory: MemoryInsightV2,
    pub parallelism: ParallelismInsightV2,
    pub serial_regions: Vec<SerialRegionV2>,
    /// Micro-functions sorted by summed time, largest first.
    pub stages: Vec<StageAttributionV2>,
    pub backends: Vec<BackendAttributionV2>,
    pub caches: Vec<CacheEffectivenessV2>,
    pub retries: Vec<RetryRecordV2>,
    #[serde(default)]
    pub compile_surfaces: Vec<CompileSurfaceRecordV2>,
    pub coverage: InsightCoverageV2,
}

impl RunInsightV2 {
    /// Derive every answer from one finished profile.
    pub fn derive(profile: &CausalProfileV2) -> Self {
        let wall_ns = profile.wall_time_ns;
        let identity = &profile.identity;
        let input_bytes = identity.workload.raw_source_bytes;
        let input_units = identity.workload.source_units;
        let logical_cpus = u64::from(identity.host.logical_cpus);
        let scanner_threads = u64::try_from(identity.scanner_threads_requested).unwrap_or(0);

        let process_cpu_ns = process_cpu_ns(profile);
        let phases = derive_phases(profile, wall_ns, input_bytes, input_units);
        let memory = derive_memory(profile, input_bytes, scanner_threads.max(1));
        let (serial_regions, serial_wall_ns) = derive_serial(profile, &phases, wall_ns);
        let parallelism = derive_parallelism(
            profile,
            wall_ns,
            process_cpu_ns,
            logical_cpus,
            scanner_threads,
            serial_wall_ns,
        );
        let stages = derive_stages(profile, input_bytes, input_units);
        let backends = derive_backends(profile);
        let coverage = derive_coverage(profile, &memory, &parallelism);

        let throughput = ThroughputInsightV2 {
            version: RUN_INSIGHT_V2_VERSION,
            wall_ns,
            input_bytes,
            input_units,
            mib_per_second_milli: mib_per_second_milli(input_bytes, wall_ns),
            units_per_second_milli: per_second_milli(input_units, wall_ns),
            ns_per_unit: if input_units == 0 {
                0
            } else {
                wall_ns / input_units
            },
            ns_per_byte_milli: milli(wall_ns, input_bytes),
            cpu_ns_per_byte_milli: milli(process_cpu_ns, input_bytes),
            phases,
        };

        let findings = rank_findings(
            wall_ns,
            &throughput,
            &memory,
            &parallelism,
            &serial_regions,
            &stages,
            &profile.caches,
            &profile.retries,
        );

        Self {
            version: RUN_INSIGHT_V2_VERSION,
            findings,
            throughput,
            memory,
            parallelism,
            serial_regions,
            stages,
            backends,
            caches: profile.caches.clone(),
            retries: profile.retries.clone(),
            compile_surfaces: profile.compile_surfaces.clone(),
            coverage,
        }
    }

    /// The run's limiting factor, or an insufficient-evidence finding.
    pub fn bottleneck(&self) -> &FindingV2 {
        self.findings.first().expect("findings is never empty")
    }

    /// Render the operator summary, leading with the bottleneck.
    ///
    /// The first line is the conclusion. Everything after it is the evidence
    /// for that conclusion, in the order an operator would ask for it.
    pub fn render_summary(&self) -> String {
        let mut out = String::with_capacity(2_048);
        let bottleneck = self.bottleneck();
        out.push_str(&format!(
            "bottleneck {} {}\n",
            bottleneck.kind.as_str(),
            bottleneck.statement
        ));
        for finding in self.findings.iter().skip(1) {
            out.push_str(&format!(
                "  also {} {}\n",
                finding.kind.as_str(),
                finding.statement
            ));
        }

        let throughput = &self.throughput;
        // A ratio taken against a handful of bytes is arithmetic, not
        // information. Say so rather than print eight significant digits.
        let small_input = throughput.input_bytes < AMPLIFICATION_FLOOR_BYTES;
        let per_mib = if small_input {
            "n/a (input below 1 MiB)".to_owned()
        } else {
            format_ms(throughput.ns_per_byte_milli * 1_048_576 / 1_000)
        };
        out.push_str(&format!(
            "throughput wall={} input={} units={} rate={:.2} MiB/s files_per_s={:.1} per_file={} per_MiB={per_mib}\n",
            format_ms(throughput.wall_ns),
            format_bytes(throughput.input_bytes),
            throughput.input_units,
            throughput.mib_per_second_milli as f64 / 1_000.0,
            throughput.units_per_second_milli as f64 / 1_000.0,
            format_ms(throughput.ns_per_unit),
        ));

        for phase in &throughput.phases {
            out.push_str(&format!(
                "  phase {:<10} wall={:>12} share={:>6} cpu={:>8} rss={:>10} -> {:<10} threads={}->{}{}\n",
                phase_name(phase.state),
                format_ms(phase.wall_ns),
                format_percent_ppm(phase.share_ppm),
                format_ratio(phase.speedup_milli),
                format_bytes(phase.resident_start_bytes),
                format_bytes(phase.resident_end_bytes),
                phase.threads_start,
                phase.threads_end,
                if phase.serial { "  SERIAL" } else { "" },
            ));
        }

        let memory = &self.memory;
        let amplification = if small_input {
            "n/a (input below 1 MiB)".to_owned()
        } else {
            format_ratio(memory.amplification_milli)
        };
        out.push_str(&format!(
            "memory peak={} ({}) engine_init_floor={} input_driven={} amplification={amplification} per_scanner_thread={} threads={}\n",
            format_bytes(memory.peak_resident_bytes),
            memory.peak_source,
            format_bytes(memory.engine_init_resident_bytes),
            format_bytes(memory.input_driven_resident_bytes),
            format_bytes(memory.resident_per_scanner_thread_bytes),
            memory.scanner_threads,
        ));
        if memory.allocated_bytes != 0 {
            out.push_str(&format!(
                "  allocator allocations={} allocated={} freed={} peak_live={} per_input_byte={}\n",
                memory.allocations,
                format_bytes(memory.allocated_bytes),
                format_bytes(memory.deallocated_bytes),
                format_bytes(memory.allocation_peak_live_bytes),
                format_ratio(memory.allocated_per_input_byte_milli),
            ));
        }
        for stage in memory.stages.iter().take(5) {
            out.push_str(&format!(
                "  owns {:<24} allocated={:>10} peak_live={:>10} allocations={}\n",
                stage
                    .metric_id
                    .map_or("outside-any-span", crate::MetricId::as_str),
                format_bytes(stage.allocated_bytes),
                format_bytes(stage.peak_live_bytes),
                stage.allocations,
            ));
        }

        let parallel = &self.parallelism;
        out.push_str(&format!(
            "parallelism achieved={} of {} cpus (efficiency={}) ceiling={} workers={}/{} busy={} blocked={} idle={} ({})\n",
            format_ratio(parallel.achieved_speedup_milli),
            parallel.logical_cpus,
            format_percent_ppm(parallel.parallel_efficiency_ppm),
            format_ratio(parallel.speedup_ceiling_milli),
            parallel.active_worker_count,
            parallel.worker_count,
            format_ms(parallel.instrumented_busy_ns),
            format_ms(parallel.instrumented_blocked_ns),
            format_ms(parallel.idle_ns),
            format_percent_ppm(parallel.idle_share_ppm),
        ));
        out.push_str(&format!(
            "  workers busiest={} median={} imbalance={} process_cpu={} in_span_off_cpu={} source_wait={} scanner_wait={}\n",
            format_ms(parallel.busiest_busy_ns),
            format_ms(parallel.median_busy_ns),
            format_percent_ppm(parallel.imbalance_ppm),
            format_ms(parallel.process_cpu_ns),
            format_ms(parallel.busy_off_cpu_ns),
            format_ms(parallel.source_blocked_ns),
            format_ms(parallel.scanner_blocked_ns),
        ));
        for queue in &parallel.queues {
            out.push_str(&format!(
                "  queue {:?} high_water={} enqueued={} dequeued={}\n",
                queue.queue, queue.high_water, queue.enqueues, queue.dequeues,
            ));
        }

        for region in self.serial_regions.iter().take(8) {
            out.push_str(&format!(
                "serial {:<6} {:<22} wall={:>12} share={:>6} concurrency={} exclusivity={} workers={}{}\n",
                match region.scope {
                    SerialScopeV2::Phase => "phase",
                    SerialScopeV2::Stage => "stage",
                },
                region.subject,
                format_ms(region.wall_ns),
                format_percent_ppm(region.share_ppm),
                format_ratio(region.concurrency_milli),
                format_percent_ppm(region.exclusivity_ppm),
                region.worker_count,
                if region.declared { " declared" } else { "" },
            ));
        }

        for stage in self.stages.iter().take(8) {
            out.push_str(&format!(
                "cost {:<24} total={:>12} share={:>6} calls={:<9} per_call={:>10} per_file={:>10} concurrency={}\n",
                stage.metric_id.as_str(),
                format_ms(stage.elapsed_ns),
                format_percent_ppm(stage.share_of_recorded_ppm),
                stage.calls,
                format_ms(stage.ns_per_call),
                format_ms(stage.ns_per_input_unit),
                format_ratio(stage.concurrency_milli),
            ));
        }

        for backend in &self.backends {
            out.push_str(&format!(
                "backend {:<16} batches={} recovered={} share={}\n",
                backend.backend,
                backend.batches,
                backend.recovered_batches,
                format_percent_ppm(backend.share_ppm),
            ));
        }

        for record in &self.retries {
            out.push_str(&format!(
                "retry {:<24} attempts={}\n",
                record.cause.as_str(),
                record.attempts,
            ));
        }

        for cache in &self.caches {
            out.push_str(&format!(
                "cache {:<24} hits={} misses={} hit_rate={}\n",
                cache.cache.as_str(),
                cache.hits,
                cache.misses,
                format_percent_ppm(cache.hit_rate_ppm),
            ));
        }

        for surface in &self.compile_surfaces {
            out.push_str(&format!(
                "compile {:<28} runtime_compiles={} loads={} install_compiles={} update_compiles={} developer_compiles={}\n",
                surface.surface.as_str(),
                surface.runtime_compiles,
                surface.loads,
                surface.install_compiles,
                surface.update_compiles,
                surface.developer_compiles,
            ));
        }

        for note in &self.coverage.notes {
            out.push_str(&format!("gap {note}\n"));
        }
        out
    }
}

fn phase_name(state: RunState) -> &'static str {
    match state {
        RunState::Created => "created",
        RunState::Acquiring => "acquiring",
        RunState::Scanning => "scanning",
        RunState::Resolving => "resolving",
        RunState::Verifying => "verifying",
        RunState::Reporting => "reporting",
        RunState::Completed => "completed",
        RunState::Failed => "failed",
    }
}

fn process_cpu_ns(profile: &CausalProfileV2) -> u64 {
    let start = profile.resources.start.cpu_time_ms.unwrap_or_default();
    let finish = profile.resources.finish.cpu_time_ms.unwrap_or_default();
    finish.saturating_sub(start).saturating_mul(1_000_000)
}

fn derive_phases(
    profile: &CausalProfileV2,
    wall_ns: u64,
    input_bytes: u64,
    input_units: u64,
) -> Vec<PhaseInsightV2> {
    profile
        .states
        .iter()
        .map(|state: &StateMeasurement| {
            let cpu_ns = state
                .cpu_time_ms
                .unwrap_or_default()
                .saturating_mul(1_000_000);
            let speedup_milli = milli(cpu_ns, state.elapsed_ns);
            // Only the scanning phases can be parallel; naming a single
            // threaded startup "serial" is noise, not a finding.
            let parallel_capable = matches!(
                state.state,
                RunState::Acquiring | RunState::Scanning | RunState::Verifying
            );
            PhaseInsightV2 {
                version: RUN_INSIGHT_V2_VERSION,
                state: state.state,
                wall_ns: state.elapsed_ns,
                share_ppm: ppm(state.elapsed_ns, wall_ns),
                cpu_ns,
                speedup_milli,
                serial: parallel_capable
                    && speedup_milli < SERIAL_CONCURRENCY_MILLI
                    && ppm(state.elapsed_ns, wall_ns) >= SERIAL_REPORT_SHARE_PPM,
                mib_per_second_milli: mib_per_second_milli(input_bytes, state.elapsed_ns),
                units_per_second_milli: per_second_milli(input_units, state.elapsed_ns),
                resident_start_bytes: state.resident_start_bytes.unwrap_or_default(),
                resident_end_bytes: state.resident_end_bytes.unwrap_or_default(),
                threads_start: state.threads_start.unwrap_or_default(),
                threads_end: state.threads_end.unwrap_or_default(),
            }
        })
        .collect()
}

fn derive_memory(
    profile: &CausalProfileV2,
    input_bytes: u64,
    scanner_threads: u64,
) -> MemoryInsightV2 {
    let kernel_peak = match &profile.system {
        Evidence::Recorded { value } => match &value.memory.resident_high_water_bytes.value {
            Evidence::Recorded { value } => Some(*value),
            Evidence::Unavailable { .. } => None,
        },
        Evidence::Unavailable { .. } => None,
    };
    let sampled_peak = profile.resources.max_observed_resident_bytes;
    let (peak_resident_bytes, peak_source) = match (kernel_peak, sampled_peak) {
        // The kernel high water covers the whole process lifetime including
        // allocations that were freed before any boundary sample was taken.
        (Some(kernel), sampled) => (kernel.max(sampled.unwrap_or(0)), "kernel-vmhwm"),
        (None, Some(sampled)) => (sampled, "boundary-samples"),
        (None, None) => (0, "unavailable"),
    };

    let baseline_resident_bytes = profile
        .resources
        .start
        .resident_bytes
        .or_else(|| {
            profile
                .states
                .first()
                .and_then(|state| state.resident_start_bytes)
        })
        .unwrap_or_default();
    // Resident memory on entry to scanning is the engine-init floor: detectors
    // compiled, matchers built, pool stood up, before a single input byte.
    let engine_init_resident_bytes = profile
        .states
        .iter()
        .find(|state| state.state == RunState::Scanning)
        .and_then(|state| state.resident_start_bytes)
        .or(Some(baseline_resident_bytes))
        .unwrap_or_default();

    let (allocations, allocated_bytes, deallocated_bytes, allocation_peak_live_bytes, stages) =
        match &profile.system {
            Evidence::Recorded { value } => {
                let totals = match &value.allocation.totals {
                    Evidence::Recorded { value } => (
                        value.allocations,
                        value.allocated_bytes,
                        value.deallocated_bytes,
                        value.peak_live_bytes,
                    ),
                    Evidence::Unavailable { .. } => (0, 0, 0, 0),
                };
                let mut stages: Vec<StageMemoryV2> = value
                    .allocation
                    .stages
                    .iter()
                    .filter(|stage| stage.allocated_bytes != 0 || stage.peak_live_bytes != 0)
                    .map(|stage| StageMemoryV2 {
                        version: RUN_INSIGHT_V2_VERSION,
                        metric_id: stage.metric_id,
                        allocations: stage.allocations,
                        allocated_bytes: stage.allocated_bytes,
                        live_bytes: stage.live_bytes,
                        peak_live_bytes: stage.peak_live_bytes,
                    })
                    .collect();
                stages.sort_by(|left, right| {
                    right
                        .allocated_bytes
                        .cmp(&left.allocated_bytes)
                        .then_with(|| left.metric_id.cmp(&right.metric_id))
                });
                (totals.0, totals.1, totals.2, totals.3, stages)
            }
            Evidence::Unavailable { .. } => (0, 0, 0, 0, Vec::new()),
        };

    let input_driven_resident_bytes =
        peak_resident_bytes.saturating_sub(engine_init_resident_bytes);
    MemoryInsightV2 {
        version: RUN_INSIGHT_V2_VERSION,
        peak_resident_bytes,
        peak_source: peak_source.to_owned(),
        baseline_resident_bytes,
        engine_init_resident_bytes,
        input_driven_resident_bytes,
        input_bytes,
        amplification_milli: milli(peak_resident_bytes, input_bytes),
        scanner_threads,
        resident_per_scanner_thread_bytes: peak_resident_bytes / scanner_threads.max(1),
        input_driven_per_scanner_thread_bytes: input_driven_resident_bytes / scanner_threads.max(1),
        allocations,
        allocated_bytes,
        deallocated_bytes,
        allocation_peak_live_bytes,
        allocated_per_input_byte_milli: milli(allocated_bytes, input_bytes),
        stages,
    }
}

/// Work recorded by every other micro-function while `subject` was open.
///
/// Each stage's time is spread evenly over its own window, so overlapping a
/// fraction of that window charges that fraction of its time. This is what
/// separates a real barrier from an inclusive wrapper: a wrapper's children
/// run inside its window, so the wrapper scores low.
fn overlapping_work_ns(
    stages: &[crate::schema_v2::StageConcurrencyV2],
    subject: &crate::schema_v2::StageConcurrencyV2,
) -> u64 {
    stages
        .iter()
        .filter(|other| other.metric_id != subject.metric_id && other.window_ns != 0)
        .fold(0_u64, |total, other| {
            let start = other.first_start_ns.max(subject.first_start_ns);
            let end = other.last_end_ns.min(subject.last_end_ns);
            let Some(overlap) = end.checked_sub(start) else {
                return total;
            };
            // Weight by the capped concurrency, not raw elapsed, so a stage
            // entered recursively on one thread cannot drown out a barrier it
            // sits inside.
            let density_milli = other.concurrency_milli;
            let share = u64::try_from((u128::from(density_milli) * u128::from(overlap)) / 1_000)
                .unwrap_or(u64::MAX);
            total.saturating_add(share)
        })
}

fn derive_serial(
    profile: &CausalProfileV2,
    phases: &[PhaseInsightV2],
    wall_ns: u64,
) -> (Vec<SerialRegionV2>, u64) {
    let mut regions: Vec<SerialRegionV2> = phases
        .iter()
        .filter(|phase| phase.serial && phase.wall_ns != 0)
        .map(|phase| SerialRegionV2 {
            version: RUN_INSIGHT_V2_VERSION,
            scope: SerialScopeV2::Phase,
            subject: phase_name(phase.state).to_owned(),
            wall_ns: phase.wall_ns,
            share_ppm: phase.share_ppm,
            concurrency_milli: phase.speedup_milli,
            worker_count: 1,
            // A macro phase is measured by process CPU over its own wall, so
            // it already accounts for everything running at the time.
            exclusivity_ppm: 1_000_000,
            declared: false,
        })
        .collect();
    // A phase's serial wall time is the wall time no extra thread can remove.
    let serial_wall_ns = regions
        .iter()
        .fold(0_u64, |total, region| total.saturating_add(region.wall_ns));

    regions.extend(profile.stage_concurrency.iter().filter_map(|stage| {
        if stage.window_ns == 0 {
            return None;
        }
        let share_ppm = ppm(stage.window_ns, wall_ns);
        if share_ppm < SERIAL_REPORT_SHARE_PPM {
            return None;
        }
        let other_ns = overlapping_work_ns(&profile.stage_concurrency, stage);
        let own_ns = u64::try_from(
            (u128::from(stage.concurrency_milli) * u128::from(stage.window_ns)) / 1_000,
        )
        .unwrap_or(u64::MAX);
        let exclusivity_ppm = ppm(own_ns, own_ns.saturating_add(other_ns));
        // Three conditions, and all three are needed. Concurrency near
        // one rules out a sparse stage that merely spans a long window.
        // Exclusivity rules out an inclusive wrapper whose children are
        // the parallel work. A declaration overrides both because the
        // caller knows something the aggregates cannot show.
        let looks_serial = stage.concurrency_milli >= SERIAL_FLOOR_MILLI
            && stage.concurrency_milli < SERIAL_CONCURRENCY_MILLI
            && exclusivity_ppm >= SERIAL_EXCLUSIVITY_PPM;
        if !looks_serial && stage.declared_serial_calls == 0 {
            return None;
        }
        Some(SerialRegionV2 {
            version: RUN_INSIGHT_V2_VERSION,
            scope: SerialScopeV2::Stage,
            subject: stage.metric_id.as_str().to_owned(),
            wall_ns: stage.window_ns,
            share_ppm,
            concurrency_milli: stage.concurrency_milli,
            worker_count: stage.worker_count,
            exclusivity_ppm,
            declared: stage.declared_serial_calls != 0,
        })
    }));
    regions.sort_by(|left, right| {
        right
            .wall_ns
            .cmp(&left.wall_ns)
            .then_with(|| left.subject.cmp(&right.subject))
    });
    (regions, serial_wall_ns)
}

fn derive_parallelism(
    profile: &CausalProfileV2,
    wall_ns: u64,
    process_cpu_ns: u64,
    logical_cpus: u64,
    scanner_threads: u64,
    serial_wall_ns: u64,
) -> ParallelismInsightV2 {
    let occupancy = profile.worker_occupancy.as_ref();
    let worker_count = occupancy.map_or(0, |occupancy| occupancy.worker_count);
    let instrumented_busy_ns = occupancy.map_or(0, |occupancy| occupancy.busy_ns);
    let instrumented_blocked_ns = occupancy.map_or(0, |occupancy| occupancy.blocked_ns);
    let worker_capacity_ns = wall_ns.saturating_mul(worker_count);
    let idle_ns = worker_capacity_ns
        .saturating_sub(instrumented_busy_ns)
        .saturating_sub(instrumented_blocked_ns);
    let busiest_busy_ns = occupancy.map_or(0, |occupancy| occupancy.busiest_busy_ns);
    let median_busy_ns = occupancy.map_or(0, |occupancy| occupancy.median_busy_ns);

    let blocked_ns_for = |metric: MetricId| -> u64 {
        profile
            .blocked_waits
            .iter()
            .find(|record| record.metric_id == metric)
            .map_or(0, |record| record.blocked_ns)
    };

    // Amdahl: with a serial part that no thread count removes, the ceiling is
    // wall over serial. A run with no measured serial part is unbounded here,
    // which we report as the logical CPU count rather than infinity.
    let speedup_ceiling_milli = if serial_wall_ns == 0 {
        logical_cpus.saturating_mul(1_000)
    } else {
        milli(wall_ns, serial_wall_ns)
    };

    ParallelismInsightV2 {
        version: RUN_INSIGHT_V2_VERSION,
        logical_cpus,
        scanner_threads,
        wall_ns,
        process_cpu_ns,
        achieved_speedup_milli: milli(process_cpu_ns, wall_ns),
        parallel_efficiency_ppm: ppm(process_cpu_ns, wall_ns.saturating_mul(logical_cpus)),
        speedup_ceiling_milli,
        worker_count,
        active_worker_count: occupancy.map_or(0, |occupancy| occupancy.active_worker_count),
        instrumented_busy_ns,
        instrumented_blocked_ns,
        worker_capacity_ns,
        idle_ns,
        idle_share_ppm: ppm(idle_ns, worker_capacity_ns),
        busiest_busy_ns,
        median_busy_ns,
        imbalance_ppm: ppm(
            busiest_busy_ns.saturating_sub(median_busy_ns),
            busiest_busy_ns,
        ),
        busy_off_cpu_ns: instrumented_busy_ns.saturating_sub(process_cpu_ns),
        source_blocked_ns: blocked_ns_for(MetricId::SourceQueueWait),
        scanner_blocked_ns: blocked_ns_for(MetricId::ScannerQueueWait),
        queues: profile.queue_depths.clone(),
    }
}

fn derive_stages(
    profile: &CausalProfileV2,
    input_bytes: u64,
    input_units: u64,
) -> Vec<StageAttributionV2> {
    let recorded_ns = profile
        .stages
        .iter()
        .fold(0_u64, |total, stage| total.saturating_add(stage.elapsed_ns));
    let mut rows: Vec<StageAttributionV2> = profile
        .stages
        .iter()
        .filter(|stage| stage.calls != 0)
        .map(|stage| {
            let concurrency = profile
                .stage_concurrency
                .iter()
                .find(|record| record.metric_id == stage.stage.metric_id());
            let bytes = concurrency.map_or(0, |record| record.bytes);
            StageAttributionV2 {
                version: RUN_INSIGHT_V2_VERSION,
                metric_id: stage.stage.metric_id(),
                macro_stage_id: stage.stage.macro_stage_id(),
                calls: stage.calls,
                elapsed_ns: stage.elapsed_ns,
                share_of_recorded_ppm: ppm(stage.elapsed_ns, recorded_ns),
                ns_per_call: stage.elapsed_ns / stage.calls.max(1),
                ns_per_input_unit: if input_units == 0 {
                    0
                } else {
                    stage.elapsed_ns / input_units
                },
                ns_per_input_byte_milli: milli(stage.elapsed_ns, input_bytes),
                bytes,
                mib_per_second_milli: mib_per_second_milli(
                    bytes,
                    concurrency.map_or(0, |record| record.window_ns),
                ),
                concurrency_milli: concurrency.map_or(0, |record| record.concurrency_milli),
                worker_count: concurrency.map_or(0, |record| record.worker_count),
            }
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .elapsed_ns
            .cmp(&left.elapsed_ns)
            .then_with(|| left.metric_id.cmp(&right.metric_id))
    });
    rows
}

fn derive_backends(profile: &CausalProfileV2) -> Vec<BackendAttributionV2> {
    let mut totals: Vec<(String, u64, u64)> = Vec::new();
    for batch in &profile.identity.route.batches {
        let recovered = u64::from(matches!(
            batch.recovered_from_backend,
            Evidence::Recorded { .. }
        ));
        match totals
            .iter_mut()
            .find(|(backend, _, _)| backend == &batch.completed_backend)
        {
            Some(entry) => {
                entry.1 += 1;
                entry.2 += recovered;
            }
            None => totals.push((batch.completed_backend.clone(), 1, recovered)),
        }
    }
    let batch_total = totals.iter().fold(0_u64, |total, entry| total + entry.1);
    let mut rows: Vec<BackendAttributionV2> = totals
        .into_iter()
        .map(
            |(backend, batches, recovered_batches)| BackendAttributionV2 {
                version: RUN_INSIGHT_V2_VERSION,
                backend,
                batches,
                recovered_batches,
                share_ppm: ppm(batches, batch_total),
            },
        )
        .collect();
    rows.sort_by(|left, right| {
        right
            .batches
            .cmp(&left.batches)
            .then_with(|| left.backend.cmp(&right.backend))
    });
    rows
}

fn derive_coverage(
    profile: &CausalProfileV2,
    memory: &MemoryInsightV2,
    parallelism: &ParallelismInsightV2,
) -> InsightCoverageV2 {
    let mut notes = Vec::new();
    let process_metrics = memory.peak_resident_bytes != 0;
    if !process_metrics {
        notes.push(
            "resident memory is unavailable, so every memory conclusion is missing".to_owned(),
        );
    }
    let allocation_tracking = memory.allocated_bytes != 0;
    if !allocation_tracking {
        notes.push(
            "the tracking allocator is not installed, so allocation volume and per-stage ownership are absent"
                .to_owned(),
        );
    }
    let stage_concurrency = !profile.stage_concurrency.is_empty();
    if !stage_concurrency {
        notes.push(
            "no micro-function recorded a span, so serial detection falls back to phase CPU ratios"
                .to_owned(),
        );
    }
    let worker_occupancy = parallelism.worker_count != 0;
    if !worker_occupancy {
        notes.push("no worker shard registered, so busy versus idle time is absent".to_owned());
    }
    if parallelism.process_cpu_ns == 0 {
        notes.push(
            "process CPU time is unavailable, so achieved speedup cannot be computed".to_owned(),
        );
    }
    if profile.events.dropped_span_events != 0 {
        notes.push(format!(
            "{} span records were dropped for capacity; aggregate counters remain exact",
            profile.events.dropped_span_events
        ));
    }
    InsightCoverageV2 {
        version: RUN_INSIGHT_V2_VERSION,
        process_metrics,
        allocation_tracking,
        stage_concurrency,
        worker_occupancy,
        dropped_span_events: profile.events.dropped_span_events,
        notes,
    }
}

fn finding(
    kind: BottleneckKindV2,
    severity: u8,
    impact_ns: u64,
    wall_ns: u64,
    subject: impl Into<String>,
    statement: impl Into<String>,
) -> FindingV2 {
    FindingV2 {
        version: RUN_INSIGHT_V2_VERSION,
        kind,
        severity,
        impact_ns,
        impact_share_ppm: ppm(impact_ns, wall_ns),
        subject: subject.into(),
        statement: statement.into(),
    }
}

fn rank_findings(
    wall_ns: u64,
    throughput: &ThroughputInsightV2,
    memory: &MemoryInsightV2,
    parallelism: &ParallelismInsightV2,
    serial_regions: &[SerialRegionV2],
    stages: &[StageAttributionV2],
    caches: &[CacheEffectivenessV2],
    retries: &[RetryRecordV2],
) -> Vec<FindingV2> {
    let mut findings = Vec::new();

    for region in serial_regions
        .iter()
        .filter(|region| region.share_ppm >= MATERIAL_SHARE_PPM)
        .take(3)
    {
        findings.push(finding(
            BottleneckKindV2::SerialPhase,
            if region.share_ppm >= 250_000 { 3 } else { 2 },
            region.wall_ns,
            wall_ns,
            region.subject.clone(),
            format!(
                "{} is a serial barrier: {} of wall ({}) at {} workers, and no extra thread removes it",
                region.subject,
                format_ms(region.wall_ns),
                format_percent_ppm(region.share_ppm),
                format_ratio(region.concurrency_milli),
            ),
        ));
    }

    if parallelism.logical_cpus > 1 && parallelism.process_cpu_ns != 0 {
        let half_the_box = parallelism.logical_cpus.saturating_mul(500);
        if parallelism.achieved_speedup_milli < half_the_box {
            findings.push(finding(
                BottleneckKindV2::ParallelStarvation,
                if parallelism.parallel_efficiency_ppm < 250_000 {
                    3
                } else {
                    2
                },
                wall_ns.saturating_sub(
                    parallelism
                        .process_cpu_ns
                        .checked_div(parallelism.logical_cpus)
                        .unwrap_or(wall_ns),
                ),
                wall_ns,
                "worker-pool",
                format!(
                    "the run reached {} of {} logical CPUs ({} efficiency); {} of CPU time ran in {} of wall, and the Amdahl ceiling from measured serial work is {}",
                    format_ratio(parallelism.achieved_speedup_milli),
                    parallelism.logical_cpus,
                    format_percent_ppm(parallelism.parallel_efficiency_ppm),
                    format_ms(parallelism.process_cpu_ns),
                    format_ms(wall_ns),
                    format_ratio(parallelism.speedup_ceiling_milli),
                ),
            ));
        }
    }

    if parallelism.instrumented_blocked_ns > parallelism.instrumented_busy_ns
        && parallelism.instrumented_blocked_ns != 0
    {
        findings.push(finding(
            BottleneckKindV2::QueueStarvation,
            2,
            parallelism.instrumented_blocked_ns,
            wall_ns,
            "source-queue",
            format!(
                "workers spent {} blocked against {} busy; the source side is not feeding the pool",
                format_ms(parallelism.instrumented_blocked_ns),
                format_ms(parallelism.instrumented_busy_ns),
            ),
        ));
    }

    if memory.peak_resident_bytes >= MEMORY_FLOOR_BYTES
        && memory.engine_init_resident_bytes.saturating_mul(2) >= memory.peak_resident_bytes
    {
        findings.push(finding(
            BottleneckKindV2::MemoryFloor,
            if memory.input_bytes < 1_048_576 { 3 } else { 1 },
            0,
            wall_ns,
            "engine-init",
            format!(
                "{} of the {} peak is standing the engine up, not the input: {} of input produced only {} of extra resident memory",
                format_bytes(memory.engine_init_resident_bytes),
                format_bytes(memory.peak_resident_bytes),
                format_bytes(memory.input_bytes),
                format_bytes(memory.input_driven_resident_bytes),
            ),
        ));
    }

    if memory.input_bytes >= MEMORY_FLOOR_BYTES && memory.amplification_milli >= AMPLIFICATION_MILLI
    {
        findings.push(finding(
            BottleneckKindV2::MemoryAmplification,
            2,
            0,
            wall_ns,
            "resident-amplification",
            format!(
                "peak resident is {} of the input: {} held for {}",
                format_ratio(memory.amplification_milli),
                format_bytes(memory.peak_resident_bytes),
                format_bytes(memory.input_bytes),
            ),
        ));
    }

    for cache in caches
        .iter()
        .filter(|cache| cache.hit_rate_ppm < 500_000 && cache.misses >= 8)
    {
        findings.push(finding(
            BottleneckKindV2::CacheMiss,
            1,
            0,
            wall_ns,
            cache.cache.as_str(),
            format!(
                "{} served {} of {} lookups ({}); every miss pays the full cost again",
                cache.cache.as_str(),
                cache.hits,
                cache.hits.saturating_add(cache.misses),
                format_percent_ppm(cache.hit_rate_ppm),
            ),
        ));
    }

    let retry_attempts = retries
        .iter()
        .fold(0_u64, |total, record| total.saturating_add(record.attempts));
    if retry_attempts != 0 {
        let worst = retries
            .iter()
            .max_by_key(|record| record.attempts)
            .expect("a nonzero total implies at least one record");
        findings.push(finding(
            BottleneckKindV2::RetriedWork,
            2,
            0,
            wall_ns,
            worst.cause.as_str(),
            format!(
                "{retry_attempts} operations were attempted again, {} of them for {}; a retry that fires is a failure that was not designed out",
                worst.attempts,
                worst.cause.as_str(),
            ),
        ));
    }

    let scanning_ns = throughput
        .phases
        .iter()
        .filter(|phase| phase.state == RunState::Scanning)
        .fold(0_u64, |total, phase| total.saturating_add(phase.wall_ns));
    let non_scanning_ns = wall_ns.saturating_sub(scanning_ns);
    if scanning_ns != 0 && non_scanning_ns > scanning_ns {
        findings.push(finding(
            BottleneckKindV2::FixedOverhead,
            2,
            non_scanning_ns,
            wall_ns,
            "outside-scanning",
            format!(
                "{} of {} wall ran outside scanning; scanning itself took {}",
                format_ms(non_scanning_ns),
                format_ms(wall_ns),
                format_ms(scanning_ns),
            ),
        ));
    }

    if let Some(stage) = stages.first() {
        if stage.share_of_recorded_ppm >= 400_000 && stage.concurrency_milli != 0 {
            findings.push(finding(
                BottleneckKindV2::StageBound,
                1,
                stage.elapsed_ns,
                wall_ns,
                stage.metric_id.as_str(),
                format!(
                    "{} holds {} of recorded stage time across {} calls at {} per call",
                    stage.metric_id.as_str(),
                    format_percent_ppm(stage.share_of_recorded_ppm),
                    stage.calls,
                    format_ms(stage.ns_per_call),
                ),
            ));
        }
    }

    if findings.is_empty() {
        findings.push(finding(
            BottleneckKindV2::Insufficient,
            0,
            wall_ns,
            wall_ns,
            "run",
            format!(
                "no phase, worker, cache, or memory measurement crossed a reporting threshold in {}",
                format_ms(wall_ns)
            ),
        ));
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.impact_ns.cmp(&left.impact_ns))
            .then_with(|| left.subject.cmp(&right.subject))
    });
    // Three nested serial regions are one conclusion, not three. Keep the
    // largest of each kind here; the sections below carry the full lists.
    let mut seen: Vec<BottleneckKindV2> = Vec::with_capacity(findings.len());
    findings.retain(|finding| {
        if seen.contains(&finding.kind) {
            return false;
        }
        seen.push(finding.kind);
        true
    });
    findings
}
