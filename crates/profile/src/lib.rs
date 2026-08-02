//! Low-overhead causal profiling for KeyHog runs.
//!
//! The disabled hot path performs one relaxed atomic load and does not read the
//! clock. An enabled run records fixed scanner stages with allocation-free atomic
//! counters. Run identity, state transitions, and process resources are sampled
//! only at macro boundaries.

use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(not(target_os = "linux"))]
use sysinfo::{ProcessesToUpdate, System};

/// Stable wire schema for persisted profiling records.
pub const PROFILE_SCHEMA: &str = "keyhog-profile-v1";

/// Fixed measurement stages shared by scanner, source, verifier, and reporter paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(usize)]
pub enum Stage {
    SourceAcquire = 0,
    SourceWalk,
    SourceRead,
    Preprocess,
    Phase1Triggers,
    BackendDispatch,
    HotPatterns,
    ConfirmedPatterns,
    Phase2Prefilter,
    Phase2KeywordAc,
    Phase2SharedAc,
    Phase2AnchoredVerify,
    Phase2WholeChunk,
    GenericDetection,
    Entropy,
    MachineLearning,
    Decode,
    Suppression,
    LiveVerification,
    Reporting,
    SourceQueueWait,
    IncrementalLookup,
    BackendSelect,
    ResultMerge,
    ScannerQueueWait,
}

impl Stage {
    /// Every stage in stable wire order.
    pub const ALL: [Self; 25] = [
        Self::SourceAcquire,
        Self::SourceWalk,
        Self::SourceRead,
        Self::Preprocess,
        Self::Phase1Triggers,
        Self::BackendDispatch,
        Self::HotPatterns,
        Self::ConfirmedPatterns,
        Self::Phase2Prefilter,
        Self::Phase2KeywordAc,
        Self::Phase2SharedAc,
        Self::Phase2AnchoredVerify,
        Self::Phase2WholeChunk,
        Self::GenericDetection,
        Self::Entropy,
        Self::MachineLearning,
        Self::Decode,
        Self::Suppression,
        Self::LiveVerification,
        Self::Reporting,
        Self::SourceQueueWait,
        Self::IncrementalLookup,
        Self::BackendSelect,
        Self::ResultMerge,
        Self::ScannerQueueWait,
    ];

    #[inline]
    const fn index(self) -> usize {
        self as usize
    }

    /// Stable text label used by human reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceAcquire => "source-acquire",
            Self::SourceWalk => "source-walk",
            Self::SourceRead => "source-read",
            Self::Preprocess => "preprocess",
            Self::Phase1Triggers => "phase1-triggers",
            Self::BackendDispatch => "backend-dispatch",
            Self::HotPatterns => "hot-patterns",
            Self::ConfirmedPatterns => "confirmed-patterns",
            Self::Phase2Prefilter => "phase2-prefilter",
            Self::Phase2KeywordAc => "phase2-keyword-ac",
            Self::Phase2SharedAc => "phase2-shared-ac",
            Self::Phase2AnchoredVerify => "phase2-anchored-verify",
            Self::Phase2WholeChunk => "phase2-whole-chunk",
            Self::GenericDetection => "generic-detection",
            Self::Entropy => "entropy",
            Self::MachineLearning => "machine-learning",
            Self::Decode => "decode",
            Self::Suppression => "suppression",
            Self::LiveVerification => "live-verification",
            Self::Reporting => "reporting",
            Self::SourceQueueWait => "source-queue-wait",
            Self::IncrementalLookup => "incremental-lookup",
            Self::BackendSelect => "backend-select",
            Self::ResultMerge => "result-merge",
            Self::ScannerQueueWait => "scanner-queue-wait",
        }
    }
}

const STAGE_COUNT: usize = Stage::ALL.len();
const fn zero_counters() -> [AtomicU64; STAGE_COUNT] {
    [const { AtomicU64::new(0) }; STAGE_COUNT]
}
static ENABLED: AtomicBool = AtomicBool::new(false);
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);
static ELAPSED_NS: [AtomicU64; STAGE_COUNT] = zero_counters();
static CALLS: [AtomicU64; STAGE_COUNT] = zero_counters();
static ATTRIBUTED_NS: [AtomicU64; STAGE_COUNT] = zero_counters();
static SESSION_ELAPSED_NS: [AtomicU64; STAGE_COUNT] = zero_counters();
static SESSION_CALLS: [AtomicU64; STAGE_COUNT] = zero_counters();
static SESSION_ATTRIBUTED_NS: [AtomicU64; STAGE_COUNT] = zero_counters();
static INPUT_BYTES: AtomicU64 = AtomicU64::new(0);
static INPUT_UNITS: AtomicU64 = AtomicU64::new(0);
static SESSION_INPUT_BYTES: AtomicU64 = AtomicU64::new(0);
static SESSION_INPUT_UNITS: AtomicU64 = AtomicU64::new(0);
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Optional attribution for work performed inside a derived input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum Attribution {
    #[default]
    Root = 0,
    Decoded = 1,
}

thread_local! {
    static ATTRIBUTION: Cell<Attribution> = const { Cell::new(Attribution::Root) };
}

/// Replace this thread's attribution and return its previous value.
pub fn set_attribution(attribution: Attribution) -> Attribution {
    ATTRIBUTION.with(|slot| slot.replace(attribution))
}

/// Return whether fixed-stage profiling is active.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Enable or disable fixed-stage profiling.
///
/// Prefer [`Session::start`] for operator runs because it also captures identity,
/// resources, and state transitions. This switch remains available to libraries
/// and microbenchmarks that only need stage counters.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// Allocation-free stage guard. It contains no start timestamp while disabled.
#[must_use]
pub struct Span {
    stage: Stage,
    started: Option<Instant>,
    session_recording: bool,
}

impl Span {
    /// Whether this span reads and will record a clock measurement.
    pub fn is_recording(&self) -> bool {
        self.started.is_some()
    }
}

/// Start one fixed-stage measurement.
#[inline]
pub fn span(stage: Stage) -> Span {
    let recording = enabled();
    Span {
        stage,
        started: recording.then(Instant::now),
        session_recording: recording && SESSION_ACTIVE.load(Ordering::Relaxed),
    }
}

impl Drop for Span {
    #[inline]
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let index = self.stage.index();
        ELAPSED_NS[index].fetch_add(elapsed, Ordering::Relaxed);
        CALLS[index].fetch_add(1, Ordering::Relaxed);
        if self.session_recording {
            SESSION_ELAPSED_NS[index].fetch_add(elapsed, Ordering::Relaxed);
            SESSION_CALLS[index].fetch_add(1, Ordering::Relaxed);
        }
        if ATTRIBUTION.with(|slot| slot.get()) == Attribution::Decoded {
            ATTRIBUTED_NS[index].fetch_add(elapsed, Ordering::Relaxed);
            if self.session_recording {
                SESSION_ATTRIBUTED_NS[index].fetch_add(elapsed, Ordering::Relaxed);
            }
        }
    }
}

/// Add source bytes processed by the current profile.
#[inline]
pub fn add_input_bytes(bytes: u64) {
    if enabled() {
        INPUT_BYTES.fetch_add(bytes, Ordering::Relaxed);
        if SESSION_ACTIVE.load(Ordering::Relaxed) {
            SESSION_INPUT_BYTES.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

/// Add source units such as files, objects, responses, or chunks.
#[inline]
pub fn add_input_units(units: u64) {
    if enabled() {
        INPUT_UNITS.fetch_add(units, Ordering::Relaxed);
        if SESSION_ACTIVE.load(Ordering::Relaxed) {
            SESSION_INPUT_UNITS.fetch_add(units, Ordering::Relaxed);
        }
    }
}

/// One aggregate fixed-stage measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageMeasurement {
    pub stage: Stage,
    pub elapsed_ns: u64,
    pub calls: u64,
    pub attributed_ns: u64,
}

/// Atomically read and clear all fixed-stage counters.
pub fn take_stage_measurements() -> Vec<StageMeasurement> {
    take_measurements_from(&ELAPSED_NS, &CALLS, &ATTRIBUTED_NS)
}

fn take_measurements_from(
    elapsed: &[AtomicU64; STAGE_COUNT],
    calls: &[AtomicU64; STAGE_COUNT],
    attributed: &[AtomicU64; STAGE_COUNT],
) -> Vec<StageMeasurement> {
    Stage::ALL
        .into_iter()
        .filter_map(|stage| {
            let index = stage.index();
            let elapsed_ns = elapsed[index].swap(0, Ordering::Relaxed);
            let calls = calls[index].swap(0, Ordering::Relaxed);
            let attributed_ns = attributed[index].swap(0, Ordering::Relaxed);
            (elapsed_ns != 0 || calls != 0 || attributed_ns != 0).then_some(StageMeasurement {
                stage,
                elapsed_ns,
                calls,
                attributed_ns,
            })
        })
        .collect()
}

fn take_session_stage_measurements() -> Vec<StageMeasurement> {
    take_measurements_from(&SESSION_ELAPSED_NS, &SESSION_CALLS, &SESSION_ATTRIBUTED_NS)
}

/// Atomically read and clear aggregate input bytes and units.
pub fn take_input_totals() -> (u64, u64) {
    (
        INPUT_BYTES.swap(0, Ordering::Relaxed),
        INPUT_UNITS.swap(0, Ordering::Relaxed),
    )
}

fn take_session_input_totals() -> (u64, u64) {
    (
        SESSION_INPUT_BYTES.swap(0, Ordering::Relaxed),
        SESSION_INPUT_UNITS.swap(0, Ordering::Relaxed),
    )
}

/// Discard fixed-stage counters and input totals.
pub fn reset() {
    let _ = take_stage_measurements();
    INPUT_BYTES.store(0, Ordering::Relaxed);
    INPUT_UNITS.store(0, Ordering::Relaxed);
}

fn reset_session() {
    let _ = take_session_stage_measurements();
    SESSION_INPUT_BYTES.store(0, Ordering::Relaxed);
    SESSION_INPUT_UNITS.store(0, Ordering::Relaxed);
}

/// Cache state that materially changes run cost.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheState {
    #[default]
    Unknown,
    Disabled,
    Cold,
    Warm,
}

/// Daemon state that materially changes startup and resident work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DaemonState {
    #[default]
    Off,
    Client,
    Worker,
    Mass,
}

/// Coarse causal state of a profiling run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunState {
    Created,
    Acquiring,
    Scanning,
    Resolving,
    Verifying,
    Reporting,
    Completed,
    Failed,
}

/// Identity and execution choices required to compare two run records honestly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunIdentity {
    pub run_id: String,
    pub binary_version: String,
    pub detector_digest: String,
    pub config_digest: String,
    pub source_kind: String,
    pub workload_class: String,
    pub backend_requested: String,
    pub backend_selected: Option<String>,
    pub cache_state: CacheState,
    pub daemon_state: DaemonState,
    pub scanner_threads: usize,
    pub reader_threads: Option<usize>,
    pub logical_cpus: usize,
}

impl RunIdentity {
    /// Construct a run identity with a process-unique identifier and explicit state.
    pub fn new(
        binary_version: impl Into<String>,
        detector_digest: impl Into<String>,
        config_digest: impl Into<String>,
        source_kind: impl Into<String>,
        workload_class: impl Into<String>,
        backend_requested: impl Into<String>,
    ) -> Self {
        let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            run_id: format!("{}-{unix_ns}-{sequence}", std::process::id()),
            binary_version: binary_version.into(),
            detector_digest: detector_digest.into(),
            config_digest: config_digest.into(),
            source_kind: source_kind.into(),
            workload_class: workload_class.into(),
            backend_requested: backend_requested.into(),
            backend_selected: None,
            cache_state: CacheState::Unknown,
            daemon_state: DaemonState::Off,
            scanner_threads: 0,
            reader_threads: None,
            logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        }
    }
}

/// One run-state transition relative to session start.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateTransition {
    pub state: RunState,
    pub elapsed_ns: u64,
}

/// Process resource observation associated with a run-state boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSample {
    pub state: RunState,
    pub elapsed_ns: u64,
    pub snapshot: ResourceSnapshot,
}

/// Process resource observation at a macro boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub cpu_time_ms: Option<u64>,
    pub resident_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub thread_count: Option<u64>,
}

/// One completed macro state with its wall time and boundary resource deltas.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateMeasurement {
    pub state: RunState,
    pub elapsed_ns: u64,
    pub cpu_time_ms: Option<u64>,
    pub aggregate_cpu_milli_percent: Option<u64>,
    pub resident_start_bytes: Option<u64>,
    pub resident_end_bytes: Option<u64>,
    pub threads_start: Option<u64>,
    pub threads_end: Option<u64>,
}

#[cfg(target_os = "linux")]
fn process_resources() -> ResourceSnapshot {
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
    let cpu_time_ms = cpu_time_ms();
    ResourceSnapshot {
        cpu_time_ms,
        resident_bytes: status_value(&status, "VmRSS:", 1024),
        virtual_bytes: status_value(&status, "VmSize:", 1024),
        thread_count: status_value(&status, "Threads:", 1),
    }
}

#[cfg(not(target_os = "linux"))]
fn process_resources() -> ResourceSnapshot {
    let Ok(pid) = sysinfo::get_current_pid() else {
        return ResourceSnapshot::default();
    };
    let mut system = System::new();
    let pids = [pid];
    system.refresh_processes(ProcessesToUpdate::Some(&pids), true);
    let Some(process) = system.process(pid) else {
        return ResourceSnapshot::default();
    };
    ResourceSnapshot {
        cpu_time_ms: Some(process.accumulated_cpu_time()),
        resident_bytes: Some(process.memory()),
        virtual_bytes: Some(process.virtual_memory()),
        thread_count: process.tasks().map(|tasks| tasks.len() as u64),
    }
}

/// Resource change across a completed profile session.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub start: ResourceSnapshot,
    pub finish: ResourceSnapshot,
    pub max_observed_resident_bytes: Option<u64>,
    pub max_observed_threads: Option<u64>,
    pub aggregate_cpu_percent: Option<f64>,
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

fn resource_usage(
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
        max_observed_resident_bytes,
        max_observed_threads,
        start,
        finish,
        aggregate_cpu_percent,
    }
}

fn state_measurements(
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

/// Complete replayable profile record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunProfile {
    pub schema: String,
    pub identity: RunIdentity,
    pub status: RunState,
    pub wall_time_ns: u64,
    pub input_bytes: u64,
    pub input_units: u64,
    pub stages: Vec<StageMeasurement>,
    pub transitions: Vec<StateTransition>,
    #[serde(default)]
    pub states: Vec<StateMeasurement>,
    pub resource_samples: Vec<ResourceSample>,
    pub resources: ResourceUsage,
}

impl RunProfile {
    /// Serialize the stable record as pretty JSON.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Render a compact operator report without secrets or source content.
    pub fn render_text(&self) -> String {
        let reader_threads = self
            .identity
            .reader_threads
            .map_or_else(|| "auto".to_owned(), |threads| threads.to_string());
        let throughput_mib_s = if self.wall_time_ns == 0 {
            0.0
        } else {
            self.input_bytes as f64 * 1_000_000_000.0 / self.wall_time_ns as f64 / (1024.0 * 1024.0)
        };
        let mut output = format!(
            "KeyHog profile {}\n\
             state={} source={} workload={} backend_requested={} backend_selected={} cache={} daemon={} wall_ms={:.3}\n\
             version={} detector_digest={} config_digest={}\n\
             input_bytes={} input_units={} throughput_mib_s={throughput_mib_s:.3} scanner_threads={} reader_threads={} logical_cpus={}\n",
            self.identity.run_id,
            state_name(self.status),
            self.identity.source_kind,
            self.identity.workload_class,
            self.identity.backend_requested,
            self.identity
                .backend_selected
                .as_deref()
                .unwrap_or("unselected"),
            cache_name(self.identity.cache_state),
            daemon_name(self.identity.daemon_state),
            self.wall_time_ns as f64 / 1_000_000.0,
            self.identity.binary_version,
            self.identity.detector_digest,
            self.identity.config_digest,
            self.input_bytes,
            self.input_units,
            self.identity.scanner_threads,
            reader_threads,
            self.identity.logical_cpus,
        );
        for state in &self.states {
            output.push_str(&format!(
                "macro {:<12} wall_ms={:.3}",
                state_name(state.state),
                state.elapsed_ns as f64 / 1_000_000.0,
            ));
            if let Some(cpu) = state.aggregate_cpu_milli_percent {
                output.push_str(&format!(" cpu={:.1}%", cpu as f64 / 1_000.0));
            } else {
                output.push_str(" cpu=unavailable");
            }
            if let (Some(start), Some(finish)) =
                (state.resident_start_bytes, state.resident_end_bytes)
            {
                output.push_str(&format!(" rss_bytes={start}->{finish}"));
            }
            if let (Some(start), Some(finish)) = (state.threads_start, state.threads_end) {
                output.push_str(&format!(" threads={start}->{finish}"));
            }
            output.push('\n');
        }
        for stage in &self.stages {
            let per_call_us = if stage.calls == 0 {
                0.0
            } else {
                stage.elapsed_ns as f64 / stage.calls as f64 / 1_000.0
            };
            output.push_str(&format!(
                "  {:<24} {:>10.3} ms calls={} per_call_us={per_call_us:.3} attributed_ms={:.3}\n",
                stage.stage.as_str(),
                stage.elapsed_ns as f64 / 1_000_000.0,
                stage.calls,
                stage.attributed_ns as f64 / 1_000_000.0,
            ));
        }
        if let Some(state) = self.states.iter().max_by_key(|state| state.elapsed_ns) {
            output.push_str(&format!(
                "bottleneck macro={} wall_ms={:.3}",
                state_name(state.state),
                state.elapsed_ns as f64 / 1_000_000.0,
            ));
        }
        if let Some(stage) = self
            .stages
            .iter()
            .filter(|stage| stage.stage != Stage::BackendDispatch)
            .max_by_key(|stage| stage.elapsed_ns)
        {
            output.push_str(&format!(
                " summed_stage={} summed_ms={:.3}",
                stage.stage.as_str(),
                stage.elapsed_ns as f64 / 1_000_000.0,
            ));
        }
        if !self.states.is_empty() || !self.stages.is_empty() {
            output.push('\n');
        }
        if let Some(cpu) = self.resources.aggregate_cpu_percent {
            output.push_str(&format!("resources aggregate_cpu={cpu:.1}%"));
        } else {
            output.push_str("resources aggregate_cpu=unavailable");
        }
        if let Some(rss) = self.resources.max_observed_resident_bytes {
            output.push_str(&format!(" max_observed_rss_bytes={rss}"));
        }
        if let Some(threads) = self.resources.max_observed_threads {
            output.push_str(&format!(" max_observed_threads={threads}"));
        }
        output.push('\n');
        output
    }
}

fn state_name(state: RunState) -> &'static str {
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

fn cache_name(state: CacheState) -> &'static str {
    match state {
        CacheState::Unknown => "unknown",
        CacheState::Disabled => "disabled",
        CacheState::Cold => "cold",
        CacheState::Warm => "warm",
    }
}

fn daemon_name(state: DaemonState) -> &'static str {
    match state {
        DaemonState::Off => "off",
        DaemonState::Client => "client",
        DaemonState::Worker => "worker",
        DaemonState::Mass => "mass",
    }
}

/// Error returned when a process-global profile session is already active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionActive;

impl fmt::Display for SessionActive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a KeyHog profile session is already active in this process")
    }
}

impl std::error::Error for SessionActive {}

/// One causal profiling session.
///
/// Sessions are process-global because deep scanner spans use allocation-free
/// static counters. Concurrent daemon requests must profile separately rather
/// than merge unrelated state into one record.
pub struct Session {
    identity: Option<RunIdentity>,
    started: Instant,
    resources_at_start: ResourceSnapshot,
    transitions: Vec<StateTransition>,
    resource_samples: Vec<ResourceSample>,
    finished: bool,
}

impl Session {
    /// Start a fresh session and reset all fixed-stage counters.
    pub fn start(identity: RunIdentity) -> Result<Self, SessionActive> {
        SESSION_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SessionActive)?;
        reset();
        reset_session();
        set_enabled(true);
        let started = Instant::now();
        let resources_at_start = process_resources();
        Ok(Self {
            identity: Some(identity),
            started,
            resources_at_start,
            transitions: vec![StateTransition {
                state: RunState::Created,
                elapsed_ns: 0,
            }],
            resource_samples: vec![ResourceSample {
                state: RunState::Created,
                elapsed_ns: 0,
                snapshot: resources_at_start,
            }],
            finished: false,
        })
    }

    /// Mutate run identity before the session is finalized.
    pub fn identity_mut(&mut self) -> &mut RunIdentity {
        self.identity
            .as_mut()
            .expect("unfinished profile owns identity")
    }

    /// Record an explicit macro state transition.
    pub fn transition(&mut self, state: RunState) {
        let elapsed_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.transitions.push(StateTransition { state, elapsed_ns });
        self.resource_samples.push(ResourceSample {
            state,
            elapsed_ns,
            snapshot: process_resources(),
        });
    }

    /// Finish the session and return its complete structured record.
    pub fn finish(mut self, status: RunState) -> RunProfile {
        self.transition(status);
        set_enabled(false);
        let wall = self.started.elapsed();
        let finish_resources = self
            .resource_samples
            .last()
            .map_or(self.resources_at_start, |sample| sample.snapshot);
        let (input_bytes, input_units) = take_session_input_totals();
        let stages = take_session_stage_measurements();
        reset();
        let resource_samples = std::mem::take(&mut self.resource_samples);
        let states = state_measurements(&self.transitions, &resource_samples);
        let resources = resource_usage(
            self.resources_at_start,
            finish_resources,
            wall,
            &resource_samples,
        );
        let profile = RunProfile {
            schema: PROFILE_SCHEMA.to_string(),
            identity: self
                .identity
                .take()
                .expect("unfinished profile owns identity"),
            status,
            wall_time_ns: u64::try_from(wall.as_nanos()).unwrap_or(u64::MAX),
            input_bytes,
            input_units,
            stages,
            transitions: std::mem::take(&mut self.transitions),
            states,
            resource_samples,
            resources,
        };
        self.finished = true;
        SESSION_ACTIVE.store(false, Ordering::Release);
        profile
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.finished {
            set_enabled(false);
            reset();
            reset_session();
            SESSION_ACTIVE.store(false, Ordering::Release);
        }
    }
}
