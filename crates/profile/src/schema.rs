use crate::collector::CollectorCapability;
use crate::metrics::{MacroStageId, MetricId, METRICS};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable wire schema for persisted profiling records.
pub const PROFILE_SCHEMA: &str = "keyhog-profile-v1";

const fn legacy_component_version() -> u16 {
    1
}

pub const STAGE_MEASUREMENT_VERSION: u16 = 1;
pub const RUN_IDENTITY_VERSION: u16 = 1;
pub const STATE_TRANSITION_VERSION: u16 = 1;
pub const RESOURCE_SAMPLE_VERSION: u16 = 1;
pub const RESOURCE_SNAPSHOT_VERSION: u16 = 2;
pub const STATE_MEASUREMENT_VERSION: u16 = 1;
pub const RESOURCE_USAGE_VERSION: u16 = 1;
pub const RUN_PROFILE_VERSION: u16 = 3;
pub const WORKLOAD_MEASUREMENTS_VERSION: u16 = 1;

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stable micro-function identifier shared by scanner, source, verifier, and reporter paths.
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
    /// Timing a probe scan to choose a backend, not scanning for credentials.
    AutorouteCalibration,
    /// Rescanning the seam between adjacent chunks so a match spanning the
    /// boundary is not lost. Separated from the phase-2 leaves it sits inside
    /// because seam work grows with chunk count, not with input size.
    BoundaryScan,
    /// Loading detector bytes, cache entries, and parsed specifications.
    DetectorLoad,
    /// Validating detector selection, policy, and effective corpus identity.
    DetectorValidate,
    /// Selecting the backend- and policy-specific execution plan generation.
    ExecutionPackSelect,
    /// Materializing the selected execution plan into the scanner runtime.
    ExecutionPackMap,
    /// Discovering backend hardware and runtime availability.
    BackendAcquire,
    /// Initializing the selected backend runtime and compiled databases.
    BackendInit,
    /// Releasing scanner plans, backend resources, and retained buffers.
    Teardown,
}

impl Stage {
    /// Every stage in stable wire order.
    pub const ALL: [Self; 34] = [
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
        Self::AutorouteCalibration,
        Self::BoundaryScan,
        Self::DetectorLoad,
        Self::DetectorValidate,
        Self::ExecutionPackSelect,
        Self::ExecutionPackMap,
        Self::BackendAcquire,
        Self::BackendInit,
        Self::Teardown,
    ];

    #[inline]
    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    /// Stable metric identifier shared by wire records and runtime storage.
    ///
    /// Named explicitly rather than derived from position, so a metric can be
    /// appended to the registry without silently re-pointing a stage.
    pub const fn metric_id(self) -> MetricId {
        match self {
            Self::SourceAcquire => MetricId::SourceAcquire,
            Self::SourceWalk => MetricId::SourceWalk,
            Self::SourceRead => MetricId::SourceRead,
            Self::Preprocess => MetricId::Preprocess,
            Self::Phase1Triggers => MetricId::Phase1Triggers,
            Self::BackendDispatch => MetricId::BackendDispatch,
            Self::HotPatterns => MetricId::HotPatterns,
            Self::ConfirmedPatterns => MetricId::ConfirmedPatterns,
            Self::Phase2Prefilter => MetricId::Phase2Prefilter,
            Self::Phase2KeywordAc => MetricId::Phase2KeywordAc,
            Self::Phase2SharedAc => MetricId::Phase2SharedAc,
            Self::Phase2AnchoredVerify => MetricId::Phase2AnchoredVerify,
            Self::Phase2WholeChunk => MetricId::Phase2WholeChunk,
            Self::GenericDetection => MetricId::GenericDetection,
            Self::Entropy => MetricId::Entropy,
            Self::MachineLearning => MetricId::MachineLearning,
            Self::Decode => MetricId::Decode,
            Self::Suppression => MetricId::Suppression,
            Self::LiveVerification => MetricId::LiveVerification,
            Self::Reporting => MetricId::Reporting,
            Self::SourceQueueWait => MetricId::SourceQueueWait,
            Self::IncrementalLookup => MetricId::IncrementalLookup,
            Self::BackendSelect => MetricId::BackendSelect,
            Self::ResultMerge => MetricId::ResultMerge,
            Self::ScannerQueueWait => MetricId::ScannerQueueWait,
            Self::AutorouteCalibration => MetricId::AutorouteCalibration,
            Self::BoundaryScan => MetricId::BoundaryScan,
            Self::DetectorLoad => MetricId::DetectorLoad,
            Self::DetectorValidate => MetricId::DetectorValidate,
            Self::ExecutionPackSelect => MetricId::ExecutionPackSelect,
            Self::ExecutionPackMap => MetricId::ExecutionPackMap,
            Self::BackendAcquire => MetricId::BackendAcquire,
            Self::BackendInit => MetricId::BackendInit,
            Self::Teardown => MetricId::Teardown,
        }
    }

    /// Stable text label used by human reports.
    pub const fn as_str(self) -> &'static str {
        METRICS[self.metric_id() as usize].name
    }

    /// Stable macro-stage identifier that owns this micro-function.
    pub const fn macro_stage_id(self) -> MacroStageId {
        match self {
            Self::SourceAcquire | Self::SourceWalk | Self::SourceRead | Self::SourceQueueWait => {
                MacroStageId::Acquire
            }
            Self::Preprocess
            | Self::Phase1Triggers
            | Self::BackendDispatch
            | Self::HotPatterns
            | Self::ConfirmedPatterns
            | Self::Phase2Prefilter
            | Self::Phase2KeywordAc
            | Self::Phase2SharedAc
            | Self::Phase2AnchoredVerify
            | Self::Phase2WholeChunk
            | Self::GenericDetection
            | Self::Entropy
            | Self::MachineLearning
            | Self::Decode
            | Self::IncrementalLookup
            | Self::BackendSelect
            | Self::ScannerQueueWait
            | Self::AutorouteCalibration
            | Self::BoundaryScan
            | Self::DetectorLoad
            | Self::DetectorValidate
            | Self::ExecutionPackSelect
            | Self::ExecutionPackMap
            | Self::BackendAcquire
            | Self::BackendInit
            | Self::Teardown => MacroStageId::Scan,
            Self::Suppression | Self::ResultMerge => MacroStageId::Resolve,
            Self::LiveVerification => MacroStageId::Verify,
            Self::Reporting => MacroStageId::Report,
        }
    }
}

/// One aggregate fixed-stage measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageMeasurement {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub stage: Stage,
    pub elapsed_ns: u64,
    pub calls: u64,
    pub attributed_ns: u64,
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
    #[serde(default = "legacy_component_version")]
    pub version: u16,
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
            version: RUN_IDENTITY_VERSION,
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
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub state: RunState,
    pub elapsed_ns: u64,
}

/// Process resource observation associated with a run-state boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSample {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub state: RunState,
    pub elapsed_ns: u64,
    pub snapshot: ResourceSnapshot,
}

/// Process resource observation at a macro boundary.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub cpu_time_ms: Option<u64>,
    pub resident_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub thread_count: Option<u64>,
    /// Kernel-maintained exact resident high water (VmHWM); version 2 field.
    #[serde(default)]
    pub resident_high_water_bytes: Option<u64>,
    /// Bytes swapped out at sample time (VmSwap); version 2 field.
    #[serde(default)]
    pub swap_bytes: Option<u64>,
}

impl Default for ResourceSnapshot {
    fn default() -> Self {
        Self {
            version: RESOURCE_SNAPSHOT_VERSION,
            cpu_time_ms: None,
            resident_bytes: None,
            virtual_bytes: None,
            thread_count: None,
            resident_high_water_bytes: None,
            swap_bytes: None,
        }
    }
}

/// One completed macro state with its wall time and boundary resource deltas.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StateMeasurement {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub state: RunState,
    pub elapsed_ns: u64,
    pub cpu_time_ms: Option<u64>,
    pub aggregate_cpu_milli_percent: Option<u64>,
    pub resident_start_bytes: Option<u64>,
    pub resident_end_bytes: Option<u64>,
    pub threads_start: Option<u64>,
    pub threads_end: Option<u64>,
}

/// Resource change across a completed profile session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub start: ResourceSnapshot,
    pub finish: ResourceSnapshot,
    pub max_observed_resident_bytes: Option<u64>,
    pub max_observed_threads: Option<u64>,
    pub aggregate_cpu_percent: Option<f64>,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            version: RESOURCE_USAGE_VERSION,
            start: ResourceSnapshot::default(),
            finish: ResourceSnapshot::default(),
            max_observed_resident_bytes: None,
            max_observed_threads: None,
            aggregate_cpu_percent: None,
        }
    }
}

/// Optional byte domains whose totals distinguish source, expansion, decode, and dispatch work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkloadMeasurements {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub container_bytes: Option<u64>,
    pub expanded_payload_bytes: Option<u64>,
    pub derived_decoder_bytes: Option<u64>,
    pub backend_dispatched_bytes: Option<u64>,
}

impl Default for WorkloadMeasurements {
    fn default() -> Self {
        Self {
            version: WORKLOAD_MEASUREMENTS_VERSION,
            container_bytes: None,
            expanded_payload_bytes: None,
            derived_decoder_bytes: None,
            backend_dispatched_bytes: None,
        }
    }
}

impl WorkloadMeasurements {
    pub(crate) fn measured(derived_decoder_bytes: u64, backend_dispatched_bytes: u64) -> Self {
        Self {
            version: WORKLOAD_MEASUREMENTS_VERSION,
            container_bytes: None,
            expanded_payload_bytes: None,
            derived_decoder_bytes: Some(derived_decoder_bytes),
            backend_dispatched_bytes: Some(backend_dispatched_bytes),
        }
    }
}

/// Complete replayable profile record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunProfile {
    #[serde(default = "legacy_component_version")]
    pub version: u16,
    pub schema: String,
    pub identity: RunIdentity,
    pub status: RunState,
    pub wall_time_ns: u64,
    pub input_bytes: u64,
    pub input_units: u64,
    #[serde(default)]
    pub workload: WorkloadMeasurements,
    pub stages: Vec<StageMeasurement>,
    pub transitions: Vec<StateTransition>,
    #[serde(default)]
    pub states: Vec<StateMeasurement>,
    #[serde(default)]
    pub collectors: Vec<CollectorCapability>,
    pub resource_samples: Vec<ResourceSample>,
    pub resources: ResourceUsage,
    /// CPU hardware evidence; absent in profiles recorded before version 2.
    #[serde(default = "legacy_hardware_gap")]
    pub hardware: crate::Evidence<crate::hardware::HardwareRunEvidenceV2>,
    /// Memory, IO, and system evidence; absent in profiles before version 3.
    #[serde(default = "legacy_system_gap")]
    pub system: crate::Evidence<crate::system::SystemRunEvidenceV2>,
    /// Compile surface invocations and loads across all 13 compiler surfaces.
    #[serde(default)]
    pub compile_surfaces: Vec<crate::schema_v2::CompileSurfaceRecordV2>,
}

fn legacy_system_gap() -> crate::Evidence<crate::system::SystemRunEvidenceV2> {
    crate::Evidence::unavailable(crate::EvidenceGap::LegacyV1NotRecorded)
}

fn legacy_hardware_gap() -> crate::Evidence<crate::hardware::HardwareRunEvidenceV2> {
    crate::Evidence::unavailable(crate::EvidenceGap::LegacyV1NotRecorded)
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
        for capability in &self.collectors {
            output.push_str(&format!(
                "collector {} availability={}",
                capability.collector.as_str(),
                capability.availability.as_str(),
            ));
            if let Some(detail) = &capability.detail {
                output.push_str(&format!(" detail={detail}"));
            }
            output.push('\n');
        }
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
