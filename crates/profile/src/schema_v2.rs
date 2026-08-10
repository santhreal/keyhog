use crate::{
    CacheState, CollectorCapability, DaemonState, ResourceSample, ResourceUsage, RunProfile,
    RunState, StageMeasurement, StateMeasurement, StateTransition,
};
use serde::{Deserialize, Serialize};

pub const PROFILE_SCHEMA_V2: &str = "keyhog-profile";
pub const PROFILE_SCHEMA_V2_MAJOR: u16 = 2;
pub const PROFILE_SCHEMA_V2_MINOR: u16 = 8;
pub const PROFILE_ENVELOPE_V2_VERSION: u16 = 1;
pub const CAUSAL_PROFILE_V2_VERSION: u16 = 8;
pub const CAUSAL_IDENTITY_V2_VERSION: u16 = 1;
pub const EVENT_SCHEMA_VERSION: u16 = 7;
pub const METRIC_REGISTRY_VERSION: u16 = 6;
pub const EXPORTER_VERSION: u16 = 1;
pub const STAGE_CONCURRENCY_V2_VERSION: u16 = 1;
pub const WORKER_OCCUPANCY_V2_VERSION: u16 = 1;
pub const CACHE_EFFECTIVENESS_V2_VERSION: u16 = 1;
pub const INDEXED_COUNTER_V2_VERSION: u16 = 1;
pub const RETRY_RECORD_V2_VERSION: u16 = 1;

/// Why a v2 evidence field has no measured value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceGap {
    LegacyV1NotRecorded,
    CollectorDisabled,
    PermissionDenied,
    Unsupported,
    Unavailable,
}

/// A measured value or an explicit reason why no value exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Evidence<T> {
    Recorded { value: T },
    Unavailable { reason: EvidenceGap },
}

impl<T> Evidence<T> {
    pub fn recorded(value: T) -> Self {
        Self::Recorded { value }
    }

    pub const fn unavailable(reason: EvidenceGap) -> Self {
        Self::Unavailable { reason }
    }
}

fn legacy_gap<T>() -> Evidence<T> {
    Evidence::unavailable(EvidenceGap::LegacyV1NotRecorded)
}

/// Independent major and minor version for one schema family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaVersionV2 {
    pub version: u16,
    pub major: u16,
    pub minor: u16,
}

/// Producer identity for the code that emitted an artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProducerIdentityV2 {
    pub version: u16,
    pub profile_crate_version: String,
    pub exporter_version: u16,
}

/// Digest protecting the canonical profile artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactIntegrityV2 {
    pub version: u16,
    pub algorithm: String,
    pub digest: String,
}

/// Self-describing envelope for a v2 causal profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileEnvelopeV2 {
    pub version: u16,
    pub schema: String,
    pub schema_version: SchemaVersionV2,
    pub event_schema_version: u16,
    pub metric_registry_version: u16,
    pub producer: ProducerIdentityV2,
    pub integrity: Evidence<ArtifactIntegrityV2>,
}

/// Exact host and operating environment used by one run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostIdentityV2 {
    pub version: u16,
    pub operating_system: Evidence<String>,
    pub kernel_version: Evidence<String>,
    pub architecture: Evidence<String>,
    pub cpu_model: Evidence<String>,
    pub logical_cpus: u32,
    pub physical_cores: Evidence<u32>,
    pub cpu_features_digest: Evidence<String>,
    pub affinity_digest: Evidence<String>,
    pub numa_digest: Evidence<String>,
}

/// Exact executable and toolchain identity used by one run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BuildIdentityV2 {
    pub version: u16,
    pub binary_version: String,
    pub binary_digest: Evidence<String>,
    pub source_revision: Evidence<String>,
    pub build_profile: Evidence<String>,
    pub target_triple: Evidence<String>,
    pub feature_digest: Evidence<String>,
    pub compiler_identity: Evidence<String>,
    pub allocator_identity: Evidence<String>,
    pub linked_backend_digest: Evidence<String>,
}

/// Detector corpus and compiled execution-plan identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DetectorIdentityV2 {
    pub version: u16,
    pub corpus_digest: String,
    pub compiled_plan_digest: Evidence<String>,
    pub enabled_detector_digest: Evidence<String>,
    pub backend_database_digest: Evidence<String>,
    pub external_provenance_digest: Evidence<String>,
}

/// Canonical resolved configuration and policy identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigIdentityV2 {
    pub version: u16,
    pub resolved_config_digest: String,
    pub policy_digest: Evidence<String>,
    pub preset: Evidence<String>,
    pub protection_state: Evidence<String>,
}

/// Safe source adapter and target identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceIdentityV2 {
    pub version: u16,
    pub adapters: Vec<String>,
    pub target_digest: Evidence<String>,
    pub partition_digest: Evidence<String>,
}

/// Measured workload shape used to classify comparable runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WorkloadIdentityV2 {
    pub version: u16,
    pub class: String,
    pub raw_source_bytes: u64,
    pub source_units: u64,
    pub container_bytes: Evidence<u64>,
    pub expanded_payload_bytes: Evidence<u64>,
    pub derived_decoder_bytes: Evidence<u64>,
    pub backend_dispatched_bytes: Evidence<u64>,
    pub size_bucket: Evidence<String>,
    pub fanout_bucket: Evidence<String>,
}

/// One actual route completed for a measured batch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BatchRouteV2 {
    pub version: u16,
    pub batch_sequence: u64,
    pub workload_key_digest: String,
    pub requested_backend: String,
    pub selected_backend: String,
    pub completed_backend: String,
    pub recovered_from_backend: Evidence<String>,
}

/// Requested, selected, completed, and recovered backend identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteIdentityV2 {
    pub version: u16,
    pub request_mode: String,
    pub requested_backend: String,
    pub selected_backend: Evidence<String>,
    pub completed_backend: Evidence<String>,
    pub autoroute_decision_digest: Evidence<String>,
    pub batches: Vec<BatchRouteV2>,
    /// Routes omitted after the retained-batch cap; defaults to 0 for older profiles.
    #[serde(default)]
    pub dropped_batches: u64,
}

impl RouteIdentityV2 {
    /// Build aggregate route identity from the exact completed batch records.
    pub fn from_recorded_batches(requested_backend: String, batches: Vec<BatchRouteV2>) -> Self {
        Self::from_recorded_batches_with_drops(requested_backend, batches, 0)
    }

    /// Build aggregate route identity, including explicit drop accounting.
    pub fn from_recorded_batches_with_drops(
        requested_backend: String,
        batches: Vec<BatchRouteV2>,
        dropped_batches: u64,
    ) -> Self {
        let request_mode = if requested_backend == "auto" {
            "autoroute"
        } else {
            "explicit"
        };
        Self {
            version: 1,
            request_mode: request_mode.to_owned(),
            selected_backend: aggregate_backend(&batches, |batch| &batch.selected_backend),
            completed_backend: aggregate_backend(&batches, |batch| &batch.completed_backend),
            requested_backend,
            autoroute_decision_digest: Evidence::unavailable(EvidenceGap::Unavailable),
            batches,
            dropped_batches,
        }
    }
}

fn aggregate_backend(
    batches: &[BatchRouteV2],
    backend: impl Fn(&BatchRouteV2) -> &str,
) -> Evidence<String> {
    let mut labels = batches.iter().map(backend);
    let Some(first) = labels.next() else {
        return Evidence::unavailable(EvidenceGap::Unavailable);
    };
    if labels.all(|label| label == first) {
        Evidence::recorded(first.to_owned())
    } else {
        Evidence::recorded("mixed".to_owned())
    }
}

/// Cache families whose preparation state changes run cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheLayerKindV2 {
    LegacyAggregate,
    Detector,
    Merkle,
    Autoroute,
    Verifier,
    Daemon,
    PageCache,
}

/// State and generation identity for one cache layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CacheLayerV2 {
    pub version: u16,
    pub layer: CacheLayerKindV2,
    pub state: CacheState,
    pub generation: Evidence<String>,
    pub digest: Evidence<String>,
}

/// Daemon mode and request linkage for one run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DaemonIdentityV2 {
    pub version: u16,
    pub state: DaemonState,
    pub generation: Evidence<String>,
    pub request_id: Evidence<String>,
    pub parent_request_id: Evidence<String>,
    pub ready_age_ns: Evidence<u64>,
}

/// Whether scanner coverage was complete, partial, or unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageStateV2 {
    Complete,
    Partial,
    Failed,
    Cancelled,
    Unknown,
}

/// Terminal outcome and result identity for one run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutcomeIdentityV2 {
    pub version: u16,
    pub status: RunState,
    pub coverage: CoverageStateV2,
    pub error_count: Evidence<u64>,
    pub exit_code: Evidence<i32>,
    pub findings_digest: Evidence<String>,
    pub report_digest: Evidence<String>,
}

impl OutcomeIdentityV2 {
    /// Construct terminal outcome evidence recorded by the production caller.
    pub fn recorded(
        status: RunState,
        coverage: CoverageStateV2,
        error_count: u64,
        exit_code: i32,
        findings_digest: Evidence<String>,
        report_digest: Evidence<String>,
    ) -> Self {
        Self {
            version: 1,
            status,
            coverage,
            error_count: Evidence::recorded(error_count),
            exit_code: Evidence::recorded(exit_code),
            findings_digest,
            report_digest,
        }
    }
}

/// Comparison identity joining every timing-relevant dimension.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalRunIdentityV2 {
    pub version: u16,
    pub run_id: String,
    pub parent_run_id: Evidence<String>,
    pub benchmark_pair_id: Evidence<String>,
    pub repeat_group_id: Evidence<String>,
    pub host: HostIdentityV2,
    pub build: BuildIdentityV2,
    pub detectors: DetectorIdentityV2,
    pub config: ConfigIdentityV2,
    pub source: SourceIdentityV2,
    pub workload: WorkloadIdentityV2,
    pub route: RouteIdentityV2,
    pub caches: Vec<CacheLayerV2>,
    pub daemon: DaemonIdentityV2,
    pub outcome: OutcomeIdentityV2,
    pub scanner_threads_requested: usize,
    pub reader_threads_requested: Evidence<usize>,
    pub reader_threads_resolved: Evidence<usize>,
}

/// Causal origin of the work measured by one span.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum WorkOrigin {
    /// Work performed directly on the caller's own input.
    #[default]
    Root = 0,
    /// Work performed inside an accepted decode-through input.
    Decoded = 1,
    /// Work performed on input derived from earlier pipeline output.
    Derived = 2,
    /// Work repeated after an earlier attempt failed or was recovered.
    Retried = 3,
}

impl WorkOrigin {
    /// Every work origin in stable wire order.
    pub const ALL: [Self; 4] = [Self::Root, Self::Decoded, Self::Derived, Self::Retried];

    /// Whether this origin counts as attributed (non-root) pipeline work.
    pub const fn is_attributed_work(self) -> bool {
        !matches!(self, Self::Root)
    }
}

/// One nested or linked causal interval.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpanRecordV2 {
    pub version: u16,
    pub span_id: u64,
    pub parent_span_id: Evidence<u64>,
    pub metric_id: crate::MetricId,
    pub start_ns: u64,
    pub inclusive_ns: u64,
    pub exclusive_ns: u64,
    pub thread_id: u64,
    pub task_id: Evidence<u64>,
    #[serde(default = "legacy_gap")]
    pub worker_id: Evidence<u64>,
    #[serde(default)]
    pub work_origin: WorkOrigin,
    /// Raw cycle and instruction readings captured at span begin and end.
    #[serde(default = "legacy_gap")]
    pub hardware: Evidence<crate::hardware::SpanHardwareV2>,
}

/// One exact logarithmic bucket of a caller-recorded value distribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DistributionBucketV2 {
    pub version: u16,
    pub lower_bound: u64,
    pub upper_bound: u64,
    pub count: u64,
}

/// Caller-recorded logarithmic distribution for one typed metric.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetricDistributionV2 {
    pub version: u16,
    pub metric_id: crate::MetricId,
    pub call_count: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub buckets: Vec<DistributionBucketV2>,
}

/// One matched producer enqueue and consumer dequeue through a bounded queue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueueLinkV2 {
    pub version: u16,
    pub queue: crate::QueueId,
    pub sequence: u64,
    pub producer_thread_id: u64,
    pub producer_elapsed_ns: u64,
    pub consumer_thread_id: u64,
    pub consumer_elapsed_ns: u64,
}

/// Current depth and high-water mark for one bounded queue slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueueDepthV2 {
    pub version: u16,
    pub queue: crate::QueueId,
    pub current: u64,
    pub high_water: u64,
    pub enqueues: u64,
    pub dequeues: u64,
}

/// Per-worker load observed from one counter shard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerLoadV2 {
    pub version: u16,
    pub worker_id: u64,
    pub calls: u64,
    pub elapsed_ns: u64,
}

/// Work-stealing imbalance evidence merged from every worker shard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerImbalanceV2 {
    pub version: u16,
    pub worker_count: u64,
    pub total_calls: u64,
    pub total_elapsed_ns: u64,
    /// Share of total calls handled by the busiest worker, in parts per million.
    pub max_share_ppm: u64,
    /// Upper-median per-worker share of total calls, in parts per million.
    pub median_share_ppm: u64,
    /// Share of registered workers that recorded zero calls, in parts per million.
    pub idle_share_ppm: u64,
    pub workers: Vec<WorkerLoadV2>,
}

/// Wall-clock occupancy of one micro-function across every worker.
///
/// `window_ns` is the span from the first start to the last end of any call to
/// this micro-function, so `elapsed_ns / window_ns` is the average number of
/// workers inside it while it was running. A stage whose concurrency is near
/// one ran serially even when the pool was large.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StageConcurrencyV2 {
    pub version: u16,
    pub metric_id: crate::MetricId,
    pub macro_stage_id: crate::MacroStageId,
    pub calls: u64,
    /// Summed inclusive time across every call on every worker.
    pub elapsed_ns: u64,
    /// First start to last end across every worker, relative to session start.
    pub window_ns: u64,
    pub first_start_ns: u64,
    pub last_end_ns: u64,
    /// Workers that recorded at least one call.
    pub worker_count: u64,
    /// Largest single-worker contribution to `elapsed_ns`.
    pub max_worker_elapsed_ns: u64,
    /// `elapsed_ns / window_ns` in thousandths; 1000 means strictly serial.
    pub concurrency_milli: u64,
    /// Time inside calls the caller explicitly declared serial.
    pub declared_serial_ns: u64,
    pub declared_serial_calls: u64,
    /// Bytes the caller attributed to this micro-function.
    pub bytes: u64,
}

/// Busy, blocked, and idle time for one worker across the whole session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerOccupancyRowV2 {
    pub version: u16,
    pub worker_id: u64,
    /// Time inside outermost non-blocked spans; nested spans are not counted twice.
    pub busy_ns: u64,
    /// Time inside outermost blocked-wait spans.
    pub blocked_ns: u64,
    /// Outermost spans entered by this worker.
    pub calls: u64,
}

/// Pool-wide busy versus idle accounting merged from every worker shard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerOccupancyV2 {
    pub version: u16,
    /// Workers that registered a counter shard, busy or not.
    pub worker_count: u64,
    /// Workers that recorded at least one outermost span.
    pub active_worker_count: u64,
    pub busy_ns: u64,
    pub blocked_ns: u64,
    pub calls: u64,
    pub busiest_busy_ns: u64,
    pub median_busy_ns: u64,
    pub workers: Vec<WorkerOccupancyRowV2>,
}

/// Hit and miss counts for one reuse cache.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheEffectivenessV2 {
    pub version: u16,
    pub cache: crate::CacheId,
    pub hits: u64,
    pub misses: u64,
    /// `hits / (hits + misses)` in parts per million.
    pub hit_rate_ppm: u64,
}

/// Retry attempts recorded for one cause.
///
/// `attempts` counts every attempt, not every operation that was eventually
/// retried, so a path that retries a thousand times reads as a thousand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetryRecordV2 {
    pub version: u16,
    pub cause: crate::RetryCause,
    pub attempts: u64,
}

/// One indexed counter family, summed per slot across every worker.
///
/// The caller owns the slot labels. `slots` is always
/// [`crate::INDEXED_COUNTER_SLOTS`] long so two runs diff positionally.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedCounterRecordV2 {
    pub version: u16,
    pub counter: crate::IndexedCounterId,
    pub slots: Vec<u64>,
    /// Records addressed to a slot outside the fixed range, never folded in.
    pub dropped_out_of_range: u64,
}

/// Blocked wait time attributed separately from runnable execution for one stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockedWaitRecordV2 {
    pub version: u16,
    pub metric_id: crate::MetricId,
    pub macro_stage_id: crate::MacroStageId,
    pub calls: u64,
    pub blocked_ns: u64,
}

/// One exact logarithmic latency bucket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LatencyBucketV2 {
    pub version: u16,
    pub lower_bound_ns: u64,
    pub upper_bound_ns: u64,
    pub count: u64,
}

/// Allocation-free hot-path call latency distribution for one micro-function.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LatencyDistributionV2 {
    pub version: u16,
    pub metric_id: crate::MetricId,
    pub macro_stage_id: crate::MacroStageId,
    pub call_count: u64,
    pub minimum_ns: u64,
    pub maximum_ns: u64,
    /// Nearest-rank p50, represented by the retained logarithmic bucket's upper bound.
    pub p50_ns: u64,
    /// Nearest-rank p90, represented by the retained logarithmic bucket's upper bound.
    pub p90_ns: u64,
    /// Nearest-rank p95, represented by the retained logarithmic bucket's upper bound.
    pub p95_ns: u64,
    /// Nearest-rank p99, represented by the retained logarithmic bucket's upper bound.
    pub p99_ns: u64,
    pub buckets: Vec<LatencyBucketV2>,
}

/// One typed counter or gauge materialized from fixed runtime storage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TypedMetricRecordV2 {
    pub version: u16,
    pub metric_id: crate::MetricId,
    pub kind: crate::MetricKind,
    pub value: u64,
}

/// One bounded instantaneous event with a typed numeric payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PointEventV2 {
    pub version: u16,
    pub sequence: u64,
    pub event_id: crate::EventId,
    pub elapsed_ns: u64,
    pub thread_id: u64,
    pub value: u64,
    #[serde(default = "legacy_gap")]
    pub task_id: Evidence<u64>,
    #[serde(default = "legacy_gap")]
    pub worker_id: Evidence<u64>,
}

/// One bounded typed numeric annotation on the run timeline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnnotationV2 {
    pub version: u16,
    pub sequence: u64,
    pub annotation_id: crate::AnnotationId,
    pub elapsed_ns: u64,
    pub thread_id: u64,
    pub value: u64,
    #[serde(default = "legacy_gap")]
    pub task_id: Evidence<u64>,
    #[serde(default = "legacy_gap")]
    pub worker_id: Evidence<u64>,
}

/// Bounded event stream with explicit availability and loss accounting.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventStreamV2 {
    pub version: u16,
    pub availability: Evidence<bool>,
    pub dropped_events: u64,
    #[serde(default)]
    pub dropped_span_events: u64,
    #[serde(default)]
    pub dropped_point_events: u64,
    #[serde(default)]
    pub dropped_annotations: u64,
    #[serde(default)]
    pub sampled_out_events: u64,
    pub spans: Vec<SpanRecordV2>,
    #[serde(default)]
    pub point_events: Vec<PointEventV2>,
    #[serde(default)]
    pub annotations: Vec<AnnotationV2>,
}

/// Versioned causal profile envelope and measurements.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalProfileV2 {
    pub version: u16,
    pub envelope: ProfileEnvelopeV2,
    pub identity: CausalRunIdentityV2,
    pub status: RunState,
    pub wall_time_ns: u64,
    pub stages: Vec<StageMeasurement>,
    pub transitions: Vec<StateTransition>,
    pub states: Vec<StateMeasurement>,
    pub collectors: Vec<CollectorCapability>,
    pub resource_samples: Vec<ResourceSample>,
    pub resources: ResourceUsage,
    #[serde(default)]
    pub typed_metrics: Vec<TypedMetricRecordV2>,
    #[serde(default)]
    pub latency_distributions: Vec<LatencyDistributionV2>,
    /// Wall-clock occupancy per micro-function; empty on profiles before 2.8.
    #[serde(default)]
    pub stage_concurrency: Vec<StageConcurrencyV2>,
    /// Per-worker busy and blocked time; absent on profiles before 2.8.
    #[serde(default)]
    pub worker_occupancy: Option<WorkerOccupancyV2>,
    /// Queue depth high-water evidence; empty on profiles before 2.8.
    #[serde(default)]
    pub queue_depths: Vec<QueueDepthV2>,
    /// Per-stage blocked wait time; empty on profiles before 2.8.
    #[serde(default)]
    pub blocked_waits: Vec<BlockedWaitRecordV2>,
    /// Reuse-cache hit rates; empty on profiles before 2.8.
    #[serde(default)]
    pub caches: Vec<CacheEffectivenessV2>,
    /// Indexed counter families; empty on profiles before 2.8.
    #[serde(default)]
    pub indexed_counters: Vec<IndexedCounterRecordV2>,
    /// Retry attempts by cause; empty on profiles before 2.8.
    #[serde(default)]
    pub retries: Vec<RetryRecordV2>,
    /// Derived bottleneck analysis; absent on profiles before 2.8.
    #[serde(default)]
    pub insight: Option<crate::insight::RunInsightV2>,
    pub events: EventStreamV2,
    /// CPU hardware evidence collected across the run.
    #[serde(default = "legacy_gap")]
    pub hardware: Evidence<crate::hardware::HardwareRunEvidenceV2>,
    /// Memory, IO, and system evidence collected across the run.
    #[serde(default = "legacy_gap")]
    pub system: Evidence<crate::system::SystemRunEvidenceV2>,
}

impl CausalProfileV2 {
    /// Migrate a v1 aggregate profile and capture build evidence available to this executable.
    pub fn from_v1(profile: RunProfile) -> Self {
        let build = BuildIdentityV2::capture_legacy(&profile.identity.binary_version);
        Self::from_v1_with_build(profile, build)
    }

    /// Migrate a v1 aggregate profile with exact final-binary build identity.
    pub fn from_v1_with_build(profile: RunProfile, build: BuildIdentityV2) -> Self {
        let RunProfile {
            identity,
            status,
            wall_time_ns,
            input_bytes,
            input_units,
            workload,
            stages,
            transitions,
            states,
            collectors,
            resource_samples,
            resources,
            hardware,
            system,
            ..
        } = profile;
        let selected_backend = identity
            .backend_selected
            .clone()
            .map_or_else(legacy_gap, Evidence::recorded);
        let reader_threads_requested = identity
            .reader_threads
            .map_or_else(legacy_gap, Evidence::recorded);
        let causal_identity = CausalRunIdentityV2 {
            version: CAUSAL_IDENTITY_V2_VERSION,
            run_id: identity.run_id,
            parent_run_id: legacy_gap(),
            benchmark_pair_id: legacy_gap(),
            repeat_group_id: legacy_gap(),
            host: HostIdentityV2::capture(),
            build,
            detectors: DetectorIdentityV2 {
                version: 1,
                corpus_digest: identity.detector_digest,
                compiled_plan_digest: legacy_gap(),
                enabled_detector_digest: legacy_gap(),
                backend_database_digest: legacy_gap(),
                external_provenance_digest: legacy_gap(),
            },
            config: ConfigIdentityV2 {
                version: 1,
                resolved_config_digest: identity.config_digest,
                policy_digest: legacy_gap(),
                preset: legacy_gap(),
                protection_state: legacy_gap(),
            },
            source: SourceIdentityV2 {
                version: 1,
                adapters: vec![identity.source_kind],
                target_digest: legacy_gap(),
                partition_digest: legacy_gap(),
            },
            workload: WorkloadIdentityV2::capture(crate::WorkloadIdentityInput {
                class: &identity.workload_class,
                raw_source_bytes: input_bytes,
                source_units: input_units,
                container_bytes: workload.container_bytes,
                expanded_payload_bytes: workload.expanded_payload_bytes,
                derived_decoder_bytes: workload.derived_decoder_bytes,
                backend_dispatched_bytes: workload.backend_dispatched_bytes,
            }),
            route: RouteIdentityV2 {
                version: 1,
                request_mode: "legacy-v1".to_owned(),
                requested_backend: identity.backend_requested,
                selected_backend,
                completed_backend: legacy_gap(),
                autoroute_decision_digest: legacy_gap(),
                batches: Vec::new(),
                dropped_batches: 0,
            },
            caches: vec![CacheLayerV2 {
                version: 1,
                layer: CacheLayerKindV2::LegacyAggregate,
                state: identity.cache_state,
                generation: legacy_gap(),
                digest: legacy_gap(),
            }],
            daemon: DaemonIdentityV2 {
                version: 1,
                state: identity.daemon_state,
                generation: legacy_gap(),
                request_id: legacy_gap(),
                parent_request_id: legacy_gap(),
                ready_age_ns: legacy_gap(),
            },
            outcome: OutcomeIdentityV2 {
                version: 1,
                status,
                coverage: CoverageStateV2::Unknown,
                error_count: legacy_gap(),
                exit_code: legacy_gap(),
                findings_digest: legacy_gap(),
                report_digest: legacy_gap(),
            },
            scanner_threads_requested: identity.scanner_threads,
            reader_threads_requested,
            reader_threads_resolved: legacy_gap(),
        };
        Self {
            version: CAUSAL_PROFILE_V2_VERSION,
            envelope: ProfileEnvelopeV2 {
                version: PROFILE_ENVELOPE_V2_VERSION,
                schema: PROFILE_SCHEMA_V2.to_owned(),
                schema_version: SchemaVersionV2 {
                    version: 1,
                    major: PROFILE_SCHEMA_V2_MAJOR,
                    minor: PROFILE_SCHEMA_V2_MINOR,
                },
                event_schema_version: EVENT_SCHEMA_VERSION,
                metric_registry_version: METRIC_REGISTRY_VERSION,
                producer: ProducerIdentityV2 {
                    version: 1,
                    profile_crate_version: env!("CARGO_PKG_VERSION").to_owned(),
                    exporter_version: EXPORTER_VERSION,
                },
                integrity: legacy_gap(),
            },
            identity: causal_identity,
            status,
            wall_time_ns,
            stages,
            transitions,
            states,
            collectors,
            resource_samples,
            resources,
            typed_metrics: Vec::new(),
            latency_distributions: Vec::new(),
            stage_concurrency: Vec::new(),
            worker_occupancy: None,
            queue_depths: Vec::new(),
            blocked_waits: Vec::new(),
            caches: Vec::new(),
            indexed_counters: Vec::new(),
            retries: Vec::new(),
            insight: None,
            events: EventStreamV2 {
                version: 3,
                availability: legacy_gap(),
                dropped_events: 0,
                dropped_span_events: 0,
                dropped_point_events: 0,
                dropped_annotations: 0,
                sampled_out_events: 0,
                spans: Vec::new(),
                point_events: Vec::new(),
                annotations: Vec::new(),
            },
            hardware,
            system,
        }
    }
}
