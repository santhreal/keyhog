//! Record causal performance evidence for one KeyHog run.
//!
//! Start a [`Session`] at the beginning of the production operation. Record
//! macro state changes with [`Session::transition`]. Wrap measured work in
//! [`span`], then call [`Session::finish`] to produce a versioned [`RunProfile`].
//!
//! ```
//! use keyhog_profile::{RunIdentity, RunState, Session, Stage, span};
//!
//! let identity = RunIdentity::new(
//!     "0.5.49",
//!     "detector-digest",
//!     "config-digest",
//!     "filesystem",
//!     "small-text",
//!     "auto",
//! );
//! let mut session = Session::start(identity).expect("start profile");
//! session.transition(RunState::Scanning);
//! {
//!     let _read = span(Stage::SourceRead);
//!     std::hint::black_box(42);
//! }
//! let profile = session.finish(RunState::Completed);
//!
//! assert_eq!(profile.status, RunState::Completed);
//! assert_eq!(profile.stages[0].stage, Stage::SourceRead);
//! assert_eq!(profile.stages[0].calls, 1);
//! ```
//!
//! # Runtime ownership
//!
//! A session owns an isolated [`Runtime`]. The session enters that runtime on
//! the calling thread. Propagate a clone explicitly when work crosses a thread
//! boundary. This keeps concurrent runs isolated.
//!
//! ```
//! use keyhog_profile::{RunIdentity, RunState, Session, Stage, span};
//!
//! let identity = RunIdentity::new("0.5.49", "d", "c", "stdin", "stream", "auto");
//! let session = Session::start(identity).expect("start profile");
//! let runtime = session.runtime();
//! std::thread::spawn(move || runtime.scope(|| {
//!     let _scan = span(Stage::BackendDispatch);
//! }))
//! .join()
//! .expect("join worker");
//! let profile = session.finish(RunState::Completed);
//! assert_eq!(profile.stages[0].stage, Stage::BackendDispatch);
//! ```
//!
//! # Recording cost
//!
//! The disabled span path checks one relaxed atomic and does not read the clock.
//! Enabled spans update fixed atomic counters indexed by [`MetricId`]. They do
//! not allocate, hash metric names, or format text. Vector construction, JSON
//! serialization, and report analysis run only when counters are drained or a
//! session is finished.
//!
//! `cargo bench -p keyhog-profile --bench overhead_budget` enforces absolute
//! median budgets for disabled checks, aggregate spans, and causal spans. The
//! regular CI workflow runs this gate with an optimized benchmark build.
//!
//! # Metrics and collectors
//!
//! [`METRICS`] is the static registry for metric names, kinds, and units. A
//! collector implements [`SnapshotCollector`] and reports a
//! [`CollectorCapability`] before sampling. The default `process-metrics`
//! feature samples process CPU time, resident memory, virtual memory, and thread
//! count. Disable default features when you need stage timing without platform
//! process sampling. The profile then reports the collector as disabled instead
//! of silently emitting unavailable measurements.
//!
//! # Persisted records
//!
//! [`PROFILE_SCHEMA`] identifies the profile envelope. Every persisted component
//! also carries its own numeric version. Missing component versions decode as
//! version one for compatibility with early records. Compare identity fields,
//! collector capabilities, workload state, and metric units before comparing
//! measurements from two profiles.
//!
//! # Privacy
//!
//! The profiler records counts, durations, run identity, execution choices, and
//! process resources. Do not use source content, credentials, raw URLs, or
//! sensitive paths as identity labels. [`RunProfile::render_text`] and
//! [`RunProfile::to_json_pretty`] serialize the labels supplied by the caller.

mod allocation;
mod analysis;
mod collector;
mod comparison;
mod config;
mod detail;
mod hardware;
mod host_parallelism;
mod identity;
pub mod insight;
mod metrics;
mod resources;
mod runtime;
mod schema;
mod schema_v2;
mod session;
mod system;

pub use allocation::{
    allocation_snapshot, allocation_tracking_installed, reset_allocation_peaks, AllocationSlotV2,
    AllocationSnapshotV2, TrackingAllocator, ROOT_SLOT, STAGE_SLOTS,
};
pub use analysis::take_stage_measurements;
pub use collector::{
    CollectorAvailability, CollectorCapability, CollectorId, SnapshotCollector,
    COLLECTOR_CAPABILITY_VERSION,
};
pub use comparison::{
    compare_profiles, ComparisonDifference, ProfileComparison, StageComparison,
    COMPARISON_DIFFERENCE_VERSION, PROFILE_COMPARISON_VERSION, STAGE_COMPARISON_VERSION,
};
pub use config::{
    lookup_profile_name, resolve_profile_from_env, resolve_profile_from_env_value,
    resolve_profile_from_env_var, KnownProfile, ProfileConfig, ProfileName, PROFILE_ENV_VARS,
};
pub use detail::{detail, set_detail, Detail};
pub use hardware::{
    aggregate_span_hardware, milli_ratio, CpuFrequencySampleV2, HardwareCounterCollector,
    HardwareCounterSampleV2, HardwareCounterSetV2, HardwareFieldSourceV2, HardwareRunEvidenceV2,
    RunSpanHardwareV2, SchedulerCollector, SchedulerEvidenceV2, SchedulerSampleV2,
    SourcedEvidenceV2, SpanHardwareAggregationV2, SpanHardwareV2, StageHardwareV2, ThreadCpuV2,
    ThreadHardwareV2, ThreadUtilizationCollector, ThreadUtilizationSampleV2, ThreadUtilizationV2,
    TopologyCollector, TopologyEvidenceV2, UtilizationEvidenceV2, HARDWARE_EVIDENCE_V2_VERSION,
    MAX_SAMPLE_THREADS, MAX_UTILIZATION_SAMPLES, SPAN_HARDWARE_V2_VERSION,
};
pub use host_parallelism::{
    clear_host_parallelism_override, host_parallelism, logical_cpu_count, logical_cpus,
    set_forced_probe_failure, set_host_parallelism_override, HostParallelism, ParallelismProvenance,
    FALLBACK_LOGICAL_CPUS, HOST_PARALLELISM_VERSION,
};
pub use identity::{
    BuildIdentityInput, ConfigIdentityInput, DetectorIdentityInput, SourceIdentityInput,
    WorkloadIdentityInput,
};
pub use insight::{
    BackendAttributionV2, BottleneckKindV2, FindingV2, InsightCoverageV2, MemoryInsightV2,
    ParallelismInsightV2, PhaseInsightV2, RunInsightV2, SerialRegionV2, SerialScopeV2,
    StageAttributionV2, StageMemoryV2, ThroughputInsightV2, RUN_INSIGHT_V2_VERSION,
};
pub use metrics::{
    gpu_dispatch_decomposition_counters, gpu_dispatch_phase_counters, AnnotationId, CacheId,
    CounterId, EventId, GaugeId, IndexedCounterId, MacroStageId, MetricDescriptor, MetricId,
    MetricKind, MetricUnit, QueueId, RetryCause, GPU_DISPATCH_DECOMPOSITION_COUNTERS,
    GPU_DISPATCH_PHASE_COUNTERS, INDEXED_COUNTER_SLOTS, METRICS,
};
pub use runtime::{
    add_backend_dispatched_bytes, add_counter, add_derived_decoder_bytes, add_indexed_counter,
    add_input_bytes, add_input_units, add_stage_bytes, blocked, counter_span,
    current_causal_parent, current_runtime, current_task_id, current_work_origin, decision_timer,
    enabled, instrument_future, instrument_future_with_parent, record_annotation,
    record_batch_route, record_cache_hit, record_cache_miss, record_distribution, record_event,
    record_fs_metadata_latency_ns, record_fs_open_latency_ns, record_fs_read_latency_ns,
    record_io_cache_state, record_network_bytes, record_network_latency_ns, record_network_request,
    record_queue_depth_dequeue, record_queue_depth_enqueue, record_queue_dequeue,
    record_queue_enqueue, record_retained_buffer_bytes, record_retry, record_sampled_event, reset,
    serial_span, set_attribution, set_enabled, set_gauge, set_queue_depth, set_task_id,
    set_work_origin, span, span_with_parent, take_input_totals, take_metric_distributions,
    take_typed_metrics, Attribution, CausalParent, ContextGuard, CounterSpan, DecisionTimer,
    EventLossCounts, QueueLinkLossCounts, Runtime, SamplingPolicy, Span, MAX_ANNOTATIONS,
    MAX_BATCH_ROUTES, MAX_POINT_EVENTS, MAX_QUEUE_LINKS, MAX_RECORDED_SPANS,
};
pub use schema::{
    CacheState, DaemonState, ResourceSample, ResourceSnapshot, ResourceUsage, RunIdentity,
    RunProfile, RunState, Stage, StageMeasurement, StateMeasurement, StateTransition,
    WorkloadMeasurements, PROFILE_SCHEMA, RESOURCE_SAMPLE_VERSION, RESOURCE_SNAPSHOT_VERSION,
    RESOURCE_USAGE_VERSION, RUN_IDENTITY_VERSION, RUN_PROFILE_VERSION, STAGE_MEASUREMENT_VERSION,
    STATE_MEASUREMENT_VERSION, STATE_TRANSITION_VERSION, WORKLOAD_MEASUREMENTS_VERSION,
};
pub use schema_v2::{
    AnnotationV2, ArtifactIntegrityV2, BatchRouteV2, BlockedWaitRecordV2, BuildIdentityV2,
    CacheEffectivenessV2, CacheLayerKindV2, CacheLayerV2, CausalProfileV2, CausalRunIdentityV2,
    ConfigIdentityV2, CoverageStateV2, DaemonIdentityV2, DetectorIdentityV2, DistributionBucketV2,
    EventStreamV2, Evidence, EvidenceGap, HostIdentityV2, IndexedCounterRecordV2, LatencyBucketV2,
    LatencyDistributionV2, MetricDistributionV2, ObserverEffectV2, OutcomeIdentityV2, PointEventV2,
    ProducerIdentityV2, ProfileEnvelopeV2, QueueDepthV2, QueueLinkV2, RetryRecordV2,
    RouteIdentityV2, SchemaVersionV2, SourceIdentityV2, SpanRecordV2, StageConcurrencyV2,
    StageOverheadV2, TypedMetricRecordV2, WorkOrigin, WorkerImbalanceV2, WorkerLoadV2,
    WorkerOccupancyRowV2, WorkerOccupancyV2, WorkloadIdentityV2, CACHE_EFFECTIVENESS_V2_VERSION,
    CAUSAL_IDENTITY_V2_VERSION, CAUSAL_PROFILE_V2_VERSION, ESTIMATED_NS_PER_SPAN_EVENT,
    EVENT_SCHEMA_VERSION, EXPORTER_VERSION, INDEXED_COUNTER_V2_VERSION, METRIC_REGISTRY_VERSION,
    OBSERVER_EFFECT_V2_VERSION, PROFILE_ENVELOPE_V2_VERSION, PROFILE_SCHEMA_V2,
    PROFILE_SCHEMA_V2_MAJOR, PROFILE_SCHEMA_V2_MINOR, RETRY_RECORD_V2_VERSION,
    STAGE_CONCURRENCY_V2_VERSION, WORKER_OCCUPANCY_V2_VERSION,
};
pub use session::{Session, SessionActive};
pub use system::{
    AllocationEvidenceV2, AllocationTotalsV2, DecodeRetentionEvidenceV2, FaultEvidenceV2,
    IoCacheStateV2, IoEvidenceV2, MemoryEvidenceV2, NetworkEvidenceV2, NetworkProcessCountersV2,
    PressureEvidenceV2, PressureThermalCollector, PressureThermalSampleV2, StageAllocationV2,
    SystemIoCollector, SystemIoSampleV2, SystemRunEvidenceV2, ThermalEvidenceV2,
    SYSTEM_EVIDENCE_V2_VERSION,
};
