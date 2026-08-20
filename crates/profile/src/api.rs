//! Curated public re-export surface for `keyhog-profile`.

pub use crate::allocation::{
    allocation_snapshot, allocation_tracking_installed, reset_allocation_peaks, AllocationSlotV2,
    AllocationSnapshotV2, TrackingAllocator, ROOT_SLOT, STAGE_SLOTS,
};
pub use crate::analysis::take_stage_measurements;
pub use crate::collector::{
    CollectorAvailability, CollectorCapability, CollectorId, SnapshotCollector,
    COLLECTOR_CAPABILITY_VERSION,
};
pub use crate::comparison::{
    compare_profiles, ComparisonDifference, ProfileComparison, StageComparison,
    COMPARISON_DIFFERENCE_VERSION, PROFILE_COMPARISON_VERSION, STAGE_COMPARISON_VERSION,
};
pub use crate::config::{
    lookup_profile_name, resolve_profile_from_env, resolve_profile_from_env_value,
    resolve_profile_from_env_var, KnownProfile, ProfileConfig, ProfileName, PROFILE_ENV_VARS,
};
pub use crate::detail::{detail, set_detail, Detail};
pub use crate::hardware::{
    aggregate_span_hardware, milli_ratio, CpuFrequencySampleV2, HardwareCounterCollector,
    HardwareCounterSampleV2, HardwareCounterSetV2, HardwareFieldSourceV2, HardwareRunEvidenceV2,
    RunSpanHardwareV2, SchedulerCollector, SchedulerEvidenceV2, SchedulerSampleV2,
    SourcedEvidenceV2, SpanHardwareAggregationV2, SpanHardwareV2, StageHardwareV2, ThreadCpuV2,
    ThreadHardwareV2, ThreadUtilizationCollector, ThreadUtilizationSampleV2, ThreadUtilizationV2,
    TopologyCollector, TopologyEvidenceV2, UtilizationEvidenceV2, HARDWARE_EVIDENCE_V2_VERSION,
    MAX_SAMPLE_THREADS, MAX_UTILIZATION_SAMPLES, SPAN_HARDWARE_V2_VERSION,
};
pub use crate::host_parallelism::{
    clear_host_parallelism_override, host_parallelism, logical_cpu_count, logical_cpus,
    set_forced_probe_failure, set_host_parallelism_override, HostParallelism,
    ParallelismProvenance, FALLBACK_LOGICAL_CPUS, HOST_PARALLELISM_VERSION,
};
pub use crate::identity::{
    BuildIdentityInput, ConfigIdentityInput, DetectorIdentityInput, SourceIdentityInput,
    WorkloadIdentityInput,
};
pub use crate::insight::{
    BackendAttributionV2, BottleneckKindV2, FindingV2, InsightCoverageV2, MemoryInsightV2,
    ParallelismInsightV2, PhaseInsightV2, RunInsightV2, SerialRegionV2, SerialScopeV2,
    StageAttributionV2, StageMemoryV2, ThroughputInsightV2, RUN_INSIGHT_V2_VERSION,
};
pub use crate::metrics::{
    gpu_dispatch_decomposition_counters, gpu_dispatch_phase_counters, AnnotationId, CacheId,
    CompilePhase, CompileSurfaceId, CounterId, EventId, GaugeId, IndexedCounterId, MacroStageId,
    MetricDescriptor, MetricId, MetricKind, MetricUnit, QueueId, RetryCause,
    GPU_DISPATCH_DECOMPOSITION_COUNTERS, GPU_DISPATCH_PHASE_COUNTERS, INDEXED_COUNTER_SLOTS,
    METRICS,
};
pub use crate::runtime::{
    active_compile_phase, add_backend_dispatched_bytes, add_counter, add_derived_decoder_bytes,
    add_indexed_counter, add_input_bytes, add_input_units, add_stage_bytes, blocked, cache_hits,
    cache_misses, compile_surface_reports, counter_span, current_causal_parent, current_runtime,
    current_task_id, current_work_origin, decision_timer, enabled, instrument_future,
    instrument_future_with_parent, record_annotation, record_batch_route, record_cache_hit,
    record_cache_miss, record_compile_surface_invocation,
    record_compile_surface_invocation_with_phase, record_compile_surface_load, record_distribution,
    record_event, record_fs_metadata_latency_ns, record_fs_open_latency_ns,
    record_fs_read_latency_ns, record_io_cache_state, record_network_bytes,
    record_network_latency_ns, record_network_request, record_queue_depth_dequeue,
    record_queue_depth_enqueue, record_queue_dequeue, record_queue_enqueue,
    record_retained_buffer_bytes, record_retry, record_sampled_event, reset, serial_span,
    set_attribution, set_compile_phase, set_enabled, set_gauge, set_queue_depth, set_task_id,
    set_work_origin, span, span_with_parent, take_input_totals, take_metric_distributions,
    take_typed_metrics, total_runtime_compiles, Attribution, CausalParent, ContextGuard,
    CounterSpan, DecisionTimer, EventLossCounts, QueueLinkLossCounts, Runtime, SamplingPolicy,
    Span, MAX_ANNOTATIONS, MAX_BATCH_ROUTES, MAX_POINT_EVENTS, MAX_QUEUE_LINKS, MAX_RECORDED_SPANS,
};
pub use crate::schema::{
    CacheState, DaemonState, ResourceSample, ResourceSnapshot, ResourceUsage, RunIdentity,
    RunProfile, RunState, Stage, StageMeasurement, StateMeasurement, StateTransition,
    WorkloadMeasurements, PROFILE_SCHEMA, RESOURCE_SAMPLE_VERSION, RESOURCE_SNAPSHOT_VERSION,
    RESOURCE_USAGE_VERSION, RUN_IDENTITY_VERSION, RUN_PROFILE_VERSION, STAGE_MEASUREMENT_VERSION,
    STATE_MEASUREMENT_VERSION, STATE_TRANSITION_VERSION, WORKLOAD_MEASUREMENTS_VERSION,
};
pub use crate::schema_v2::{
    AnnotationV2, ArtifactIntegrityV2, BatchRouteV2, BlockedWaitRecordV2, BuildIdentityV2,
    CacheEffectivenessV2, CacheLayerKindV2, CacheLayerV2, CausalProfileV2, CausalRunIdentityV2,
    CompileSurfaceRecordV2, ConfigIdentityV2, CoverageStateV2, DaemonIdentityV2,
    DetectorIdentityV2, DistributionBucketV2, EventStreamV2, Evidence, EvidenceGap, HostIdentityV2,
    IndexedCounterRecordV2, LatencyBucketV2, LatencyDistributionV2, MetricDistributionV2,
    ObserverEffectV2, OutcomeIdentityV2, PointEventV2, ProducerIdentityV2, ProfileEnvelopeV2,
    QueueDepthV2, QueueLinkV2, RetryRecordV2, RouteIdentityV2, SchemaVersionV2, SourceIdentityV2,
    SpanRecordV2, StageConcurrencyV2, StageOverheadV2, TypedMetricRecordV2, WorkOrigin,
    WorkerImbalanceV2, WorkerLoadV2, WorkerOccupancyRowV2, WorkerOccupancyV2, WorkloadIdentityV2,
    CACHE_EFFECTIVENESS_V2_VERSION, CAUSAL_IDENTITY_V2_VERSION, CAUSAL_PROFILE_V2_VERSION,
    COMPILE_SURFACE_RECORD_V2_VERSION, ESTIMATED_NS_PER_SPAN_EVENT, EVENT_SCHEMA_VERSION,
    EXPORTER_VERSION, INDEXED_COUNTER_V2_VERSION, METRIC_REGISTRY_VERSION,
    OBSERVER_EFFECT_V2_VERSION, PROFILE_ENVELOPE_V2_VERSION, PROFILE_SCHEMA_V2,
    PROFILE_SCHEMA_V2_MAJOR, PROFILE_SCHEMA_V2_MINOR, RETRY_RECORD_V2_VERSION,
    STAGE_CONCURRENCY_V2_VERSION, WORKER_OCCUPANCY_V2_VERSION,
};
pub use crate::session::{Session, SessionActive};
pub use crate::system::{
    AllocationEvidenceV2, AllocationTotalsV2, DecodeRetentionEvidenceV2, FaultEvidenceV2,
    IoCacheStateV2, IoEvidenceV2, MemoryEvidenceV2, NetworkEvidenceV2, NetworkProcessCountersV2,
    PressureEvidenceV2, PressureThermalCollector, PressureThermalSampleV2, StageAllocationV2,
    SystemIoCollector, SystemIoSampleV2, SystemRunEvidenceV2, ThermalEvidenceV2,
    SYSTEM_EVIDENCE_V2_VERSION,
};
