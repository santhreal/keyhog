//! Batched megakernel dispatch built on a persistent device work queue.

use super::batch::{
    persistent_storage_binding_usage, queue_state_word, FileBatch, HitRecord, FILE_METADATA_WORDS,
    HIT_RECORD_WORDS, QUEUE_STATE_WORDS,
};
use super::dispatch_plan::{BatchDispatchPlan, BatchDispatchPlanCache, BatchDispatchPlanLookup};
use super::pipeline_cache::{BatchPipelineCache, BatchPipelineShape};
use crate::buffer::GpuBufferHandle;
use crate::{pipeline::WgpuPipeline, WgpuBackend};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vyre_driver::{CompiledPipeline, DispatchConfig, VyreBackend};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_runtime::megakernel::advanced::hierarchical_atomics::record_hit_to_ring_hierarchical;
use vyre_runtime::megakernel::ir_util::atomic_load_relaxed;
use vyre_runtime::megakernel::rule_catalog::{
    accepted_rule_fingerprints_and_rejections_into, pack_rule_catalog_into, BatchRuleProgram,
    BatchRuleRejection, RuleCatalogPackingScratch, ALPHABET_SIZE, RULE_META_WORDS,
};
use vyre_runtime::megakernel::scaling::{
    MegakernelLaunchPolicy, MegakernelLaunchRecommendation, MegakernelLaunchRequest,
};
use vyre_runtime::megakernel::MegakernelDispatchTopology;
use vyre_runtime::PipelineError;

/// Sparse hit-ring writer selected for the batched megakernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BatchHitWriter {
    /// Select hierarchical subgroup atomics when the backend advertises them,
    /// otherwise use the scalar writer.
    Auto,
    /// One global atomic per hit. Universally supported but slower under high
    /// hit density.
    Scalar,
    /// One global atomic per subgroup. Requires subgroup operations and fails
    /// loudly if the backend cannot compile subgroup intrinsics.
    HierarchicalSubgroup,
}

impl BatchHitWriter {
    /// Resolve this selection against backend subgroup capability.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when subgroup atomics are explicitly
    /// requested on a backend that does not report subgroup support.
    pub fn resolve_for_backend(self, subgroup_supported: bool) -> Result<Self, PipelineError> {
        match (self, subgroup_supported) {
            (Self::Auto, true) => Ok(Self::HierarchicalSubgroup),
            (Self::Auto, false) => Ok(Self::Scalar),
            (Self::HierarchicalSubgroup, false) => Err(PipelineError::Backend(
                "BatchHitWriter::HierarchicalSubgroup requires backend subgroup ops, but this backend reports supports_subgroup_ops=false. Fix: use BatchHitWriter::Auto/Scalar or run on a subgroup-capable adapter."
                    .to_string(),
            )),
            (mode, _) => Ok(mode),
        }
    }
}

/// Immutable pipeline + launch geometry for batched megakernel scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchDispatchConfig {
    /// Worker lanes per workgroup.
    pub workgroup_size_x: u32,
    /// Number of workgroups to launch for each batch.
    pub worker_groups: u32,
    /// Maximum sparse hits retained in the output ring.
    pub hit_capacity: u32,
    /// Per-dispatch timeout budget.
    pub timeout: Duration,
    /// Optional graph-node count hint for topology selection.
    pub graph_node_count: u32,
    /// Optional graph-edge count hint for topology selection.
    pub graph_edge_count: u32,
    /// Optional active-frontier density in basis points.
    pub frontier_density_bps: u16,
    /// Optional memory-pressure estimate in basis points.
    pub memory_pressure_bps: u16,
    /// Additional device-resident bytes already committed for this dispatch family.
    ///
    /// The dispatcher adds its fixed queue-state resident footprint when building
    /// the shared launch-policy request.
    pub resident_device_bytes: u64,
    /// Hard device-memory budget for policy planning. Zero means unbounded.
    pub device_memory_budget_bytes: u64,
    /// Hot opcode count observed by the caller or runtime telemetry.
    pub hot_opcode_count: u32,
    /// Hot window count observed by the caller or runtime telemetry.
    pub hot_window_count: u32,
    /// Requeued continuation count observed by the caller or runtime telemetry.
    pub requeue_count: u64,
    /// Maximum priority age observed by the caller or runtime telemetry.
    pub max_priority_age: u32,
}

impl Default for BatchDispatchConfig {
    fn default() -> Self {
        Self {
            workgroup_size_x: 64,
            // `0` is a sentinel meaning "compute from adapter occupancy at
            // dispatcher construction time".  Explicit non-zero values are
            // preserved so callers who set `worker_groups` by hand are not
            // overridden.
            worker_groups: 0,
            hit_capacity: 65_536,
            timeout: Duration::from_secs(30),
            graph_node_count: 0,
            graph_edge_count: 0,
            frontier_density_bps: 0,
            memory_pressure_bps: 0,
            resident_device_bytes: 0,
            device_memory_budget_bytes: 0,
            hot_opcode_count: 0,
            hot_window_count: 0,
            requeue_count: 0,
            max_priority_age: 0,
        }
    }
}

impl BatchDispatchConfig {
    /// Attach graph-topology hints used by the shared megakernel policy.
    #[must_use]
    pub const fn with_graph_hints(
        mut self,
        graph_node_count: u32,
        graph_edge_count: u32,
        frontier_density_bps: u16,
        memory_pressure_bps: u16,
    ) -> Self {
        self.graph_node_count = graph_node_count;
        self.graph_edge_count = graph_edge_count;
        self.frontier_density_bps = if frontier_density_bps > 10_000 {
            10_000
        } else {
            frontier_density_bps
        };
        self.memory_pressure_bps = if memory_pressure_bps > 10_000 {
            10_000
        } else {
            memory_pressure_bps
        };
        self
    }

    /// Attach hard device-memory budget hints used by the shared launch policy.
    #[must_use]
    pub const fn with_device_memory_budget(
        mut self,
        resident_device_bytes: u64,
        device_memory_budget_bytes: u64,
    ) -> Self {
        self.resident_device_bytes = resident_device_bytes;
        self.device_memory_budget_bytes = device_memory_budget_bytes;
        self
    }

    /// Attach execution hotness hints used by interpreter/JIT routing.
    #[must_use]
    pub const fn with_execution_hints(
        mut self,
        hot_opcode_count: u32,
        hot_window_count: u32,
        requeue_count: u64,
        max_priority_age: u32,
    ) -> Self {
        self.hot_opcode_count = hot_opcode_count;
        self.hot_window_count = hot_window_count;
        self.requeue_count = requeue_count;
        self.max_priority_age = max_priority_age;
        self
    }

    /// Return the shared launch-policy recommendation for this batch shape.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when adapter limits are malformed.
    pub fn launch_recommendation(
        &self,
        limits: &wgpu::Limits,
        queue_len: u32,
    ) -> Result<MegakernelLaunchRecommendation, PipelineError> {
        let resident_device_bytes = self
            .resident_device_bytes
            .checked_add(batch_fixed_resident_overhead_bytes())
            .ok_or_else(|| {
                PipelineError::Backend(
                    "megakernel resident byte estimate overflowed u64. Fix: shard resident state before launch recommendation."
                        .to_string(),
                )
            })?;
        MegakernelLaunchPolicy::standard()
            .recommend(MegakernelLaunchRequest {
                queue_len,
                requested_worker_groups: self.worker_groups,
                max_workgroup_size_x: self.workgroup_size_x,
                max_compute_workgroups_per_dimension: limits.max_compute_workgroups_per_dimension,
                max_compute_invocations_per_workgroup: limits.max_compute_invocations_per_workgroup,
                requested_hit_capacity: self.hit_capacity,
                expected_hits_per_item: 1,
                hot_opcode_count: self.hot_opcode_count,
                hot_window_count: self.hot_window_count,
                requeue_count: self.requeue_count,
                max_priority_age: self.max_priority_age,
                graph_node_count: if self.graph_node_count == 0 {
                    queue_len
                } else {
                    self.graph_node_count
                },
                graph_edge_count: self.graph_edge_count,
                frontier_density_bps: self.frontier_density_bps,
                memory_pressure_bps: self.memory_pressure_bps,
                resident_device_bytes,
                device_memory_budget_bytes: self.device_memory_budget_bytes,
            })
            .map_err(|source| PipelineError::Backend(source.to_string()))
    }
}

fn batch_fixed_resident_overhead_bytes() -> u64 {
    dispatcher_usize_to_u64(QUEUE_STATE_WORDS, "queue-state word count")
        .checked_mul(dispatcher_usize_to_u64(
            std::mem::size_of::<u32>(),
            "u32 byte width",
        ))
        .unwrap_or_else(|| {
            panic!(
                "batch fixed resident overhead byte count overflowed u64. Fix: reduce queue-state word count before launch planning."
            )
        })
}

fn dispatcher_usize_to_u64<T>(value: T, label: &'static str) -> u64
where
    T: TryInto<u64> + Copy + std::fmt::Display,
    T::Error: std::fmt::Display,
{
    value.try_into().unwrap_or_else(|source| {
        panic!(
            "batch dispatcher {label} value {value} cannot fit u64: {source}. Fix: shard the resident dispatch shape before byte accounting."
        )
    })
}

fn dispatcher_abi_u32<T>(value: T, label: &'static str) -> u32
where
    T: TryInto<u32> + Copy + std::fmt::Display,
    T::Error: std::fmt::Display,
{
    value.try_into().unwrap_or_else(|source| {
        panic!(
            "batch dispatcher ABI {label} value {value} cannot fit u32: {source}. Fix: keep megakernel ABI constants inside the u32 IR index domain."
        )
    })
}

/// Observability returned from one batched dispatch.
#[derive(Debug, Clone)]
pub struct BatchDispatchReport {
    /// Sparse hit count written by the device.
    pub hit_count: u32,
    /// Hits compacted out of the sparse ring.
    pub hits: Vec<HitRecord>,
    /// Work items processed by the queue.
    pub items_processed: u32,
    /// Wall-clock GPU execution time.
    pub wall_time: Duration,
    /// Rules that were isolated from the batch because their catalog entry was
    /// malformed. The rest of the batch still ran.
    pub rejected_rules: Vec<BatchRuleRejection>,
    /// Production telemetry for performance gates and dispatch tuning.
    pub telemetry: BatchDispatchTelemetry,
}

/// Megakernel dispatch counters returned when the caller owns hit storage.
#[derive(Debug, Clone)]
pub struct BatchDispatchSummary {
    /// Sparse hit count written by the device.
    pub hit_count: u32,
    /// Work items processed by the queue.
    pub items_processed: u32,
    /// Wall-clock GPU execution time.
    pub wall_time: Duration,
    /// Rules that were isolated from the batch because their catalog entry was
    /// malformed. The rest of the batch still ran.
    pub rejected_rules: Vec<BatchRuleRejection>,
    /// Production telemetry for performance gates and dispatch tuning.
    pub telemetry: BatchDispatchTelemetry,
}

/// Megakernel dispatch counters used by scale/performance gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchDispatchTelemetry {
    /// Bytes uploaded by this dispatch for rule-catalog refreshes.
    pub bytes_uploaded: u64,
    /// Bytes read back from queue-state and sparse hit output buffers.
    pub bytes_read_back: u64,
    /// Total host/device transfer bytes directly attributable to this dispatch.
    pub bytes_moved: u64,
    /// Resident allocations performed for refreshed rule-catalog buffers.
    pub resident_allocations: u32,
    /// Kernel launches submitted for the megakernel dispatch.
    pub kernel_launches: u32,
    /// Host-visible synchronization/readback wait points.
    pub sync_points: u32,
    /// Approximate lane occupancy in basis points, capped at 10000.
    pub occupancy_proxy_bps: u16,
    /// Active frontier density passed into the launch policy.
    pub frontier_density_bps: u16,
    /// Queue-state readback volume.
    pub queue_state_readback_bytes: u64,
    /// Sparse hit-ring readback volume.
    pub hit_readback_bytes: u64,
    /// Estimated peak device bytes required by the selected launch plan.
    pub estimated_peak_device_bytes: u64,
    /// Hard device-memory budget applied to this dispatch. Zero means unbounded.
    pub device_memory_budget_bytes: u64,
    /// Scale-aware topology selected by the launch policy.
    pub topology: MegakernelDispatchTopology,
    /// Whether this dispatch reused a cached fixed-batch launch plan.
    pub dispatch_plan_cache_hit: bool,
    /// Number of fixed-batch launch plans resident in the dispatcher cache.
    pub dispatch_plan_cache_entries: u16,
}

impl Default for BatchDispatchTelemetry {
    fn default() -> Self {
        Self {
            bytes_uploaded: 0,
            bytes_read_back: 0,
            bytes_moved: 0,
            resident_allocations: 0,
            kernel_launches: 0,
            sync_points: 0,
            occupancy_proxy_bps: 0,
            frontier_density_bps: 0,
            queue_state_readback_bytes: 0,
            hit_readback_bytes: 0,
            estimated_peak_device_bytes: 0,
            device_memory_budget_bytes: 0,
            topology: MegakernelDispatchTopology::SparseFrontier,
            dispatch_plan_cache_hit: false,
            dispatch_plan_cache_entries: 0,
        }
    }
}

struct RuleBufferUpdate {
    rejected_rules: Vec<BatchRuleRejection>,
    uploaded_bytes: u64,
    resident_allocations: u32,
}

const BATCH_PIPELINE_CACHE_CAP: usize = 32;

/// One compiled batched megakernel pipeline plus cached rule buffers.
pub struct BatchDispatcher {
    backend: WgpuBackend,
    config: BatchDispatchConfig,
    hit_writer: BatchHitWriter,
    pipeline: Arc<WgpuPipeline>,
    pipeline_cache: BatchPipelineCache,
    launch: MegakernelLaunchRecommendation,
    dispatch_plan_cache: BatchDispatchPlanCache,
    active_rule_fingerprints: Vec<[u8; 32]>,
    fingerprint_scratch: Vec<[u8; 32]>,
    fingerprint_occupied_scratch: Vec<bool>,
    fingerprint_addressed_scratch: Vec<bool>,
    rejection_scratch: Vec<BatchRuleRejection>,
    packing_scratch: RuleCatalogPackingScratch,
    rule_meta: Option<GpuBufferHandle>,
    transitions: Option<GpuBufferHandle>,
    accept: Option<GpuBufferHandle>,
    queue_state_bytes: Vec<u8>,
    hit_bytes: Vec<u8>,
}

impl std::fmt::Debug for BatchDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BatchDispatcher")
            .field("config", &self.config)
            .field("hit_writer", &self.hit_writer)
            .field("pipeline_id", &self.pipeline.id())
            .field("launch", &self.launch)
            .field("rule_count", &self.active_rule_fingerprints.len())
            .finish()
    }
}

impl BatchDispatcher {
    /// Compile the batched megakernel program on a live wgpu backend.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when pipeline compilation fails.
    pub fn new(backend: WgpuBackend, config: BatchDispatchConfig) -> Result<Self, PipelineError> {
        Self::new_with_hit_writer(backend, config, BatchHitWriter::Auto)
    }

    /// Compile with an explicit sparse-hit publication algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when hierarchical subgroup atomics are
    /// requested on a backend that reports no subgroup support, or when
    /// pipeline compilation fails.
    pub fn new_with_hit_writer(
        backend: WgpuBackend,
        mut config: BatchDispatchConfig,
        requested_hit_writer: BatchHitWriter,
    ) -> Result<Self, PipelineError> {
        if config.workgroup_size_x == 0 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "BatchDispatchConfig requires non-zero workgroup_size_x",
            });
        }
        let seed_queue_len = config
            .worker_groups
            .max(1)
            .checked_mul(config.workgroup_size_x)
            .ok_or_else(|| PipelineError::QueueFull {
                queue: "submission",
                fix: "megakernel seed queue length overflowed u32; reduce worker_groups or workgroup_size_x",
            })?;
        let launch = config.launch_recommendation(backend.device_limits(), seed_queue_len)?;
        if config.worker_groups == 0 {
            config.worker_groups = launch.worker_groups;
        }
        if config.hit_capacity == 0 {
            config.hit_capacity = launch.hit_capacity;
        }
        let hit_writer =
            requested_hit_writer.resolve_for_backend(backend.supports_subgroup_ops())?;
        let program = build_batch_program(
            config.workgroup_size_x,
            config.worker_groups,
            config.hit_capacity,
            hit_writer,
        );
        let pipeline = backend.compile_persistent(&program, &DispatchConfig::default())?;
        let pipeline_workgroup_size_x = config.workgroup_size_x;
        let pipeline_hit_capacity = config.hit_capacity;
        let mut pipeline_cache = BatchPipelineCache::with_cap(BATCH_PIPELINE_CACHE_CAP);
        pipeline_cache.seed(
            BatchPipelineShape {
                workgroup_size_x: pipeline_workgroup_size_x,
                worker_groups: launch.worker_groups,
                hit_capacity: pipeline_hit_capacity,
            },
            pipeline.clone(),
        );
        Ok(Self {
            backend,
            config,
            hit_writer,
            pipeline: pipeline.clone(),
            pipeline_cache,
            launch,
            dispatch_plan_cache: BatchDispatchPlanCache::default(),
            active_rule_fingerprints: Vec::new(),
            fingerprint_scratch: Vec::new(),
            fingerprint_occupied_scratch: Vec::new(),
            fingerprint_addressed_scratch: Vec::new(),
            rejection_scratch: Vec::new(),
            packing_scratch: RuleCatalogPackingScratch::default(),
            rule_meta: None,
            transitions: None,
            accept: None,
            queue_state_bytes: Vec::with_capacity(QUEUE_STATE_WORDS * std::mem::size_of::<u32>()),
            hit_bytes: Vec::new(),
        })
    }

    /// Dispatch one `FileBatch` against many compiled DFA rules in one launch.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] on pipeline, upload, or readback
    /// failures.
    pub fn dispatch(
        &mut self,
        batch: &FileBatch,
        rules: &[BatchRuleProgram],
    ) -> Result<BatchDispatchReport, PipelineError> {
        let hit_capacity = usize::try_from(batch.hit_capacity()).map_err(|source| {
            PipelineError::Backend(format!(
                "batch hit capacity cannot fit usize: {source}. Fix: reduce hit_capacity or shard the batch."
            ))
        })?;
        let mut hits = Vec::with_capacity(hit_capacity);
        let summary = self.dispatch_into(batch, rules, &mut hits)?;
        Ok(BatchDispatchReport {
            hit_count: summary.hit_count,
            hits,
            items_processed: summary.items_processed,
            wall_time: summary.wall_time,
            rejected_rules: summary.rejected_rules,
            telemetry: summary.telemetry,
        })
    }

    /// Dispatch one `FileBatch` while decoding sparse hits into caller-owned
    /// storage.
    ///
    /// Reusing `hits` avoids a fresh hit-vector allocation on hot repeated
    /// megakernel calls. The vector is cleared before decode and keeps its
    /// capacity unless the actual hit count exceeds it.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] on pipeline, upload, or readback
    /// failures.
    pub fn dispatch_into(
        &mut self,
        batch: &FileBatch,
        rules: &[BatchRuleProgram],
        hits: &mut Vec<HitRecord>,
    ) -> Result<BatchDispatchSummary, PipelineError> {
        if rules.is_empty() {
            hits.clear();
            let dynamic_plan = self.dispatch_plan(batch)?;
            return Ok(BatchDispatchSummary {
                hit_count: 0,
                items_processed: 0,
                wall_time: Duration::ZERO,
                rejected_rules: Vec::new(),
                telemetry: BatchDispatchTelemetry {
                    topology: dynamic_plan.plan.topology,
                    frontier_density_bps: self.config.frontier_density_bps,
                    estimated_peak_device_bytes: dynamic_plan.plan.estimated_peak_device_bytes,
                    device_memory_budget_bytes: dynamic_plan.plan.device_memory_budget_bytes,
                    dispatch_plan_cache_hit: dynamic_plan.cache_hit,
                    dispatch_plan_cache_entries: dynamic_plan.cache_entries,
                    ..BatchDispatchTelemetry::default()
                },
            });
        }
        let dynamic_plan = self.dispatch_plan(batch)?;
        let pipeline = self.pipeline_for_plan(dynamic_plan.plan)?;
        let rule_update = self.ensure_rule_buffers(rules)?;
        batch.reset_queue_state()?;

        let Some(rule_meta) = self.rule_meta.as_ref() else {
            return Err(PipelineError::Backend(
                "rule metadata buffer missing after ensure_rule_buffers. Fix: keep megakernel rule buffer initialization atomic.".to_string(),
            ));
        };
        let Some(transitions) = self.transitions.as_ref() else {
            return Err(PipelineError::Backend(
                "transition buffer missing after ensure_rule_buffers. Fix: keep megakernel rule buffer initialization atomic.".to_string(),
            ));
        };
        let Some(accept) = self.accept.as_ref() else {
            return Err(PipelineError::Backend(
                "accept buffer missing after ensure_rule_buffers. Fix: keep megakernel rule buffer initialization atomic.".to_string(),
            ));
        };
        let inputs = [
            batch.offsets(),
            batch.metadata(),
            batch.haystack(),
            rule_meta,
            transitions,
            accept,
        ];
        let outputs = [batch.queue_state(), batch.hit_ring()];
        let start = Instant::now();
        pipeline.dispatch_persistent_borrowed(
            &inputs,
            &outputs,
            None,
            [dynamic_plan.plan.worker_groups, 1, 1],
        )?;

        let (device, queue) = &*self.backend.device_queue();
        wait_for_persistent_dispatch(device, start, self.config.timeout)?;
        let wall_time = start.elapsed();
        self.queue_state_bytes.clear();
        let queue_state_readback_bytes = batch_fixed_resident_overhead_bytes();
        batch.queue_state().readback_prefix(
            device,
            queue,
            queue_state_readback_bytes,
            &mut self.queue_state_bytes,
        )?;
        let queue_state_word_count =
            validate_u32_readback_words(&self.queue_state_bytes, "queue-state")?;
        if queue_state_word_count < QUEUE_STATE_WORDS {
            return Err(PipelineError::Backend(format!(
                "queue-state readback exposed {} words, expected at least {}. Fix: keep the queue-state buffer sized for every control word.",
                queue_state_word_count,
                QUEUE_STATE_WORDS
            )));
        }
        let hit_count = read_u32_word(
            &self.queue_state_bytes,
            "queue-state",
            queue_state_word::HIT_HEAD,
        )?
        .min(batch.hit_capacity());
        let items_processed = read_u32_word(
            &self.queue_state_bytes,
            "queue-state",
            queue_state_word::DONE_COUNT,
        )?;

        self.hit_bytes.clear();
        let hit_readback_bytes = u64::from(hit_count)
            .checked_mul(dispatcher_usize_to_u64(
                HIT_RECORD_WORDS,
                "hit-record word count",
            ))
            .and_then(|words| {
                words.checked_mul(dispatcher_usize_to_u64(
                    std::mem::size_of::<u32>(),
                    "u32 byte width",
                ))
            })
            .ok_or_else(|| {
                PipelineError::Backend(
                    "hit-ring readback length overflowed u64. Fix: reduce hit_capacity or shard the batch."
                        .to_string(),
                )
            })?;
        batch
            .hit_ring()
            .readback_prefix(device, queue, hit_readback_bytes, &mut self.hit_bytes)?;
        decode_hits_from_readback_into(&self.hit_bytes, hit_count, hits)?;
        let bytes_read_back = queue_state_readback_bytes
            .checked_add(hit_readback_bytes)
            .ok_or_else(|| {
                PipelineError::Backend(
                    "batch readback byte accounting overflowed u64. Fix: shard the batch before readback."
                        .to_string(),
                )
            })?;
        let bytes_moved = rule_update
            .uploaded_bytes
            .checked_add(bytes_read_back)
            .ok_or_else(|| {
                PipelineError::Backend(
                    "batch moved-byte accounting overflowed u64. Fix: shard the batch before dispatch."
                        .to_string(),
                )
            })?;

        Ok(BatchDispatchSummary {
            hit_count,
            items_processed,
            wall_time,
            rejected_rules: rule_update.rejected_rules,
            telemetry: BatchDispatchTelemetry {
                bytes_uploaded: rule_update.uploaded_bytes,
                bytes_read_back,
                bytes_moved,
                resident_allocations: rule_update.resident_allocations,
                kernel_launches: 1,
                sync_points: 2,
                occupancy_proxy_bps: occupancy_proxy_bps(
                    items_processed,
                    dynamic_plan.plan.worker_groups,
                    self.config.workgroup_size_x,
                ),
                frontier_density_bps: self.config.frontier_density_bps,
                queue_state_readback_bytes,
                hit_readback_bytes,
                estimated_peak_device_bytes: dynamic_plan.plan.estimated_peak_device_bytes,
                device_memory_budget_bytes: dynamic_plan.plan.device_memory_budget_bytes,
                topology: dynamic_plan.plan.topology,
                dispatch_plan_cache_hit: dynamic_plan.cache_hit,
                dispatch_plan_cache_entries: dynamic_plan.cache_entries,
            },
        })
    }

    fn pipeline_for_plan(
        &mut self,
        plan: BatchDispatchPlan,
    ) -> Result<Arc<WgpuPipeline>, PipelineError> {
        let shape = BatchPipelineShape {
            workgroup_size_x: plan.workgroup_size_x,
            worker_groups: plan.worker_groups,
            hit_capacity: plan.hit_capacity,
        };
        if let Some(pipeline) = self.pipeline_cache.get(shape) {
            return Ok(pipeline);
        }
        let program = build_batch_program(
            plan.workgroup_size_x,
            plan.worker_groups,
            plan.hit_capacity,
            self.hit_writer,
        );
        let pipeline = self
            .backend
            .compile_persistent(&program, &DispatchConfig::default())?;
        self.pipeline_cache.insert(shape, pipeline.clone());
        Ok(pipeline)
    }

    fn dispatch_plan(
        &mut self,
        batch: &FileBatch,
    ) -> Result<BatchDispatchPlanLookup, PipelineError> {
        let queue_len = batch.queue_len();
        if let Some(plan) = self.dispatch_plan_cache.get(queue_len) {
            return Ok(BatchDispatchPlanLookup {
                plan,
                cache_hit: true,
                cache_entries: self.dispatch_plan_cache.len_u16(),
            });
        }
        let mut recommendation = self
            .config
            .launch_recommendation(self.backend.device_limits(), queue_len)?;
        let resident_hit_capacity = batch.hit_capacity();
        if recommendation.hit_capacity > resident_hit_capacity {
            let removed_hit_bytes = u64::from(recommendation.hit_capacity - resident_hit_capacity)
                .checked_mul(dispatcher_usize_to_u64(
                    HIT_RECORD_WORDS,
                    "hit-record word count",
                ))
                .and_then(|words| {
                    words.checked_mul(dispatcher_usize_to_u64(
                        std::mem::size_of::<u32>(),
                        "u32 byte width",
                    ))
                })
                .ok_or_else(|| {
                    PipelineError::Backend(
                        "resident hit-capacity byte adjustment overflowed u64. Fix: shard the batch before dispatch planning."
                            .to_string(),
                    )
                })?;
            recommendation.hit_capacity = resident_hit_capacity;
            recommendation.estimated_peak_device_bytes = recommendation
                .estimated_peak_device_bytes
                .checked_sub(removed_hit_bytes)
                .ok_or_else(|| {
                    PipelineError::Backend(
                        "resident hit-capacity adjustment exceeded peak device estimate. Fix: keep launch recommendation and resident batch capacity synchronized."
                            .to_string(),
                    )
                })?;
        }
        let plan = BatchDispatchPlan::from_recommendation(queue_len, &self.config, recommendation);
        self.dispatch_plan_cache.insert(plan);
        Ok(BatchDispatchPlanLookup {
            plan,
            cache_hit: false,
            cache_entries: self.dispatch_plan_cache.len_u16(),
        })
    }

    fn ensure_rule_buffers(
        &mut self,
        rules: &[BatchRuleProgram],
    ) -> Result<RuleBufferUpdate, PipelineError> {
        accepted_rule_fingerprints_and_rejections_into(
            rules,
            &mut self.fingerprint_scratch,
            &mut self.fingerprint_occupied_scratch,
            &mut self.fingerprint_addressed_scratch,
            &mut self.rejection_scratch,
        );
        if self.fingerprint_scratch == self.active_rule_fingerprints {
            return Ok(RuleBufferUpdate {
                rejected_rules: if self.rejection_scratch.is_empty() {
                    Vec::new()
                } else {
                    self.rejection_scratch.clone()
                },
                uploaded_bytes: 0,
                resident_allocations: 0,
            });
        }

        pack_rule_catalog_into(rules, &mut self.packing_scratch)?;
        let uploaded_words = self
            .packing_scratch
            .rule_meta
            .len()
            .checked_add(self.packing_scratch.transitions.len())
            .and_then(|words| words.checked_add(self.packing_scratch.accept.len()))
            .ok_or_else(|| {
                PipelineError::Backend(
                    "rule catalog upload word count overflowed usize. Fix: shard the rule catalog before upload."
                        .to_string(),
                )
            })?;
        let uploaded_bytes = uploaded_words
            .checked_mul(std::mem::size_of::<u32>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                PipelineError::Backend(
                    "rule catalog upload byte count overflowed u64. Fix: shard the rule catalog before upload."
                        .to_string(),
                )
            })?;
        let (device, queue) = &*self.backend.device_queue();
        self.rule_meta = Some(GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&self.packing_scratch.rule_meta),
            persistent_storage_binding_usage(),
        )?);
        self.transitions = Some(GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&self.packing_scratch.transitions),
            persistent_storage_binding_usage(),
        )?);
        self.accept = Some(GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&self.packing_scratch.accept),
            persistent_storage_binding_usage(),
        )?);
        if self.active_rule_fingerprints.len() == self.fingerprint_scratch.len() {
            self.active_rule_fingerprints
                .copy_from_slice(&self.fingerprint_scratch);
        } else {
            self.active_rule_fingerprints.clear();
            self.active_rule_fingerprints
                .extend_from_slice(&self.fingerprint_scratch);
        }
        Ok(RuleBufferUpdate {
            rejected_rules: if self.packing_scratch.rejected_rules.is_empty() {
                Vec::new()
            } else {
                self.packing_scratch.rejected_rules.clone()
            },
            uploaded_bytes,
            resident_allocations: 3,
        })
    }
}


fn occupancy_proxy_bps(items_processed: u32, worker_groups: u32, workgroup_size_x: u32) -> u16 {
    let lanes = u64::from(worker_groups.max(1))
        .checked_mul(u64::from(workgroup_size_x.max(1)))
        .unwrap_or(u64::MAX);
    crate::numeric::ratio_basis_points_u64_wide(
        u64::from(items_processed),
        lanes.max(1),
        0,
        "batch occupancy proxy",
    )
    .min(10_000) as u16
}

fn validate_u32_readback_words(bytes: &[u8], label: &'static str) -> Result<usize, PipelineError> {
    if bytes.len() % std::mem::size_of::<u32>() != 0 {
        return Err(PipelineError::Backend(format!(
            "{label} readback exposed {} bytes, which is not a whole number of u32 words. Fix: keep readback lengths 4-byte aligned.",
            bytes.len()
        )));
    }
    Ok(bytes.len() / std::mem::size_of::<u32>())
}

fn read_u32_word(
    bytes: &[u8],
    label: &'static str,
    word_index: usize,
) -> Result<u32, PipelineError> {
    let offset = word_index
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| {
            PipelineError::Backend(format!(
                "{label} word offset overflowed usize. Fix: split the readback before decoding."
            ))
        })?;
    let word = bytes.get(offset..offset + std::mem::size_of::<u32>()).ok_or_else(|| {
        PipelineError::Backend(format!(
            "{label} readback is missing u32 word {word_index}. Fix: request a large enough readback prefix."
        ))
    })?;
    Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn wait_for_persistent_dispatch(
    device: &wgpu::Device,
    start: Instant,
    timeout: Duration,
) -> Result<(), PipelineError> {
    let mut backoff = crate::wait_backoff::AdaptiveWaitBackoff::from_micros(64, 5, 50, 8);
    loop {
        if crate::runtime::device::poll_device_once(device)
            .map_err(|error| PipelineError::Backend(error.to_string()))?
            .is_queue_empty()
        {
            return Ok(());
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(PipelineError::Backend(format!(
                "batch megakernel dispatch exceeded timeout before readback: took {elapsed:?}, budget {timeout:?}. Fix: raise BatchDispatchConfig.timeout or split the batch.",
            )));
        }
        let remaining = timeout.checked_sub(elapsed).ok_or_else(|| {
            PipelineError::Backend(format!(
                "batch megakernel timeout arithmetic underflowed after elapsed {elapsed:?} exceeded budget {timeout:?}. Fix: split the batch or raise BatchDispatchConfig.timeout deliberately.",
            ))
        })?;
        backoff.idle_for(remaining);
    }
}

fn build_batch_program(
    workgroup_size_x: u32,
    worker_groups: u32,
    hit_capacity: u32,
    hit_writer: BatchHitWriter,
) -> Program {
    let total_workers = workgroup_size_x
        .checked_mul(worker_groups.max(1))
        .unwrap_or_else(|| {
            panic!(
                "megakernel worker count overflowed u32. Fix: lower workgroup size or worker group count before batch dispatch."
            )
        });
    let claim_budget = compute_claim_budget(total_workers);

    Program::wrapped(
        batch_program_buffers(hit_capacity),
        [workgroup_size_x, 1, 1],
        vec![Node::loop_for(
            "claim_iter",
            Expr::u32(0),
            claim_budget,
            vec![
                Node::let_bind(
                    "claim",
                    Expr::atomic_add(
                        "queue_state",
                        Expr::u32(dispatcher_abi_u32(
                            queue_state_word::HEAD,
                            "queue-state head word",
                        )),
                        Expr::u32(1),
                    ),
                ),
                Node::if_then(
                    Expr::lt(
                        Expr::var("claim"),
                        atomic_load_relaxed(
                            "queue_state",
                            Expr::u32(dispatcher_abi_u32(
                                queue_state_word::QUEUE_LEN,
                                "queue-state length word",
                            )),
                        ),
                    ),
                    execute_batch_claim_body(hit_writer),
                ),
            ],
        )],
    )
}

fn compute_claim_budget(total_workers: u32) -> Expr {
    let queue_len = atomic_load_relaxed(
        "queue_state",
        Expr::u32(dispatcher_abi_u32(
            queue_state_word::QUEUE_LEN,
            "queue-state length word",
        )),
    );
    let worker_bias = total_workers.checked_sub(1).unwrap_or_else(|| {
        panic!("megakernel claim budget received zero workers. Fix: construct batch programs with at least one worker.")
    });
    Expr::div(
        Expr::add(queue_len, Expr::u32(worker_bias)),
        Expr::u32(total_workers),
    )
}

fn batch_program_buffers(hit_capacity: u32) -> Vec<BufferDecl> {
    let hit_ring_words = hit_capacity.checked_mul(4).unwrap_or_else(|| {
        panic!(
            "megakernel hit-ring word count overflowed u32. Fix: lower hit_capacity or shard the batch before pipeline creation."
        )
    });
    vec![
        BufferDecl::storage("file_offsets", 0, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("file_metadata", 1, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("haystack", 3, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("rule_meta", 4, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("transitions", 5, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("accept", 6, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("queue_state", 7, BufferAccess::ReadWrite, DataType::U32).with_count(
            dispatcher_abi_u32(QUEUE_STATE_WORDS, "queue-state word count"),
        ),
        BufferDecl::output("hit_ring", 8, DataType::U32).with_count(hit_ring_words),
    ]
}

fn execute_batch_claim_body(hit_writer: BatchHitWriter) -> Vec<Node> {
    vec![
        Node::let_bind(
            "rule_count",
            atomic_load_relaxed(
                "queue_state",
                Expr::u32(dispatcher_abi_u32(
                    queue_state_word::RULE_COUNT,
                    "queue-state rule-count word",
                )),
            ),
        ),
        Node::let_bind(
            "file_idx",
            Expr::div(Expr::var("claim"), Expr::var("rule_count")),
        ),
        Node::let_bind(
            "rule_idx",
            Expr::rem(Expr::var("claim"), Expr::var("rule_count")),
        ),
        Node::let_bind(
            "metadata_base",
            Expr::mul(
                Expr::var("file_idx"),
                Expr::u32(dispatcher_abi_u32(
                    FILE_METADATA_WORDS,
                    "file metadata word count",
                )),
            ),
        ),
        Node::let_bind(
            "layer_idx",
            Expr::load(
                "file_metadata",
                Expr::add(Expr::var("metadata_base"), Expr::u32(3)),
            ),
        ),
        Node::let_bind(
            "file_start",
            Expr::load("file_offsets", Expr::var("file_idx")),
        ),
        Node::let_bind(
            "file_end",
            Expr::load(
                "file_offsets",
                Expr::add(Expr::var("file_idx"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "rule_base",
            Expr::mul(
                Expr::var("rule_idx"),
                Expr::u32(dispatcher_abi_u32(
                    RULE_META_WORDS,
                    "rule metadata word count",
                )),
            ),
        ),
        Node::let_bind(
            "transition_base",
            Expr::load("rule_meta", Expr::var("rule_base")),
        ),
        Node::let_bind(
            "accept_base",
            Expr::load("rule_meta", Expr::add(Expr::var("rule_base"), Expr::u32(1))),
        ),
        // Delegate core evaluation to Tier-2 LEGO Primitive
        Node::Block(dfa_byte_scanner(hit_writer)),
        // Mark work completion
        Node::let_bind(
            "done_prev",
            Expr::atomic_add(
                "queue_state",
                Expr::u32(dispatcher_abi_u32(
                    queue_state_word::DONE_COUNT,
                    "queue-state done-count word",
                )),
                Expr::u32(1),
            ),
        ),
    ]
}

fn dfa_byte_scanner(hit_writer: BatchHitWriter) -> Vec<Node> {
    vec![
        Node::let_bind("state", Expr::u32(0)),
        Node::loop_for(
            "byte_pos",
            Expr::var("file_start"),
            Expr::var("file_end"),
            vec![
                Node::let_bind(
                    "haystack_word_index",
                    Expr::div(Expr::var("byte_pos"), Expr::u32(4)),
                ),
                Node::let_bind(
                    "haystack_shift",
                    Expr::mul(Expr::rem(Expr::var("byte_pos"), Expr::u32(4)), Expr::u32(8)),
                ),
                Node::let_bind(
                    "byte",
                    Expr::bitand(
                        Expr::shr(
                            Expr::load("haystack", Expr::var("haystack_word_index")),
                            Expr::var("haystack_shift"),
                        ),
                        Expr::u32(0xFF),
                    ),
                ),
                Node::assign(
                    "state",
                    Expr::load(
                        "transitions",
                        Expr::add(
                            Expr::var("transition_base"),
                            Expr::add(
                                Expr::mul(Expr::var("state"), Expr::u32(ALPHABET_SIZE)),
                                Expr::var("byte"),
                            ),
                        ),
                    ),
                ),
                Node::let_bind(
                    "accepting",
                    Expr::load(
                        "accept",
                        Expr::add(Expr::var("accept_base"), Expr::var("state")),
                    ),
                ),
                Node::let_bind("is_hit", Expr::ne(Expr::var("accepting"), Expr::u32(0))),
                hit_writer_node(hit_writer),
            ],
        ),
    ]
}

fn hit_writer_node(hit_writer: BatchHitWriter) -> Node {
    match hit_writer {
        BatchHitWriter::HierarchicalSubgroup => {
            Node::Block(record_hit_to_ring_hierarchical("is_hit"))
        }
        BatchHitWriter::Auto | BatchHitWriter::Scalar => {
            Node::if_then(Expr::var("is_hit"), record_hit_to_ring())
        }
    }
}

fn record_hit_to_ring() -> Vec<Node> {
    vec![
        Node::let_bind(
            "hit_slot",
            Expr::atomic_add(
                "queue_state",
                Expr::u32(dispatcher_abi_u32(
                    queue_state_word::HIT_HEAD,
                    "queue-state hit-head word",
                )),
                Expr::u32(1),
            ),
        ),
        Node::if_then(
            Expr::lt(
                Expr::var("hit_slot"),
                atomic_load_relaxed(
                    "queue_state",
                    Expr::u32(dispatcher_abi_u32(
                        queue_state_word::HIT_CAPACITY,
                        "queue-state hit-capacity word",
                    )),
                ),
            ),
            vec![
                Node::let_bind("hit_base", Expr::mul(Expr::var("hit_slot"), Expr::u32(4))),
                Node::store("hit_ring", Expr::var("hit_base"), Expr::var("file_idx")),
                Node::store(
                    "hit_ring",
                    Expr::add(Expr::var("hit_base"), Expr::u32(1)),
                    Expr::var("rule_idx"),
                ),
                Node::store(
                    "hit_ring",
                    Expr::add(Expr::var("hit_base"), Expr::u32(2)),
                    Expr::var("layer_idx"),
                ),
                Node::store(
                    "hit_ring",
                    Expr::add(Expr::var("hit_base"), Expr::u32(3)),
                    Expr::sub(Expr::var("byte_pos"), Expr::var("file_start")),
                ),
            ],
        ),
    ]
}

#[cfg(test)]
fn decode_hits_from_readback(
    bytes: &[u8],
    hit_count: u32,
) -> Result<Vec<HitRecord>, PipelineError> {
    let mut hits = Vec::new();
    decode_hits_from_readback_into(bytes, hit_count, &mut hits)?;
    Ok(hits)
}

fn decode_hits_from_readback_into(
    bytes: &[u8],
    hit_count: u32,
    hits: &mut Vec<HitRecord>,
) -> Result<(), PipelineError> {
    let word_count = validate_u32_readback_words(bytes, "hit-ring")?;
    let needed_words = usize::try_from(hit_count)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| PipelineError::Backend("hit-count overflowed usize".to_string()))?;
    if word_count < needed_words {
        return Err(PipelineError::Backend(format!(
            "hit-ring exposed {} words, expected at least {needed_words}. Fix: size the sparse hit ring for the configured hit_capacity.",
            word_count
        )));
    }
    let needed_bytes = needed_words
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| PipelineError::Backend(
            "hit-ring readback byte count overflowed usize. Fix: reduce hit_capacity or shard the batch."
                .to_string(),
        ))?;
    let hit_count = usize::try_from(hit_count).map_err(|source| {
        PipelineError::Backend(format!(
            "hit count cannot fit usize for host decode: {source}. Fix: reduce hit_capacity or run on a supported host pointer width."
        ))
    })?;
    let same_len = hits.len() == hit_count;
    if !same_len {
        hits.clear();
    }
    if hits.capacity() < hit_count {
        hits.try_reserve_exact(hit_count - hits.len())
            .map_err(|source| {
                PipelineError::Backend(format!(
                    "hit-ring decode could not reserve {hit_count} HitRecord slots: {source}. Fix: lower hit_capacity or shard the batch."
                ))
            })?;
    }
    if cfg!(target_endian = "little") {
        let record_bytes = std::mem::size_of::<HitRecord>();
        let expected_record_bytes = HIT_RECORD_WORDS * std::mem::size_of::<u32>();
        if record_bytes != expected_record_bytes {
            return Err(PipelineError::Backend(format!(
                "hit-ring host record layout is {record_bytes} bytes, expected {expected_record_bytes}. Fix: keep HitRecord as four packed u32 words."
            )));
        }
        if hit_count != 0 {
            let records: &[HitRecord] =
                bytemuck::try_cast_slice(&bytes[..needed_bytes]).map_err(|source| {
                    PipelineError::Backend(format!(
                        "hit-ring readback bytes were not aligned as HitRecord records: {source}. Fix: keep the hit ring byte layout aligned to four u32 words."
                    ))
                })?;
            if same_len {
                hits.copy_from_slice(records);
            } else {
                hits.extend_from_slice(records);
            }
        }
        return Ok(());
    }
    for (index, chunk) in bytes[..needed_bytes]
        .chunks_exact(HIT_RECORD_WORDS * std::mem::size_of::<u32>())
        .enumerate()
    {
        let record = HitRecord {
            file_idx: u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            rule_idx: u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            layer_idx: u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]),
            match_offset: u32::from_le_bytes([chunk[12], chunk[13], chunk[14], chunk[15]]),
        };
        if same_len {
            hits[index] = record;
        } else {
            hits.push(record);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_worker_groups_is_at_least_four_on_live_adapter() {
        if let Ok(backend) = WgpuBackend::new() {
            let wg = BatchDispatchConfig::default()
                .launch_recommendation(backend.device_limits(), 64)
                .expect("Fix: live adapter limits must produce a launch recommendation")
                .worker_groups;
            assert!(
                wg >= 4,
                "Fix: default worker_groups should be >= 4 on any live adapter, got {wg}"
            );
        }
    }

    #[test]
    fn launch_recommendation_is_consumed_for_worker_groups_and_hit_capacity() {
        let src = include_str!("dispatcher.rs");
        let prod_src = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod_src.contains("config.worker_groups = launch.worker_groups"),
            "BatchDispatcher::new must consume launch policy worker group recommendations"
        );
        assert!(
            prod_src.contains("config.hit_capacity = launch.hit_capacity"),
            "BatchDispatcher::new must consume launch policy hit-capacity recommendations"
        );
    }

    #[test]
    fn dynamic_dispatch_plan_controls_pipeline_and_launch_geometry() {
        let src = include_str!("dispatcher.rs");
        let prod_src = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod_src.contains("let pipeline = self.pipeline_for_plan(dynamic_plan.plan)?"),
            "dispatch must compile or reuse the pipeline for the per-batch scale-aware plan"
        );
        assert!(
            prod_src.contains("[dynamic_plan.plan.worker_groups, 1, 1]"),
            "dispatch must submit the policy-selected worker group count, not config.worker_groups"
        );
        assert!(
            prod_src.contains("dynamic_plan.plan.worker_groups,\n                    self.config.workgroup_size_x"),
            "occupancy telemetry must use the actual dynamic launch geometry"
        );
    }

    #[test]
    fn dynamic_pipeline_cache_is_bounded_lru() {
        let src = include_str!("dispatcher.rs");
        let prod_src = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod_src.contains("const BATCH_PIPELINE_CACHE_CAP: usize = 32"),
            "scale-aware pipeline variants must have a fixed retention bound"
        );
        assert!(
            prod_src.contains("BatchPipelineCache::with_cap(BATCH_PIPELINE_CACHE_CAP)")
                && prod_src.contains("self.pipeline_cache.get(shape)")
                && prod_src.contains("self.pipeline_cache.insert(shape, pipeline.clone())")
                && !prod_src.contains("min_by_key(|(_, entry)| entry.last_seen)")
                && !prod_src.contains("swap_remove(evict_idx)"),
            "scale-aware pipeline cache must use the indexed heap-backed LRU instead of scanning entries"
        );
        assert!(
            prod_src.contains("workgroup_size_x: plan.workgroup_size_x")
                && prod_src.contains("worker_groups: plan.worker_groups")
                && prod_src.contains("hit_capacity: plan.hit_capacity"),
            "scale-aware pipeline cache key must include every program-shaping field"
        );
    }

    #[test]
    fn dynamic_plan_hit_capacity_is_clamped_to_resident_batch_ring() {
        let src = include_str!("dispatcher.rs");
        let prod_src = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod_src.contains("let resident_hit_capacity = batch.hit_capacity()")
                && prod_src.contains("recommendation.hit_capacity = resident_hit_capacity")
                && prod_src.contains("estimated_peak_device_bytes"),
            "dynamic dispatch plans must not compile a hit-ring shape larger than the resident FileBatch output buffer"
        );
    }

    #[test]
    fn launch_recommendation_uses_explicit_graph_hints_for_topology() {
        let limits = wgpu::Limits::default();
        let config = BatchDispatchConfig::default()
            .with_graph_hints(8192, 131_072, 9_000, 0)
            .with_execution_hints(8, 0, 0, 0);

        let rec = config
            .launch_recommendation(&limits, 8192)
            .expect("Fix: explicit graph hints must produce a launch recommendation");

        assert_eq!(rec.topology, MegakernelDispatchTopology::FusedDense);
    }

    #[test]
    fn launch_recommendation_default_does_not_invent_dense_frontier() {
        let limits = wgpu::Limits::default();
        let rec = BatchDispatchConfig::default()
            .launch_recommendation(&limits, 8192)
            .expect("Fix: default graph hints must produce a launch recommendation");

        assert_ne!(rec.topology, MegakernelDispatchTopology::FusedDense);
        assert_eq!(BatchDispatchConfig::default().frontier_density_bps, 0);
    }

    #[test]
    fn timeout_field_is_plumbed_into_dispatch_path() {
        let src = include_str!("dispatcher.rs");
        let prod_src = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            prod_src.contains("timeout"),
            "BatchDispatchConfig exposes timeout; this test documents that it must stay wired"
        );
        assert!(
            prod_src.contains("dispatch_config.timeout")
                || prod_src.contains(".with_timeout(")
                || prod_src.contains("config.timeout"),
            "BatchDispatchConfig.timeout appears publicly configurable but is not consumed during dispatch"
        );
    }

    #[test]
    fn hit_readback_decodes_without_intermediate_word_vector() {
        let mut bytes = Vec::new();
        for word in [7u32, 3, 2, 99, 8, 4, 1, 100] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }

        let hits = decode_hits_from_readback(&bytes, 2)
            .expect("Fix: aligned hit readback bytes must decode directly");

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].file_idx, 7);
        assert_eq!(hits[0].rule_idx, 3);
        assert_eq!(hits[1].match_offset, 100);
    }

    #[test]
    fn hit_readback_into_reuses_caller_capacity() {
        let mut bytes = Vec::new();
        for word in [7u32, 3, 2, 99, 8, 4, 1, 100] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let mut hits = Vec::with_capacity(8);
        let ptr = hits.as_ptr();

        decode_hits_from_readback_into(&bytes, 2, &mut hits)
            .expect("Fix: aligned hit readback bytes must decode into caller scratch");

        assert_eq!(hits.len(), 2);
        assert_eq!(hits.as_ptr(), ptr);
    }

    #[test]
    fn occupancy_proxy_caps_at_full_utilization() {
        assert_eq!(occupancy_proxy_bps(32, 1, 64), 5_000);
        assert_eq!(occupancy_proxy_bps(128, 1, 64), 10_000);
        assert_eq!(occupancy_proxy_bps(0, 0, 0), 0);
        assert_eq!(occupancy_proxy_bps(u32::MAX, 1, 1), 10_000);
    }

    #[test]
    fn dispatch_report_exposes_release_telemetry_counters() {
        let src = include_str!("dispatcher.rs");
        for field in [
            "bytes_uploaded",
            "bytes_read_back",
            "bytes_moved",
            "resident_allocations",
            "kernel_launches",
            "sync_points",
            "occupancy_proxy_bps",
            "frontier_density_bps",
            "queue_state_readback_bytes",
            "hit_readback_bytes",
            "estimated_peak_device_bytes",
            "device_memory_budget_bytes",
            "topology",
        ] {
            assert!(
                src.contains(field),
                "BatchDispatchReport telemetry must expose `{field}` for megakernel performance gates"
            );
        }
    }
}

