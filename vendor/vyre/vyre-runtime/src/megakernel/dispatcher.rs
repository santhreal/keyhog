//! Batched megakernel dispatch built on a persistent device work queue.

use super::advanced::hierarchical_atomics::record_hit_to_ring_hierarchical;
use super::batch::{queue_state_word, FileBatch, HitRecord, HIT_RECORD_WORDS, QUEUE_STATE_WORDS};
use super::rule_catalog::{
    accepted_rule_fingerprints, pack_rule_catalog, BatchRuleProgram, BatchRuleRejection,
    ALPHABET_SIZE, RULE_META_WORDS,
};
use super::scaling::{
    MegakernelLaunchPolicy, MegakernelLaunchRecommendation, MegakernelLaunchRequest,
};
use crate::PipelineError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vyre_driver::{CompiledPipeline, DispatchConfig, VyreBackend};
use vyre_driver_wgpu::buffer::GpuBufferHandle;
use vyre_driver_wgpu::{pipeline::WgpuPipeline, WgpuBackend};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

fn atomic_load_relaxed(buffer: &str, index: Expr) -> Expr {
    Expr::atomic_add(buffer, index, Expr::u32(0))
}

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
        }
    }
}

impl BatchDispatchConfig {
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
        MegakernelLaunchPolicy::standard()
            .recommend(MegakernelLaunchRequest {
                queue_len,
                requested_worker_groups: self.worker_groups,
                max_workgroup_size_x: self.workgroup_size_x,
                max_compute_workgroups_per_dimension: limits.max_compute_workgroups_per_dimension,
                max_compute_invocations_per_workgroup: limits.max_compute_invocations_per_workgroup,
                requested_hit_capacity: self.hit_capacity,
                expected_hits_per_item: 1,
                hot_opcode_count: 0,
                hot_window_count: 0,
                requeue_count: 0,
                max_priority_age: 0,
            })
            .map_err(|source| PipelineError::Backend(source.to_string()))
    }
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
}

/// One compiled batched megakernel pipeline plus cached rule buffers.
pub struct BatchDispatcher {
    backend: WgpuBackend,
    config: BatchDispatchConfig,
    hit_writer: BatchHitWriter,
    pipeline: Arc<WgpuPipeline>,
    launch: MegakernelLaunchRecommendation,
    active_rule_fingerprints: Vec<[u8; 32]>,
    rule_meta: Option<GpuBufferHandle>,
    transitions: Option<GpuBufferHandle>,
    accept: Option<GpuBufferHandle>,
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
            .saturating_mul(config.workgroup_size_x);
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
        Ok(Self {
            backend,
            config,
            hit_writer,
            pipeline,
            launch,
            active_rule_fingerprints: Vec::new(),
            rule_meta: None,
            transitions: None,
            accept: None,
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
        if rules.is_empty() {
            return Ok(BatchDispatchReport {
                hit_count: 0,
                hits: Vec::new(),
                items_processed: 0,
                wall_time: Duration::ZERO,
                rejected_rules: Vec::new(),
            });
        }
        let rejected_rules = self.ensure_rule_buffers(rules)?;
        batch.reset_queue_state()?;

        let inputs = [
            batch.offsets().clone(),
            batch.metadata().clone(),
            batch.work_queue().clone(),
            batch.haystack().clone(),
            self.rule_meta
                .as_ref()
                .expect("rule_meta populated by ensure_rule_buffers")
                .clone(),
            self.transitions
                .as_ref()
                .expect("transitions populated by ensure_rule_buffers")
                .clone(),
            self.accept
                .as_ref()
                .expect("accept populated by ensure_rule_buffers")
                .clone(),
        ];
        let mut outputs = [batch.queue_state().clone(), batch.hit_ring().clone()];
        let start = Instant::now();
        self.pipeline.dispatch_persistent(
            &inputs,
            &mut outputs,
            None,
            [self.config.worker_groups, 1, 1],
        )?;

        let (device, queue) = &*self.backend.device_queue();
        wait_for_persistent_dispatch(device, start, self.config.timeout)?;
        let wall_time = start.elapsed();
        let mut queue_state_bytes = Vec::new();
        batch.queue_state().readback_prefix(
            device,
            queue,
            (QUEUE_STATE_WORDS * std::mem::size_of::<u32>()) as u64,
            &mut queue_state_bytes,
        )?;
        let queue_state_words = u32_words_from_readback(&queue_state_bytes, "queue-state")?;
        if queue_state_words.len() < QUEUE_STATE_WORDS {
            return Err(PipelineError::Backend(format!(
                "queue-state readback exposed {} words, expected at least {}. Fix: keep the queue-state buffer sized for every control word.",
                queue_state_words.len(),
                QUEUE_STATE_WORDS
            )));
        }
        let hit_count = queue_state_words[queue_state_word::HIT_HEAD].min(batch.hit_capacity());
        let items_processed = queue_state_words[queue_state_word::DONE_COUNT];

        let mut hit_bytes = Vec::new();
        let hit_readback_bytes = u64::from(hit_count)
            .checked_mul(HIT_RECORD_WORDS as u64)
            .and_then(|words| words.checked_mul(std::mem::size_of::<u32>() as u64))
            .ok_or_else(|| {
                PipelineError::Backend(
                    "hit-ring readback length overflowed u64. Fix: reduce hit_capacity or shard the batch."
                        .to_string(),
                )
            })?;
        batch
            .hit_ring()
            .readback_prefix(device, queue, hit_readback_bytes, &mut hit_bytes)?;
        let hit_words = u32_words_from_readback(&hit_bytes, "hit-ring")?;
        let hits = decode_hits(&hit_words, hit_count)?;

        Ok(BatchDispatchReport {
            hit_count,
            hits,
            items_processed,
            wall_time,
            rejected_rules,
        })
    }

    fn ensure_rule_buffers(
        &mut self,
        rules: &[BatchRuleProgram],
    ) -> Result<Vec<BatchRuleRejection>, PipelineError> {
        let (fingerprints, rejected_rules) = accepted_rule_fingerprints(rules);
        if fingerprints == self.active_rule_fingerprints {
            return Ok(rejected_rules);
        }

        let packed = pack_rule_catalog(rules)?;
        let (device, queue) = &*self.backend.device_queue();
        self.rule_meta = Some(GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&packed.rule_meta),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?);
        self.transitions = Some(GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&packed.transitions),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?);
        self.accept = Some(GpuBufferHandle::upload(
            device,
            queue,
            bytemuck::cast_slice(&packed.accept),
            wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        )?);
        self.active_rule_fingerprints = fingerprints;
        Ok(packed.rejected_rules)
    }
}

fn u32_words_from_readback(bytes: &[u8], label: &'static str) -> Result<Vec<u32>, PipelineError> {
    if bytes.len() % std::mem::size_of::<u32>() != 0 {
        return Err(PipelineError::Backend(format!(
            "{label} readback exposed {} bytes, which is not a whole number of u32 words. Fix: keep readback lengths 4-byte aligned.",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks_exact(std::mem::size_of::<u32>())
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("u32 chunk width")))
        .collect())
}

fn wait_for_persistent_dispatch(
    device: &wgpu::Device,
    start: Instant,
    timeout: Duration,
) -> Result<(), PipelineError> {
    const SPIN_POLLS: u32 = 64;
    const MIN_PARK: Duration = Duration::from_micros(50);
    const MAX_PARK: Duration = Duration::from_millis(2);
    let mut polls = 0u32;
    loop {
        match device.poll(wgpu::Maintain::Poll) {
            wgpu::MaintainResult::SubmissionQueueEmpty => return Ok(()),
            wgpu::MaintainResult::Ok => {}
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(PipelineError::Backend(format!(
                "batch megakernel dispatch exceeded timeout before readback: took {elapsed:?}, budget {timeout:?}. Fix: raise BatchDispatchConfig.timeout or split the batch.",
            )));
        }
        polls = polls.saturating_add(1);
        if polls <= SPIN_POLLS {
            std::thread::yield_now();
            continue;
        }

        let remaining = timeout.saturating_sub(elapsed);
        let shift = (polls - SPIN_POLLS).min(8);
        let park = MIN_PARK
            .saturating_mul(1u32 << shift)
            .min(MAX_PARK)
            .min(remaining);
        if park.is_zero() {
            std::thread::yield_now();
        } else {
            std::thread::park_timeout(park);
        }
    }
}

fn build_batch_program(
    workgroup_size_x: u32,
    worker_groups: u32,
    hit_capacity: u32,
    hit_writer: BatchHitWriter,
) -> Program {
    let total_workers = workgroup_size_x.saturating_mul(worker_groups.max(1));
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
                        Expr::u32(queue_state_word::HEAD as u32),
                        Expr::u32(1),
                    ),
                ),
                Node::if_then(
                    Expr::lt(
                        Expr::var("claim"),
                        atomic_load_relaxed(
                            "queue_state",
                            Expr::u32(queue_state_word::QUEUE_LEN as u32),
                        ),
                    ),
                    execute_batch_claim_body(hit_writer),
                ),
            ],
        )],
    )
}

fn compute_claim_budget(total_workers: u32) -> Expr {
    let queue_len =
        atomic_load_relaxed("queue_state", Expr::u32(queue_state_word::QUEUE_LEN as u32));
    Expr::div(
        Expr::add(queue_len, Expr::u32(total_workers.saturating_sub(1))),
        Expr::u32(total_workers.max(1)),
    )
}

fn batch_program_buffers(hit_capacity: u32) -> Vec<BufferDecl> {
    vec![
        BufferDecl::storage("file_offsets", 0, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("file_metadata", 1, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("work_queue", 2, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("haystack", 3, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("rule_meta", 4, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("transitions", 5, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("accept", 6, BufferAccess::ReadOnly, DataType::U32),
        BufferDecl::storage("queue_state", 7, BufferAccess::ReadWrite, DataType::U32)
            .with_count(QUEUE_STATE_WORDS as u32),
        BufferDecl::output("hit_ring", 8, DataType::U32).with_count(hit_capacity.saturating_mul(4)),
    ]
}

fn execute_batch_claim_body(hit_writer: BatchHitWriter) -> Vec<Node> {
    vec![
        Node::let_bind("work_base", Expr::mul(Expr::var("claim"), Expr::u32(3))),
        Node::let_bind("file_idx", Expr::load("work_queue", Expr::var("work_base"))),
        Node::let_bind(
            "rule_idx",
            Expr::load(
                "work_queue",
                Expr::add(Expr::var("work_base"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "layer_idx",
            Expr::load(
                "work_queue",
                Expr::add(Expr::var("work_base"), Expr::u32(2)),
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
            Expr::mul(Expr::var("rule_idx"), Expr::u32(RULE_META_WORDS as u32)),
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
                Expr::u32(queue_state_word::DONE_COUNT as u32),
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
                Expr::u32(queue_state_word::HIT_HEAD as u32),
                Expr::u32(1),
            ),
        ),
        Node::if_then(
            Expr::lt(
                Expr::var("hit_slot"),
                atomic_load_relaxed(
                    "queue_state",
                    Expr::u32(queue_state_word::HIT_CAPACITY as u32),
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

fn decode_hits(words: &[u32], hit_count: u32) -> Result<Vec<HitRecord>, PipelineError> {
    let needed_words = usize::try_from(hit_count)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| PipelineError::Backend("hit-count overflowed usize".to_string()))?;
    if words.len() < needed_words {
        return Err(PipelineError::Backend(format!(
            "hit-ring exposed {} words, expected at least {needed_words}. Fix: size the sparse hit ring for the configured hit_capacity.",
            words.len()
        )));
    }
    let mut hits = Vec::with_capacity(hit_count as usize);
    for chunk in words[..needed_words].chunks_exact(4) {
        hits.push(HitRecord {
            file_idx: chunk[0],
            rule_idx: chunk[1],
            layer_idx: chunk[2],
            match_offset: chunk[3],
        });
    }
    Ok(hits)
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
}
