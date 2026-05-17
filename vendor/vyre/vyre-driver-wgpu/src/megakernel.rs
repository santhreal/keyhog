//! WGPU-owned megakernel dispatch wrapper.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Instant;
use vyre_driver::{
    BackendError, CompiledPipeline, DispatchConfig, OutputBuffers, Resource, VyreBackend,
};
use vyre_foundation::ir::Program;

use vyre_runtime::megakernel::io::{
    try_encode_empty_io_queue_into, validate_io_queue_bytes, IO_SLOT_COUNT,
};
use vyre_runtime::megakernel::protocol;
use vyre_runtime::megakernel::{
    build_program_sharded_once_slots_control_report_shared, build_scallop_lineage_with_scratch,
    plan_compact_fusion_into, prune_redundant_work_items_into, CompactFusionPlanningScratch,
    CrossArmRedundancy, Megakernel, MegakernelConfig, MegakernelDispatch, MegakernelReport,
    MegakernelWorkItem, IO_SLOT_WORDS,
};

#[cfg(feature = "megakernel-batch")]
#[path = "megakernel/batch.rs"]
pub mod batch;
#[cfg(feature = "megakernel-batch")]
#[path = "megakernel/dispatcher.rs"]
pub mod dispatcher;

#[cfg(feature = "megakernel-batch")]
pub use batch::{
    queue_state_word, BatchFile, FileBatch, FileMetadata, HitRecord, WorkTriple,
    FILE_METADATA_WORDS, HIT_RECORD_WORDS, QUEUE_STATE_WORDS, WORK_TRIPLE_WORDS,
};
#[cfg(feature = "megakernel-batch")]
pub use dispatcher::{BatchDispatchConfig, BatchDispatchReport, BatchDispatcher, BatchHitWriter};

thread_local! {
    static DISPATCH_SCRATCH: RefCell<DispatchScratch> = RefCell::new(DispatchScratch::default());
}

const MAX_INLINE_LINEAGE_ITEMS: usize = 256;

#[derive(Default)]
struct DispatchScratch {
    io_queue_bytes: Vec<u8>,
    control_bytes: Vec<u8>,
    ring_words: Vec<u32>,
    debug_log_bytes: Vec<u8>,
    fusion: CompactFusionPlanningScratch,
    lineage_state: Vec<u32>,
    lineage_next: Vec<u32>,
    lineage_changed: [u32; 1],
    deduped_items: Vec<MegakernelWorkItem>,
    compiled: Option<CompiledMegakernelPipeline>,
    resident: Option<ResidentMegakernelBuffers>,
    outputs: OutputBuffers,
}

struct CompiledMegakernelPipeline {
    backend_id: &'static str,
    workgroup_size_x: u32,
    slot_count: u32,
    dispatch_config: DispatchConfig,
    program: Arc<Program>,
    pipeline: Arc<dyn CompiledPipeline>,
}

struct ResidentMegakernelBuffers {
    backend_id: &'static str,
    workgroup_size_x: u32,
    slot_count: u32,
    input_lens: [usize; 4],
    resources: Vec<Resource>,
}

enum IoQueueInput<'a> {
    Scratch,
    Borrowed(&'a [u8]),
}

/// Runtime wrapper for persistent megakernel dispatch.
pub struct WgpuMegakernelDispatcher<'a> {
    backend: &'a dyn VyreBackend,
}

impl<'a> WgpuMegakernelDispatcher<'a> {
    /// Create a new dispatcher.
    #[must_use]
    pub fn new(backend: &'a dyn VyreBackend) -> Self {
        Self { backend }
    }

    /// Decode a raw little-endian `MegakernelWorkItem` queue and launch the megakernel.
    ///
    /// # Errors
    ///
    /// Returns a backend error when `work_queue_bytes` is not exactly aligned to
    /// [`MegakernelWorkItem`] records or when backend dispatch fails.
    pub fn dispatch_megakernel_bytes(
        &self,
        work_queue_bytes: &[u8],
        config: &MegakernelConfig,
    ) -> Result<MegakernelReport, BackendError> {
        if work_queue_bytes.len() % std::mem::size_of::<MegakernelWorkItem>() != 0 {
            return Err(BackendError::new(format!(
                "megakernel work queue has {} bytes, which is not a multiple of sizeof(MegakernelWorkItem)={}. Fix: encode whole MegakernelWorkItem records before dispatch.",
                work_queue_bytes.len(),
                std::mem::size_of::<MegakernelWorkItem>()
            )));
        }
        let work_items = bytemuck::try_cast_slice::<u8, MegakernelWorkItem>(work_queue_bytes).map_err(|err| {
            BackendError::new(format!(
                "megakernel work queue bytes are not aligned as MegakernelWorkItem records: {err}. Fix: allocate or copy the queue into aligned MegakernelWorkItem storage before dispatch."
            ))
        })?;
        self.dispatch_megakernel(work_items, config)
    }

    /// Launch the megakernel.
    pub fn dispatch_megakernel(
        &self,
        work_items: &[MegakernelWorkItem],
        config: &MegakernelConfig,
    ) -> Result<MegakernelReport, BackendError> {
        config.validate()?;

        if work_items.is_empty() {
            return Ok(MegakernelReport::default());
        }

        DISPATCH_SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            ensure_empty_io_queue_bytes(&mut scratch.io_queue_bytes)?;
            self.dispatch_megakernel_with_io_queue_ref(
                work_items,
                config,
                IoQueueInput::Scratch,
                &mut scratch,
            )
        })
    }

    /// Launch the megakernel with a caller-supplied IO queue.
    ///
    /// The queue is validated against the megakernel ABI before any backend
    /// work starts, so malformed queue views fail before compilation or GPU
    /// submission.
    pub fn dispatch_megakernel_with_io_queue(
        &self,
        work_items: &[MegakernelWorkItem],
        config: &MegakernelConfig,
        io_queue_bytes: Vec<u8>,
    ) -> Result<MegakernelReport, BackendError> {
        DISPATCH_SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            self.dispatch_megakernel_with_io_queue_ref(
                work_items,
                config,
                IoQueueInput::Borrowed(io_queue_bytes.as_slice()),
                &mut scratch,
            )
        })
    }

    fn dispatch_megakernel_with_io_queue_ref(
        &self,
        work_items: &[MegakernelWorkItem],
        config: &MegakernelConfig,
        io_queue: IoQueueInput<'_>,
        scratch: &mut DispatchScratch,
    ) -> Result<MegakernelReport, BackendError> {
        config.validate()?;
        let io_queue_bytes = match io_queue {
            IoQueueInput::Scratch => scratch.io_queue_bytes.as_slice(),
            IoQueueInput::Borrowed(bytes) => bytes,
        };
        validate_io_queue_bytes(io_queue_bytes).map_err(|e| BackendError::new(e.to_string()))?;

        let initial_item_count = work_items.len();
        if initial_item_count == 0 {
            return Ok(MegakernelReport::default());
        }

        let plan_start = Instant::now();
        let redundancy = prune_redundant_work_items_into(work_items, &mut scratch.deduped_items);
        let planning_items = if redundancy.is_empty() {
            work_items
        } else {
            scratch.deduped_items.as_slice()
        };

        let track_lineage = should_track_lineage(planning_items.len());
        if track_lineage {
            let _fusion_plan = plan_compact_fusion_into(planning_items, &mut scratch.fusion);
        } else {
            let empty_fusion_plan = plan_compact_fusion_into(&[], &mut scratch.fusion);
            debug_assert!(
                empty_fusion_plan.is_empty(),
                "empty megakernel fusion planning input must produce an empty plan"
            );
        }
        let dispatch_items = planning_items;
        let item_count = dispatch_items.len();
        let queue_plan_ns = nanos_u64(plan_start.elapsed().as_nanos());

        let queue_len = u32::try_from(item_count).map_err(|_| {
            BackendError::new(
                "megakernel work queue length exceeds u32::MAX. Fix: shard the queue before dispatch.",
            )
        })?;
        let max_workgroup_size_x = self.backend.max_workgroup_size()[0];
        if max_workgroup_size_x == 0 {
            return Err(BackendError::new(format!(
                "backend `{}` reported max_workgroup_size.x=0. Fix: use a backend that exposes real adapter limits before megakernel dispatch.",
                self.backend.id()
            )));
        }
        let launch = config.launch_recommendation(
            queue_len,
            max_workgroup_size_x,
            self.backend.max_compute_workgroups_per_dimension(),
            self.backend.max_compute_invocations_per_workgroup(),
        )?;
        let geometry = launch.geometry;

        let publish_start = Instant::now();
        let dispatch_config = geometry.dispatch_config(Some(config.max_wall_time));
        let compiled_cache_hit = compiled_pipeline_cache_matches(
            self.backend,
            geometry.workgroup_size_x,
            geometry.slot_count,
            &dispatch_config,
            &scratch.compiled,
        );
        let program = if compiled_cache_hit {
            None
        } else {
            Some(build_program_sharded_once_slots_control_report_shared(
                geometry.workgroup_size_x,
                geometry.slot_count,
                &[],
            ))
        };
        let compiled = if compiled_cache_hit {
            scratch
                .compiled
                .as_ref()
                .map(|cached| cached.pipeline.as_ref())
        } else {
            let program = program.as_ref().ok_or_else(|| {
                BackendError::new(
                    "megakernel cache miss had no Program to compile. Fix: build the sharded megakernel Program before compiling a new geometry."
                        .to_string(),
                )
            })?;
            compiled_pipeline_for_geometry(
                self.backend,
                program.clone(),
                geometry.workgroup_size_x,
                geometry.slot_count,
                &dispatch_config,
                &mut scratch.compiled,
            )?
        };
        Megakernel::encode_work_items_ring_words_into(
            geometry.slot_count,
            0,
            dispatch_items,
            &mut scratch.ring_words,
        )
        .map_err(|e| BackendError::new(e.to_string()))?;
        ensure_control_bytes(&mut scratch.control_bytes)?;
        ensure_empty_debug_log_bytes(&mut scratch.debug_log_bytes)?;
        let queue_publish_ns = nanos_u64(publish_start.elapsed().as_nanos());

        let start = Instant::now();
        scratch.outputs.clear();
        let inputs = [
            scratch.control_bytes.as_slice(),
            bytemuck::cast_slice(scratch.ring_words.as_slice()),
            scratch.debug_log_bytes.as_slice(),
            io_queue_bytes,
        ];
        if let Some(compiled) = compiled {
            if let Some(resources) = ensure_resident_megakernel_buffers(
                self.backend,
                geometry.workgroup_size_x,
                geometry.slot_count,
                &inputs,
                &mut scratch.resident,
            )? {
                scratch.outputs =
                    compiled.dispatch_persistent_handles(resources, &dispatch_config)?;
            } else {
                compiled
                    .dispatch_borrowed_into(&inputs, &dispatch_config, &mut scratch.outputs)?;
            }
        } else {
            let program = program.ok_or_else(|| {
                BackendError::new(
                    "megakernel cache-miss dispatch had no compiled pipeline and no Program. Fix: build the megakernel Program on every non-native-cache path.".to_string(),
                )
            })?;
            scratch.outputs = self
                .backend
                .dispatch_borrowed(program.as_ref(), &inputs, &dispatch_config)?;
        }
        let wall_time = start.elapsed();

        let control_done_count = scratch
            .outputs
            .first()
            .map(|b| Megakernel::read_done_count(b))
            .unwrap_or(0) as u64;
        let slot_done_count = scratch
            .outputs
            .iter()
            .filter_map(|bytes| protocol::count_done_ring_slots(bytes, item_count))
            .max()
            .unwrap_or(0);
        let done_count = control_done_count.max(slot_done_count);

        // P-RUNTIME-1: attach scallop-provenance lineage per dispatched
        // region so observability collectors can attribute outputs back
        // to the source rules that derived them. We seed the lineage
        // bitset from work_items[i].op_handle (each op contributes its
        // own bit, capped at 32 distinct ops per dispatch — the u32
        // word width) and run the substrate provenance closure across
        // the same exchange_adj that the matroid scheduler used. The
        // closure propagates lineage through any fused-region edges,
        // so a fused region's lineage bitset = union of contributing
        // ops' bits.
        let lineage_start = Instant::now();
        let region_lineage = if track_lineage {
            build_scallop_lineage_with_scratch(
                self.backend,
                planning_items,
                scratch.fusion.exchange_adj(),
                planning_items.len(),
                &mut scratch.lineage_state,
                &mut scratch.lineage_next,
                &mut scratch.lineage_changed,
                config.max_wall_time,
            )?
        } else {
            Vec::new()
        };
        let lineage_ns = nanos_u64(lineage_start.elapsed().as_nanos());

        let redundant_items = retained_redundant_done_count(
            work_items,
            dispatch_items,
            done_count,
            item_count,
            &redundancy,
        );
        let logical_done_count = done_count.saturating_add(redundant_items);
        Ok(MegakernelReport {
            items_processed: logical_done_count,
            items_remaining: (initial_item_count as u64).saturating_sub(logical_done_count),
            wall_time,
            queue_plan_ns,
            queue_publish_ns,
            backend_dispatch_ns: nanos_u64(wall_time.as_nanos()),
            lineage_ns,
            deduped_items: redundancy.total_redundant_ops as u64,
            published_items: item_count as u64,
            lineage_items: if track_lineage { item_count as u64 } else { 0 },
            region_lineage,
        })
    }
}

fn ensure_resident_megakernel_buffers<'a>(
    backend: &dyn VyreBackend,
    workgroup_size_x: u32,
    slot_count: u32,
    inputs: &[&[u8]; 4],
    cache: &'a mut Option<ResidentMegakernelBuffers>,
) -> Result<Option<&'a [Resource]>, BackendError> {
    if backend.id() != "cuda" {
        return Ok(None);
    }

    let input_lens = [
        inputs[0].len(),
        inputs[1].len(),
        inputs[2].len(),
        inputs[3].len(),
    ];
    let matches_cache = cache.as_ref().is_some_and(|resident| {
        resident.backend_id == backend.id()
            && resident.workgroup_size_x == workgroup_size_x
            && resident.slot_count == slot_count
            && resident.input_lens == input_lens
    });

    if !matches_cache {
        if let Some(old) = cache.take() {
            for resource in old.resources {
                backend.free_resident(resource)?;
            }
        }
        let mut resources = Vec::with_capacity(inputs.len());
        for input in inputs {
            match backend.allocate_resident(input.len()) {
                Ok(resource) => resources.push(resource),
                Err(BackendError::UnsupportedFeature { .. }) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        for (resource, input) in resources.iter().zip(inputs.iter()) {
            backend.upload_resident(resource, input)?;
        }
        *cache = Some(ResidentMegakernelBuffers {
            backend_id: backend.id(),
            workgroup_size_x,
            slot_count,
            input_lens,
            resources,
        });
    } else if let Some(resident) = cache.as_ref() {
        backend.upload_resident(&resident.resources[1], inputs[1])?;
    }

    Ok(cache.as_ref().map(|resident| resident.resources.as_slice()))
}

fn ensure_empty_io_queue_bytes(bytes: &mut Vec<u8>) -> Result<(), BackendError> {
    let expected = (IO_SLOT_COUNT as usize)
        .checked_mul(IO_SLOT_WORDS as usize)
        .and_then(|words| words.checked_mul(std::mem::size_of::<u32>()))
        .ok_or_else(|| {
            BackendError::new(
                "megakernel IO queue byte length overflowed usize. Fix: shard IO queue slots before dispatch.".to_string(),
            )
        })?;
    if bytes.len() != expected {
        try_encode_empty_io_queue_into(IO_SLOT_COUNT, bytes)
            .map_err(|error| BackendError::new(error.to_string()))?;
    }
    Ok(())
}

fn ensure_control_bytes(bytes: &mut Vec<u8>) -> Result<(), BackendError> {
    let expected = protocol::control_byte_len(0).ok_or_else(|| {
        BackendError::new(
            "megakernel control byte length overflowed usize. Fix: reduce observable slot count.".to_string(),
        )
    })?;
    if bytes.len() != expected {
        Megakernel::try_encode_control_into(false, 1, 0, bytes)
            .map_err(|error| BackendError::new(error.to_string()))?;
    }
    Ok(())
}

fn ensure_empty_debug_log_bytes(bytes: &mut Vec<u8>) -> Result<(), BackendError> {
    let expected = protocol::debug_log_byte_len(protocol::debug::RECORD_CAPACITY).ok_or_else(|| {
        BackendError::new(
            "megakernel debug-log byte length overflowed usize. Fix: reduce debug record capacity.".to_string(),
        )
    })?;
    if bytes.len() != expected {
        Megakernel::try_encode_empty_debug_log_into(protocol::debug::RECORD_CAPACITY, bytes)
            .map_err(|error| BackendError::new(error.to_string()))?;
    }
    Ok(())
}

fn compiled_pipeline_cache_matches(
    backend: &dyn VyreBackend,
    workgroup_size_x: u32,
    slot_count: u32,
    dispatch_config: &DispatchConfig,
    cache: &Option<CompiledMegakernelPipeline>,
) -> bool {
    cache.as_ref().is_some_and(|cached| {
        cached.backend_id == backend.id()
            && cached.workgroup_size_x == workgroup_size_x
            && cached.slot_count == slot_count
            && same_dispatch_shape(&cached.dispatch_config, dispatch_config)
    })
}

fn compiled_pipeline_for_geometry<'a>(
    backend: &dyn VyreBackend,
    program: Arc<Program>,
    workgroup_size_x: u32,
    slot_count: u32,
    dispatch_config: &DispatchConfig,
    cache: &'a mut Option<CompiledMegakernelPipeline>,
) -> Result<Option<&'a dyn CompiledPipeline>, BackendError> {
    if compiled_pipeline_cache_matches(
        backend,
        workgroup_size_x,
        slot_count,
        dispatch_config,
        cache,
    ) && cache
        .as_ref()
        .is_some_and(|cached| Arc::ptr_eq(&cached.program, &program))
    {
        return Ok(cache.as_ref().map(|cached| cached.pipeline.as_ref()));
    }

    match backend.compile_native_shared(program.clone(), dispatch_config)? {
        Some(pipeline) => {
            *cache = Some(CompiledMegakernelPipeline {
                backend_id: backend.id(),
                workgroup_size_x,
                slot_count,
                dispatch_config: dispatch_config.clone(),
                program,
                pipeline,
            });
            Ok(cache.as_ref().map(|cached| cached.pipeline.as_ref()))
        }
        None => {
            *cache = None;
            Ok(None)
        }
    }
}

fn same_dispatch_shape(left: &DispatchConfig, right: &DispatchConfig) -> bool {
    left.profile == right.profile
        && left.ulp_budget == right.ulp_budget
        && left.max_output_bytes == right.max_output_bytes
        && left.workgroup_override == right.workgroup_override
        && left.grid_override == right.grid_override
        && left.fixpoint_iterations == right.fixpoint_iterations
        && left.speculation == right.speculation
        && left.persistent_thread == right.persistent_thread
        && left.cooperative == right.cooperative
        && left.timeout == right.timeout
}

fn retained_redundant_done_count(
    work_items: &[MegakernelWorkItem],
    dispatch_items: &[MegakernelWorkItem],
    done_count: u64,
    dispatch_item_count: usize,
    redundancy: &CrossArmRedundancy,
) -> u64 {
    if done_count < dispatch_item_count as u64 {
        return 0;
    }
    redundancy
        .redundant_pairs
        .iter()
        .filter(|(early_idx, _, _)| {
            work_items
                .get(*early_idx)
                .is_some_and(|item| dispatch_items.iter().any(|queued| queued == item))
        })
        .count() as u64
}

fn nanos_u64(nanos: u128) -> u64 {
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn should_track_lineage(item_count: usize) -> bool {
    item_count <= MAX_INLINE_LINEAGE_ITEMS
}

impl MegakernelDispatch for WgpuMegakernelDispatcher<'_> {
    fn dispatch_megakernel(
        &self,
        work_queue: &[MegakernelWorkItem],
        config: &MegakernelConfig,
    ) -> Result<MegakernelReport, BackendError> {
        WgpuMegakernelDispatcher::dispatch_megakernel(self, work_queue, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(op: u32, input: u32, output: u32, param: u32) -> MegakernelWorkItem {
        MegakernelWorkItem {
            op_handle: op,
            input_handle: input,
            output_handle: output,
            param,
        }
    }

    #[test]
    fn retained_redundant_done_count_is_zero_without_full_dispatch_completion() {
        let a = item(1, 0, 5, 7);
        let work_items = [a, a];
        let redundancy = CrossArmRedundancy {
            redundant_pairs: vec![(0, 1, 0)],
            total_redundant_ops: 1,
        };

        let count = retained_redundant_done_count(&work_items, &[a], 0, 1, &redundancy);

        assert_eq!(count, 0);
    }

    #[test]
    fn retained_redundant_done_count_counts_duplicates_when_producer_finished() {
        let a = item(1, 0, 5, 7);
        let b = item(2, 5, 6, 0);
        let work_items = [a, b, a, a];
        let redundancy = CrossArmRedundancy {
            redundant_pairs: vec![(0, 2, 0), (0, 3, 0)],
            total_redundant_ops: 2,
        };

        let count = retained_redundant_done_count(&work_items, &[a, b], 2, 2, &redundancy);

        assert_eq!(count, 2);
    }

    #[test]
    fn retained_redundant_done_count_ignores_redundancy_without_queued_producer() {
        let a = item(1, 0, 5, 7);
        let b = item(2, 5, 6, 0);
        let work_items = [a, a, b];
        let redundancy = CrossArmRedundancy {
            redundant_pairs: vec![(0, 1, 0)],
            total_redundant_ops: 1,
        };

        let count = retained_redundant_done_count(&work_items, &[b], 1, 1, &redundancy);

        assert_eq!(count, 0);
    }

    #[test]
    fn retained_redundant_done_count_ignores_invalid_indices() {
        let a = item(1, 0, 5, 7);
        let redundancy = CrossArmRedundancy {
            redundant_pairs: vec![(99, 1, 0)],
            total_redundant_ops: 1,
        };

        let count = retained_redundant_done_count(&[a], &[a], 1, 1, &redundancy);

        assert_eq!(count, 0);
    }

    #[test]
    fn lineage_tracking_is_capped_for_large_hot_queues() {
        assert!(should_track_lineage(MAX_INLINE_LINEAGE_ITEMS));
        assert!(!should_track_lineage(MAX_INLINE_LINEAGE_ITEMS + 1));
    }

    #[test]
    fn dispatch_shape_distinguishes_timeout() {
        let mut left = DispatchConfig::default();
        let mut right = DispatchConfig::default();
        left.timeout = Some(std::time::Duration::from_millis(1));
        right.timeout = Some(std::time::Duration::from_millis(2));

        assert!(!same_dispatch_shape(&left, &right));
    }
}
