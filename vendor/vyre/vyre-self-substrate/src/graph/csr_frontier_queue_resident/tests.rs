use super::*;
use crate::graph::csr_frontier_queue_scratch::{
    ResidentCsrQueueMaterializer, STRIDED_FORWARD_MIN_ROW_DEGREE,
};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};
use std::cell::{Cell, RefCell};
use vyre_foundation::ir::Program;
use vyre_primitives::graph::csr_queue_strided::csr_queue_strided_forward_dispatch_grid;

#[derive(Default)]
struct RecordingResidentDispatcher {
    next_handle: Cell<u64>,
    allocs: RefCell<Vec<usize>>,
    uploads: RefCell<Vec<Vec<u8>>>,
    sequence_upload_handles: RefCell<Vec<Vec<u64>>>,
    sequence_step_handles: RefCell<Vec<Vec<Vec<u64>>>>,
    sequence_step_grids: RefCell<Vec<Vec<Option<[u32; 3]>>>>,
    freed: RefCell<Vec<u64>>,
}

impl OptimizerDispatcher for RecordingResidentDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: resident queue tests should not use non-resident dispatch.".to_string(),
        ))
    }

    fn alloc_resident(&self, byte_len: usize) -> Result<u64, DispatchError> {
        self.allocs.borrow_mut().push(byte_len);
        let handle = self.next_handle.get() + 1;
        self.next_handle.set(handle);
        Ok(handle)
    }

    fn upload_resident_many(&self, uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
        self.uploads
            .borrow_mut()
            .extend(uploads.iter().map(|(_, bytes)| bytes.to_vec()));
        Ok(())
    }

    fn upload_resident_many_sequence_read_ranges_into(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), DispatchError> {
        self.sequence_upload_handles
            .borrow_mut()
            .push(uploads.iter().map(|(handle, _)| *handle).collect());
        self.sequence_step_handles
            .borrow_mut()
            .push(steps.iter().map(|step| step.handle_ids.to_vec()).collect());
        self.sequence_step_grids
            .borrow_mut()
            .push(steps.iter().map(|step| step.grid_override).collect());
        outputs.clear();
        outputs.extend(read_ranges.iter().map(|range| vec![0u8; range.byte_len]));
        Ok(())
    }

    fn free_resident(&self, handle: u64) -> Result<(), DispatchError> {
        self.freed.borrow_mut().push(handle);
        Ok(())
    }
}

#[test]
fn zero_edge_graph_uploads_padded_resident_edge_buffers() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = upload_resident_csr_queue_graph(&dispatcher, 3, &[0, 0, 0, 0], &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");

    assert_eq!(graph.edge_count(), 0);
    assert_eq!(graph.high_degree_source_count(), 0);
    assert_eq!(*dispatcher.allocs.borrow(), vec![16, 4, 4]);
    assert_eq!(
        *dispatcher.uploads.borrow(),
        vec![vec![0; 16], vec![0; 4], vec![0; 4]]
    );
}

#[test]
fn resident_upload_records_exact_high_degree_source_count() {
    let dispatcher = RecordingResidentDispatcher::default();
    let mut edge_offsets = Vec::new();
    let mut edge_targets = Vec::new();
    let mut edge_kind_mask = Vec::new();
    edge_offsets.push(0);
    for degree in [
        STRIDED_FORWARD_MIN_ROW_DEGREE,
        STRIDED_FORWARD_MIN_ROW_DEGREE - 1,
        STRIDED_FORWARD_MIN_ROW_DEGREE + 7,
        0,
        2,
    ] {
        edge_targets.extend((0..degree).map(|edge| edge % 5));
        edge_kind_mask.extend(std::iter::repeat(1).take(degree as usize));
        edge_offsets.push(edge_targets.len() as u32);
    }

    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        5,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: high-degree resident CSR graph upload should validate");

    assert_eq!(graph.max_row_degree(), STRIDED_FORWARD_MIN_ROW_DEGREE + 7);
    assert_eq!(
        graph.high_degree_source_count(),
        2,
        "resident graph metadata must count rows, not infer high-row capacity from total edge count"
    );
}

#[test]
fn resident_upload_uses_primitive_csr_validation() {
    let dispatcher = RecordingResidentDispatcher::default();
    let err = upload_resident_csr_queue_graph(&dispatcher, 2, &[0, 1, 1], &[5], &[1])
        .expect_err("out-of-range targets must be rejected before upload");
    assert!(
        matches!(err, DispatchError::BadInputs(message) if message.contains("outside node_count"))
    );
    assert!(dispatcher.allocs.borrow().is_empty());
    assert!(dispatcher.uploads.borrow().is_empty());
}

#[test]
fn resident_query_initializes_queue_len_on_device() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentCsrQueueGraph {
        node_count: 1,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words: 1,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &[1],
        1,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: resident CSR queue query should allocate scratch handles");
    assert_eq!(
        dispatcher
            .sequence_upload_handles
            .borrow()
            .last()
            .cloned()
            .expect("Fix: expected one resident sequence"),
        vec![handles.frontier],
        "resident CSR queue query must only upload frontier bytes; queue_len and output clear must stay device-side"
    );
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(
        steps.len(),
        3,
        "atomic-word resident CSR queue should initialize queue_len, compact packed words while clearing output, then traverse"
    );
    assert_eq!(steps[0], vec![handles.queue_len]);
    assert_eq!(
        steps[1],
        vec![
            handles.frontier,
            handles.active_queue,
            handles.queue_len,
            handles.frontier_out,
        ]
    );
    assert_eq!(output, vec![0, 0, 0, 0]);
}

#[test]
fn skewed_high_degree_resident_query_uses_bounded_split_queue() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentCsrQueueGraph {
        node_count: 16,
        edge_count: STRIDED_FORWARD_MIN_ROW_DEGREE,
        max_row_degree: STRIDED_FORWARD_MIN_ROW_DEGREE,
        high_degree_source_count: 1,
        words: 1,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &[0x1ff],
        1024,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete high-degree resident CSR query");

    let handles = scratch
        .handles
        .expect("Fix: mixed split resident query should allocate scratch handles");
    let high_queue = handles
        .high_queue
        .expect("Fix: mixed split resident query should allocate high_queue");
    let high_len = handles
        .high_len
        .expect("Fix: mixed split resident query should allocate high_len");
    assert_eq!(handles.high_queue_capacity, 1);
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(
        steps.len(),
        5,
        "skewed high-degree query should compact all active sources, split low/high rows, then traverse only bounded high rows"
    );
    assert_eq!(
        steps[3],
        vec![
            handles.active_queue,
            handles.queue_len,
            graph.edge_offsets_handle,
            graph.edge_targets_handle,
            graph.edge_kind_mask_handle,
            handles.frontier_out,
            high_queue,
            high_len,
        ],
        "split-low pass must bind active queue plus bounded high-row scratch"
    );
    assert_eq!(
        steps[4],
        vec![
            high_queue,
            high_len,
            graph.edge_offsets_handle,
            graph.edge_targets_handle,
            graph.edge_kind_mask_handle,
            handles.frontier_out,
        ],
        "strided follow-up must consume the bounded high-row queue"
    );
    let grids = dispatcher
        .sequence_step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step grid sequence");
    assert_eq!(
        grids[4],
        Some(csr_queue_strided_forward_dispatch_grid(1)),
        "skewed high-degree resident CSR queue traversal must launch row-strided teams only for the graph-wide high-row bound"
    );
}

#[test]
fn single_superhub_resident_query_sizes_split_queue_from_high_row_count() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentCsrQueueGraph {
        node_count: 16,
        edge_count: STRIDED_FORWARD_MIN_ROW_DEGREE * 9,
        max_row_degree: STRIDED_FORWARD_MIN_ROW_DEGREE * 9,
        high_degree_source_count: 1,
        words: 1,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &[0x1ff],
        1024,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete superhub resident CSR query");

    let handles = scratch
        .handles
        .expect("Fix: superhub mixed split query should allocate scratch handles");
    assert_eq!(
        handles.high_queue_capacity, 1,
        "one enormous row should allocate one high-row slot, not edge_count / threshold slots"
    );
    assert_eq!(
        dispatcher.allocs.borrow().as_slice(),
        &[4, 64, 4, 4, 4, 4],
        "superhub split scratch should allocate frontier, 16-slot active queue, queue_len, frontier_out, one high_queue word, and high_len"
    );
}

#[test]
fn uniformly_high_degree_resident_query_uses_row_strided_traverse_grid() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentCsrQueueGraph {
        node_count: 16,
        edge_count: STRIDED_FORWARD_MIN_ROW_DEGREE * 16,
        max_row_degree: STRIDED_FORWARD_MIN_ROW_DEGREE,
        high_degree_source_count: 16,
        words: 1,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &[0x1ff],
        1024,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete uniformly high-degree resident CSR query");

    let handles = scratch
        .handles
        .expect("Fix: resident CSR query should allocate scratch handles");
    assert!(handles.high_queue.is_none());
    assert!(handles.high_len.is_none());
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(steps.len(), 3);
    let grids = dispatcher
        .sequence_step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step grid sequence");
    assert_eq!(
        grids[2],
        Some(csr_queue_strided_forward_dispatch_grid(16)),
        "uniformly high-degree resident CSR queue traversal must still use the full row-strided path"
    );
}

#[test]
fn resident_query_buckets_graph_sized_capacity_from_frontier_popcount() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 4096u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentCsrQueueGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut frontier = vec![0u32; words];
    for node in 0..257u32 {
        frontier[(node / 32) as usize] |= 1 << (node % 32);
    }
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        node_count,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete bucketed resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: resident CSR queue query should allocate scratch handles");
    assert_eq!(
        handles.queue_capacity, 512,
        "257 active sources should use the 512-slot bucket, not graph-sized scratch"
    );
    assert_eq!(
        dispatcher.allocs.borrow().as_slice(),
        &[
            words * std::mem::size_of::<u32>(),
            512 * std::mem::size_of::<u32>(),
            std::mem::size_of::<u32>(),
            words * std::mem::size_of::<u32>(),
        ]
    );
    let grids = dispatcher
        .sequence_step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step grid sequence");
    assert_eq!(grids[2], Some([2, 1, 1]));
}

#[test]
fn resident_query_reuses_larger_queue_scratch_for_smaller_effective_capacity() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 4096u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentCsrQueueGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut larger_frontier = vec![0u32; words];
    for node in 0..257u32 {
        larger_frontier[(node / 32) as usize] |= 1 << (node % 32);
    }
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &larger_frontier,
        node_count,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: first resident CSR queue query should allocate the larger bucket");

    let handles = scratch
        .handles
        .expect("Fix: resident CSR queue query should retain handles");
    let retained_queue_handle = handles.active_queue;
    let alloc_count = dispatcher.allocs.borrow().len();
    let mut single_frontier = vec![0u32; words];
    single_frontier[0] = 1;

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &single_frontier,
        node_count,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: second resident CSR queue query should reuse the larger bucket");

    let handles = scratch
        .handles
        .expect("Fix: resident CSR queue query should retain handles");
    assert_eq!(handles.active_queue, retained_queue_handle);
    assert_eq!(handles.queue_capacity, 512);
    assert_eq!(
        dispatcher.allocs.borrow().len(),
        alloc_count,
        "smaller sparse frontiers should not free and reallocate resident queue scratch"
    );
    assert!(dispatcher.freed.borrow().is_empty());
    let grids = dispatcher
        .sequence_step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected second resident step grid sequence");
    assert_eq!(
        grids[2],
        Some([1, 1, 1]),
        "the rebuilt program should still launch at the smaller effective capacity"
    );
}

#[test]
fn generated_resident_csr_queue_free_releases_each_handle_once_in_first_seen_order() {
    for seed in 0..4096_u64 {
        let dispatcher = RecordingResidentDispatcher::default();
        let base = 30_000 + seed * 16;
        let graph = ResidentCsrQueueGraph {
            node_count: 4,
            edge_count: 3,
            max_row_degree: 1,
            high_degree_source_count: 0,
            words: 1,
            edge_offsets_handle: base,
            edge_targets_handle: base + 1,
            edge_kind_mask_handle: base,
        };
        graph.free(&dispatcher).expect("Fix: graph free dedup");
        assert_eq!(dispatcher.freed.borrow().as_slice(), &[base, base + 1]);

        dispatcher.freed.borrow_mut().clear();
        let mut scratch = ResidentCsrQueueScratch::default();
        scratch.handles = Some(ResidentCsrQueueScratchHandles {
            frontier: base + 2,
            active_queue: base + 2,
            queue_len: base + 3,
            frontier_out: base + 4,
            word_partials: None,
            block_totals: None,
            high_queue: None,
            high_len: None,
            queue_capacity: 4,
            high_queue_capacity: 0,
            frontier_bytes: 4,
            materializer: ResidentCsrQueueMaterializer::AtomicWordScan,
        });
        scratch.free(&dispatcher).expect("Fix: scratch free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[base + 2, base + 3, base + 4]
        );

        dispatcher.freed.borrow_mut().clear();
        scratch.handles = Some(ResidentCsrQueueScratchHandles {
            frontier: base + 5,
            active_queue: base + 6,
            queue_len: base + 6,
            frontier_out: base + 7,
            word_partials: Some(base + 8),
            block_totals: Some(base + 8),
            high_queue: Some(base + 9),
            high_len: Some(base + 9),
            queue_capacity: 4,
            high_queue_capacity: 1,
            frontier_bytes: 4,
            materializer: ResidentCsrQueueMaterializer::DeterministicWordPrefix,
        });
        scratch
            .free(&dispatcher)
            .expect("Fix: word-prefix scratch free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[base + 5, base + 6, base + 7, base + 8, base + 9]
        );
    }
}

#[test]
fn large_single_word_resident_query_uses_atomic_word_materializer() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 8_193u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentCsrQueueGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        edge_offsets_handle: 201,
        edge_targets_handle: 202,
        edge_kind_mask_handle: 203,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();
    let mut frontier = vec![0u32; words];
    frontier[0] = 1;

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        8,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete large resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: large resident CSR queue query should allocate scratch handles");
    assert_eq!(
        handles.materializer,
        ResidentCsrQueueMaterializer::AtomicWordScan
    );
    assert!(handles.word_partials.is_none());
    assert!(handles.block_totals.is_none());
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");

    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0], vec![handles.queue_len]);
    assert_eq!(
        steps[1],
        vec![
            handles.frontier,
            handles.active_queue,
            handles.queue_len,
            handles.frontier_out,
        ],
        "wide graph with one nonzero frontier word should use the single-pass atomic word materializer"
    );
    assert_eq!(output, vec![0; words * std::mem::size_of::<u32>()]);
}

#[test]
fn large_dense_resident_query_uses_word_prefix_queue_materializer() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 8_193u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentCsrQueueGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        edge_offsets_handle: 201,
        edge_targets_handle: 202,
        edge_kind_mask_handle: 203,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();
    let frontier = vec![u32::MAX; words];

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        node_count,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete large dense resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: large dense resident CSR queue query should allocate scratch handles");
    assert_eq!(
        handles.materializer,
        ResidentCsrQueueMaterializer::DeterministicWordPrefix
    );
    let word_partials = handles
        .word_partials
        .expect("Fix: word-prefix query should allocate word_partials");
    let block_totals = handles
        .block_totals
        .expect("Fix: word-prefix query should allocate block_totals");
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");

    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0], vec![handles.frontier_out]);
    assert_eq!(
        steps[1],
        vec![handles.frontier, word_partials, block_totals]
    );
    assert_eq!(
        steps[2],
        vec![
            handles.frontier,
            word_partials,
            block_totals,
            handles.active_queue,
            handles.queue_len,
        ]
    );
    assert_eq!(output, vec![0; words * std::mem::size_of::<u32>()]);
}

#[test]
fn small_multiblock_resident_query_inlines_block_offsets() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 32_897u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentCsrQueueGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        edge_offsets_handle: 201,
        edge_targets_handle: 202,
        edge_kind_mask_handle: 203,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();
    let frontier = vec![u32::MAX; words];

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        node_count,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete multiblock resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: multiblock resident CSR queue query should allocate scratch handles");
    let word_partials = handles
        .word_partials
        .expect("Fix: multiblock word-prefix query should allocate word_partials");
    let block_totals = handles
        .block_totals
        .expect("Fix: multiblock word-prefix query should allocate block_totals");
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");

    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0], vec![handles.frontier_out]);
    assert_eq!(
        steps[1],
        vec![handles.frontier, word_partials, block_totals]
    );
    assert_eq!(
        steps[2],
        vec![
            handles.frontier,
            word_partials,
            block_totals,
            handles.active_queue,
            handles.queue_len,
        ]
    );
    assert_eq!(output, vec![0; words * std::mem::size_of::<u32>()]);
}

#[test]
fn many_block_resident_query_scans_block_offsets_once() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 262_177u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentCsrQueueGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        edge_offsets_handle: 201,
        edge_targets_handle: 202,
        edge_kind_mask_handle: 203,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();
    let frontier = vec![u32::MAX; words];

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontier,
        node_count,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete many-block resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: many-block resident CSR queue query should allocate scratch handles");
    let word_partials = handles
        .word_partials
        .expect("Fix: many-block word-prefix query should allocate word_partials");
    let block_totals = handles
        .block_totals
        .expect("Fix: many-block word-prefix query should allocate block_totals");
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");

    assert_eq!(steps.len(), 5);
    assert_eq!(steps[0], vec![handles.frontier_out]);
    assert_eq!(
        steps[1],
        vec![handles.frontier, word_partials, block_totals]
    );
    assert_eq!(
        steps[2],
        vec![block_totals],
        "many-block query must convert block totals into offsets once"
    );
    assert_eq!(
        steps[3],
        vec![
            handles.frontier,
            word_partials,
            block_totals,
            handles.active_queue,
            handles.queue_len,
        ]
    );
    assert_eq!(output, vec![0; words * std::mem::size_of::<u32>()]);
}
