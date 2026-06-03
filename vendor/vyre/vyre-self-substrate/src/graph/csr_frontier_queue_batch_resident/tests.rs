use super::*;
use crate::csr_frontier_queue_resident::upload_resident_csr_queue_graph;
use crate::graph::csr_frontier_queue_scratch::{
    resident_csr_queue_split_low_grid, ResidentCsrQueueMaterializer, STRIDED_FORWARD_MIN_ROW_DEGREE,
};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};
use std::cell::{Cell, RefCell};
use vyre_foundation::ir::Program;
use vyre_primitives::graph::csr_queue_strided::csr_queue_strided_forward_dispatch_grid;

#[derive(Default)]
struct RecordingBatchDispatcher {
    next_handle: Cell<u64>,
    upload_handles: RefCell<Vec<Vec<u64>>>,
    step_handles: RefCell<Vec<Vec<Vec<u64>>>>,
    step_grids: RefCell<Vec<Vec<Option<[u32; 3]>>>>,
    freed: RefCell<Vec<u64>>,
}

impl OptimizerDispatcher for RecordingBatchDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: batch resident queue tests should not use non-resident dispatch.".to_string(),
        ))
    }

    fn alloc_resident(&self, _byte_len: usize) -> Result<u64, DispatchError> {
        let handle = self.next_handle.get() + 1;
        self.next_handle.set(handle);
        Ok(handle)
    }

    fn upload_resident_many(&self, _uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
        Ok(())
    }

    fn upload_resident_many_sequence_read_ranges_into(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), DispatchError> {
        self.upload_handles
            .borrow_mut()
            .push(uploads.iter().map(|(handle, _)| *handle).collect());
        self.step_handles
            .borrow_mut()
            .push(steps.iter().map(|step| step.handle_ids.to_vec()).collect());
        self.step_grids
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
fn batch_queries_initialize_queue_len_on_device() {
    let dispatcher = RecordingBatchDispatcher::default();
    let graph = upload_resident_csr_queue_graph(&dispatcher, 2, &[0, 0, 0], &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let first = [1u32];
    let second = [2u32];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        2,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: recording dispatcher should complete resident CSR queue batch");

    let expected_uploads: Vec<u64> = scratch
        .handles
        .iter()
        .map(|handles| handles.frontier)
        .collect();
    assert_eq!(
        dispatcher
            .upload_handles
            .borrow()
            .last()
            .cloned()
            .expect("Fix: expected one resident upload sequence"),
        expected_uploads,
        "batch CSR queue traversal must only upload per-query frontier bytes; queue_len and output clear must stay device-side"
    );
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(
        steps.len(),
        6,
        "atomic-word resident CSR queue batches should initialize queue_len, compact packed words while clearing output, then traverse per query"
    );
    assert_eq!(steps[0], vec![scratch.handles[0].queue_len]);
    assert_eq!(
        steps[1],
        vec![
            scratch.handles[0].frontier,
            scratch.handles[0].active_queue,
            scratch.handles[0].queue_len,
            scratch.handles[0].frontier_out,
        ]
    );
    assert_eq!(steps[3], vec![scratch.handles[1].queue_len]);
    assert_eq!(
        steps[4],
        vec![
            scratch.handles[1].frontier,
            scratch.handles[1].active_queue,
            scratch.handles[1].queue_len,
            scratch.handles[1].frontier_out,
        ]
    );
    assert_eq!(outputs, vec![vec![0; 4], vec![0; 4]]);
}

#[test]
fn skewed_high_degree_batch_queries_use_bounded_split_queue() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 16u32;
    let mut edge_offsets = vec![0u32; node_count as usize + 1];
    for offset in edge_offsets.iter_mut().skip(1) {
        *offset = STRIDED_FORWARD_MIN_ROW_DEGREE;
    }
    let edge_targets = vec![1u32; STRIDED_FORWARD_MIN_ROW_DEGREE as usize];
    let edge_kind_mask = vec![1u32; STRIDED_FORWARD_MIN_ROW_DEGREE as usize];
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: high-degree resident CSR graph is valid");
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let first = [0x1ffu32];
    let second = [0x1ffu32];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        1024,
        u32::MAX,
        &mut outputs,
    )
    .expect(
        "Fix: recording dispatcher should complete skewed high-degree resident CSR queue batch",
    );

    assert_eq!(
        scratch
            .shape
            .expect("Fix: batch scratch shape should be retained")
            .high_queue_capacity,
        1
    );
    let first_high_queue = scratch.handles[0]
        .high_queue
        .expect("Fix: first mixed-split batch query should allocate high_queue");
    let first_high_len = scratch.handles[0]
        .high_len
        .expect("Fix: first mixed-split batch query should allocate high_len");
    let second_high_queue = scratch.handles[1]
        .high_queue
        .expect("Fix: second mixed-split batch query should allocate high_queue");
    let second_high_len = scratch.handles[1]
        .high_len
        .expect("Fix: second mixed-split batch query should allocate high_len");
    assert_eq!(scratch.high_len_handle_sets.len(), 2);
    assert_eq!(scratch.split_low_handle_sets.len(), 2);
    assert_eq!(scratch.high_traverse_handle_sets.len(), 2);
    assert_eq!(scratch.high_len_handle_sets[0], [first_high_len]);
    assert_eq!(
        scratch.split_low_handle_sets[0],
        [
            scratch.handles[0].active_queue,
            scratch.handles[0].queue_len,
            graph.edge_offsets_handle(),
            graph.edge_targets_handle(),
            graph.edge_kind_mask_handle(),
            scratch.handles[0].frontier_out,
            first_high_queue,
            first_high_len,
        ]
    );
    assert_eq!(
        scratch.high_traverse_handle_sets[1],
        [
            second_high_queue,
            second_high_len,
            graph.edge_offsets_handle(),
            graph.edge_targets_handle(),
            graph.edge_kind_mask_handle(),
            scratch.handles[1].frontier_out,
        ]
    );
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident batch step sequence");
    assert_eq!(
        steps.len(),
        10,
        "skewed high-degree batch queries should add high-len init, split-low, and bounded high-row traverse per query"
    );
    assert_eq!(steps[3], scratch.split_low_handle_sets[0].as_slice());
    assert_eq!(steps[4], scratch.high_traverse_handle_sets[0].as_slice());
    assert_eq!(steps[8], scratch.split_low_handle_sets[1].as_slice());
    assert_eq!(steps[9], scratch.high_traverse_handle_sets[1].as_slice());

    let grids = dispatcher
        .step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident batch grid sequence");
    assert_eq!(
        grids[3],
        Some(resident_csr_queue_split_low_grid(16)),
        "first skewed high-degree batch query must split low rows across the active queue"
    );
    assert_eq!(
        grids[4],
        Some(csr_queue_strided_forward_dispatch_grid(1)),
        "first skewed high-degree batch query must traverse only the bounded high-row queue"
    );
    assert_eq!(
        grids[8],
        Some(resident_csr_queue_split_low_grid(16)),
        "second skewed high-degree batch query must split low rows across the active queue"
    );
    assert_eq!(
        grids[9],
        Some(csr_queue_strided_forward_dispatch_grid(1)),
        "second skewed high-degree batch query must traverse only the bounded high-row queue"
    );
}

#[test]
fn uniformly_high_degree_batch_queries_use_row_strided_traverse_grid() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 16u32;
    let mut edge_offsets = vec![0u32; node_count as usize + 1];
    for (row, offset) in edge_offsets.iter_mut().enumerate() {
        *offset = STRIDED_FORWARD_MIN_ROW_DEGREE * row as u32;
    }
    let edge_count = STRIDED_FORWARD_MIN_ROW_DEGREE as usize * node_count as usize;
    let edge_targets = vec![1u32; edge_count];
    let edge_kind_mask = vec![1u32; edge_count];
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: uniformly high-degree resident CSR graph is valid");
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let first = [0x1ffu32];
    let second = [0x1ffu32];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        1024,
        u32::MAX,
        &mut outputs,
    )
    .expect(
        "Fix: recording dispatcher should complete uniformly high-degree resident CSR queue batch",
    );

    assert_eq!(
        scratch
            .shape
            .expect("Fix: batch scratch shape should be retained")
            .high_queue_capacity,
        0
    );
    assert!(scratch
        .handles
        .iter()
        .all(|handles| handles.high_queue.is_none()));
    assert!(scratch
        .handles
        .iter()
        .all(|handles| handles.high_len.is_none()));
    assert!(scratch.high_len_handle_sets.is_empty());
    assert!(scratch.split_low_handle_sets.is_empty());
    assert!(scratch.high_traverse_handle_sets.is_empty());
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident batch step sequence");
    assert_eq!(steps.len(), 6);
    let grids = dispatcher
        .step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident batch grid sequence");
    assert_eq!(
        grids[2],
        Some(csr_queue_strided_forward_dispatch_grid(16)),
        "first uniformly high-degree batch query must use row-strided traverse launch at the sparse effective capacity"
    );
    assert_eq!(
        grids[5],
        Some(csr_queue_strided_forward_dispatch_grid(16)),
        "second uniformly high-degree batch query must use row-strided traverse launch at the sparse effective capacity"
    );
}

#[test]
fn batch_queries_bucket_graph_sized_capacity_from_max_frontier_popcount() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 4096u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let mut first = vec![0u32; words];
    first[0] = 1;
    let mut second = vec![0u32; words];
    for node in 0..257u32 {
        second[(node / 32) as usize] |= 1 << (node % 32);
    }
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        node_count,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: recording dispatcher should complete bucketed resident CSR queue batch");

    assert_eq!(
        scratch
            .shape
            .expect("Fix: batch scratch shape should be retained")
            .queue_capacity,
        512,
        "batch queue capacity should be bucketed from the max active frontier, not graph size"
    );
    let grids = dispatcher
        .step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident batch grid sequence");
    assert_eq!(grids[2], Some([2, 1, 1]));
    assert_eq!(grids[5], Some([2, 1, 1]));
}

#[test]
fn batch_queries_reuse_larger_queue_scratch_for_smaller_effective_capacity() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 4096u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let mut larger = vec![0u32; words];
    for node in 0..257u32 {
        larger[(node / 32) as usize] |= 1 << (node % 32);
    }
    let large_frontiers: [&[u32]; 2] = [&larger, &larger];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &large_frontiers,
        node_count,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: first resident CSR queue batch dispatch should allocate the larger bucket");

    let retained_queue_handles: Vec<u64> = scratch
        .handles
        .iter()
        .map(|handles| handles.active_queue)
        .collect();
    let next_handle_after_large = dispatcher.next_handle.get();
    let mut single = vec![0u32; words];
    single[0] = 1;
    let small_frontiers: [&[u32]; 2] = [&single, &single];

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &small_frontiers,
        node_count,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: second resident CSR queue batch dispatch should reuse the larger bucket");

    assert_eq!(
        scratch
            .handles
            .iter()
            .map(|handles| handles.active_queue)
            .collect::<Vec<_>>(),
        retained_queue_handles
    );
    assert_eq!(
        scratch
            .shape
            .expect("Fix: batch scratch shape should be retained")
            .queue_capacity,
        512
    );
    assert_eq!(
        dispatcher.next_handle.get(),
        next_handle_after_large,
        "smaller sparse batches should not allocate new resident queue scratch"
    );
    assert!(dispatcher.freed.borrow().is_empty());
    let grids = dispatcher
        .step_grids
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected second resident batch grid sequence");
    assert_eq!(
        grids[2],
        Some([1, 1, 1]),
        "first reused batch query should launch traversal at the smaller effective capacity"
    );
    assert_eq!(
        grids[5],
        Some([1, 1, 1]),
        "second reused batch query should launch traversal at the smaller effective capacity"
    );
}

#[test]
fn budgeted_batch_memory_plan_uses_effective_queue_capacity() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 4096u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let mut one = vec![0u32; words];
    one[0] = 1;
    let frontiers: [&[u32]; 4] = [&one, &one, &one, &one];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    let plan = run_resident_csr_queue_batch_budgeted_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        node_count,
        u32::MAX,
        2 * (words * std::mem::size_of::<u32>() * 2 + 2 * std::mem::size_of::<u32>()),
        &mut outputs,
    )
    .expect("Fix: sparse frontiers should fit a budget that graph-sized queues would exceed");

    assert_eq!(plan.query_count, frontiers.len());
    assert_eq!(
        plan.bytes_per_query,
        words * std::mem::size_of::<u32>() * 2 + 2 * std::mem::size_of::<u32>()
    );
    assert_eq!(plan.max_queries_per_dispatch, 2);
    assert_eq!(plan.dispatch_batches, 2);
    assert_eq!(
        outputs,
        vec![vec![0; words * std::mem::size_of::<u32>()]; 4]
    );
}

#[test]
fn budgeted_batch_memory_plan_accounts_for_split_high_queue_scratch() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 16u32;
    let mut edge_offsets = vec![0u32; node_count as usize + 1];
    for offset in edge_offsets.iter_mut().skip(1) {
        *offset = STRIDED_FORWARD_MIN_ROW_DEGREE;
    }
    let edge_targets = vec![1u32; STRIDED_FORWARD_MIN_ROW_DEGREE as usize];
    let edge_kind_mask = vec![1u32; STRIDED_FORWARD_MIN_ROW_DEGREE as usize];
    let graph = upload_resident_csr_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: skewed high-degree resident CSR graph is valid");
    let first = [0x1ffu32];
    let second = [0x1ffu32];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    let plan = run_resident_csr_queue_batch_budgeted_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        1024,
        u32::MAX,
        152,
        &mut outputs,
    )
    .expect("Fix: split high-row scratch should fit one query per dispatch under this budget");

    assert_eq!(
        plan.bytes_per_query, 84,
        "budgeted split batches must count frontier, active queue, queue_len, frontier_out, high_queue, and high_len"
    );
    assert_eq!(plan.max_queries_per_dispatch, 1);
    assert_eq!(plan.dispatch_batches, 2);
    assert_eq!(plan.peak_batch_scratch_bytes, 84);
}

#[test]
fn budgeted_batch_packs_sparse_runs_around_dense_outlier() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 4096u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let mut sparse = vec![0u32; words];
    sparse[0] = 1;
    let dense = vec![u32::MAX; words];
    let frontiers: [&[u32]; 7] = [&sparse, &sparse, &sparse, &dense, &sparse, &sparse, &sparse];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();
    let dense_bytes_per_query =
        words * std::mem::size_of::<u32>() * 2 + node_count as usize * 4 + 4;

    let plan = run_resident_csr_queue_batch_budgeted_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        node_count,
        u32::MAX,
        dense_bytes_per_query,
        &mut outputs,
    )
    .expect("Fix: sparse runs should pack into large chunks around one dense outlier");

    assert_eq!(plan.query_count, frontiers.len());
    assert_eq!(
        plan.max_queries_per_dispatch, 3,
        "sparse runs should not inherit the dense outlier's graph-sized queue capacity"
    );
    assert_eq!(plan.dispatch_batches, 3);
    assert_eq!(plan.bytes_per_query, dense_bytes_per_query);
    assert_eq!(plan.peak_batch_scratch_bytes, dense_bytes_per_query);
    assert_eq!(
        dispatcher
            .upload_handles
            .borrow()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![3, 1, 3],
        "budgeted dispatch should preserve order while packing sparse chunks on both sides of the dense frontier"
    );
    assert_eq!(
        outputs,
        vec![vec![0; words * std::mem::size_of::<u32>()]; frontiers.len()]
    );
}

#[test]
fn large_sparse_batch_queries_use_atomic_word_materializer() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 8_193u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge large resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let mut first = vec![0u32; words];
    first[0] = 1;
    let second = vec![0u32; words];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        8,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: recording dispatcher should complete large resident CSR queue batch");

    assert_eq!(
        scratch
            .shape
            .expect("Fix: batch scratch shape should be retained")
            .materializer,
        ResidentCsrQueueMaterializer::AtomicWordScan
    );
    assert_eq!(scratch.word_count_handle_sets.len(), 0);
    assert_eq!(scratch.word_prefix_queue_handle_sets.len(), 0);
    assert_eq!(scratch.atomic_word_queue_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.queue_handle_sets.len(), frontiers.len());
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(steps.len(), 6);
    assert_eq!(steps[0], vec![scratch.handles[0].queue_len]);
    assert_eq!(
        steps[1],
        scratch.atomic_word_queue_handle_sets[0].as_slice(),
        "wide sparse batch query should use single-pass atomic word compaction"
    );
    assert_eq!(steps[3], vec![scratch.handles[1].queue_len]);
    assert_eq!(
        steps[4],
        scratch.atomic_word_queue_handle_sets[1].as_slice()
    );
    assert_eq!(
        outputs,
        vec![
            vec![0; words * std::mem::size_of::<u32>()],
            vec![0; words * std::mem::size_of::<u32>()],
        ]
    );
}

#[test]
fn large_dense_batch_queries_use_word_prefix_queue_materializer() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 8_193u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge large resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let first = vec![u32::MAX; words];
    let second = vec![0u32; words];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        node_count,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: recording dispatcher should complete large resident CSR queue batch");

    assert_eq!(
        scratch
            .shape
            .expect("Fix: batch scratch shape should be retained")
            .materializer,
        ResidentCsrQueueMaterializer::DeterministicWordPrefix
    );
    assert_eq!(scratch.word_count_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.word_prefix_queue_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.queue_handle_sets.len(), frontiers.len());
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(steps.len(), 8);
    assert_eq!(steps[0], vec![scratch.handles[0].frontier_out]);
    assert_eq!(
        steps[1],
        scratch.word_count_handle_sets[0].as_slice(),
        "large dense batch query must run word popcount scan before queue scatter"
    );
    assert_eq!(
        steps[2],
        scratch.word_prefix_queue_handle_sets[0].as_slice(),
        "large dense batch query must run deterministic word-prefix scatter"
    );
    assert_eq!(steps[4], vec![scratch.handles[1].frontier_out]);
    assert_eq!(steps[5], scratch.word_count_handle_sets[1].as_slice());
    assert_eq!(
        steps[6],
        scratch.word_prefix_queue_handle_sets[1].as_slice()
    );
    assert_eq!(
        outputs,
        vec![
            vec![0; words * std::mem::size_of::<u32>()],
            vec![0; words * std::mem::size_of::<u32>()],
        ]
    );
}

#[test]
fn small_multiblock_batch_queries_inline_block_offsets() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 32_897u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge multiblock resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let first = vec![u32::MAX; words];
    let second = vec![0u32; words];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        node_count,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: recording dispatcher should complete multiblock resident CSR queue batch");

    assert_eq!(scratch.word_count_handle_sets.len(), frontiers.len());
    assert_eq!(
        scratch.word_block_offsets_handle_sets.len(),
        0,
        "small multiblock batch queries should not pay a block-offset scan launch"
    );
    assert_eq!(scratch.word_prefix_queue_handle_sets.len(), frontiers.len());
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(steps.len(), 8);
    assert_eq!(steps[0], vec![scratch.handles[0].frontier_out]);
    assert_eq!(steps[1], scratch.word_count_handle_sets[0].as_slice());
    assert_eq!(
        steps[2],
        scratch.word_prefix_queue_handle_sets[0].as_slice()
    );
    assert_eq!(steps[4], vec![scratch.handles[1].frontier_out]);
    assert_eq!(steps[5], scratch.word_count_handle_sets[1].as_slice());
    assert_eq!(
        steps[6],
        scratch.word_prefix_queue_handle_sets[1].as_slice()
    );
    assert_eq!(
        outputs,
        vec![
            vec![0; words * std::mem::size_of::<u32>()],
            vec![0; words * std::mem::size_of::<u32>()],
        ]
    );
}

#[test]
fn many_block_batch_queries_scan_block_offsets_once_per_query() {
    let dispatcher = RecordingBatchDispatcher::default();
    let node_count = 262_177u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let graph = upload_resident_csr_queue_graph(&dispatcher, node_count, &edge_offsets, &[], &[])
        .expect("Fix: zero-edge many-block resident CSR graph is valid");
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let first = vec![u32::MAX; words];
    let second = vec![0u32; words];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        node_count,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: recording dispatcher should complete many-block resident CSR queue batch");

    assert_eq!(scratch.word_count_handle_sets.len(), frontiers.len());
    assert_eq!(
        scratch.word_block_offsets_handle_sets.len(),
        frontiers.len()
    );
    assert_eq!(scratch.word_prefix_queue_handle_sets.len(), frontiers.len());
    let steps = dispatcher
        .step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(steps.len(), 10);
    assert_eq!(steps[0], vec![scratch.handles[0].frontier_out]);
    assert_eq!(steps[1], scratch.word_count_handle_sets[0].as_slice());
    assert_eq!(
        steps[2],
        scratch.word_block_offsets_handle_sets[0].as_slice(),
        "many-block batch query must scan block offsets before scatter"
    );
    assert_eq!(
        steps[3],
        scratch.word_prefix_queue_handle_sets[0].as_slice()
    );
    assert_eq!(steps[5], vec![scratch.handles[1].frontier_out]);
    assert_eq!(steps[6], scratch.word_count_handle_sets[1].as_slice());
    assert_eq!(
        steps[7],
        scratch.word_block_offsets_handle_sets[1].as_slice()
    );
    assert_eq!(
        steps[8],
        scratch.word_prefix_queue_handle_sets[1].as_slice()
    );
    assert_eq!(
        outputs,
        vec![
            vec![0; words * std::mem::size_of::<u32>()],
            vec![0; words * std::mem::size_of::<u32>()],
        ]
    );
}

#[test]
fn generated_batch_dispatch_tables_reuse_capacity_across_calls() {
    let dispatcher = RecordingBatchDispatcher::default();
    let graph = upload_resident_csr_queue_graph(&dispatcher, 4, &[0, 0, 0, 0, 0], &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");
    let mut scratch = ResidentCsrQueueBatchScratch::default();
    let first = [1_u32];
    let second = [2_u32];
    let frontiers: [&[u32]; 2] = [&first, &second];
    let mut outputs = Vec::new();

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        4,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: first resident CSR queue batch dispatch should succeed");
    let retained_capacities = (
        scratch.clear_handle_sets.capacity(),
        scratch.queue_len_handle_sets.capacity(),
        scratch.word_count_handle_sets.capacity(),
        scratch.word_block_offsets_handle_sets.capacity(),
        scratch.queue_handle_sets.capacity(),
        scratch.atomic_word_queue_handle_sets.capacity(),
        scratch.word_prefix_queue_handle_sets.capacity(),
        scratch.traverse_handle_sets.capacity(),
        scratch.high_len_handle_sets.capacity(),
        scratch.split_low_handle_sets.capacity(),
        scratch.high_traverse_handle_sets.capacity(),
        scratch.read_ranges.capacity(),
    );

    run_resident_csr_queue_batch_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &frontiers,
        4,
        u32::MAX,
        &mut outputs,
    )
    .expect("Fix: second resident CSR queue batch dispatch should reuse prepared scratch");

    assert_eq!(
        (
            scratch.clear_handle_sets.capacity(),
            scratch.queue_len_handle_sets.capacity(),
            scratch.word_count_handle_sets.capacity(),
            scratch.word_block_offsets_handle_sets.capacity(),
            scratch.queue_handle_sets.capacity(),
            scratch.atomic_word_queue_handle_sets.capacity(),
            scratch.word_prefix_queue_handle_sets.capacity(),
            scratch.traverse_handle_sets.capacity(),
            scratch.high_len_handle_sets.capacity(),
            scratch.split_low_handle_sets.capacity(),
            scratch.high_traverse_handle_sets.capacity(),
            scratch.read_ranges.capacity(),
        ),
        retained_capacities,
        "resident batch sequence tables must retain allocation capacity across repeated dispatches"
    );
    assert_eq!(scratch.clear_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.queue_len_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.word_count_handle_sets.len(), 0);
    assert_eq!(scratch.word_block_offsets_handle_sets.len(), 0);
    assert_eq!(scratch.queue_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.atomic_word_queue_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.word_prefix_queue_handle_sets.len(), 0);
    assert_eq!(scratch.traverse_handle_sets.len(), frontiers.len());
    assert_eq!(scratch.high_len_handle_sets.len(), 0);
    assert_eq!(scratch.split_low_handle_sets.len(), 0);
    assert_eq!(scratch.high_traverse_handle_sets.len(), 0);
    assert_eq!(scratch.read_ranges.len(), frontiers.len());

    scratch
        .free(&dispatcher)
        .expect("Fix: resident CSR batch scratch free should release query handles");
    assert!(scratch.clear_handle_sets.is_empty());
    assert!(scratch.queue_len_handle_sets.is_empty());
    assert!(scratch.word_count_handle_sets.is_empty());
    assert!(scratch.word_block_offsets_handle_sets.is_empty());
    assert!(scratch.queue_handle_sets.is_empty());
    assert!(scratch.atomic_word_queue_handle_sets.is_empty());
    assert!(scratch.word_prefix_queue_handle_sets.is_empty());
    assert!(scratch.traverse_handle_sets.is_empty());
    assert!(scratch.high_len_handle_sets.is_empty());
    assert!(scratch.split_low_handle_sets.is_empty());
    assert!(scratch.high_traverse_handle_sets.is_empty());
    assert!(scratch.read_ranges.is_empty());
}

#[test]
fn generated_batch_scratch_free_releases_each_handle_once_in_first_seen_order() {
    for seed in 0..4096_u64 {
        let dispatcher = RecordingBatchDispatcher::default();
        let base = 40_000 + seed * 16;
        let mut scratch = ResidentCsrQueueBatchScratch::default();
        scratch.handles.push(ResidentCsrQueueBatchQueryHandles {
            frontier: base,
            active_queue: base + 1,
            queue_len: base,
            frontier_out: base + 2,
            word_partials: None,
            block_totals: None,
            high_queue: None,
            high_len: None,
        });
        scratch.handles.push(ResidentCsrQueueBatchQueryHandles {
            frontier: base + 2,
            active_queue: base + 3,
            queue_len: base + 3,
            frontier_out: base + 4,
            word_partials: Some(base + 5),
            block_totals: Some(base + 5),
            high_queue: Some(base + 6),
            high_len: Some(base + 6),
        });
        scratch
            .free(&dispatcher)
            .expect("Fix: batch scratch free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[
                base,
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6
            ]
        );
    }
}
