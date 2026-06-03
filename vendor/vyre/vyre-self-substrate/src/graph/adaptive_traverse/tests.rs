use super::state::{
    adaptive_four_russians_layout_hash, adaptive_traversal_layout_hash, AdaptiveTraversalPlanCache,
};
use super::*;
use crate::graph::csr_frontier_queue_scratch::STRIDED_FORWARD_MIN_ROW_DEGREE;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};
use crate::optimizer::dispatcher::{ResidentDispatchStep, ResidentReadRange};
use std::cell::{Cell, RefCell};
use vyre_foundation::ir::Program;

#[derive(Default)]
struct RecordingResidentDispatcher {
    next_handle: Cell<u64>,
    alloc_count: Cell<usize>,
    alloc_lengths: RefCell<Vec<usize>>,
    resident_uploads: RefCell<Vec<(u64, usize)>>,
    upload_handles: RefCell<Vec<Vec<u64>>>,
    step_handles: RefCell<Vec<Vec<Vec<u64>>>>,
    step_grids: RefCell<Vec<Vec<Option<[u32; 3]>>>>,
    freed: RefCell<Vec<u64>>,
}

impl RecordingResidentDispatcher {
    fn last_upload_handles(&self) -> Vec<u64> {
        self.upload_handles
            .borrow()
            .last()
            .cloned()
            .expect("Fix: test dispatcher expected at least one resident upload sequence")
    }

    fn last_step_handles(&self) -> Vec<Vec<u64>> {
        self.step_handles
            .borrow()
            .last()
            .cloned()
            .expect("Fix: test dispatcher expected at least one resident dispatch sequence")
    }

    fn last_step_grids(&self) -> Vec<Option<[u32; 3]>> {
        self.step_grids
            .borrow()
            .last()
            .cloned()
            .expect("Fix: test dispatcher expected at least one resident dispatch sequence")
    }

    fn resident_alloc_lengths(&self) -> Vec<usize> {
        self.alloc_lengths.borrow().clone()
    }

    fn resident_upload_lengths(&self) -> Vec<usize> {
        self.resident_uploads
            .borrow()
            .iter()
            .map(|(_, bytes)| *bytes)
            .collect()
    }

    fn assert_no_resident_work(&self) {
        assert_eq!(
            self.alloc_count.get(),
            0,
            "zero-frontier fast paths must not allocate resident scratch"
        );
        assert!(
            self.upload_handles.borrow().is_empty(),
            "zero-frontier fast paths must not upload resident inputs"
        );
        assert!(
            self.step_handles.borrow().is_empty(),
            "zero-frontier fast paths must not dispatch resident kernels"
        );
    }
}

impl OptimizerDispatcher for RecordingResidentDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: recording dispatcher only supports resident sequence tests.".to_string(),
        ))
    }

    fn supports_persistent(&self) -> bool {
        true
    }

    fn alloc_resident(&self, byte_len: usize) -> Result<u64, DispatchError> {
        self.alloc_count.set(self.alloc_count.get() + 1);
        self.alloc_lengths.borrow_mut().push(byte_len);
        let handle = self.next_handle.get() + 1;
        self.next_handle.set(handle);
        Ok(handle)
    }

    fn free_resident(&self, handle: u64) -> Result<(), DispatchError> {
        self.freed.borrow_mut().push(handle);
        Ok(())
    }

    fn upload_resident(&self, handle: u64, bytes: &[u8]) -> Result<(), DispatchError> {
        self.resident_uploads
            .borrow_mut()
            .push((handle, bytes.len()));
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
}

#[test]
fn selector_uses_queue_for_tiny_sparse_frontier() {
    assert_eq!(
        select_adaptive_traversal_mode(1_000, 10_000, 1, 25),
        AdaptiveTraversalMode::SparseQueue
    );
}

#[test]
fn selector_uses_sparse_dense_at_dense_cutover() {
    assert_eq!(
        select_adaptive_traversal_mode(1_000, 10_000, 260, 25),
        AdaptiveTraversalMode::SparseDense
    );
}

#[test]
fn selector_exports_four_russians_dense_kernel_choice() {
    assert_eq!(
        select_dense_traversal_kernel(1_024, 900, 2),
        DenseTraversalKernel::FourRussiansByteTile
    );
}

#[test]
fn layout_hash_distinguishes_dense_rows() {
    let offsets = [0, 0];
    let targets = [];
    let masks = [];
    let a = adaptive_traversal_layout_hash(1, &offsets, &targets, &masks, &[1]);
    let b = adaptive_traversal_layout_hash(1, &offsets, &targets, &masks, &[2]);
    assert_ne!(a, b);
}

#[test]
fn four_russians_layout_hash_distinguishes_dense_rows() {
    let a = adaptive_four_russians_layout_hash(8, &[0b0000_0001, 0, 0, 0, 0, 0, 0, 0]);
    let b = adaptive_four_russians_layout_hash(8, &[0b0000_0010, 0, 0, 0, 0, 0, 0, 0]);
    assert_ne!(a, b);
}

#[test]
fn matches_primitive_directly_by_wiring_release_programs() {
    let upload_source = include_str!("upload.rs");
    let resident_source = include_str!("resident_steps.rs");
    let release_path = format!("{upload_source}\n{resident_source}");

    for primitive_call in [
        "primitive_adaptive_sparse_dense_step(",
        "primitive_adaptive_four_russians_dense_step(",
        "primitive_four_russians_dense_lut_from_adj_rows(",
        "primitive_frontier_queue_len_init(",
        "primitive_frontier_words_to_queue_clear_out(",
        "primitive_frontier_word_counts(",
        "primitive_frontier_word_block_offsets(",
        "primitive_frontier_word_block_offsets_queue(",
        "primitive_frontier_word_prefix_queue(",
        "primitive_csr_queue_forward_traverse(",
        "primitive_csr_queue_split_low_forward_traverse(",
    ] {
        assert!(
            release_path.contains(primitive_call),
            "adaptive traversal release path must call primitive output wiring {primitive_call}"
        );
    }
}

#[test]
fn release_resident_paths_do_not_call_cpu_or_local_saturating_helpers() {
    let upload_source = include_str!("upload.rs");
    let resident_source = include_str!("resident_steps.rs");
    let release_path = format!("{upload_source}\n{resident_source}");

    assert!(!release_path.contains("reference_adaptive_sparse_dense_step("));
    assert!(!release_path.contains("cpu_sparse_dense_step("));
    assert!(!release_path.contains("saturating_mul"));
    assert!(!release_path.contains("u32_word_bytes("));
    assert!(!release_path.contains(".div_ceil(256)"));
    assert!(release_path.contains("plan_adaptive_resident_frontier_step"));
    assert!(release_path.contains("plan_adaptive_resident_sparse_queue_step"));
    assert!(release_path.contains("plan_adaptive_resident_auto_step"));
}

#[test]
fn sparse_dense_zero_frontier_returns_zero_without_resident_work_or_cache() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words: 2,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = vec![9, 9, 9];

    adaptive_traverse_resident_graph_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[0, 0],
        u32::MAX,
        25,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: zero sparse/dense frontier should complete on host");

    assert_eq!(frontier_out, vec![0, 0]);
    assert!(scratch.handles.is_none());
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot::default()
    );
    dispatcher.assert_no_resident_work();
}

#[test]
fn four_russians_zero_frontier_returns_zero_without_resident_work_or_cache() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveFourRussiansDenseGraph {
        node_count: 33,
        words: 2,
        layout_hash: 7,
        lut_handle: 201,
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = vec![9, 9, 9];

    adaptive_traverse_resident_graph_four_russians_dense_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[0, 0],
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: zero Four-Russians frontier should complete on host");

    assert_eq!(frontier_out, vec![0, 0]);
    assert!(scratch.handles.is_none());
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot::default()
    );
    dispatcher.assert_no_resident_work();
}

#[test]
fn sparse_queue_zero_frontier_returns_zero_without_queue_allocation_or_cache() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words: 2,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = vec![9, 9, 9];

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[0, 0],
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: zero sparse-queue frontier should complete on host");

    assert_eq!(frontier_out, vec![0, 0]);
    assert!(scratch.handles.is_none());
    assert!(scratch.queue_handle.is_none());
    assert!(scratch.word_partials_handle.is_none());
    assert!(scratch.word_block_totals_handle.is_none());
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot::default()
    );
    dispatcher.assert_no_resident_work();
}

#[test]
fn sparse_queue_graph_upload_skips_dense_adjacency_rows() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 4u32;
    let edge_offsets = [0, 1, 1, 1, 1];
    let edge_targets = [2];
    let edge_kind_mask = [1];

    let graph = upload_resident_adaptive_sparse_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: CSR-only adaptive sparse-queue graph upload should accept canonical CSR");

    assert_eq!(graph.node_count(), node_count);
    assert_eq!(graph.edge_count(), 1);
    assert_eq!(graph.words(), 1);
    assert_eq!(dispatcher.alloc_count.get(), 3);
    assert_eq!(
        dispatcher.resident_upload_lengths(),
        vec![
            edge_offsets.len() * std::mem::size_of::<u32>(),
            edge_targets.len() * std::mem::size_of::<u32>(),
            edge_kind_mask.len() * std::mem::size_of::<u32>(),
        ],
        "CSR-only sparse-queue upload must not allocate or upload dense adjacency rows"
    );
}

#[test]
fn adaptive_upload_records_exact_high_degree_source_count() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 5u32;
    let degrees = [
        STRIDED_FORWARD_MIN_ROW_DEGREE,
        STRIDED_FORWARD_MIN_ROW_DEGREE - 1,
        STRIDED_FORWARD_MIN_ROW_DEGREE + 11,
        0,
        3,
    ];
    let mut edge_offsets = Vec::with_capacity(degrees.len() + 1);
    let mut edge_targets = Vec::new();
    let mut edge_kind_mask = Vec::new();
    edge_offsets.push(0);
    for degree in degrees {
        edge_targets.extend((0..degree).map(|edge| edge % node_count));
        edge_kind_mask.extend(std::iter::repeat(1).take(degree as usize));
        edge_offsets.push(edge_targets.len() as u32);
    }
    let adj_rows_dense = vec![0u32; node_count as usize];

    let full_graph = upload_resident_adaptive_traversal_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj_rows_dense,
    )
    .expect("Fix: full adaptive resident upload should accept high-degree CSR");
    let sparse_graph = upload_resident_adaptive_sparse_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: CSR-only adaptive resident upload should accept high-degree CSR");

    assert_eq!(
        full_graph.high_degree_source_count(),
        2,
        "full adaptive graph metadata must count high-degree rows exactly"
    );
    assert_eq!(
        sparse_graph.high_degree_source_count(),
        2,
        "CSR-only adaptive graph metadata must count high-degree rows exactly"
    );
}

#[test]
fn sparse_queue_step_accepts_csr_only_resident_graph() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 4u32;
    let edge_offsets = [0, 1, 1, 1, 1];
    let edge_targets = [2];
    let edge_kind_mask = [1];
    let graph = upload_resident_adaptive_sparse_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: CSR-only adaptive sparse-queue graph upload should accept canonical CSR");
    let graph_handles = graph.handles();
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let frontier_in = [1u32];
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: CSR-only adaptive sparse-queue resident step should dispatch");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse queue step should allocate frontier scratch");
    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse queue step should allocate active queue");
    let steps = dispatcher.last_step_handles();
    assert_eq!(steps.len(), 3);
    assert_eq!(
        steps[2],
        vec![
            queue_handle,
            scratch_handles[2],
            graph_handles[0],
            graph_handles[1],
            graph_handles[2],
            scratch_handles[1],
        ],
        "CSR-only sparse queue traversal must bind only CSR graph handles"
    );
    assert_eq!(frontier_out, vec![0]);
}

#[test]
fn sparse_queue_step_sizes_active_queue_from_frontier_popcount() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 8_000u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_in = vec![0u32; words];
    frontier_in[0] = 1;
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete sparse queue traversal");

    assert_eq!(
        scratch.queue_bytes,
        std::mem::size_of::<u32>(),
        "single-source frontier must not allocate a graph-sized active queue"
    );
    assert_eq!(
        dispatcher.resident_alloc_lengths().last().copied(),
        Some(std::mem::size_of::<u32>()),
        "active queue allocation should be sized from frontier popcount"
    );
    assert_eq!(frontier_out, vec![0; words]);
}

#[test]
fn sparse_queue_step_reuses_larger_queue_scratch_for_smaller_frontier() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 4096u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        layout_hash: 11,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut larger_frontier = vec![0u32; words];
    for node in 0..300u32 {
        larger_frontier[(node / 32) as usize] |= 1 << (node % 32);
    }
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &larger_frontier,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete larger sparse queue traversal");

    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse queue step must allocate active queue");
    assert_eq!(scratch.queue_bytes, 512 * std::mem::size_of::<u32>());
    let allocs_after_large = dispatcher.alloc_count.get();
    let mut single_frontier = vec![0u32; words];
    single_frontier[0] = 1;

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &single_frontier,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete smaller sparse queue traversal");

    assert_eq!(scratch.queue_handle, Some(queue_handle));
    assert_eq!(
        scratch.queue_bytes,
        512 * std::mem::size_of::<u32>(),
        "scratch should keep the larger reusable queue buffer instead of shrinking"
    );
    assert_eq!(
        dispatcher.alloc_count.get(),
        allocs_after_large,
        "smaller frontiers should reuse the existing resident queue allocation"
    );
    assert!(
        dispatcher.freed.borrow().is_empty(),
        "smaller frontiers should not free and reallocate resident queue scratch"
    );
}

#[test]
fn skewed_high_degree_sparse_queue_step_uses_bounded_split_queue() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 2048u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: crate::graph::csr_frontier_queue_scratch::STRIDED_FORWARD_MIN_ROW_DEGREE,
        max_row_degree: crate::graph::csr_frontier_queue_scratch::STRIDED_FORWARD_MIN_ROW_DEGREE,
        high_degree_source_count: 1,
        words,
        layout_hash: 13,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_in = vec![0u32; words];
    for node in 0..9u32 {
        frontier_in[(node / 32) as usize] |= 1 << (node % 32);
    }
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete high-degree sparse queue traversal");

    assert_eq!(scratch.queue_bytes, 16 * std::mem::size_of::<u32>());
    assert_eq!(
        scratch.high_queue_bytes,
        std::mem::size_of::<u32>(),
        "a graph with one possible hub must not launch a strided team for every active source"
    );
    let high_queue = scratch
        .high_queue_handle
        .expect("Fix: mixed split traversal should allocate a high-degree queue");
    let high_len = scratch
        .high_len_handle
        .expect("Fix: mixed split traversal should allocate a high-degree queue length");
    let scratch_handles = scratch
        .handles
        .expect("Fix: mixed split traversal should allocate frontier scratch");
    let active_queue = scratch
        .queue_handle
        .expect("Fix: mixed split traversal should allocate active queue scratch");
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        5,
        "skewed sparse queue traversal should materialize active sources, clear high_len, split low/high rows, then traverse only bounded high rows"
    );
    assert_eq!(
        steps[3],
        vec![
            active_queue,
            scratch_handles[2],
            graph.handles[0],
            graph.handles[1],
            graph.handles[2],
            scratch_handles[1],
            high_queue,
            high_len,
        ],
        "split-low pass must read the active queue and write only bounded high-row scratch"
    );
    assert_eq!(
        steps[4],
        vec![
            high_queue,
            high_len,
            graph.handles[0],
            graph.handles[1],
            graph.handles[2],
            scratch_handles[1],
        ],
        "strided follow-up must consume the bounded high-row queue, not the whole active queue"
    );
    assert_eq!(
        dispatcher.last_step_grids()[4],
        Some(vyre_primitives::graph::csr_queue_strided::csr_queue_strided_forward_dispatch_grid(1)),
        "skewed high-degree sparse queue traversal must launch row-strided teams only for the graph-wide high-row bound"
    );
}

#[test]
fn single_superhub_csr_only_sparse_queue_sizes_split_queue_from_high_row_count() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 2048u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let hub_degree = STRIDED_FORWARD_MIN_ROW_DEGREE * 9;
    let mut edge_offsets = vec![hub_degree; node_count as usize + 1];
    edge_offsets[0] = 0;
    let edge_targets = vec![1u32; hub_degree as usize];
    let edge_kind_mask = vec![1u32; hub_degree as usize];
    let graph = upload_resident_adaptive_sparse_queue_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
    )
    .expect("Fix: CSR-only adaptive sparse queue graph should accept a one-superhub graph");
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_in = vec![0u32; words];
    for node in 0..9u32 {
        frontier_in[(node / 32) as usize] |= 1 << (node % 32);
    }
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: CSR-only adaptive sparse queue step should complete one-superhub traversal");

    assert_eq!(graph.high_degree_source_count(), 1);
    assert_eq!(scratch.queue_bytes, 16 * std::mem::size_of::<u32>());
    assert_eq!(
        scratch.high_queue_bytes,
        std::mem::size_of::<u32>(),
        "one enormous row should allocate one adaptive high-row slot, not edge_count / threshold slots"
    );
    assert_eq!(
        dispatcher.last_step_grids()[4],
        Some(vyre_primitives::graph::csr_queue_strided::csr_queue_strided_forward_dispatch_grid(1)),
        "one-superhub adaptive traversal must launch only one row-strided team"
    );
}

#[test]
fn uniformly_high_degree_sparse_queue_step_keeps_global_strided_consumer() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 2048u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let queue_slots = 16u32;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: crate::graph::csr_frontier_queue_scratch::STRIDED_FORWARD_MIN_ROW_DEGREE
            * queue_slots,
        max_row_degree: crate::graph::csr_frontier_queue_scratch::STRIDED_FORWARD_MIN_ROW_DEGREE,
        high_degree_source_count: queue_slots,
        words,
        layout_hash: 17,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_in = vec![0u32; words];
    for node in 0..9u32 {
        frontier_in[(node / 32) as usize] |= 1 << (node % 32);
    }
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete uniformly high-degree traversal");

    assert!(scratch.high_queue_handle.is_none());
    assert!(scratch.high_len_handle.is_none());
    assert_eq!(
        scratch.queue_bytes,
        queue_slots as usize * std::mem::size_of::<u32>()
    );
    assert_eq!(dispatcher.last_step_handles().len(), 3);
    assert_eq!(
        dispatcher.last_step_grids()[2],
        Some(
            vyre_primitives::graph::csr_queue_strided::csr_queue_strided_forward_dispatch_grid(
                queue_slots
            )
        ),
        "uniformly high-degree sparse queue traversal should keep the single row-strided consumer"
    );
}

#[test]
fn auto_zero_frontier_returns_sparse_queue_without_resident_work_or_cache() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 128,
        max_row_degree: 8,
        high_degree_source_count: 0,
        words: 2,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = vec![9, 9, 9];

    let mode = adaptive_traverse_resident_graph_auto_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[0, 0],
        u32::MAX,
        25,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: zero auto frontier should complete on host");

    assert_eq!(mode, AdaptiveTraversalMode::SparseQueue);
    assert_eq!(frontier_out, vec![0, 0]);
    assert!(scratch.handles.is_none());
    assert!(scratch.queue_handle.is_none());
    assert!(scratch.word_partials_handle.is_none());
    assert!(scratch.word_block_totals_handle.is_none());
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot::default()
    );
    dispatcher.assert_no_resident_work();
}

#[test]
fn sparse_dense_resident_step_does_not_upload_popcount_zero_seed() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 1,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words: 1,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[1],
        u32::MAX,
        25,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete resident sparse/dense sequence");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse/dense resident step must allocate frontier/popcount handles");
    assert_eq!(
        dispatcher.last_upload_handles(),
        vec![scratch_handles[0]],
        "sparse/dense traversal must upload only frontier input; output and popcount are initialized on device"
    );
    assert_eq!(frontier_out, vec![0]);
}

#[test]
fn sparse_dense_resident_program_cache_reuses_same_shape_graphs() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph_a = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 8,
        max_row_degree: 2,
        high_degree_source_count: 0,
        words: 2,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let graph_b = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 8,
        max_row_degree: 2,
        high_degree_source_count: 0,
        words: 2,
        layout_hash: 99,
        handles: [201, 202, 203, 204],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_step_with_scratch_into(
        &dispatcher,
        &graph_a,
        &[1, 0],
        u32::MAX,
        25,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: first adaptive resident step should dispatch");
    adaptive_traverse_resident_graph_step_with_scratch_into(
        &dispatcher,
        &graph_b,
        &[1, 0],
        u32::MAX,
        25,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: second adaptive resident step should dispatch");

    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot {
            entries: 3,
            hits: 3,
            misses: 3,
        },
        "adaptive resident programs must be cached by shape/options, not resident graph contents"
    );
}

#[test]
fn sparse_queue_resident_step_initializes_queue_len_on_device() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 1,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words: 1,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[1],
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete resident sparse-queue sequence");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse-queue resident step must allocate frontier/queue-len handles");
    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse-queue resident step must allocate active queue");
    assert_eq!(
        dispatcher.last_upload_handles(),
        vec![scratch_handles[0]],
        "sparse-queue traversal must upload only frontier input"
    );
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        3,
        "sparse-queue traversal should initialize queue_len, compact packed frontier words while clearing output, then traverse"
    );
    assert_eq!(
        steps[0],
        vec![scratch_handles[2]],
        "first sparse-queue resident step must initialize queue_len on device"
    );
    assert_eq!(
        steps[1],
        vec![
            scratch_handles[0],
            queue_handle,
            scratch_handles[2],
            scratch_handles[1],
        ],
        "second sparse-queue resident step must compact packed words while clearing frontier_out"
    );
    assert_eq!(frontier_out, vec![0]);
}

#[test]
fn large_single_word_sparse_queue_resident_step_uses_atomic_materializer() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 8_193u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_in = vec![0u32; words];
    frontier_in[0] = 1;
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete large resident sparse-queue sequence");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse-queue resident step must allocate frontier/queue-len handles");
    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse-queue resident step must allocate active queue");
    assert!(scratch.word_partials_handle.is_none());
    assert!(scratch.word_block_totals_handle.is_none());
    assert_eq!(dispatcher.last_upload_handles(), vec![scratch_handles[0]]);
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        3,
        "wide graph with one nonzero frontier word should keep the single-pass atomic word materializer"
    );
    assert_eq!(
        steps[0],
        vec![scratch_handles[2]],
        "first sparse-queue resident step must initialize queue_len on device"
    );
    assert_eq!(
        steps[1],
        vec![
            scratch_handles[0],
            queue_handle,
            scratch_handles[2],
            scratch_handles[1],
        ],
        "single-word sparse queue traversal must compact packed words while clearing frontier_out"
    );
    assert_eq!(frontier_out, vec![0; words]);
}

#[test]
fn large_dense_sparse_queue_resident_step_uses_word_prefix_materializer() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 8_193u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let frontier_in = vec![u32::MAX; words];
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete dense resident sparse-queue sequence");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse-queue resident step must allocate frontier/queue-len handles");
    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse-queue resident step must allocate active queue");
    let word_partials = scratch
        .word_partials_handle
        .expect("Fix: dense sparse-queue step must allocate word partials");
    let block_totals = scratch
        .word_block_totals_handle
        .expect("Fix: dense sparse-queue step must allocate block totals");
    assert_eq!(dispatcher.last_upload_handles(), vec![scratch_handles[0]]);
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        4,
        "large dense sparse-queue traversal should clear output, scan words, scatter queue, then traverse"
    );
    assert_eq!(steps[0], vec![scratch_handles[1]]);
    assert_eq!(
        steps[1],
        vec![scratch_handles[0], word_partials, block_totals]
    );
    assert_eq!(
        steps[2],
        vec![
            scratch_handles[0],
            word_partials,
            block_totals,
            queue_handle,
            scratch_handles[2],
        ],
        "large dense sparse-queue traversal must use deterministic word-prefix queue scatter"
    );
    assert_eq!(frontier_out, vec![0; words]);
}

#[test]
fn small_multiblock_sparse_queue_resident_step_inlines_block_offsets() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 32_897u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        layout_hash: 11,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let frontier_in = vec![u32::MAX; words];
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete multiblock resident sparse-queue sequence");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse-queue resident step must allocate frontier/queue-len handles");
    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse-queue resident step must allocate active queue");
    let word_partials = scratch
        .word_partials_handle
        .expect("Fix: multiblock sparse-queue step must allocate word partials");
    let block_totals = scratch
        .word_block_totals_handle
        .expect("Fix: multiblock sparse-queue step must allocate block totals");
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        4,
        "small multiblock sparse-queue traversal should clear, count words, scatter with inline block offsets, then traverse"
    );
    assert_eq!(steps[0], vec![scratch_handles[1]]);
    assert_eq!(
        steps[1],
        vec![scratch_handles[0], word_partials, block_totals]
    );
    assert_eq!(
        steps[2],
        vec![
            scratch_handles[0],
            word_partials,
            block_totals,
            queue_handle,
            scratch_handles[2],
        ],
        "small multiblock sparse-queue traversal must scatter with inline block offsets"
    );
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot {
            entries: 4,
            hits: 0,
            misses: 4,
        }
    );
    assert_eq!(frontier_out, vec![0; words]);
}

#[test]
fn many_block_sparse_queue_resident_step_scans_block_offsets_once() {
    let dispatcher = RecordingResidentDispatcher::default();
    let node_count = 262_177u32;
    let words = vyre_primitives::bitset::bitset_words(node_count) as usize;
    let graph = ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words,
        layout_hash: 11,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let frontier_in = vec![u32::MAX; words];
    let mut frontier_out = Vec::new();

    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        u32::MAX,
        &mut scratch,
        &mut frontier_out,
    )
    .expect("Fix: recording dispatcher should complete many-block resident sparse-queue sequence");

    let scratch_handles = scratch
        .handles
        .expect("Fix: sparse-queue resident step must allocate frontier/queue-len handles");
    let queue_handle = scratch
        .queue_handle
        .expect("Fix: sparse-queue resident step must allocate active queue");
    let word_partials = scratch
        .word_partials_handle
        .expect("Fix: many-block sparse-queue step must allocate word partials");
    let block_totals = scratch
        .word_block_totals_handle
        .expect("Fix: many-block sparse-queue step must allocate block totals");
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        5,
        "many-block sparse-queue traversal should clear, count words, scan block offsets once, scatter, then traverse"
    );
    assert_eq!(steps[0], vec![scratch_handles[1]]);
    assert_eq!(
        steps[1],
        vec![scratch_handles[0], word_partials, block_totals]
    );
    assert_eq!(
        steps[2],
        vec![block_totals],
        "many-block sparse-queue traversal must convert block totals into offsets once"
    );
    assert_eq!(
        steps[3],
        vec![
            scratch_handles[0],
            word_partials,
            block_totals,
            queue_handle,
            scratch_handles[2],
        ],
        "many-block sparse-queue traversal must scatter with precomputed block offsets"
    );
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot {
            entries: 5,
            hits: 0,
            misses: 5,
        }
    );
    assert_eq!(frontier_out, vec![0; words]);
}

#[test]
fn generated_adaptive_resident_free_releases_each_handle_once_in_first_seen_order() {
    for seed in 0..4096_u64 {
        let dispatcher = RecordingResidentDispatcher::default();
        let base = 20_000 + seed * 16;
        let graph = ResidentAdaptiveTraversalGraph {
            node_count: 4,
            edge_count: 3,
            max_row_degree: 1,
            high_degree_source_count: 0,
            words: 1,
            layout_hash: seed,
            handles: [base, base + 1, base + 2, base],
        };
        graph.free(&dispatcher).expect("Fix: graph free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[base, base + 1, base + 2]
        );

        dispatcher.freed.borrow_mut().clear();
        let mut scratch = AdaptiveTraversalResidentScratch {
            handles: Some([base + 3, base + 4, base + 3]),
            queue_handle: Some(base + 4),
            high_queue_handle: Some(base + 6),
            high_len_handle: Some(base + 6),
            word_partials_handle: Some(base + 5),
            word_block_totals_handle: Some(base + 5),
            frontier_bytes: 4,
            queue_bytes: 4,
            high_queue_bytes: 4,
            word_partials_bytes: 4,
            word_block_totals_bytes: 4,
            frontier_in_bytes: Vec::new(),
            readbacks: Vec::new(),
            plan_cache: AdaptiveTraversalPlanCache::default(),
        };
        scratch.free(&dispatcher).expect("Fix: scratch free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[base + 3, base + 4, base + 6, base + 5]
        );
    }
}

#[test]

fn auto_step_rejects_bad_frontier_before_resident_allocation() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 0,
        max_row_degree: 0,
        high_degree_source_count: 0,
        words: 2,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut frontier_out = vec![123];

    let err = adaptive_traverse_resident_graph_auto_step_with_scratch_into(
        &dispatcher,
        &graph,
        &[1],
        u32::MAX,
        25,
        &mut scratch,
        &mut frontier_out,
    )
    .expect_err("Fix: malformed frontier must be rejected before mode dispatch");

    assert!(
        err.to_string().contains("expected 2 word(s)"),
        "unexpected frontier validation error: {err}"
    );
    assert_eq!(
        dispatcher.alloc_count.get(),
        0,
        "auto mode must validate frontier shape before allocating resident scratch"
    );
    assert_eq!(
        frontier_out,
        vec![123],
        "failed validation must not mutate caller output storage"
    );
}
