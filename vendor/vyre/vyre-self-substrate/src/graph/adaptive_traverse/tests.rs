use super::state::{
    adaptive_four_russians_layout_hash, adaptive_traversal_layout_hash, AdaptiveTraversalPlanCache,
};
use super::*;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};
use crate::optimizer::dispatcher::{ResidentDispatchStep, ResidentReadRange};
use std::cell::{Cell, RefCell};
use vyre_foundation::ir::Program;

#[derive(Default)]
struct RecordingResidentDispatcher {
    next_handle: Cell<u64>,
    alloc_count: Cell<usize>,
    upload_handles: RefCell<Vec<Vec<u64>>>,
    step_handles: RefCell<Vec<Vec<Vec<u64>>>>,
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

    fn alloc_resident(&self, _byte_len: usize) -> Result<u64, DispatchError> {
        self.alloc_count.set(self.alloc_count.get() + 1);
        let handle = self.next_handle.get() + 1;
        self.next_handle.set(handle);
        Ok(handle)
    }

    fn free_resident(&self, handle: u64) -> Result<(), DispatchError> {
        self.freed.borrow_mut().push(handle);
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
        "primitive_frontier_to_queue(",
        "primitive_csr_queue_forward_traverse(",
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
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot::default()
    );
    dispatcher.assert_no_resident_work();
}

#[test]
fn auto_zero_frontier_returns_sparse_queue_without_resident_work_or_cache() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 128,
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
        words: 2,
        layout_hash: 7,
        handles: [101, 102, 103, 104],
    };
    let graph_b = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 8,
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
    assert_eq!(
        dispatcher.last_upload_handles(),
        vec![scratch_handles[0]],
        "sparse-queue traversal must upload only frontier input"
    );
    let steps = dispatcher.last_step_handles();
    assert_eq!(
        steps.len(),
        4,
        "sparse-queue traversal should init queue_len, clear output, compact, then traverse"
    );
    assert_eq!(
        steps[0],
        vec![scratch_handles[2]],
        "first sparse-queue resident step must initialize queue_len on device"
    );
    assert_eq!(
        steps[1],
        vec![scratch_handles[1]],
        "second sparse-queue resident step must clear frontier_out on device"
    );
    assert_eq!(frontier_out, vec![0]);
}

#[test]
fn generated_adaptive_resident_free_releases_each_handle_once_in_first_seen_order() {
    for seed in 0..4096_u64 {
        let dispatcher = RecordingResidentDispatcher::default();
        let base = 20_000 + seed * 16;
        let graph = ResidentAdaptiveTraversalGraph {
            node_count: 4,
            edge_count: 3,
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
            frontier_bytes: 4,
            queue_bytes: 4,
            frontier_in_bytes: Vec::new(),
            readbacks: Vec::new(),
            plan_cache: AdaptiveTraversalPlanCache::default(),
        };
        scratch.free(&dispatcher).expect("Fix: scratch free dedup");
        assert_eq!(dispatcher.freed.borrow().as_slice(), &[base + 3, base + 4]);
    }
}

#[test]

fn auto_step_rejects_bad_frontier_before_resident_allocation() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentAdaptiveTraversalGraph {
        node_count: 33,
        edge_count: 0,
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

