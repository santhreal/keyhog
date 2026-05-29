use super::state::PersistentBfsPlanCache;
use super::*;
use crate::dispatch_buffers::u32_slice_to_le_bytes;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher, ResidentReadRange};
use std::cell::{Cell, RefCell};
use vyre_foundation::ir::Program;
use vyre_primitives::graph::persistent_bfs::cpu_ref as reference_persistent_bfs;

#[test]
fn checked_reference_surfaces_bad_frontier_width() {
    let offsets = vec![0u32; 65];
    let err = try_bfs_expand(64, &offsets, &[], &[], &[1], 0xFFFF_FFFF, 1)
        .expect_err("short persistent BFS seed frontier must fail through substrate wrapper");

    assert!(
        err.contains("frontier"),
        "Fix: persistent BFS checked wrapper must preserve primitive frontier diagnostics, got: {err}"
    );
}

struct PersistentBfsDispatcher {
    outputs: Vec<Vec<u8>>,
}

impl OptimizerDispatcher for PersistentBfsDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(grid_override, Some([1, 1, 1]));
        if inputs.len() != 8 {
            return Err(DispatchError::BadInputs(format!(
                "Fix: persistent BFS test dispatcher expected 8 inputs, got {}.",
                inputs.len()
            )));
        }
        Ok(self.outputs.clone())
    }
}

struct RecordingPersistentBfsDispatcher {
    outputs: Vec<Vec<u8>>,
    edge_targets: RefCell<Vec<Vec<u32>>>,
}

impl OptimizerDispatcher for RecordingPersistentBfsDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(grid_override, Some([1, 1, 1]));
        if inputs.len() != 8 {
            return Err(DispatchError::BadInputs(format!(
                "Fix: persistent BFS recording dispatcher expected 8 inputs, got {}.",
                inputs.len()
            )));
        }
        self.edge_targets
            .borrow_mut()
            .push(crate::hardware::dispatch_buffers::read_u32s(&inputs[2]));
        Ok(self.outputs.clone())
    }
}

#[derive(Default)]
struct ResidentPersistentBfsDispatcher {
    next_handle: RefCell<u64>,
    device_features: Cell<u64>,
    alloc_attempts: Cell<usize>,
    fail_alloc_attempt: Cell<Option<usize>>,
    alloc_sizes: RefCell<Vec<usize>>,
    topology_upload_batch_sizes: RefCell<Vec<usize>>,
    query_upload_batch_sizes: RefCell<Vec<usize>>,
    step_handle_sets: RefCell<Vec<Vec<u64>>>,
    freed: RefCell<Vec<u64>>,
}

impl ResidentPersistentBfsDispatcher {
    fn new() -> Self {
        Self {
            next_handle: RefCell::new(10),
            ..Self::default()
        }
    }
}

impl OptimizerDispatcher for ResidentPersistentBfsDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: resident persistent BFS test dispatcher only supports resident APIs.".to_string(),
        ))
    }

    fn supports_persistent(&self) -> bool {
        true
    }

    fn device_feature_cache_key(&self) -> u64 {
        self.device_features.get()
    }

    fn alloc_resident(&self, byte_len: usize) -> Result<u64, DispatchError> {
        let attempt = self.alloc_attempts.get() + 1;
        self.alloc_attempts.set(attempt);
        if self.fail_alloc_attempt.get() == Some(attempt) {
            return Err(DispatchError::BackendError(format!(
                "Fix: injected resident allocation failure at attempt {attempt}."
            )));
        }
        let mut next = self.next_handle.borrow_mut();
        let handle = *next;
        *next += 1;
        self.alloc_sizes.borrow_mut().push(byte_len);
        Ok(handle)
    }

    fn upload_resident_many(&self, uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
        self.topology_upload_batch_sizes
            .borrow_mut()
            .push(uploads.len());
        Ok(())
    }

    fn upload_resident_many_sequence_read_ranges_into(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[crate::optimizer::dispatcher::ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), DispatchError> {
        assert_eq!(uploads.len(), 1);
        assert_eq!(steps.len(), 1);
        assert_eq!(read_ranges.len(), 2);
        self.query_upload_batch_sizes
            .borrow_mut()
            .push(uploads.len());
        self.step_handle_sets
            .borrow_mut()
            .push(steps[0].handle_ids.to_vec());
        outputs.clear();
        let frontier_words = read_ranges[0].byte_len / std::mem::size_of::<u32>();
        let changed_words = read_ranges[1].byte_len / std::mem::size_of::<u32>();
        outputs.push(u32_slice_to_le_bytes(&vec![0b1111; frontier_words]));
        outputs.push(u32_slice_to_le_bytes(&vec![1; changed_words]));
        Ok(())
    }

    fn free_resident(&self, handle: u64) -> Result<(), DispatchError> {
        self.freed.borrow_mut().push(handle);
        Ok(())
    }
}

fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    // 0 -> 1 -> 2 -> 3
    (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
}

#[test]
fn expand_chain_saturates() {
    let (off, tgt, msk) = linear_graph();
    let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 8);
    assert_eq!(out, vec![0b1111]);
    assert_eq!(changed, 1);
}

#[test]
fn empty_seed_yields_empty_with_no_change() {
    let (off, tgt, msk) = linear_graph();
    let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF, 4);
    assert_eq!(out, vec![0u32]);
    assert_eq!(changed, 0);
}

#[test]
fn saturated_seed_reports_no_change() {
    let (off, tgt, msk) = linear_graph();
    let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b1111], 0xFFFF_FFFF, 4);
    assert_eq!(out, vec![0b1111]);
    assert_eq!(changed, 0);
}

/// Closure-bar: substrate output equals primitive output exactly.
#[test]
fn matches_primitive_directly() {
    let (off, tgt, msk) = linear_graph();
    let seed = vec![0b0001];
    let via_substrate = bfs_expand(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
    let via_primitive = reference_persistent_bfs(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
    assert_eq!(via_substrate, via_primitive);
}

/// Adversarial: max_iters bound is honored even on a chain
/// longer than the budget. With 1 iter on a 4-chain from {0},
/// only {0, 1} should be flagged (not the full chain).
#[test]
fn max_iters_bound_honored() {
    let (off, tgt, msk) = linear_graph();
    let (out, _) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 1);
    assert_eq!(out[0] & 0b1111, 0b0011);
}

/// Adversarial: allow_mask with kind bit not present in any
/// edge must report no change, no expansion.
#[test]
fn allow_mask_filters_all_edges() {
    let (off, tgt, msk) = linear_graph();
    let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0b0010, 4);
    // No edges of kind 1 → seed only.
    assert_eq!(out, vec![0b0001]);
    assert_eq!(changed, 0);
}

/// forward_reach helper saturates with an n-iteration budget on
/// a chain shorter than n.
#[test]
fn forward_reach_saturates_chain() {
    let (off, tgt, msk) = linear_graph();
    let out = forward_reach(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
    assert_eq!(out, vec![0b1111]);
}

#[test]
fn via_into_decodes_exact_outputs_into_reused_frontier() {
    let dispatcher = PersistentBfsDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[1]),
        ],
    };
    let (off, tgt, msk) = linear_graph();
    let mut frontier = Vec::with_capacity(4);
    let ptr = frontier.as_ptr();
    let changed = bfs_expand_via_into(
        &dispatcher,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut frontier,
    )
    .expect("Fix: dispatch succeeds");
    assert_eq!(frontier, vec![0b1111]);
    assert_eq!(changed, 1);
    assert_eq!(frontier.as_ptr(), ptr);
}

#[test]
fn via_into_rejects_non_boolean_changed_flag_readback() {
    let dispatcher = PersistentBfsDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[7]),
        ],
    };
    let (off, tgt, msk) = linear_graph();
    let mut frontier = vec![0xDEAD_BEEF];
    let capacity = frontier.capacity();

    let err = bfs_expand_via_into(
        &dispatcher,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut frontier,
    )
    .expect_err("Fix: persistent BFS wrapper must reject malformed changed-flag readback");

    assert!(
        matches!(err, DispatchError::BackendError(_)),
        "unexpected error variant: {err:?}"
    );
    assert_eq!(
        frontier,
        vec![0b1111],
        "frontier readback remains available for diagnostics even when the scalar flag is malformed"
    );
    assert_eq!(frontier.capacity(), capacity);
}

#[test]
fn via_with_scratch_reuses_dispatch_storage() {
    let dispatcher = PersistentBfsDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[1]),
        ],
    };
    let (off, tgt, msk) = linear_graph();
    let mut scratch = PersistentBfsGpuScratch::default();
    let mut frontier = Vec::with_capacity(1);

    let changed = bfs_expand_via_with_scratch_into(
        &dispatcher,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: dispatch succeeds");
    assert_eq!(changed, 1);
    assert_eq!(frontier, vec![0b1111]);
    let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
    let frontier_capacity = frontier.capacity();

    let changed = bfs_expand_via_with_scratch_into(
        &dispatcher,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0011],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: dispatch succeeds");
    assert_eq!(changed, 1);
    assert_eq!(
        scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
        input_capacities
    );
    assert_eq!(frontier.capacity(), frontier_capacity);
}

#[test]
fn via_refreshes_static_graph_inputs_for_same_shape_content_change() {
    let dispatcher = RecordingPersistentBfsDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[1]),
        ],
        edge_targets: RefCell::new(Vec::new()),
    };
    let edge_offsets = vec![0, 1, 2, 3, 3];
    let first_targets = vec![1, 2, 3];
    let second_targets = vec![2, 3, 0];
    let edge_kind_mask = vec![1, 1, 1];
    let mut scratch = PersistentBfsGpuScratch::default();
    let mut frontier = Vec::new();

    bfs_expand_via_with_scratch_into(
        &dispatcher,
        4,
        &edge_offsets,
        &first_targets,
        &edge_kind_mask,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: first same-shape persistent BFS dispatch should succeed");
    bfs_expand_via_with_scratch_into(
        &dispatcher,
        4,
        &edge_offsets,
        &second_targets,
        &edge_kind_mask,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: second same-shape persistent BFS dispatch should refresh graph inputs");

    assert_eq!(
        dispatcher.edge_targets.borrow().as_slice(),
        &[first_targets, second_targets]
    );
    let snapshot = scratch.plan_cache.snapshot();
    assert_eq!(snapshot.entries, 1);
    assert_eq!(snapshot.misses, 1);
    assert_eq!(snapshot.hits, 1);
}

#[test]
fn via_zero_iters_validates_and_returns_seed_without_dispatch_or_cache() {
    struct NoDispatch;

    impl OptimizerDispatcher for NoDispatch {
        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            panic!("zero-iteration persistent BFS must not dispatch");
        }
    }

    let (off, tgt, msk) = linear_graph();
    let mut scratch = PersistentBfsGpuScratch::default();
    let mut frontier = Vec::with_capacity(8);
    let ptr = frontier.as_ptr();
    let changed = bfs_expand_via_with_scratch_into(
        &NoDispatch,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0011],
        0xFFFF_FFFF,
        0,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: zero-iteration persistent BFS should validate and return seed frontier");

    assert_eq!(changed, 0);
    assert_eq!(frontier, vec![0b0011]);
    assert_eq!(frontier.as_ptr(), ptr);
    assert!(scratch.inputs.is_empty());
    assert_eq!(scratch.static_input_key, None);
}

#[test]
fn resident_graph_uploads_topology_once_and_reuses_frontier_handles() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    let (off, tgt, msk) = linear_graph();
    let graph =
        upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("Fix: resident upload");
    assert_eq!(
        dispatcher.topology_upload_batch_sizes.borrow().as_slice(),
        &[4]
    );
    assert_eq!(dispatcher.alloc_sizes.borrow().len(), 4);

    let graph_handles = graph.handles();
    assert_eq!(
        graph_handles[0], graph_handles[4],
        "resident BFS must bind one uploaded zero node buffer to both ProgramGraph node slots"
    );
    let mut scratch = PersistentBfsResidentScratch::default();
    let mut frontier = Vec::with_capacity(4);
    let frontier_ptr = frontier.as_ptr();
    let changed = bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: first resident query");
    assert_eq!(changed, 1);
    assert_eq!(frontier, vec![0b1111]);
    assert_eq!(frontier.as_ptr(), frontier_ptr);
    assert_eq!(dispatcher.alloc_sizes.borrow().len(), 7);

    let changed = bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0011],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: second resident query");
    assert_eq!(changed, 1);
    assert_eq!(dispatcher.alloc_sizes.borrow().len(), 7);
    assert_eq!(
        dispatcher.query_upload_batch_sizes.borrow().as_slice(),
        &[1, 1]
    );
    assert_eq!(
        scratch.plan_cache_snapshot(),
        PersistentBfsPlanCacheSnapshot {
            entries: 1,
            hits: 1,
            misses: 1,
        }
    );

    let step_handles = dispatcher.step_handle_sets.borrow();
    assert_eq!(step_handles.len(), 2);
    assert_eq!(&step_handles[0][0..5], &graph_handles);
    assert_eq!(&step_handles[1][0..5], &graph_handles);
    assert_eq!(
        &step_handles[0][5..8],
        &step_handles[1][5..8],
        "frontier/change resident buffers must be reused across queries"
    );

    scratch.free(&dispatcher).expect("Fix: scratch free");
    graph.free(&dispatcher).expect("Fix: graph free");
    assert_eq!(dispatcher.freed.borrow().len(), 7);
}

#[test]

fn resident_single_zero_iters_returns_seed_without_query_allocation_or_dispatch() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    let (off, tgt, msk) = linear_graph();
    let graph =
        upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("Fix: resident upload");
    let topology_allocs = dispatcher.alloc_sizes.borrow().len();
    let mut scratch = PersistentBfsResidentScratch::default();
    let mut frontier = Vec::with_capacity(4);
    let ptr = frontier.as_ptr();

    let changed = bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0101],
        0xFFFF_FFFF,
        0,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: zero-iteration resident BFS should validate and return seed frontier");

    assert_eq!(changed, 0);
    assert_eq!(frontier, vec![0b0101]);
    assert_eq!(frontier.as_ptr(), ptr);
    assert_eq!(dispatcher.alloc_sizes.borrow().len(), topology_allocs);
    assert!(dispatcher.query_upload_batch_sizes.borrow().is_empty());
    assert!(dispatcher.step_handle_sets.borrow().is_empty());
    assert_eq!(
        scratch.plan_cache_snapshot(),
        PersistentBfsPlanCacheSnapshot::default()
    );

    graph.free(&dispatcher).expect("Fix: graph free");
}

#[test]
fn generated_resident_bfs_free_releases_each_handle_once_in_first_seen_order() {
    for seed in 0..4096_u64 {
        let dispatcher = ResidentPersistentBfsDispatcher::new();
        let base = 10_000 + seed * 16;
        let graph = ResidentBfsGraph {
            node_count: 4,
            edge_count: 3,
            words: 1,
            words_u32: 1,
            layout_hash: seed,
            handles: [base, base + 1, base + 2, base + 3, base],
        };
        graph.free(&dispatcher).expect("Fix: graph free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[base, base + 1, base + 2, base + 3]
        );

        dispatcher.freed.borrow_mut().clear();
        let mut scratch = PersistentBfsResidentScratch {
            frontier_handles: Some([base + 4, base + 4, base + 5]),
            frontier_bytes: 4,
            changed_bytes: 4,
            frontier_in_bytes: Vec::new(),
            readbacks: Vec::new(),
            changed: Vec::new(),
            plan_cache: PersistentBfsPlanCache::default(),
        };
        scratch.free(&dispatcher).expect("Fix: scratch free dedup");
        assert_eq!(dispatcher.freed.borrow().as_slice(), &[base + 4, base + 5]);
    }
}

#[test]
fn resident_query_handle_allocation_rolls_back_partial_allocations() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    dispatcher.fail_alloc_attempt.set(Some(3));
    let mut scratch = PersistentBfsResidentScratch::default();

    let err = ensure_resident_query_handles(&dispatcher, &mut scratch, 64, 4)
        .expect_err("third resident scratch allocation failure must fail the whole acquisition");

    assert!(
        err.to_string()
            .contains("injected resident allocation failure at attempt 3"),
        "Fix: scratch allocation rollback must preserve the original allocation failure, got: {err}"
    );
    assert_eq!(
        dispatcher.freed.borrow().as_slice(),
        &[10, 11],
        "Fix: failed multi-handle resident BFS scratch acquisition must free every earlier handle."
    );
    assert!(
        scratch.frontier_handles.is_none(),
        "Fix: failed scratch acquisition must not publish partial resident handles."
    );
    assert_eq!(scratch.frontier_bytes, 0);
    assert_eq!(scratch.changed_bytes, 0);
}

#[test]
fn resident_graph_batch_reuses_topology_and_frontier_handles() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    let (off, tgt, msk) = linear_graph();
    let graph =
        upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("Fix: resident upload");
    assert_eq!(graph.words(), 1);

    let mut scratch = PersistentBfsResidentScratch::default();
    let mut frontiers = Vec::with_capacity(4);
    let frontiers_ptr = frontiers.as_ptr();
    let mut changed = Vec::with_capacity(4);
    let changed_ptr = changed.as_ptr();
    bfs_expand_resident_graph_batch_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0001, 0b0011, 0b0111],
        3,
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontiers,
        &mut changed,
    )
    .expect("Fix: resident batch query");

    assert_eq!(frontiers, vec![0b1111, 0b1111, 0b1111]);
    assert_eq!(changed, vec![1, 1, 1]);
    assert_eq!(frontiers.as_ptr(), frontiers_ptr);
    assert_eq!(changed.as_ptr(), changed_ptr);
    assert_eq!(
        dispatcher.topology_upload_batch_sizes.borrow().as_slice(),
        &[4]
    );
    assert_eq!(
        dispatcher.query_upload_batch_sizes.borrow().as_slice(),
        &[1]
    );
    assert_eq!(dispatcher.alloc_sizes.borrow().len(), 7);
    assert_eq!(
        scratch.plan_cache_snapshot(),
        PersistentBfsPlanCacheSnapshot {
            entries: 1,
            hits: 0,
            misses: 1,
        }
    );

    let step_handles = dispatcher.step_handle_sets.borrow();
    assert_eq!(step_handles.len(), 1);

    scratch.free(&dispatcher).expect("Fix: scratch free");
    graph.free(&dispatcher).expect("Fix: graph free");
}

#[test]
fn resident_batch_zero_iters_returns_seed_and_zero_changed_without_query_allocation_or_dispatch() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    let (off, tgt, msk) = linear_graph();
    let graph =
        upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("Fix: resident upload");
    let topology_allocs = dispatcher.alloc_sizes.borrow().len();
    let mut scratch = PersistentBfsResidentScratch::default();
    let mut frontiers = Vec::with_capacity(4);
    let frontiers_ptr = frontiers.as_ptr();
    let mut changed = Vec::with_capacity(4);
    let changed_ptr = changed.as_ptr();

    bfs_expand_resident_graph_batch_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0001, 0b0011, 0b0101],
        3,
        0xFFFF_FFFF,
        0,
        &mut scratch,
        &mut frontiers,
        &mut changed,
    )
    .expect("Fix: zero-iteration resident batch should validate and return seed frontiers");

    assert_eq!(frontiers, vec![0b0001, 0b0011, 0b0101]);
    assert_eq!(changed, vec![0, 0, 0]);
    assert_eq!(frontiers.as_ptr(), frontiers_ptr);
    assert_eq!(changed.as_ptr(), changed_ptr);
    assert_eq!(dispatcher.alloc_sizes.borrow().len(), topology_allocs);
    assert!(dispatcher.query_upload_batch_sizes.borrow().is_empty());
    assert!(dispatcher.step_handle_sets.borrow().is_empty());
    assert_eq!(
        scratch.plan_cache_snapshot(),
        PersistentBfsPlanCacheSnapshot::default()
    );

    graph.free(&dispatcher).expect("Fix: graph free");
}

#[test]
fn resident_plan_cache_keys_include_device_features() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    let (off, tgt, msk) = linear_graph();
    let graph =
        upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("Fix: resident upload");
    let mut scratch = PersistentBfsResidentScratch::default();
    let mut frontier = Vec::new();

    dispatcher.device_features.set(0x10);
    bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: first feature-keyed query");
    dispatcher.device_features.set(0x20);
    bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: second feature-keyed query");

    assert_eq!(
        scratch.plan_cache_snapshot(),
        PersistentBfsPlanCacheSnapshot {
            entries: 2,
            hits: 0,
            misses: 2,
        },
        "plan cache key must include backend device/lowering features"
    );

    scratch.free(&dispatcher).expect("Fix: scratch free");
    graph.free(&dispatcher).expect("Fix: graph free");
}

#[test]
fn resident_plan_cache_reuses_same_shape_graph_programs() {
    let dispatcher = ResidentPersistentBfsDispatcher::new();
    let offsets = vec![0, 1, 2, 3, 3];
    let masks = vec![1, 1, 1];
    let graph_a = upload_resident_bfs_graph(&dispatcher, 4, &offsets, &[1, 2, 3], &masks)
        .expect("Fix: first resident graph upload");
    let graph_b = upload_resident_bfs_graph(&dispatcher, 4, &offsets, &[2, 3, 0], &masks)
        .expect("Fix: second resident graph upload");
    assert_ne!(graph_a.layout_hash(), graph_b.layout_hash());

    let mut scratch = PersistentBfsResidentScratch::default();
    let mut frontier = Vec::new();
    bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph_a,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: first resident query");
    bfs_expand_resident_graph_with_scratch_into(
        &dispatcher,
        &graph_b,
        &[0b0001],
        0xFFFF_FFFF,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: second resident query");

    assert_eq!(
        scratch.plan_cache_snapshot(),
        PersistentBfsPlanCacheSnapshot {
            entries: 1,
            hits: 1,
            misses: 1,
        },
        "resident BFS programs must be cached by program shape, not graph contents"
    );

    scratch.free(&dispatcher).expect("Fix: scratch free");
    graph_a.free(&dispatcher).expect("Fix: first graph free");
    graph_b.free(&dispatcher).expect("Fix: second graph free");
}

#[test]
fn via_rejects_extra_outputs() {
    let dispatcher = PersistentBfsDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[1]),
            u32_slice_to_le_bytes(&[99]),
        ],
    };
    let (off, tgt, msk) = linear_graph();
    let err = bfs_expand_via(&dispatcher, 4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 4)
        .expect_err("extra outputs must be rejected");
    assert!(
        matches!(err, DispatchError::BackendError(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn via_rejects_trailing_changed_bytes() {
    let dispatcher = PersistentBfsDispatcher {
        outputs: vec![u32_slice_to_le_bytes(&[0b1111]), vec![1, 0, 0, 0, 2]],
    };
    let (off, tgt, msk) = linear_graph();
    let err = bfs_expand_via(&dispatcher, 4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 4)
        .expect_err("trailing changed bytes must be rejected");
    assert!(
        matches!(err, DispatchError::BackendError(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn via_rejects_mismatched_edge_arrays() {
    let dispatcher = PersistentBfsDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[1]),
        ],
    };
    let err = bfs_expand_via(
        &dispatcher,
        2,
        &[0, 1, 1],
        &[1],
        &[],
        &[0b01],
        0xFFFF_FFFF,
        1,
    )
    .expect_err("mismatched edge arrays must be rejected");
    assert!(matches!(err, DispatchError::BadInputs(_)));
}

#[test]
fn release_via_path_does_not_call_cpu_or_local_saturating_helpers() {
    let source = include_str!("dispatch.rs");
    let start = source
        .find("pub fn bfs_expand_via")
        .expect("Fix: via path marker must exist");
    let release_path = &source[start..];
    assert!(!release_path.contains("reference_persistent_bfs"));
    assert!(!release_path.contains("reference_"));
    assert!(!release_path.contains("cpu_ref"));
    assert!(!release_path.contains("saturating_mul"));
    assert!(!release_path.contains("fill_"));
}

/// Adversarial: a self-loop must terminate (changed becomes 0
/// once the seed includes the self-loop node).
#[test]
fn self_loop_terminates() {
    // 0 -> 0 (self-loop), 1 isolated.
    let off = vec![0, 1, 1];
    let tgt = vec![0];
    let msk = vec![1];
    let (out, _) = bfs_expand(2, &off, &tgt, &msk, &[0b01], 0xFFFF_FFFF, 50);
    assert_eq!(out, vec![0b01]);
}

#[test]
fn persistent_bfs_uses_shared_bounded_plan_cache() {
    let source = include_str!("state.rs");
    assert!(
        source.contains("use crate::graph::plan_cache::GraphPlanCache;"),
        "Fix: persistent BFS must use the shared bounded graph plan cache."
    );
    assert!(
        !source.contains("HashMap<PersistentBfsPlanKey"),
        "Fix: persistent BFS must not carry a private unbounded Program HashMap cache."
    );
}

#[test]
fn bfs_expand_via_scratch_caches_static_graph_inputs() {
    let state_source = include_str!("state.rs");
    let dispatch_source = include_str!("dispatch.rs");

    assert!(
        state_source.contains("static_input_key: Option<PersistentBfsStaticInputKey>"),
        "Fix: persistent BFS scratch must remember the prepared static CSR graph inputs."
    );
    assert!(
        state_source.contains("PersistentBfsStaticInputKey")
            && dispatch_source.contains("plan.static_input_key()"),
        "Fix: persistent BFS static input reuse must use the primitive-owned graph input key, not call order."
    );
    assert!(
        dispatch_source.contains("refresh_keyed_dispatch_inputs("),
        "Fix: persistent BFS must use the shared keyed graph dispatch refresh helper."
    );
    assert!(
        dispatch_source.contains("program_cache_key("),
        "Fix: persistent BFS program caching must be shape-keyed instead of graph-content keyed."
    );
    assert!(
        dispatch_source.contains("(5, DispatchInput::u32_slice(frontier_in))")
            && dispatch_source.contains("DispatchInput::zero_u32_words(words, \"bfs_expand_via frontier_out\")")
            && dispatch_source.contains("DispatchInput::zero_u32_words(1, \"bfs_expand_via changed\")"),
        "Fix: repeated persistent BFS dispatches must rewrite only frontier, output, and changed slots."
    );
}

