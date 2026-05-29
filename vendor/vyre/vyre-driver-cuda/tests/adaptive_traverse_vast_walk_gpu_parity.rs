//! Parity tests for vyre-primitives graph::adaptive_traverse and
//! graph::vast_tree_walk preorder.

#![cfg(test)]

mod common;

use common::{bytes_u32, live_dispatcher, u32_bytes};
use vyre::DispatchConfig;
use vyre_driver_cuda::CudaBackend;
use vyre_foundation::vast::{walk_preorder_indices, VastNode, NODE_STRIDE_U32, SENTINEL};
use vyre_primitives::graph::adaptive_traverse::{
    adaptive_dense_step, adaptive_sparse_dense_step, cpu_dense_step, cpu_sparse_dense_step,
};
use vyre_primitives::graph::vast_tree_walk::ast_walk_preorder;
use vyre_primitives::reduce::count::reduce_count;
use vyre_self_substrate::adaptive_traverse::{
    adaptive_traverse_resident_graph_auto_step_with_scratch_into,
    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into,
    adaptive_traverse_resident_graph_step_with_scratch_into, adaptive_traverse_step,
    upload_resident_adaptive_traversal_graph, AdaptiveTraversalMode,
    AdaptiveTraversalPlanCacheSnapshot, AdaptiveTraversalResidentScratch,
};

fn bitset_words(node_count: u32) -> u32 {
    node_count.div_ceil(32).max(1)
}

fn run_dense_step(
    backend: &CudaBackend,
    frontier_in: &[u32],
    adj_rows_dense: &[u32],
    node_count: u32,
) -> Vec<u32> {
    let words = bitset_words(node_count);
    let program = adaptive_dense_step("frontier_in", "frontier_out", "adj", node_count);
    let inputs: Vec<Vec<u8>> = vec![
        u32_bytes(frontier_in),
        vec![0u8; words as usize * 4],
        u32_bytes(adj_rows_dense),
    ];
    let mut config = DispatchConfig::default();
    // workgroup [1,1,1]; one workgroup per source node.
    config.grid_override = Some([node_count.max(1), 1, 1]);
    let outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("dispatch");
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(words as usize);
    out
}

fn pack_nodes(bits: &[u32], node_count: u32) -> Vec<u32> {
    let mut buf = vec![0_u32; bitset_words(node_count) as usize];
    for &bit in bits {
        buf[bit as usize / 32] |= 1 << (bit % 32);
    }
    buf
}

fn build_dense_adj(edges: &[(u32, u32)], node_count: u32) -> Vec<u32> {
    let words = bitset_words(node_count) as usize;
    let mut rows = vec![0_u32; node_count as usize * words];
    for &(src, dst) in edges {
        rows[dst as usize * words + src as usize / 32] |= 1 << (src % 32);
    }
    rows
}

fn run_reduce_count(backend: &CudaBackend, frontier_in: &[u32]) -> Vec<u8> {
    let program = reduce_count("frontier_in", "frontier_popcount", frontier_in.len() as u32);
    let inputs = vec![u32_bytes(frontier_in), vec![0u8; 4]];
    let mut config = DispatchConfig::default();
    config.grid_override = Some([1, 1, 1]);
    let outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("reduce_count dispatch");
    outputs[0].clone()
}

fn run_sparse_dense_step(
    backend: &CudaBackend,
    frontier_in: &[u32],
    frontier_popcount: Vec<u8>,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    adj_rows_dense: &[u32],
    node_count: u32,
    dense_threshold_pct: u32,
) -> Vec<u32> {
    let words = bitset_words(node_count);
    let program = adaptive_sparse_dense_step(
        "frontier_in",
        "frontier_out",
        "frontier_popcount",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "adj_rows_dense",
        node_count,
        edge_targets.len() as u32,
        1,
        dense_threshold_pct,
    );
    let inputs: Vec<Vec<u8>> = vec![
        u32_bytes(frontier_in),
        vec![0u8; words as usize * 4],
        frontier_popcount,
        u32_bytes(edge_offsets),
        u32_bytes(edge_targets),
        u32_bytes(edge_kind_mask),
        u32_bytes(adj_rows_dense),
    ];
    let mut config = DispatchConfig::default();
    config.grid_override = Some([node_count.max(1), 1, 1]);
    let outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("adaptive hybrid dispatch");
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(words as usize);
    out
}

#[test]
fn cuda_adaptive_dense_step_chain() {
    let backend = live_dispatcher();
    // 4 nodes; reverse adjacency (row d = predecessors of d):
    // node 0 ← {3}, node 1 ← {0}, node 2 ← {1}, node 3 ← {2}.
    let node_count = 4u32;
    let words = bitset_words(node_count) as usize;
    let mut adj = vec![0u32; node_count as usize * words];
    let mut set_pred = |dst: u32, src: u32| {
        adj[(dst as usize) * words + (src as usize / 32)] |= 1u32 << (src & 31);
    };
    set_pred(0, 3);
    set_pred(1, 0);
    set_pred(2, 1);
    set_pred(3, 2);
    let frontier_in = vec![0b0001u32]; // {0}
    let cpu = cpu_dense_step(&frontier_in, &adj, node_count);
    let gpu = run_dense_step(&backend, &frontier_in, &adj, node_count);
    assert_eq!(gpu, cpu);
    // {0} reaches {1} via reverse-adj rows.
    assert_eq!(gpu, vec![0b0010u32]);
}

#[test]
fn cuda_adaptive_dense_step_empty_frontier() {
    let backend = live_dispatcher();
    let node_count = 4u32;
    let words = bitset_words(node_count) as usize;
    let mut adj = vec![0u32; node_count as usize * words];
    adj[0] = 0b0010; // node 0 ← {1}
    let frontier_in = vec![0u32];
    let cpu = cpu_dense_step(&frontier_in, &adj, node_count);
    let gpu = run_dense_step(&backend, &frontier_in, &adj, node_count);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0u32]);
}

#[test]
fn cuda_adaptive_dense_step_full_frontier_reaches_all_with_any_pred() {
    let backend = live_dispatcher();
    let node_count = 4u32;
    let words = bitset_words(node_count) as usize;
    let mut adj = vec![0u32; node_count as usize * words];
    // Nodes 0 and 1 have predecessor 0; nodes 2 and 3 have no preds.
    adj[0] = 0b0001;
    adj[words] = 0b0001;
    let frontier_in = vec![0b1111u32];
    let cpu = cpu_dense_step(&frontier_in, &adj, node_count);
    let gpu = run_dense_step(&backend, &frontier_in, &adj, node_count);
    assert_eq!(gpu, cpu);
    // Only nodes 0 and 1 see a hit because nodes 2,3 have no preds.
    assert_eq!(gpu, vec![0b0011u32]);
}

#[test]
fn cuda_adaptive_sparse_dense_sparse_branch_uses_csr_from_gpu_popcount() {
    let backend = live_dispatcher();
    let node_count = 8u32;
    let frontier_in = pack_nodes(&[0], node_count);
    let count_bytes = run_reduce_count(&backend, &frontier_in);
    let selector_count = bytes_u32(&count_bytes)[0];
    let edge_offsets = vec![0, 1, 1, 1, 1, 1, 1, 1, 1];
    let edge_targets = vec![1];
    let edge_kind_mask = vec![1];
    let adj = build_dense_adj(&[(0, 2)], node_count);

    let cpu = cpu_sparse_dense_step(
        &frontier_in,
        selector_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
        node_count,
        1,
        50,
    );
    let gpu = run_sparse_dense_step(
        &backend,
        &frontier_in,
        count_bytes,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
        node_count,
        50,
    );
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, pack_nodes(&[1], node_count));
}

#[test]
fn cuda_adaptive_sparse_dense_dense_branch_uses_rows_from_gpu_popcount() {
    let backend = live_dispatcher();
    let node_count = 8u32;
    let frontier_in = pack_nodes(&[0, 1, 2, 3], node_count);
    let count_bytes = run_reduce_count(&backend, &frontier_in);
    let selector_count = bytes_u32(&count_bytes)[0];
    let edge_offsets = vec![0, 1, 1, 1, 1, 1, 1, 1, 1];
    let edge_targets = vec![1];
    let edge_kind_mask = vec![1];
    let adj = build_dense_adj(&[(0, 5)], node_count);

    let cpu = cpu_sparse_dense_step(
        &frontier_in,
        selector_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
        node_count,
        1,
        50,
    );
    let gpu = run_sparse_dense_step(
        &backend,
        &frontier_in,
        count_bytes,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
        node_count,
        50,
    );
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, pack_nodes(&[5], node_count));
}

#[test]
fn cuda_resident_adaptive_sparse_dense_keeps_selector_on_device_sparse_branch() {
    let backend = live_dispatcher();
    let dispatcher = vyre_driver_cuda::CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let edge_offsets = vec![0, 1, 1, 1, 1, 1, 1, 1, 1];
    let edge_targets = vec![1];
    let edge_kind_mask = vec![1];
    let adj = build_dense_adj(&[(0, 2)], node_count);
    let graph = upload_resident_adaptive_traversal_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
    )
    .expect("resident adaptive graph upload");
    let frontier_in = pack_nodes(&[0], node_count);
    let expected = adaptive_traverse_step(
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
        &frontier_in,
        1,
        50,
    )
    .expect("Fix: CPU adaptive traversal oracle must accept the sparse-branch fixture.");
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut out = Vec::with_capacity(1);
    backend.reset_telemetry();
    adaptive_traverse_resident_graph_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        50,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive sparse branch");
    assert_eq!(out, expected);
    assert_eq!(out, pack_nodes(&[1], node_count));
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 3,
        "Fix: resident adaptive traversal must launch exactly reduce_count + device frontier clear + sparse/dense traversal."
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: resident adaptive traversal must fence once for upload + two kernels + compact readback."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontier_in.len() * std::mem::size_of::<u32>()) as u64,
        "Fix: resident adaptive traversal must not read back the selector count; only frontier_out is a release-path D2H payload."
    );
    scratch
        .free(&dispatcher)
        .expect("resident adaptive scratch free");
    graph
        .free(&dispatcher)
        .expect("resident adaptive graph free");
}

#[test]
fn cuda_resident_adaptive_sparse_dense_keeps_selector_on_device_dense_branch() {
    let backend = live_dispatcher();
    let dispatcher = vyre_driver_cuda::CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let edge_offsets = vec![0, 1, 1, 1, 1, 1, 1, 1, 1];
    let edge_targets = vec![1];
    let edge_kind_mask = vec![1];
    let adj = build_dense_adj(&[(0, 5)], node_count);
    let graph = upload_resident_adaptive_traversal_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
    )
    .expect("resident adaptive graph upload");
    let frontier_in = pack_nodes(&[0, 1, 2, 3], node_count);
    let expected = adaptive_traverse_step(
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
        &frontier_in,
        1,
        50,
    )
    .expect("Fix: CPU adaptive traversal oracle must accept the dense-branch fixture.");
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut out = Vec::with_capacity(1);
    backend.reset_telemetry();
    adaptive_traverse_resident_graph_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        50,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive dense branch");
    assert_eq!(out, expected);
    assert_eq!(out, pack_nodes(&[5], node_count));
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 3,
        "Fix: resident adaptive traversal must launch exactly reduce_count + device frontier clear + sparse/dense traversal."
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: resident adaptive traversal must fence once for upload + two kernels + compact readback."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontier_in.len() * std::mem::size_of::<u32>()) as u64,
        "Fix: resident adaptive traversal must not read back the selector count; only frontier_out is a release-path D2H payload."
    );
    scratch
        .free(&dispatcher)
        .expect("resident adaptive scratch free");
    graph
        .free(&dispatcher)
        .expect("resident adaptive graph free");
}

#[test]
fn cuda_resident_adaptive_sparse_queue_path_uses_self_substrate_api() {
    let backend = live_dispatcher();
    let dispatcher = vyre_driver_cuda::CudaOptimizerDispatcher::new(&backend);
    let node_count = 8u32;
    let edge_offsets = vec![0, 2, 2, 2, 5, 5, 5, 5, 5];
    let edge_targets = vec![1, 2, 4, 5, 6];
    let edge_kind_mask = vec![1, 2, 1, 1, 2];
    let adj = build_dense_adj(&[(0, 7)], node_count);
    let graph = upload_resident_adaptive_traversal_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
    )
    .expect("resident adaptive graph upload");
    let frontier_in = pack_nodes(&[0, 3], node_count);
    let expected = pack_nodes(&[1, 4, 5], node_count);
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut out = Vec::with_capacity(1);

    backend.reset_telemetry();
    adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive sparse queue path");
    assert_eq!(out, expected);
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(
        telemetry.kernel_launches, 4,
        "Fix: self-substrate sparse queue traversal must launch exactly queue length init + device frontier clear + queue-build + queue-consume kernels."
    );
    assert_eq!(
        telemetry.sync_points, 1,
        "Fix: self-substrate sparse queue traversal must fence once for upload + two kernels + compact readback."
    );
    assert_eq!(
        telemetry.readback_bytes,
        (frontier_in.len() * std::mem::size_of::<u32>()) as u64,
        "Fix: self-substrate sparse queue traversal must not read back active queue or queue length."
    );
    scratch
        .free(&dispatcher)
        .expect("resident adaptive scratch free");
    graph
        .free(&dispatcher)
        .expect("resident adaptive graph free");
}

#[test]
fn cuda_resident_adaptive_auto_selects_sparse_queue_for_tiny_frontier() {
    let backend = live_dispatcher();
    let dispatcher = vyre_driver_cuda::CudaOptimizerDispatcher::new(&backend);
    let node_count = 128u32;
    let mut edge_offsets = Vec::with_capacity(node_count as usize + 1);
    let mut edge_targets = Vec::with_capacity(node_count as usize);
    let mut edge_kind_mask = Vec::with_capacity(node_count as usize);
    for src in 0..node_count {
        edge_offsets.push(src);
        edge_targets.push((src + 1) % node_count);
        edge_kind_mask.push(1);
    }
    edge_offsets.push(node_count);
    let adj = build_dense_adj(&[(0, 64)], node_count);
    let graph = upload_resident_adaptive_traversal_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
    )
    .expect("resident adaptive graph upload");
    let frontier_in = pack_nodes(&[0], node_count);
    let expected = pack_nodes(&[1], node_count);
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut out = Vec::new();

    backend.reset_telemetry();
    let mode = adaptive_traverse_resident_graph_auto_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        25,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive auto sparse queue path");
    assert_eq!(mode, AdaptiveTraversalMode::SparseQueue);
    assert_eq!(out, expected);
    let mode_again = adaptive_traverse_resident_graph_auto_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        25,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive auto sparse queue path repeat");
    assert_eq!(mode_again, AdaptiveTraversalMode::SparseQueue);
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot {
            entries: 4,
            hits: 4,
            misses: 4,
        },
        "Fix: auto sparse queue traversal must reuse queue length init, device frontier clear, queue-build, and queue-consume Programs on repeated resident graph calls."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(telemetry.kernel_launches, 8);
    assert_eq!(telemetry.sync_points, 2);
    assert_eq!(
        telemetry.readback_bytes,
        (2 * frontier_in.len() * std::mem::size_of::<u32>()) as u64
    );
    scratch
        .free(&dispatcher)
        .expect("resident adaptive scratch free");
    graph
        .free(&dispatcher)
        .expect("resident adaptive graph free");
}

#[test]

fn cuda_resident_adaptive_auto_selects_sparse_dense_for_dense_frontier() {
    let backend = live_dispatcher();
    let dispatcher = vyre_driver_cuda::CudaOptimizerDispatcher::new(&backend);
    let node_count = 32u32;
    let edge_offsets = vec![0u32; node_count as usize + 1];
    let edge_targets = Vec::new();
    let edge_kind_mask = Vec::new();
    let adj = build_dense_adj(&[(0, 7)], node_count);
    let graph = upload_resident_adaptive_traversal_graph(
        &dispatcher,
        node_count,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &adj,
    )
    .expect("resident adaptive graph upload");
    let frontier_in = pack_nodes(&(0..16).collect::<Vec<_>>(), node_count);
    let expected = pack_nodes(&[7], node_count);
    let mut scratch = AdaptiveTraversalResidentScratch::default();
    let mut out = Vec::new();

    backend.reset_telemetry();
    let mode = adaptive_traverse_resident_graph_auto_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        25,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive auto sparse/dense path");
    assert_eq!(mode, AdaptiveTraversalMode::SparseDense);
    assert_eq!(out, expected);
    let mode_again = adaptive_traverse_resident_graph_auto_step_with_scratch_into(
        &dispatcher,
        &graph,
        &frontier_in,
        1,
        25,
        &mut scratch,
        &mut out,
    )
    .expect("resident adaptive auto sparse/dense path repeat");
    assert_eq!(mode_again, AdaptiveTraversalMode::SparseDense);
    assert_eq!(
        scratch.plan_cache_snapshot(),
        AdaptiveTraversalPlanCacheSnapshot {
            entries: 3,
            hits: 3,
            misses: 3,
        },
        "Fix: auto sparse/dense traversal must reuse popcount, device frontier clear, and traversal Programs on repeated resident graph calls."
    );
    let telemetry = backend.telemetry_snapshot();
    assert_eq!(telemetry.kernel_launches, 6);
    assert_eq!(telemetry.sync_points, 2);
    assert_eq!(
        telemetry.readback_bytes,
        (2 * frontier_in.len() * std::mem::size_of::<u32>()) as u64
    );
    scratch
        .free(&dispatcher)
        .expect("resident adaptive scratch free");
    graph
        .free(&dispatcher)
        .expect("resident adaptive graph free");
}

// ---------------------------------------------------------------------
// VAST preorder walk
// ---------------------------------------------------------------------

fn pack_vast(nodes: &[VastNode]) -> (Vec<u8>, Vec<u32>) {
    let mut bytes = Vec::with_capacity(nodes.len() * NODE_STRIDE_U32 * 4);
    for n in nodes {
        bytes.extend_from_slice(&n.to_bytes());
    }
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    (bytes, words)
}

fn run_preorder(
    backend: &CudaBackend,
    nodes_words: &[u32],
    node_count: u32,
    out_cap: u32,
) -> Vec<u32> {
    let program = ast_walk_preorder("nodes", "out", node_count, out_cap);
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(nodes_words), vec![0u8; out_cap as usize * 4]];
    let mut config = DispatchConfig::default();
    // workgroup [1,1,1]; preorder is a single-threaded walk.
    config.grid_override = Some([1, 1, 1]);
    let outputs = backend
        .dispatch(&program, &inputs, &config)
        .expect("dispatch");
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(out_cap as usize);
    out
}

fn make_node(parent: u32, first_child: u32, next_sibling: u32) -> VastNode {
    VastNode {
        kind: 0,
        parent_idx: parent,
        first_child,
        next_sibling,
        src_file: 0,
        src_byte_off: 0,
        src_byte_len: 0,
        attr_off: 0,
        attr_len: 0,
        reserved: 0,
    }
}

#[test]
fn cuda_vast_walk_preorder_balanced_tree() {
    let backend = live_dispatcher();
    // Tree:
    //       0
    //      / \
    //     1   2
    //    / \
    //   3   4
    let nodes = vec![
        make_node(SENTINEL, 1, SENTINEL), // 0: root
        make_node(0, 3, 2),               // 1: child of 0, sibling 2
        make_node(0, SENTINEL, SENTINEL), // 2: child of 0
        make_node(1, SENTINEL, 4),        // 3: child of 1, sibling 4
        make_node(1, SENTINEL, SENTINEL), // 4: child of 1
    ];
    let node_count = nodes.len() as u32;
    let (node_bytes, node_words) = pack_vast(&nodes);
    let cpu = walk_preorder_indices(&node_bytes, node_count, 64).expect("walk ok");
    // Read only the first cpu.len() entries of the GPU output (out_cap is the buffer size).
    let gpu_full = run_preorder(&backend, &node_words, node_count, node_count);
    let gpu_emitted: Vec<u32> = gpu_full.iter().take(cpu.len()).copied().collect();
    assert_eq!(gpu_emitted, cpu);
    assert_eq!(gpu_emitted, vec![0, 1, 3, 4, 2]);
}

#[test]
fn cuda_vast_walk_preorder_single_node() {
    let backend = live_dispatcher();
    let nodes = vec![make_node(SENTINEL, SENTINEL, SENTINEL)];
    let (node_bytes, node_words) = pack_vast(&nodes);
    let cpu = walk_preorder_indices(&node_bytes, 1, 64).expect("walk ok");
    let gpu_full = run_preorder(&backend, &node_words, 1, 1);
    let gpu_emitted: Vec<u32> = gpu_full.iter().take(cpu.len()).copied().collect();
    assert_eq!(gpu_emitted, cpu);
    assert_eq!(gpu_emitted, vec![0]);
}

#[test]
fn cuda_vast_walk_preorder_linear_chain() {
    let backend = live_dispatcher();
    // 0 -> 1 -> 2 -> 3 (each first_child links to the next).
    let nodes = vec![
        make_node(SENTINEL, 1, SENTINEL),
        make_node(0, 2, SENTINEL),
        make_node(1, 3, SENTINEL),
        make_node(2, SENTINEL, SENTINEL),
    ];
    let (node_bytes, node_words) = pack_vast(&nodes);
    let cpu = walk_preorder_indices(&node_bytes, 4, 64).expect("walk ok");
    let gpu_full = run_preorder(&backend, &node_words, 4, 4);
    let gpu_emitted: Vec<u32> = gpu_full.iter().take(cpu.len()).copied().collect();
    assert_eq!(gpu_emitted, cpu);
    assert_eq!(gpu_emitted, vec![0, 1, 2, 3]);
}
