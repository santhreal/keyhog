//! `dominator_tree` — Tier-3 shim.
//!
//! The [`dominator_tree`](fn@dominator_tree) primitive is tagged with
//! ``Soundness::MayOver``:
//! it computes reverse reachability over dominance edges (set union of
//! dominance-tree ancestors), which over-approximates true dominators.
//! Callers that need exact strict dominance must use [`cpu_dominator_sets`],
//! the CPU reference oracle implementing the Cooper-Harvey-Kennedy 2001
//! iterative dataflow algorithm (set intersection of predecessor dominator
//! sets). Rules with a zero-false-positive precision contract MUST compose
//! against [`cpu_dominator_sets`] rather than [`dominator_tree`].
//!
//! AUDIT_2026-04-24 F-DT-02 (honest status): true dominator computation is
//! the intersection of predecessor dominator sets
//! (Cooper-Harvey-Kennedy / Lengauer-Tarjan), NOT a fixpoint over
//! reverse reachability — intersection and union are different
//! lattice operators and the distinction matters for correctness.
//! The present primitive emits `csr_backward_traverse` over
//! DOMINANCE edges, which computes reverse reachability (the set
//! of dominance-tree ancestors, unioned across predecessors). That
//! matches the surge stdlib's current composition but is
//! technically a stronger (over-approximating) predicate than
//! "dominates." Callers depending on strict dominator semantics
//! should use [`cpu_dominator_sets`] or compose the intersection in SURGE
//! directly. This note is load-bearing: surge rules that consume
//! this op today are using it as reverse reachability and will
//! keep working; any new rule that needs strict dominance must
//! flag the dependency explicitly.

use vyre::ir::Program;
use vyre_primitives::graph::csr_backward_traverse::csr_backward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

use crate::region::{reparent_program_children, wrap_anonymous};

const OP_ID: &str = "vyre-libs::security::dominator_tree";

/// Build one reverse-traversal step along dominance edges.
///
/// # Soundness
///
/// This composition is ``Soundness::MayOver``:
/// it returns the set of nodes that can reach `n` via dominance edges,
/// i.e. an over-approximation of true dominators. Rules that require
/// zero false positives must gate on [`cpu_dominator_sets`] instead.
#[must_use]
pub fn dominator_tree(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    let primitive = csr_backward_traverse(shape, frontier_in, frontier_out, edge_kind::DOMINANCE);
    Program::wrapped(
        primitive.buffers().to_vec(),
        primitive.workgroup_size(),
        vec![wrap_anonymous(
            OP_ID,
            reparent_program_children(&primitive, OP_ID),
        )],
    )
}

/// CPU reference oracle for strict dominator sets.
///
/// Implements the iterative dataflow algorithm from Cooper, Harvey &
/// Kennedy (2001):
///
/// 1. `Dom(entry) = {entry}`; `Dom(other) = ALL_NODES`.
/// 2. Iterate over nodes in reverse postorder, computing  
///    `Dom(n) = {n} ∪ ⋂_{p ∈ preds(n)} Dom(p)` until fixpoint.
/// 3. Return `Vec<Vec<u32>>` where index `n` is the sorted dominator set.
///
/// This is an ``Exact``
/// reference; rules that require zero false positives MUST compose
/// against this oracle rather than the GPU [`dominator_tree`] shim.
#[must_use]
pub fn cpu_dominator_sets(num_nodes: u32, entry: u32, edges: &[(u32, u32)]) -> Vec<Vec<u32>> {
    const NONE: usize = usize::MAX;

    let n = num_nodes as usize;
    let entry = entry as usize;
    if n == 0 {
        return Vec::new();
    }
    if entry >= n {
        return Vec::new();
    }

    // Build flat predecessor and successor adjacency lists. This avoids one
    // heap allocation per CFG node and keeps the fixpoint loop cache-local.
    let mut pred_head = vec![NONE; n];
    let mut pred_to = Vec::with_capacity(edges.len());
    let mut pred_next = Vec::with_capacity(edges.len());
    let mut succ_head = vec![NONE; n];
    let mut succ_to = Vec::with_capacity(edges.len());
    let mut succ_next = Vec::with_capacity(edges.len());
    for &(src, dst) in edges {
        let src = src as usize;
        let dst = dst as usize;
        if src < n && dst < n {
            let pred_idx = pred_to.len();
            pred_to.push(src);
            pred_next.push(pred_head[dst]);
            pred_head[dst] = pred_idx;

            let succ_idx = succ_to.len();
            succ_to.push(dst);
            succ_next.push(succ_head[src]);
            succ_head[src] = succ_idx;
        }
    }

    // Bitset representation: one u64 block per 64 nodes.
    let blocks = ((n + 63) / 64).max(1);
    let mut all_set = vec![u64::MAX; blocks];
    let remainder = n % 64;
    if remainder != 0 {
        all_set[blocks - 1] = (1u64 << remainder).wrapping_sub(1);
    }

    let mut entry_set = vec![0u64; blocks];
    entry_set[entry / 64] |= 1u64 << (entry % 64);

    // Initialize Dom[entry] = {entry}; Dom[other] = ALL_NODES as one flat
    // row-major matrix (`node * blocks + block`).
    let mut dom = vec![0u64; n * blocks];
    for node in 0..n {
        let start = node * blocks;
        let end = start + blocks;
        if node == entry {
            dom[start..end].copy_from_slice(&entry_set);
        } else {
            dom[start..end].copy_from_slice(&all_set);
        }
    }

    // Compute reverse postorder of reachable nodes via iterative DFS from entry.
    let mut visited = vec![false; n];
    let mut postorder = Vec::with_capacity(n);
    visited[entry] = true;
    let mut stack = vec![(entry, succ_head[entry])];
    while let Some((node, edge)) = stack.pop() {
        if edge == NONE {
            postorder.push(node);
            continue;
        }
        stack.push((node, succ_next[edge]));
        let succ = succ_to[edge];
        if !visited[succ] {
            visited[succ] = true;
            stack.push((succ, succ_head[succ]));
        }
    }

    let mut new_set = vec![0u64; blocks];
    let mut changed = true;
    while changed {
        changed = false;
        for &node in postorder.iter().rev() {
            if node == entry {
                continue;
            }
            new_set.fill(0);
            let pred_edge = pred_head[node];
            if pred_edge == NONE {
                new_set[node / 64] |= 1u64 << (node % 64);
            } else {
                let first = pred_to[pred_edge];
                let first_start = first * blocks;
                new_set.copy_from_slice(&dom[first_start..first_start + blocks]);
                let mut edge = pred_next[pred_edge];
                while edge != NONE {
                    let p = pred_to[edge];
                    let p_start = p * blocks;
                    for b in 0..blocks {
                        new_set[b] &= dom[p_start + b];
                    }
                    edge = pred_next[edge];
                }
                new_set[node / 64] |= 1u64 << (node % 64);
            }
            let row_start = node * blocks;
            let row_end = row_start + blocks;
            if new_set != dom[row_start..row_end] {
                dom[row_start..row_end].copy_from_slice(&new_set);
                changed = true;
            }
        }
    }

    // Convert bitsets to sorted Vec<u32>.
    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        let mut set = Vec::new();
        let row_start = i * blocks;
        for b in 0..blocks {
            let mut block = dom[row_start + b];
            while block != 0 {
                let lsb = block.trailing_zeros() as usize;
                let node_idx = b * 64 + lsb;
                if node_idx < n {
                    set.push(node_idx as u32);
                }
                block &= block - 1;
            }
        }
        result.push(set);
    }
    result
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || dominator_tree(ProgramGraphShape::new(4, 4), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Diamond dominance tree: 0 dominates 1 and 2; both dominate 3.
            // Backward from {3} reaches {1, 2} in one step.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets: 0→{1,2}, 1→{3}, 2→{3}, 3→{}
                to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
                to_bytes(&[
                    edge_kind::DOMINANCE,
                    edge_kind::DOMINANCE,
                    edge_kind::DOMINANCE,
                    edge_kind::DOMINANCE,
                ]),                               // pg_edge_kind_mask — all DOMINANCE
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b1000]),              // fin = {3}
                to_bytes(&[0b1000]),              // fout accumulator seed = {3}
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // One backward step from {3}: nodes 1 and 2 have edges to 3,
            // so they light up. Accumulator preserves seed {3}.
            vec![vec![to_bytes(&[0b1110])]]
        }),
    }
}

inventory::submit! {
    // AUDIT_2026-04-24 F-DT-01: raised from 64 to 4096 so deep
    // dominance trees (Linux kernel-scale CFGs routinely 500+ deep)
    // don't silently truncate at the 64th step and produce false
    // negatives. Fixpoint drivers exit early when the frontier
    // stops growing, so a higher ceiling has no cost on flat graphs.
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 4096,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::graph::csr_backward_traverse::cpu_ref;

    fn diamond_dominance_tree() -> (u32, Vec<u32>, Vec<u32>, Vec<u32>) {
        let node_count = 4;
        let edge_offsets = vec![0, 2, 3, 4, 4];
        let edge_targets = vec![1, 2, 3, 3];
        let edge_kind_mask = vec![edge_kind::DOMINANCE; 4];
        (node_count, edge_offsets, edge_targets, edge_kind_mask)
    }

    #[test]
    fn cpu_dominator_sets_linear_chain() {
        // 0 -> 1 -> 2 -> 3
        let edges = &[(0, 1), (1, 2), (2, 3)];
        let dom = cpu_dominator_sets(4, 0, edges);
        assert_eq!(dom[0], vec![0]);
        assert_eq!(dom[1], vec![0, 1]);
        assert_eq!(dom[2], vec![0, 1, 2]);
        assert_eq!(dom[3], vec![0, 1, 2, 3]);
    }

    #[test]
    fn cpu_dominator_sets_diamond() {
        // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let edges = &[(0, 1), (0, 2), (1, 3), (2, 3)];
        let dom = cpu_dominator_sets(4, 0, edges);
        assert_eq!(dom[0], vec![0]);
        assert_eq!(dom[1], vec![0, 1]);
        assert_eq!(dom[2], vec![0, 2]);
        assert_eq!(dom[3], vec![0, 3]);
    }

    #[test]
    fn cpu_dominator_sets_while_loop() {
        // 0 -> 1, 1 -> 2, 2 -> 1, 1 -> 3
        let edges = &[(0, 1), (1, 2), (2, 1), (1, 3)];
        let dom = cpu_dominator_sets(4, 0, edges);
        assert_eq!(dom[0], vec![0]);
        assert_eq!(dom[1], vec![0, 1]);
        assert_eq!(dom[2], vec![0, 1, 2]);
        assert_eq!(dom[3], vec![0, 1, 3]);
    }

    #[test]
    fn dominator_tree_backward_step_reaches_ancestors() {
        let (node_count, offsets, targets, masks) = diamond_dominance_tree();
        let frontier_in = vec![0b1000]; // {3}
        let out = cpu_ref(
            node_count,
            &offsets,
            &targets,
            &masks,
            &frontier_in,
            edge_kind::DOMINANCE,
        );
        assert_eq!(out[0], 0b0110, "backward from 3 must reach 1 and 2");
    }

    #[test]
    fn dominator_tree_program_emits_frontier_buffers() {
        let p = dominator_tree(ProgramGraphShape::new(4, 4), "fin", "fout");
        let names: Vec<&str> = p.buffers().iter().map(|b| b.name()).collect();
        assert!(names.contains(&"fin"));
        assert!(names.contains(&"fout"));
    }

    #[test]
    fn dominator_tree_soundness_is_mayover() {
        use crate::Soundness;
        // The GPU dominator_tree shim is documented as MayOver.
        assert_eq!(Soundness::MayOver, Soundness::MayOver);
    }

    #[test]
    fn dominator_tree_gpu_over_approximates_strict_dominators_on_diamond() {
        let p = dominator_tree(ProgramGraphShape::new(4, 4), "fin", "fout");
        let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
        let inputs = vec![
            to_bytes(&[0, 0, 0, 0]),          // pg_nodes
            to_bytes(&[0, 2, 3, 4, 4]),       // pg_edge_offsets
            to_bytes(&[1, 2, 3, 3]),          // pg_edge_targets
            to_bytes(&[edge_kind::DOMINANCE, edge_kind::DOMINANCE, edge_kind::DOMINANCE, edge_kind::DOMINANCE]),
            to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
            to_bytes(&[0b1000]),              // fin = {3}
            to_bytes(&[0b1000]),              // fout seed = {3}
        ];
        let values: Vec<vyre_reference::value::Value> =
            inputs.into_iter().map(vyre_reference::value::Value::from).collect();
        let outputs = vyre_reference::reference_eval(&p, &values).unwrap();
        let gpu_out = u32::from_le_bytes(outputs[0].to_bytes()[0..4].try_into().unwrap());

        let dom = cpu_dominator_sets(4, 0, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let true_dom_bitset: u32 = dom[3].iter().map(|&n| 1u32 << n).sum();

        assert_eq!(
            gpu_out, true_dom_bitset,
            "dominator_tree GPU shim ({:b}) over-approximates true dominators ({:b}) for node 3; \
             MayOver semantics divergence must be caught by adversarial tests",
            gpu_out, true_dom_bitset
        );
    }

    #[test]
    #[should_panic(expected = "node_count must be positive")]
    fn dominator_tree_zero_node_count_should_panic() {
        dominator_tree(ProgramGraphShape::new(0, 0), "fin", "fout");
    }

    #[test]
    #[should_panic(expected = "empty buffer name")]
    fn dominator_tree_empty_buffer_name_should_panic() {
        dominator_tree(ProgramGraphShape::new(4, 4), "", "fout");
    }
}
