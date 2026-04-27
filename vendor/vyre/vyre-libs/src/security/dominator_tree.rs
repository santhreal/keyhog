//! `dominator_tree` — Tier-3 shim.
//!
//! The [`dominator_tree`](fn@dominator_tree) primitive is tagged with
//! [`Soundness::MayOver`](vyre_libs::dataflow::soundness::Soundness::MayOver):
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
/// This composition is [`Soundness::MayOver`](vyre_libs::dataflow::soundness::Soundness::MayOver):
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
/// This is an [`Exact`](vyre_libs::dataflow::soundness::Soundness::Exact)
/// reference; rules that require zero false positives MUST compose
/// against this oracle rather than the GPU [`dominator_tree`] shim.
#[must_use]
pub fn cpu_dominator_sets(num_nodes: u32, entry: u32, edges: &[(u32, u32)]) -> Vec<Vec<u32>> {
    let n = num_nodes as usize;
    let entry = entry as usize;
    if n == 0 {
        return Vec::new();
    }
    assert!(
        entry < n,
        "cpu_dominator_sets: entry ({entry}) out of bounds (num_nodes = {n})"
    );

    // Build predecessor and successor adjacency lists.
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &(src, dst) in edges {
        let src = src as usize;
        let dst = dst as usize;
        if src < n && dst < n {
            preds[dst].push(src);
            succs[src].push(dst);
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

    // Initialize Dom[entry] = {entry}; Dom[other] = ALL_NODES.
    let mut dom: Vec<Vec<u64>> = (0..n)
        .map(|i| {
            if i == entry {
                entry_set.clone()
            } else {
                all_set.clone()
            }
        })
        .collect();

    // Compute reverse postorder of reachable nodes via DFS from entry.
    let mut visited = vec![false; n];
    let mut postorder = Vec::with_capacity(n);
    fn dfs(node: usize, succs: &[Vec<usize>], visited: &mut [bool], postorder: &mut Vec<usize>) {
        visited[node] = true;
        for &succ in &succs[node] {
            if !visited[succ] {
                dfs(succ, succs, visited, postorder);
            }
        }
        postorder.push(node);
    }
    dfs(entry, &succs, &mut visited, &mut postorder);
    let rpo: Vec<usize> = postorder.into_iter().rev().collect();

    // Iterative fixpoint: Dom[n] = {n} ∪ intersect(Dom[p] for p in preds(n)).
    let mut changed = true;
    while changed {
        changed = false;
        for &node in &rpo {
            if node == entry {
                continue;
            }
            let mut new_set = vec![0u64; blocks];
            if preds[node].is_empty() {
                new_set[node / 64] |= 1u64 << (node % 64);
            } else {
                let first = preds[node][0];
                new_set.copy_from_slice(&dom[first]);
                for &p in &preds[node][1..] {
                    for b in 0..blocks {
                        new_set[b] &= dom[p][b];
                    }
                }
                new_set[node / 64] |= 1u64 << (node % 64);
            }
            if new_set != dom[node] {
                dom[node].copy_from_slice(&new_set);
                changed = true;
            }
        }
    }

    // Convert bitsets to sorted Vec<u32>.
    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        let mut set = Vec::new();
        for b in 0..blocks {
            let mut block = dom[i][b];
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
            // Graph with self-loops on dominance edges: 0→0, 1→1, 2→2, 3→3.
            // Starting frontier {0} is already a fixed point.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 1, 2, 3, 4]),       // pg_edge_offsets
                to_bytes(&[0, 1, 2, 3]),          // pg_edge_targets
                to_bytes(&[16, 16, 16, 16]),      // pg_edge_kind_mask (DOMINANCE)
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {0}
                to_bytes(&[0b0001]),              // fout = {0}
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0001])]]
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
}
