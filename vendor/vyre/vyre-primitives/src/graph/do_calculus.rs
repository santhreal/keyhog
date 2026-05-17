//! Pearl's do-calculus — graph surgery primitives.
//!
//! Pearl's three rules of do-calculus reduce a do-query `P(Y | do(X))`
//! to an observable-query `P(Y | X)` when the causal graph admits.
//! The Shpitser ID algorithm (2008) automates the rule application;
//! Correa-Bareinboim (2020) extends to multi-treatment identifiability.
//!
//! At the GPU primitive level, do-calculus reduces to **graph
//! surgery** — three primitive transformations on the adjacency matrix:
//!
//! 1. **Edge deletion** — `do(X = x)` removes incoming edges to X
//!    (parents no longer cause X; X is set externally).
//! 2. **Edge reversal** — needed when applying Rule 3 (action /
//!    observation exchange).
//! 3. **Subgraph extraction** — restrict to a node subset for backdoor
//!    / frontdoor adjustment.
//!
//! This file ships the **incoming-edge-deletion** primitive — the
//! most-used graph surgery, the heart of `do(X = x)`.
//!
//! # Why this primitive is dual-use
//!
//! | Consumer | Use |
//! |---|---|
//! | `vyre-libs::causal` consumers | Pearl-style counterfactuals |
//! | `vyre-libs::security::what_if` consumers | "would finding fire under fix X?" counterfactual analysis |
//! | `vyre-foundation::transform` change-impact analysis | `do(rule_X)` on the rule dependency graph predicts which downstream Programs invalidate. Replaces ad-hoc cache-invalidation tracking with formal causal analysis. |

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Op id.
pub const OP_ID: &str = "vyre-primitives::graph::do_intervention_delete_incoming";

/// Emit a Program that zeros all incoming edges to nodes marked
/// "intervened" in `intervention_mask`. The result is the post-do
/// adjacency matrix.
///
/// Inputs:
/// - `adjacency`: row-major `n × n` u32 buffer (entry `[i, j]` = edge
///   weight or 0/1 for unweighted).
/// - `intervention_mask`: `n` u32 lanes, `1` if node is do-intervened.
///
/// Output:
/// - `out_adjacency`: row-major `n × n` u32 buffer.
///
/// Per-cell rule: `out[i, j] = 0` if `intervention_mask[j] == 1`
/// (column j zeros out — incoming edges to j removed). Otherwise
/// `out[i, j] = adjacency[i, j]`.
#[must_use]
pub fn do_intervention_delete_incoming(
    adjacency: &str,
    intervention_mask: &str,
    out_adjacency: &str,
    n: u32,
) -> Program {
    if n == 0 {
        return crate::invalid_output_program(
            OP_ID,
            out_adjacency,
            DataType::U32,
            format!("Fix: do_intervention_delete_incoming requires n > 0, got {n}."),
        );
    }

    let cells = n * n;
    let t = Expr::InvocationId { axis: 0 };

    // Decode (i, j) from flat invocation t = i*n + j; only j matters.
    let j_expr = Expr::rem(t.clone(), Expr::u32(n));
    let intervened = Expr::load(intervention_mask, j_expr);
    let edge = Expr::load(adjacency, t.clone());
    let value = Expr::select(Expr::eq(intervened, Expr::u32(0)), edge, Expr::u32(0));

    let body = vec![Node::if_then(
        Expr::lt(t.clone(), Expr::u32(cells)),
        vec![Node::store(out_adjacency, t, value)],
    )];

    Program::wrapped(
        vec![
            BufferDecl::storage(adjacency, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(cells),
            BufferDecl::storage(intervention_mask, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n),
            BufferDecl::storage(out_adjacency, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(cells),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference.
#[must_use]
pub fn do_intervention_delete_incoming_cpu(
    adjacency: &[u32],
    intervention_mask: &[u32],
    n: u32,
) -> Vec<u32> {
    let mut out = Vec::new();
    do_intervention_delete_incoming_cpu_into(adjacency, intervention_mask, n, &mut out);
    out
}

/// CPU reference writing into caller-owned storage.
pub fn do_intervention_delete_incoming_cpu_into(
    adjacency: &[u32],
    intervention_mask: &[u32],
    n: u32,
    out: &mut Vec<u32>,
) {
    let n = n as usize;
    out.clear();
    out.resize(n * n, 0);
    for (dst, &src) in out.iter_mut().zip(adjacency.iter()) {
        *dst = src;
    }
    for j in 0..n {
        if intervention_mask.get(j).copied().unwrap_or(0) != 0 {
            for i in 0..n {
                out[i * n + j] = 0; // zero column j
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_no_intervention_preserves_adjacency() {
        let a = vec![1, 2, 3, 4];
        let mask = vec![0, 0];
        let out = do_intervention_delete_incoming_cpu(&a, &mask, 2);
        assert_eq!(out, a);
    }

    #[test]
    fn cpu_intervene_node_zero_zeros_column() {
        // 2-node graph, intervene on node 0.
        // Edge [0->0]=1, [0->1]=2, [1->0]=3, [1->1]=4
        // After do(0): incoming-to-0 zeroed → [0->0]=0, [1->0]=0 stay
        // existing: [0->1]=2, [1->1]=4
        let a = vec![1, 2, 3, 4];
        let mask = vec![1, 0];
        let out = do_intervention_delete_incoming_cpu(&a, &mask, 2);
        // column 0: out[0*2+0] = 0, out[1*2+0] = 0
        // column 1: out[0*2+1] = 2, out[1*2+1] = 4
        assert_eq!(out, vec![0, 2, 0, 4]);
    }

    #[test]
    fn cpu_intervene_all_zeros_all() {
        let a = vec![1, 2, 3, 4];
        let mask = vec![1, 1];
        let out = do_intervention_delete_incoming_cpu(&a, &mask, 2);
        assert_eq!(out, vec![0; 4]);
    }

    #[test]
    fn cpu_chain_graph_intervention_breaks_chain() {
        // Chain: 0 -> 1 -> 2.
        // Adjacency (row=from, col=to):
        //   [0,1]=1, [1,2]=1, others=0
        let a = vec![
            0, 1, 0, // row 0: edge to 1
            0, 0, 1, // row 1: edge to 2
            0, 0, 0, // row 2: no edges out
        ];
        // Intervene on node 1: "set node 1 externally" → break 0→1.
        let mask = vec![0, 1, 0];
        let out = do_intervention_delete_incoming_cpu(&a, &mask, 3);
        // column 1 zeroed: [0,1]=0
        // column 2 untouched: [1,2]=1
        assert_eq!(out[0 * 3 + 1], 0);
        assert_eq!(out[1 * 3 + 2], 1);
    }

    #[test]
    fn cpu_malformed_inputs_are_zero_padded() {
        let out = do_intervention_delete_incoming_cpu(&[1], &[1], 2);
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn ir_program_buffer_layout() {
        let p = do_intervention_delete_incoming("a", "m", "out", 4);
        assert_eq!(p.workgroup_size, [256, 1, 1]);
        let names: Vec<&str> = p.buffers.iter().map(|b| b.name()).collect();
        assert_eq!(names, vec!["a", "m", "out"]);
        assert_eq!(p.buffers[0].count(), 16); // n*n
        assert_eq!(p.buffers[1].count(), 4); // n
        assert_eq!(p.buffers[2].count(), 16); // n*n
    }

    #[test]
    fn zero_n_traps() {
        let p = do_intervention_delete_incoming("a", "m", "o", 0);
        assert!(p.stats().trap());
    }
}

// ===== P-PRIM-7: Rules 2 and 3 of do-calculus =====================
//
// Pearl's three rules act on a causal graph G with treatment X,
// outcome Y, and conditioning set Z:
//
//   Rule 1 (insertion/deletion of observation): if Z is conditionally
//          independent of Y given X in the mutilated graph, you can
//          drop it from the conditioning set. Implemented via the
//          do_intervention_delete_incoming primitive above + a
//          d-separation check (callers compose these).
//   Rule 2 (action / observation exchange): in the graph with edges
//          INTO X removed, observation Y | Z, X equals
//          Y | Z, do(X). Implemented as edge reversal: a treatment-
//          set's incoming edges are reversed in the working
//          adjacency.
//   Rule 3 (insertion/deletion of action): in the graph with X →·
//          edges removed (downstream of X), do(X) has no effect on
//          ancestors. Implemented as subgraph extraction.
//
// This block ships the CPU references for Rule 2 and Rule 3 so the
// substrate file actually contains all three rules. Rule 1's "remove
// incoming edges" surgery is the existing
// `do_intervention_delete_incoming_cpu`.

/// Rule 2 (do-calculus) — edge reversal on incoming edges of treatment
/// nodes. Reverses every edge `i → j` where `treatment_mask[j] != 0`
/// to `j → i`. Pre-existing reverse edges are merged via OR.
///
/// Returns the reversed adjacency matrix.
#[must_use]
pub fn do_rule2_reverse_incoming_cpu(
    adjacency: &[u32],
    treatment_mask: &[u32],
    n: u32,
) -> Vec<u32> {
    let mut out = Vec::new();
    do_rule2_reverse_incoming_cpu_into(adjacency, treatment_mask, n, &mut out);
    out
}

/// Rule 2 CPU reference writing into caller-owned storage.
pub fn do_rule2_reverse_incoming_cpu_into(
    adjacency: &[u32],
    treatment_mask: &[u32],
    n: u32,
    out: &mut Vec<u32>,
) {
    let n_us = n as usize;
    assert_eq!(adjacency.len(), n_us * n_us);
    assert_eq!(treatment_mask.len(), n_us);
    out.clear();
    out.extend_from_slice(adjacency);
    for j in 0..n_us {
        if treatment_mask[j] == 0 {
            continue;
        }
        for i in 0..n_us {
            if i == j {
                continue;
            }
            let forward = adjacency[i * n_us + j];
            if forward != 0 {
                // Move i→j to j→i, OR-merging with any existing
                // reverse edge. Read from the immutable input matrix
                // so simultaneous treatment-set reversals are not
                // affected by earlier writes in this pass.
                out[j * n_us + i] |= forward;
                out[i * n_us + j] = 0;
            }
        }
    }
}

/// Rule 3 (do-calculus) — subgraph extraction. Returns the adjacency
/// matrix restricted to nodes whose `keep_mask` bit is set. Edges
/// touching dropped nodes are removed; the result is laid out as
/// `k × k` where `k = popcount(keep_mask)`.
///
/// Returns `(reduced_adjacency, kept_index_to_original_index)`.
#[must_use]
pub fn do_rule3_subgraph_cpu(adjacency: &[u32], keep_mask: &[u32], n: u32) -> (Vec<u32>, Vec<u32>) {
    let mut reduced = Vec::new();
    let mut kept = Vec::new();
    do_rule3_subgraph_cpu_into(adjacency, keep_mask, n, &mut reduced, &mut kept);
    (reduced, kept)
}

/// Rule 3 CPU reference writing into caller-owned storage.
pub fn do_rule3_subgraph_cpu_into(
    adjacency: &[u32],
    keep_mask: &[u32],
    n: u32,
    reduced: &mut Vec<u32>,
    kept: &mut Vec<u32>,
) {
    let n_us = n as usize;
    assert_eq!(adjacency.len(), n_us * n_us);
    assert_eq!(keep_mask.len(), n_us);

    kept.clear();
    kept.reserve(n_us);
    kept.extend(keep_mask.iter().enumerate().filter_map(|(idx, &m)| {
        if m != 0 {
            Some(idx as u32)
        } else {
            None
        }
    }));
    let k = kept.len();
    reduced.clear();
    reduced.resize(k * k, 0);
    for (new_i, &old_i) in kept.iter().enumerate() {
        for (new_j, &old_j) in kept.iter().enumerate() {
            reduced[new_i * k + new_j] = adjacency[(old_i as usize) * n_us + (old_j as usize)];
        }
    }
}

#[cfg(test)]
mod rule2_tests {
    use super::*;

    #[test]
    fn no_treatment_preserves_adjacency() {
        let a = vec![0, 1, 0, 0];
        let mask = vec![0u32, 0];
        let out = do_rule2_reverse_incoming_cpu(&a, &mask, 2);
        assert_eq!(out, a);
    }

    #[test]
    fn single_treatment_reverses_incoming() {
        // 2 nodes; edge 0→1; treat node 1 → reverse to 1→0.
        let a = vec![
            0, 1, // row 0
            0, 0, // row 1
        ];
        let mask = vec![0u32, 1];
        let out = do_rule2_reverse_incoming_cpu(&a, &mask, 2);
        assert_eq!(out, vec![0, 0, 1, 0]);
    }

    #[test]
    fn reversal_or_merges_with_existing_reverse_edge() {
        // Bidirectional 0↔1 (both edges exist).
        // Treat node 1 → 0→1 reversed to 1→0; existing 1→0 stays.
        let a = vec![0, 1, 1, 0];
        let mask = vec![0u32, 1];
        let out = do_rule2_reverse_incoming_cpu(&a, &mask, 2);
        assert_eq!(out, vec![0, 0, 1, 0]);
    }

    #[test]
    fn self_edges_untouched() {
        let a = vec![1, 0, 0, 1];
        let mask = vec![1u32, 1];
        let out = do_rule2_reverse_incoming_cpu(&a, &mask, 2);
        // Self-edges are skipped; still 1 on the diagonal.
        assert_eq!(out, vec![1, 0, 0, 1]);
    }

    #[test]
    fn reversal_is_involution_under_double_treatment() {
        // Reversing twice on the same treatment set yields the
        // original adjacency (when no overlap with reverse edges).
        let a = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mask = vec![1u32, 1, 1];
        let once = do_rule2_reverse_incoming_cpu(&a, &mask, 3);
        let twice = do_rule2_reverse_incoming_cpu(&once, &mask, 3);
        assert_eq!(twice, a);
    }
}

#[cfg(test)]
mod rule3_tests {
    use super::*;

    #[test]
    fn keep_all_returns_original() {
        let a = vec![0, 1, 1, 0];
        let mask = vec![1u32, 1];
        let (out, kept) = do_rule3_subgraph_cpu(&a, &mask, 2);
        assert_eq!(out, a);
        assert_eq!(kept, vec![0, 1]);
    }

    #[test]
    fn subgraph_into_reuses_buffers() {
        let a = vec![0, 1, 1, 0];
        let mask = vec![1u32, 1];
        let mut out = Vec::with_capacity(8);
        let mut kept = Vec::with_capacity(4);
        do_rule3_subgraph_cpu_into(&a, &mask, 2, &mut out, &mut kept);
        let out_capacity = out.capacity();
        let kept_capacity = kept.capacity();
        assert_eq!(out, a);
        assert_eq!(kept, vec![0, 1]);

        do_rule3_subgraph_cpu_into(&a, &[1u32, 0], 2, &mut out, &mut kept);
        assert_eq!(out.capacity(), out_capacity);
        assert_eq!(kept.capacity(), kept_capacity);
        assert_eq!(out, vec![0]);
        assert_eq!(kept, vec![0]);
    }

    #[test]
    fn keep_none_returns_empty() {
        let a = vec![0, 1, 1, 0];
        let mask = vec![0u32, 0];
        let (out, kept) = do_rule3_subgraph_cpu(&a, &mask, 2);
        assert!(out.is_empty());
        assert!(kept.is_empty());
    }

    #[test]
    fn keep_one_extracts_self_loop_only() {
        let a = vec![1, 1, 1, 1];
        let mask = vec![1u32, 0];
        let (out, kept) = do_rule3_subgraph_cpu(&a, &mask, 2);
        assert_eq!(out, vec![1]);
        assert_eq!(kept, vec![0]);
    }

    #[test]
    fn keep_two_of_three_drops_middle() {
        // 3-node chain 0→1→2. Keep {0, 2} → 1×... wait k=2.
        // After dropping node 1, 0 and 2 share no edge directly.
        let a = vec![
            0, 1, 0, // row 0
            0, 0, 1, // row 1
            0, 0, 0, // row 2
        ];
        let mask = vec![1u32, 0, 1];
        let (out, kept) = do_rule3_subgraph_cpu(&a, &mask, 3);
        assert_eq!(out, vec![0, 0, 0, 0]);
        assert_eq!(kept, vec![0, 2]);
    }

    #[test]
    fn keep_preserves_edges_between_kept_nodes() {
        // 4-node graph. Keep {1, 3}.
        // Edge 1→3 exists; should appear in 2×2 reduced.
        let n = 4;
        let mut a = vec![0u32; (n * n) as usize];
        a[(1 * n + 3) as usize] = 7;
        a[(3 * n + 1) as usize] = 5;
        let mask = vec![0u32, 1, 0, 1];
        let (out, kept) = do_rule3_subgraph_cpu(&a, &mask, n);
        // Reduced indices: 1 → new 0, 3 → new 1. So 1→3 lands at out[0,1] = 7.
        assert_eq!(out, vec![0, 7, 5, 0]);
        assert_eq!(kept, vec![1, 3]);
    }
}
