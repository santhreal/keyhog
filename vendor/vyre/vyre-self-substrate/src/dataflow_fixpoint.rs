//! Region-graph dataflow fixpoint via #1 semiring_gemm (#26 substrate).
//!
//! Treats vyre's Region tree adjacency as a sparse boolean matrix
//! and computes reachability / liveness / dominance / constant-prop
//! via `semiring_gemm` iterations under different semirings:
//!
//! | Analysis | Semiring | Combine | Accumulate |
//! |---|---|---|---|
//! | Reachability | BoolOr | AND | OR |
//! | Liveness | BoolOr (reverse direction) | AND | OR |
//! | Reaching defs | Lineage | OR (zero-absorbing) | OR |
//! | Constant prop | Lineage | OR | OR |
//! | Min-cost path | MinPlus | + (sat) | min |
//!
//! Same primitive (#1), same Program, four different IR analyses.
//! Demonstrates the recursion thesis directly.

pub use vyre_foundation::pass_substrate::dataflow_fixpoint::Semiring;

/// Multiply matrices over the selected semiring on the CPU.
#[must_use]
pub fn semiring_gemm_cpu(
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
) -> Vec<u32> {
    let mut c = Vec::new();
    semiring_gemm_cpu_into(a, b, m, n, k, semiring, &mut c);
    c
}

/// Multiply matrices over the selected semiring into caller-owned storage.
pub fn semiring_gemm_cpu_into(
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
    c: &mut Vec<u32>,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    c.clear();
    c.resize((m * n) as usize, semiring.identity());
    for i in 0..m {
        for j in 0..n {
            let mut acc = semiring.identity();
            for kk in 0..k {
                let a_v = a[(i * k + kk) as usize];
                let b_v = b[(kk * n + j) as usize];

                let combined = match semiring {
                    Semiring::Real | Semiring::MaxTimes => a_v.wrapping_mul(b_v),
                    Semiring::MinPlus => {
                        if a_v == u32::MAX || b_v == u32::MAX {
                            u32::MAX
                        } else {
                            a_v.saturating_add(b_v)
                        }
                    }
                    Semiring::MaxPlus => a_v.saturating_add(b_v),
                    Semiring::BoolOr | Semiring::Gf2 => a_v & b_v,
                    Semiring::BoolAnd => a_v | b_v,
                    Semiring::Lineage => {
                        if a_v == 0 || b_v == 0 {
                            0
                        } else {
                            a_v | b_v
                        }
                    }
                };

                acc = match semiring {
                    Semiring::Real | Semiring::MaxPlus => acc.wrapping_add(combined),
                    Semiring::MinPlus => acc.min(combined),
                    Semiring::MaxTimes => acc.max(combined),
                    Semiring::BoolOr | Semiring::Lineage => acc | combined,
                    Semiring::BoolAnd => acc & combined,
                    Semiring::Gf2 => acc ^ combined,
                };
            }
            c[(i * n + j) as usize] = acc;
        }
    }
}

/// Compute boolean reachability closure on a Region adjacency matrix
/// via repeated `semiring_gemm` iterations under `Semiring::BoolOr`.
/// Iterates until fixpoint (max `max_iters` steps).
#[must_use]
pub fn reachability_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    reachability_closure_into(adj, n, max_iters, &mut current, &mut next);
    current
}

/// Compute boolean reachability closure into caller-owned buffers.
pub fn reachability_closure_into(
    adj: &[u32],
    n: u32,
    _max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    assert!(n > 0);
    current.clear();
    current.extend_from_slice(adj);
    next.clear();
    let n_us = n as usize;
    for k in 0..n_us {
        for i in 0..n_us {
            if current[i * n_us + k] == 0 {
                continue;
            }
            for j in 0..n_us {
                let via_k = current[k * n_us + j];
                if via_k != 0 {
                    current[i * n_us + j] |= via_k;
                }
            }
        }
    }
}

/// Compute lineage (which-clauses-used) closure under `Semiring::Lineage`.
/// Each entry of `adj` is a bitset of clause/source IDs.
#[must_use]
pub fn lineage_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    lineage_closure_into(adj, n, max_iters, &mut current, &mut next);
    current
}

/// Compute lineage closure into caller-owned buffers.
pub fn lineage_closure_into(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    assert!(n > 0);
    current.clear();
    current.extend_from_slice(adj);
    for _ in 0..max_iters {
        semiring_gemm_cpu_into(current, current, n, n, n, Semiring::Lineage, next);
        if !merge_or_changed(current, next) {
            return;
        }
    }
}

/// Compute min-cost shortest-path distance matrix under `Semiring::MinPlus`.
/// Use `u32::MAX` for "no edge".
#[must_use]
pub fn shortest_path_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    shortest_path_closure_into(adj, n, max_iters, &mut current, &mut next);
    current
}

/// Compute min-cost shortest-path closure into caller-owned buffers.
pub fn shortest_path_closure_into(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    assert!(n > 0);
    current.clear();
    current.extend_from_slice(adj);
    for _ in 0..max_iters {
        semiring_gemm_cpu_into(current, current, n, n, n, Semiring::MinPlus, next);
        // Take minimum elementwise (one more relaxation step).
        if !merge_min_changed(current, next) {
            return;
        }
    }
}

/// Reusable buffers for SCC/dataflow closure queries.
#[derive(Debug, Default)]
pub struct DataflowFixpointScratch {
    fwd_closure: Vec<u32>,
    bwd_closure: Vec<u32>,
    transpose: Vec<u32>,
    forward: Vec<u32>,
    backward: Vec<u32>,
    next_components: Vec<u32>,
}

impl DataflowFixpointScratch {
    /// Forward-reach bitset produced by the last pivot query.
    #[must_use]
    pub fn forward_bitset(&self) -> &[u32] {
        &self.forward
    }

    /// Backward-reach bitset produced by the last pivot query.
    #[must_use]
    pub fn backward_bitset(&self) -> &[u32] {
        &self.backward
    }
}

fn merge_or_changed(current: &mut [u32], next: &[u32]) -> bool {
    debug_assert_eq!(current.len(), next.len());
    let mut changed = false;
    for (dst, src) in current.iter_mut().zip(next.iter()) {
        let merged = *dst | *src;
        changed |= merged != *dst;
        *dst = merged;
    }
    changed
}

fn merge_min_changed(current: &mut [u32], next: &[u32]) -> bool {
    debug_assert_eq!(current.len(), next.len());
    let mut changed = false;
    for (dst, src) in current.iter_mut().zip(next.iter()) {
        let merged = (*dst).min(*src);
        changed |= merged != *dst;
        *dst = merged;
    }
    changed
}

/// Compute per-pivot forward + backward reach bitsets for the
/// strongly-connected-component decomposition primitive
/// (`vyre_primitives::graph::scc_decompose::cpu_ref`).
///
/// Returns `(forward, backward)` where `forward[w]` is the bitset
/// row indexed by `pivot` of the BoolOr reachability closure of
/// `adj`, and `backward[w]` is the same for the transposed
/// adjacency. The bitsets are packed 32-bits-per-u32, length
/// `bitset_words(n)`. Wires the dataflow-fixpoint primitive
/// (#26) into the SCC primitive (`scc_decompose`) so the
/// decomposition runs through vyre's substrate end-to-end.
///
/// # Panics
///
/// Panics if `pivot >= n` or `adj.len() != n*n`.
#[must_use]
pub fn forward_backward_bitsets_for_pivot(adj: &[u32], pivot: u32, n: u32) -> (Vec<u32>, Vec<u32>) {
    let mut scratch = DataflowFixpointScratch::default();
    forward_backward_bitsets_for_pivot_into(adj, pivot, n, &mut scratch);
    (scratch.forward, scratch.backward)
}

/// Compute per-pivot forward + backward reach bitsets into caller-owned scratch.
///
/// Results are written to `scratch.forward` and `scratch.backward`.
pub fn forward_backward_bitsets_for_pivot_into(
    adj: &[u32],
    pivot: u32,
    n: u32,
    scratch: &mut DataflowFixpointScratch,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    assert!(
        n > 0,
        "Fix: forward_backward_bitsets_for_pivot requires n > 0."
    );
    assert!(pivot < n, "Fix: pivot index must be < n.");
    let n_us = n as usize;
    assert_eq!(
        adj.len(),
        n_us * n_us,
        "Fix: adjacency must contain n*n entries."
    );

    let words = ((n + 31) / 32) as usize;

    reachability_closure_into(
        adj,
        n,
        n,
        &mut scratch.fwd_closure,
        &mut scratch.bwd_closure,
    );
    scratch.transpose.clear();
    scratch.transpose.resize(n_us * n_us, 0);
    for i in 0..n_us {
        for j in 0..n_us {
            scratch.transpose[j * n_us + i] = adj[i * n_us + j];
        }
    }
    reachability_closure_into(
        &scratch.transpose,
        n,
        n,
        &mut scratch.bwd_closure,
        &mut scratch.next_components,
    );

    scratch.forward.resize(words, 0);
    scratch.backward.resize(words, 0);
    write_pivot_bitsets(
        &scratch.fwd_closure,
        &scratch.bwd_closure,
        pivot,
        n_us,
        &mut scratch.forward,
        &mut scratch.backward,
    );
}

fn write_pivot_bitsets(
    fwd_closure: &[u32],
    bwd_closure: &[u32],
    pivot: u32,
    n_us: usize,
    forward: &mut [u32],
    backward: &mut [u32],
) {
    forward.fill(0);
    backward.fill(0);
    let pivot_us = pivot as usize;
    // Pivot reaches itself.
    let pivot_word = pivot_us / 32;
    let pivot_bit = 1u32 << (pivot_us % 32);
    forward[pivot_word] |= pivot_bit;
    backward[pivot_word] |= pivot_bit;
    for v in 0..n_us {
        if fwd_closure[pivot_us * n_us + v] != 0 {
            forward[v / 32] |= 1u32 << (v % 32);
        }
        if bwd_closure[pivot_us * n_us + v] != 0 {
            backward[v / 32] |= 1u32 << (v % 32);
        }
    }
}

/// Drive `vyre_primitives::graph::scc_decompose::cpu_ref` end-to-end
/// over an `n×n` adjacency: pick pivots in descending unassigned
/// order and stamp every node in `forward(p) ∩ backward(p)` with `p`.
/// Returns the per-node component-id vector. Unassigned nodes (not
/// inside any non-trivial SCC starting at the chosen pivots) carry
/// `u32::MAX`. Wires #26 (dataflow_fixpoint) and the
/// `scc_decompose` primitive together as one substrate path.
#[must_use]
pub fn scc_components_via_substrate(adj: &[u32], n: u32) -> Vec<u32> {
    let mut components = Vec::new();
    let mut scratch = DataflowFixpointScratch::default();
    scc_components_via_substrate_into(adj, n, &mut components, &mut scratch);
    components
}

/// Drive SCC decomposition into caller-owned output and scratch buffers.
pub fn scc_components_via_substrate_into(
    adj: &[u32],
    n: u32,
    components: &mut Vec<u32>,
    scratch: &mut DataflowFixpointScratch,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    components.clear();
    if n == 0 {
        return;
    }
    let n_us = n as usize;
    components.resize(n_us, u32::MAX);
    let words = ((n + 31) / 32) as usize;
    reachability_closure_into(
        adj,
        n,
        n,
        &mut scratch.fwd_closure,
        &mut scratch.bwd_closure,
    );
    scratch.transpose.clear();
    scratch.transpose.resize(n_us * n_us, 0);
    for i in 0..n_us {
        for j in 0..n_us {
            scratch.transpose[j * n_us + i] = adj[i * n_us + j];
        }
    }
    reachability_closure_into(
        &scratch.transpose,
        n,
        n,
        &mut scratch.bwd_closure,
        &mut scratch.next_components,
    );
    scratch.forward.resize(words, 0);
    scratch.backward.resize(words, 0);
    scratch.next_components.clear();
    scratch.next_components.reserve(n_us);
    for pivot in 0..n {
        if components[pivot as usize] != u32::MAX {
            continue;
        }
        write_pivot_bitsets(
            &scratch.fwd_closure,
            &scratch.bwd_closure,
            pivot,
            n_us,
            &mut scratch.forward,
            &mut scratch.backward,
        );
        vyre_primitives::graph::scc_decompose::cpu_ref_into(
            n,
            &scratch.forward,
            &scratch.backward,
            components,
            pivot,
            &mut scratch.next_components,
        );
        std::mem::swap(components, &mut scratch.next_components);
    }
}

#[cfg(test)]
#[allow(clippy::erasing_op, clippy::identity_op)]
mod tests {
    use super::*;

    #[test]
    fn reachability_chain_graph() {
        // 0 → 1 → 2 → 3
        let adj = vec![0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let closure = reachability_closure(&adj, 4, 5);
        // After closure: 0 reaches {1, 2, 3}; 1 reaches {2, 3}; 2 reaches {3}.
        assert_eq!(closure[0 * 4 + 1], 1);
        assert_eq!(closure[0 * 4 + 2], 1);
        assert_eq!(closure[0 * 4 + 3], 1);
        assert_eq!(closure[1 * 4 + 3], 1);
        // No reverse edges
        assert_eq!(closure[3 * 4 + 0], 0);
    }

    #[test]
    fn reachability_disjoint_components_stay_disjoint() {
        // 0 → 1, 2 → 3, no cross.
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let closure = reachability_closure(&adj, 4, 5);
        assert_eq!(closure[0 * 4 + 2], 0);
        assert_eq!(closure[2 * 4 + 0], 0);
    }

    #[test]
    fn lineage_closure_unions_clauses_along_paths() {
        // Edge 0→1 used clause f1 = 0b01; edge 1→2 used clause f2 = 0b10.
        // Path 0→2 uses both: 0b11.
        let f1 = 0b01;
        let f2 = 0b10;
        let adj = vec![0, f1, 0, 0, 0, f2, 0, 0, 0];
        let closure = lineage_closure(&adj, 3, 5);
        assert_eq!(closure[0 * 3 + 2], f1 | f2);
    }

    #[test]
    fn shortest_path_closure_finds_two_hop_minimum() {
        let inf = u32::MAX;
        // 0→1 cost 5, 1→2 cost 3, 0→2 cost 100 (slower direct).
        let adj = vec![inf, 5, 100, inf, inf, 3, inf, inf, inf];
        let closure = shortest_path_closure(&adj, 3, 5);
        // Best 0→2 = min(100, 5+3) = 8.
        assert_eq!(closure[0 * 3 + 2], 8);
    }

    #[test]
    fn reachability_self_loop_detected() {
        // 0 → 1, 1 → 0. Closure should mark both.
        let adj = vec![0, 1, 1, 0];
        let closure = reachability_closure(&adj, 2, 5);
        // After 1 iteration: 0 reaches 0 via 0→1→0; 1 reaches 1.
        assert_eq!(closure[0 * 2 + 0], 1);
        assert_eq!(closure[1 * 2 + 1], 1);
    }

    // ---- forward_backward_bitsets_for_pivot + scc_components_via_substrate ----

    #[test]
    fn fb_bitsets_chain_pivot_zero() {
        // 0 → 1 → 2. From pivot 0: forward = {0,1,2}, backward = {0}.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let (fwd, bwd) = forward_backward_bitsets_for_pivot(&adj, 0, 3);
        assert_eq!(fwd, vec![0b111]);
        assert_eq!(bwd, vec![0b001]);
    }

    #[test]
    fn fb_bitsets_chain_pivot_two() {
        // 0 → 1 → 2. From pivot 2: forward = {2}, backward = {0,1,2}.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let (fwd, bwd) = forward_backward_bitsets_for_pivot(&adj, 2, 3);
        assert_eq!(fwd, vec![0b100]);
        assert_eq!(bwd, vec![0b111]);
    }

    #[test]
    fn fb_bitsets_into_reuses_capacity_and_matches_owned() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mut scratch = DataflowFixpointScratch::default();
        forward_backward_bitsets_for_pivot_into(&adj, 2, 3, &mut scratch);
        let fwd_capacity = scratch.forward.capacity();
        let bwd_capacity = scratch.backward.capacity();
        assert_eq!(scratch.forward_bitset(), &[0b100]);
        assert_eq!(scratch.backward_bitset(), &[0b111]);

        forward_backward_bitsets_for_pivot_into(&adj, 0, 3, &mut scratch);
        assert_eq!(scratch.forward.capacity(), fwd_capacity);
        assert_eq!(scratch.backward.capacity(), bwd_capacity);
        assert_eq!(scratch.forward_bitset(), &[0b111]);
        assert_eq!(scratch.backward_bitset(), &[0b001]);
    }

    #[test]
    fn scc_components_chain_each_node_singleton() {
        // 0 → 1 → 2 (DAG). Every SCC is a singleton.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let comps = scc_components_via_substrate(&adj, 3);
        // Each node stamped by itself (first pivot wins).
        assert_eq!(comps, vec![0, 1, 2]);
    }

    #[test]
    fn scc_components_two_cycle_collapses_to_first_pivot() {
        // 0 → 1, 1 → 0. {0,1} is one SCC. First pivot 0 stamps both.
        let adj = vec![0, 1, 1, 0];
        let comps = scc_components_via_substrate(&adj, 2);
        assert_eq!(comps, vec![0, 0]);
    }

    #[test]
    fn scc_components_into_reuses_output_and_matches_owned() {
        let adj = vec![0, 1, 1, 0];
        let mut comps = Vec::new();
        let mut scratch = DataflowFixpointScratch::default();
        scc_components_via_substrate_into(&adj, 2, &mut comps, &mut scratch);
        let comps_capacity = comps.capacity();
        let scratch_capacity = scratch.next_components.capacity();
        assert_eq!(comps, vec![0, 0]);

        scc_components_via_substrate_into(&adj, 2, &mut comps, &mut scratch);
        assert_eq!(comps.capacity(), comps_capacity);
        assert_eq!(scratch.next_components.capacity(), scratch_capacity);
        assert_eq!(comps, scc_components_via_substrate(&adj, 2));
    }

    /// Closure-bar: the substrate-driven SCC must agree with running
    /// `scc_decompose::cpu_ref` directly with manually-prepared
    /// forward/backward bitsets. Asserts the wiring doesn't drift.
    #[test]
    fn scc_components_match_direct_primitive_call() {
        // 0 → 1 → 2 → 0 (one big cycle), 3 → 4 separate.
        let adj = vec![
            0, 1, 0, 0, 0, // 0 -> 1
            0, 0, 1, 0, 0, // 1 -> 2
            1, 0, 0, 0, 0, // 2 -> 0
            0, 0, 0, 0, 1, // 3 -> 4
            0, 0, 0, 0, 0, // 4
        ];
        let via_substrate = scc_components_via_substrate(&adj, 5);

        // Manual replay: pivot 0 stamps {0,1,2}; pivot 3 stamps {3};
        // pivot 4 stamps {4}.
        let mut manual = vec![u32::MAX; 5];
        for pivot in [0u32, 3, 4] {
            let (fwd, bwd) = forward_backward_bitsets_for_pivot(&adj, pivot, 5);
            manual = vyre_primitives::graph::scc_decompose::cpu_ref(5, &fwd, &bwd, &manual, pivot);
        }
        assert_eq!(via_substrate, manual);
        // The cycle members all carry pivot 0.
        assert_eq!(via_substrate[0..3], [0, 0, 0]);
        // Singletons keep their own pivot id.
        assert_eq!(via_substrate[3], 3);
        assert_eq!(via_substrate[4], 4);
    }

    /// Adversarial: a fully disconnected graph (no edges) must yield
    /// `[0, 1, 2, ..., n-1]` because every pivot stamps only itself.
    #[test]
    fn scc_components_no_edges_each_pivot_stamps_only_itself() {
        let n = 4;
        let adj = vec![0u32; (n * n) as usize];
        let comps = scc_components_via_substrate(&adj, n);
        assert_eq!(comps, vec![0, 1, 2, 3]);
    }

    /// Adversarial: a self-loop on a node must NOT pull other nodes
    /// into its SCC. A common bug is to over-eagerly mark every node
    /// reached via the closure's reflexive-transitive interpretation.
    #[test]
    fn scc_components_self_loop_does_not_merge_distinct_components() {
        // 0 -> 0 (self-loop), 1 isolated, 2 isolated.
        let adj = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];
        let comps = scc_components_via_substrate(&adj, 3);
        assert_eq!(comps, vec![0, 1, 2]);
    }
}
