//! Rule-graph change-impact as a Pearl do-calculus query (#36 substrate).
//!
//! Frames vyre's cache-invalidation as a `do(rule_X)` query on the
//! dependency graph. When rule `X` changes, `do(X)` on the graph
//! predicts which downstream Programs invalidate.
//!
//! This replaces ad-hoc cache invalidation with formal causal analysis.

use crate::dataflow_fixpoint::reachability_closure_into;
use vyre_primitives::graph::do_calculus::{
    do_intervention_delete_incoming_cpu_into, do_rule2_reverse_incoming_cpu_into,
    do_rule3_subgraph_cpu_into,
};

/// Reusable matrix buffers for do-calculus impact queries.
#[derive(Debug, Default)]
pub struct DoCalculusImpactScratch {
    surgically_modified_adj: Vec<u32>,
    closure: Vec<u32>,
    scratch: Vec<u32>,
    impact_mask: Vec<u32>,
    reduced_adjacency: Vec<u32>,
    kept_indices: Vec<u32>,
}

impl DoCalculusImpactScratch {
    /// Last computed impact mask.
    #[must_use]
    pub fn impact_mask(&self) -> &[u32] {
        &self.impact_mask
    }

    /// Last computed reduced adjacency.
    #[must_use]
    pub fn reduced_adjacency(&self) -> &[u32] {
        &self.reduced_adjacency
    }

    /// Original indices retained in the last reduced adjacency.
    #[must_use]
    pub fn kept_indices(&self) -> &[u32] {
        &self.kept_indices
    }
}

/// Predict which nodes in a dependency graph are impacted by a change
/// in a subset of nodes.
///
/// This performs a `do(intervened_nodes)` intervention (removing
/// incoming edges to the changed nodes) and then computes the
/// transitive closure to find all affected downstream nodes.
#[must_use]
pub fn predict_impact(adj: &[u32], intervention_mask: &[u32], n: u32) -> Vec<u32> {
    use crate::observability::{bump, do_calculus_change_impact_calls};
    bump(&do_calculus_change_impact_calls);
    if n == 0 {
        return Vec::new();
    }
    let mut scratch = DoCalculusImpactScratch::default();
    predict_impact_with_scratch(adj, intervention_mask, n, &mut scratch);
    scratch.impact_mask
}

/// Predict impact using named reusable scratch.
pub fn predict_impact_with_scratch(
    adj: &[u32],
    intervention_mask: &[u32],
    n: u32,
    scratch: &mut DoCalculusImpactScratch,
) {
    predict_impact_into(
        adj,
        intervention_mask,
        n,
        &mut scratch.surgically_modified_adj,
        &mut scratch.closure,
        &mut scratch.scratch,
        &mut scratch.impact_mask,
    );
}

/// Predict impact while reusing caller-owned matrix scratch buffers.
pub fn predict_impact_into(
    adj: &[u32],
    intervention_mask: &[u32],
    n: u32,
    surgically_modified_adj: &mut Vec<u32>,
    closure: &mut Vec<u32>,
    scratch: &mut Vec<u32>,
    impact_mask: &mut Vec<u32>,
) {
    if n == 0 {
        impact_mask.clear();
        return;
    }
    do_intervention_delete_incoming_cpu_into(adj, intervention_mask, n, surgically_modified_adj);

    reachability_closure_into(surgically_modified_adj, n, n, closure, scratch);

    // 3. The impacted set is the union of reachability sets from each changed node.
    let n_us = n as usize;
    impact_mask.clear();
    impact_mask.resize(n_us, 0);
    for i in 0..n_us {
        if intervention_mask[i] != 0 {
            impact_mask[i] = 1; // Itself is impacted.
            for j in 0..n_us {
                if closure[i * n_us + j] != 0 {
                    impact_mask[j] = 1;
                }
            }
        }
    }
}

/// Compute the impacted subgraph: the adjacency restricted to the
/// nodes [`predict_impact`] flags as stale.
///
/// Uses do-calculus Rule 3 (subgraph extraction) on the impact mask.
/// Returns `(reduced_adjacency, kept_indices)` where `reduced_adjacency`
/// is row-major `k × k` with `k = kept_indices.len()`. The reduced
/// adjacency contains only edges between impacted nodes; downstream
/// analyses (lineage walks, dependency reports) iterate `k²` cells
/// instead of `n²`.
///
/// On a hot path this lets cache invalidation skip every non-impacted
/// row outright when computing per-impacted lineage details — `k` is
/// almost always far smaller than `n`.
#[must_use]
pub fn impact_subgraph(adj: &[u32], intervention_mask: &[u32], n: u32) -> (Vec<u32>, Vec<u32>) {
    use crate::observability::{bump, do_calculus_change_impact_calls};
    bump(&do_calculus_change_impact_calls);
    if n == 0 {
        return (Vec::new(), Vec::new());
    }
    let mut scratch = DoCalculusImpactScratch::default();
    impact_subgraph_with_scratch(adj, intervention_mask, n, &mut scratch);
    (scratch.reduced_adjacency, scratch.kept_indices)
}

/// Compute impacted subgraph using named reusable scratch.
pub fn impact_subgraph_with_scratch(
    adj: &[u32],
    intervention_mask: &[u32],
    n: u32,
    scratch: &mut DoCalculusImpactScratch,
) {
    predict_impact_with_scratch(adj, intervention_mask, n, scratch);
    do_rule3_subgraph_cpu_into(
        adj,
        &scratch.impact_mask,
        n,
        &mut scratch.reduced_adjacency,
        &mut scratch.kept_indices,
    );
}

/// Predict impact under the **observation** semantics rather than
/// the **intervention** semantics.
///
/// Pearl's Rule 2 (action / observation exchange) says that for a
/// node X, we can replace `do(X)` with an observation `X` after
/// reversing the edges incoming to X. The two yield the same
/// downstream-impact set on a DAG; on a graph with feedback edges
/// into the observed node they differ — the rule-2 form lets a
/// caller answer "if we OBSERVED rule X had changed (rather than
/// explicitly invalidating it), what does the dependency graph
/// predict?". Cache-invalidation telemetry uses this to model
/// "passive change detection" against "active invalidation".
///
/// Returns a 0/1 mask over the n nodes; bit `j` set means the
/// graph's reversed-edge reachability from the observed set
/// reaches `j`.
#[must_use]
pub fn predict_impact_observation_form(adj: &[u32], observation_mask: &[u32], n: u32) -> Vec<u32> {
    use crate::observability::{bump, do_calculus_change_impact_calls};
    bump(&do_calculus_change_impact_calls);
    if n == 0 {
        return Vec::new();
    }
    let mut scratch = DoCalculusImpactScratch::default();
    predict_impact_observation_form_with_scratch(adj, observation_mask, n, &mut scratch);
    scratch.impact_mask
}

/// Predict observation-form impact using named reusable scratch.
pub fn predict_impact_observation_form_with_scratch(
    adj: &[u32],
    observation_mask: &[u32],
    n: u32,
    scratch: &mut DoCalculusImpactScratch,
) {
    predict_impact_observation_form_into(
        adj,
        observation_mask,
        n,
        &mut scratch.surgically_modified_adj,
        &mut scratch.closure,
        &mut scratch.scratch,
        &mut scratch.impact_mask,
    );
}

/// Predict observation-form impact while reusing caller-owned matrix scratch.
pub fn predict_impact_observation_form_into(
    adj: &[u32],
    observation_mask: &[u32],
    n: u32,
    reversed_adj: &mut Vec<u32>,
    closure: &mut Vec<u32>,
    scratch: &mut Vec<u32>,
    impact_mask: &mut Vec<u32>,
) {
    if n == 0 {
        impact_mask.clear();
        return;
    }
    let n_us = n as usize;
    do_rule2_reverse_incoming_cpu_into(adj, observation_mask, n, reversed_adj);
    reachability_closure_into(reversed_adj, n, n, closure, scratch);
    impact_mask.clear();
    impact_mask.resize(n_us, 0);
    for i in 0..n_us {
        if observation_mask[i] != 0 {
            impact_mask[i] = 1;
            for j in 0..n_us {
                if closure[i * n_us + j] != 0 {
                    impact_mask[j] = 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_impact() {
        // 0 -> 1 -> 2
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        // Change node 0
        let mask = vec![1, 0, 0];
        let impact = predict_impact(&adj, &mask, 3);
        // All impacted
        assert_eq!(impact, vec![1, 1, 1]);
    }

    #[test]
    fn impact_scratch_reuses_matrix_buffers() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mask = vec![1, 0, 0];
        let mut scratch = DoCalculusImpactScratch::default();
        predict_impact_with_scratch(&adj, &mask, 3, &mut scratch);
        let modified_capacity = scratch.surgically_modified_adj.capacity();
        let closure_capacity = scratch.closure.capacity();
        let temp_capacity = scratch.scratch.capacity();
        let mask_capacity = scratch.impact_mask.capacity();
        assert_eq!(scratch.impact_mask(), &[1, 1, 1]);

        predict_impact_with_scratch(&adj, &[0, 1, 0], 3, &mut scratch);
        assert_eq!(
            scratch.surgically_modified_adj.capacity(),
            modified_capacity
        );
        assert_eq!(scratch.closure.capacity(), closure_capacity);
        assert_eq!(scratch.scratch.capacity(), temp_capacity);
        assert_eq!(scratch.impact_mask.capacity(), mask_capacity);
        assert_eq!(scratch.impact_mask(), &[0, 1, 1]);
    }

    #[test]
    fn middle_chain_impact() {
        // 0 -> 1 -> 2
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        // Change node 1
        let mask = vec![0, 1, 0];
        let impact = predict_impact(&adj, &mask, 3);
        // 1 and 2 impacted, 0 not impacted
        assert_eq!(impact, vec![0, 1, 1]);
    }

    #[test]
    fn branched_impact() {
        // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let adj = vec![0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0];
        // Change node 2
        let mask = vec![0, 0, 1, 0];
        let impact = predict_impact(&adj, &mask, 4);
        // 2 and 3 impacted
        assert_eq!(impact, vec![0, 0, 1, 1]);
    }

    #[test]
    fn disjoint_impact() {
        // 0 -> 1, 2 -> 3
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        // Change node 0
        let mask = vec![1, 0, 0, 0];
        let impact = predict_impact(&adj, &mask, 4);
        // 0 and 1 impacted
        assert_eq!(impact, vec![1, 1, 0, 0]);
    }

    #[test]
    fn cycle_impact() {
        // 0 -> 1, 1 -> 0, 1 -> 2
        let adj = vec![0, 1, 0, 1, 0, 1, 0, 0, 0];
        // Change node 0.
        // do(0) removes 1 -> 0.
        // 0 -> 1 -> 2 remains.
        let mask = vec![1, 0, 0];
        let impact = predict_impact(&adj, &mask, 3);
        // All impacted
        assert_eq!(impact, vec![1, 1, 1]);
    }

    #[test]
    fn empty_graph() {
        let impact = predict_impact(&[], &[], 0);
        assert!(impact.is_empty());
    }

    // ---- impact_subgraph (Rule 3 consumer) ----

    #[test]
    fn impact_subgraph_chain_extracts_downstream() {
        // 0 -> 1 -> 2. Intervene 0: impact = {0,1,2}, subgraph = full.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mask = vec![1, 0, 0];
        let (reduced, kept) = impact_subgraph(&adj, &mask, 3);
        assert_eq!(kept, vec![0, 1, 2]);
        assert_eq!(reduced, adj);
    }

    #[test]
    fn impact_subgraph_branch_compresses_unimpacted_rows() {
        // 0 -> 1, 2 -> 3 (disjoint). Intervene 0: impact = {0,1};
        // reduced is 2×2, kept = [0, 1].
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let mask = vec![1, 0, 0, 0];
        let (reduced, kept) = impact_subgraph(&adj, &mask, 4);
        assert_eq!(kept, vec![0, 1]);
        // Edge 0->1 preserved, 2x2 layout.
        assert_eq!(reduced, vec![0, 1, 0, 0]);
    }

    #[test]
    fn impact_subgraph_scratch_reuses_reduction_buffers() {
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let mut scratch = DoCalculusImpactScratch::default();
        impact_subgraph_with_scratch(&adj, &[1, 0, 0, 0], 4, &mut scratch);
        let reduced_capacity = scratch.reduced_adjacency.capacity();
        let kept_capacity = scratch.kept_indices.capacity();
        assert_eq!(scratch.kept_indices(), &[0, 1]);
        assert_eq!(scratch.reduced_adjacency(), &[0, 1, 0, 0]);

        impact_subgraph_with_scratch(&adj, &[0, 0, 1, 0], 4, &mut scratch);
        assert_eq!(scratch.reduced_adjacency.capacity(), reduced_capacity);
        assert_eq!(scratch.kept_indices.capacity(), kept_capacity);
        assert_eq!(scratch.kept_indices(), &[2, 3]);
        assert_eq!(scratch.reduced_adjacency(), &[0, 1, 0, 0]);
    }

    #[test]
    fn impact_subgraph_empty_intervention_empty_subgraph() {
        let adj = vec![0, 1, 0, 0];
        let mask = vec![0, 0];
        let (reduced, kept) = impact_subgraph(&adj, &mask, 2);
        assert!(reduced.is_empty());
        assert!(kept.is_empty());
    }

    #[test]
    fn impact_subgraph_empty_graph() {
        let (r, k) = impact_subgraph(&[], &[], 0);
        assert!(r.is_empty());
        assert!(k.is_empty());
    }

    /// Closure-bar test: the reduced adjacency must have **exactly**
    /// `kept.len()²` cells AND every cell must equal the original
    /// adjacency restricted to the corresponding kept-index pair. If
    /// the consumer ever drifts (off-by-one indexing into the kept
    /// vector, mis-sized output buffer, etc.) this test fires.
    #[test]
    fn impact_subgraph_size_invariant_holds_under_partial_impact() {
        // 0 -> 1 -> 2, plus disjoint 3 -> 4. Intervene 1.
        // Impact = {1, 2}; subgraph keeps those two with edge 1->2.
        let adj = vec![
            0, 1, 0, 0, 0, // 0 -> 1
            0, 0, 1, 0, 0, // 1 -> 2
            0, 0, 0, 0, 0, // 2
            0, 0, 0, 0, 1, // 3 -> 4
            0, 0, 0, 0, 0, // 4
        ];
        let mask = vec![0, 1, 0, 0, 0];
        let (reduced, kept) = impact_subgraph(&adj, &mask, 5);
        // Exact size invariant.
        assert_eq!(reduced.len(), kept.len() * kept.len());
        assert_eq!(kept, vec![1, 2]);
        // Edge 1->2 preserved at (0,1) in the reduced 2×2.
        assert_eq!(reduced, vec![0, 1, 0, 0]);
    }

    /// Adversarial: intervention on a leaf must not pull in upstream
    /// nodes. `do(leaf)` only impacts leaf itself; if the consumer
    /// accidentally also kept ancestors, the kept vec would grow.
    #[test]
    fn impact_subgraph_adversarial_leaf_intervention_keeps_only_leaf() {
        // 0 -> 1 -> 2. Intervene 2 (leaf).
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mask = vec![0, 0, 1];
        let (reduced, kept) = impact_subgraph(&adj, &mask, 3);
        assert_eq!(kept, vec![2]);
        // 1×1, value = adj[2,2] = 0.
        assert_eq!(reduced, vec![0]);
    }

    /// Adversarial: every edge between kept nodes must survive in
    /// the reduced adjacency, and no edge to a dropped node may
    /// appear. A common bug is to copy the edge weight from the
    /// wrong (i, j) cell of the original — a permutation error.
    #[test]
    fn impact_subgraph_adversarial_dense_must_drop_unkept_edges() {
        // K3 over {0,1,2} plus isolated 3.
        let adj = vec![
            0, 1, 1, 0, // 0 -> 1, 0 -> 2
            1, 0, 1, 0, // 1 -> 0, 1 -> 2
            1, 1, 0, 0, // 2 -> 0, 2 -> 1
            0, 0, 0, 0, // 3 isolated
        ];
        // Intervene 0: rule-1 impact closure walks 0 -> 1 -> 2.
        let mask = vec![1, 0, 0, 0];
        let (reduced, kept) = impact_subgraph(&adj, &mask, 4);
        assert_eq!(kept, vec![0, 1, 2]);
        // Reduced is the original 3×3 corner. Every original edge
        // among {0,1,2} preserved; no row/col for 3.
        assert_eq!(
            reduced,
            vec![
                0, 1, 1, // 0 -> 1, 0 -> 2
                1, 0, 1, // 1 -> 0, 1 -> 2
                1, 1, 0, // 2 -> 0, 2 -> 1
            ]
        );
    }

    // ---- predict_impact_observation_form (Rule 2 consumer) ----

    /// On a DAG, observation-form impact equals intervention-form
    /// impact at the observed node itself (no feedback edges to
    /// reverse).
    #[test]
    fn observation_form_dag_observed_self_only() {
        // 0 -> 1 -> 2 (no incoming edges into observed node 0).
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mask = vec![1, 0, 0];
        let observed = predict_impact_observation_form(&adj, &mask, 3);
        let intervened = predict_impact(&adj, &mask, 3);
        // On this DAG, observing 0 = intervening on 0.
        assert_eq!(observed, intervened);
    }

    #[test]
    fn observation_form_scratch_reuses_buffers() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mut scratch = DoCalculusImpactScratch::default();
        predict_impact_observation_form_with_scratch(&adj, &[1, 0, 0], 3, &mut scratch);
        let reversed_capacity = scratch.surgically_modified_adj.capacity();
        let closure_capacity = scratch.closure.capacity();
        assert_eq!(scratch.impact_mask(), &[1, 1, 1]);

        predict_impact_observation_form_with_scratch(&adj, &[0, 1, 0], 3, &mut scratch);
        assert_eq!(
            scratch.surgically_modified_adj.capacity(),
            reversed_capacity
        );
        assert_eq!(scratch.closure.capacity(), closure_capacity);
        assert_eq!(scratch.impact_mask(), &[1, 1, 1]);
    }

    /// Closure-bar: observation-form must include the observed node
    /// itself as impact.
    #[test]
    fn observation_form_marks_observed_node() {
        let adj = vec![0, 1, 0, 0];
        let mask = vec![0, 1];
        let impact = predict_impact_observation_form(&adj, &mask, 2);
        assert_eq!(impact[1], 1, "observed node must be in impact set");
    }

    /// Adversarial: feedback loop into observed node. Rule-2 reverses
    /// the loop edge, so observation-form sees the loop's source as
    /// reachable along the reversed edge.
    #[test]
    fn observation_form_walks_reversed_feedback_edge() {
        // 0 -> 1, 1 -> 0 (mutual feedback), 1 -> 2.
        // Observe 0. Rule-2 reverses 1 -> 0 to 0 -> 1 (already exists,
        // OR-merged); it does NOT reverse 0 -> 1 (target is 0 only).
        // Reachable from 0 in modified graph: 0, 1, 2.
        let adj = vec![0, 1, 0, 1, 0, 1, 0, 0, 0];
        let mask = vec![1, 0, 0];
        let impact = predict_impact_observation_form(&adj, &mask, 3);
        assert_eq!(impact, vec![1, 1, 1]);
    }

    /// Adversarial: empty observation yields empty impact.
    #[test]
    fn observation_form_empty_mask_yields_empty() {
        let adj = vec![0, 1, 0, 0];
        let mask = vec![0, 0];
        let impact = predict_impact_observation_form(&adj, &mask, 2);
        assert_eq!(impact, vec![0, 0]);
    }

    /// Adversarial: empty graph returns empty result.
    #[test]
    fn observation_form_empty_graph() {
        assert!(predict_impact_observation_form(&[], &[], 0).is_empty());
    }
}
