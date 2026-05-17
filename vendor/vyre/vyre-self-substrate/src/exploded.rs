//! Exploded-supergraph (IFDS encoding) substrate consumer.
//!
//! Wires `vyre_primitives::graph::exploded::build_cpu_reference` (zero
//! prior consumers) into the substrate so the optimizer can build
//! interprocedural-dataflow graphs directly. The IFDS encoding packs
//! `(proc_id, block_id, fact_id)` into a u32 node id, then composes
//! intra-/inter-procedural edges + GEN/KILL flow into a CSR ready for
//! reachability/closure analysis.

use vyre_primitives::graph::exploded::{build_cpu_reference, dense_to_encoded, encoded_to_dense};

/// Build an exploded supergraph and return its CSR `(row_ptr, col_idx)`.
/// Inputs match the underlying primitive's contract; the wrapper bumps
/// the dataflow-fixpoint observability counter so dispatch-time IFDS
/// graph builds are visible in dashboards.
#[must_use]
pub fn build_ifds_csr(
    num_procs: u32,
    blocks_per_proc: u32,
    facts_per_proc: u32,
    intra_edges: &[(u32, u32, u32)],
    inter_edges: &[(u32, u32, u32, u32)],
    flow_gen: &[(u32, u32, u32)],
    flow_kill: &[(u32, u32, u32)],
) -> (Vec<u32>, Vec<u32>) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    build_cpu_reference(
        num_procs,
        blocks_per_proc,
        facts_per_proc,
        intra_edges,
        inter_edges,
        flow_gen,
        flow_kill,
    )
}

/// Total node count of the exploded supergraph for the given
/// dimensions. Equivalent to `row_ptr.len() - 1` after the CSR is
/// built; useful when the caller needs to size frontier bitsets
/// before invoking [`build_ifds_csr`].
#[must_use]
pub fn ifds_node_count(num_procs: u32, blocks_per_proc: u32, facts_per_proc: u32) -> u32 {
    num_procs
        .saturating_mul(blocks_per_proc)
        .saturating_mul(facts_per_proc)
}

/// Helper: round-trip a dense index through the packed encoding and
/// back. Used by callers that emit findings keyed on the packed id
/// but operate on dense indices internally.
#[must_use]
pub fn round_trip_dense(dense: u32, blocks_per_proc: u32, facts_per_proc: u32) -> Option<u32> {
    let encoded = dense_to_encoded(dense, blocks_per_proc, facts_per_proc)?;
    encoded_to_dense(encoded, blocks_per_proc, facts_per_proc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two procs, 2 blocks each, 2 facts each. One intra edge per
    /// proc, no inter, no flow. The CSR row count must equal the
    /// total node count.
    #[test]
    fn csr_row_count_matches_node_count() {
        let (row_ptr, _) = build_ifds_csr(2, 2, 2, &[(0, 0, 1), (1, 0, 1)], &[], &[], &[]);
        // Total = 2 * 2 * 2 = 8.
        assert_eq!(row_ptr.len(), 9);
        assert_eq!(ifds_node_count(2, 2, 2), 8);
    }

    /// Closure-bar: substrate output equals primitive output.
    #[test]
    fn matches_primitive_directly() {
        let intra = vec![(0, 0, 1), (1, 0, 1)];
        let inter = vec![(0, 1, 1, 0)];
        let gen = vec![(0, 0, 1)];
        let kill = vec![(1, 0, 0)];
        let via_substrate = build_ifds_csr(2, 2, 2, &intra, &inter, &gen, &kill);
        let via_primitive = build_cpu_reference(2, 2, 2, &intra, &inter, &gen, &kill);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Empty graph (no procs) is degenerate; CSR is `(vec![0], vec![])`.
    /// Common bug: emit `vec![]` instead of `vec![0]` for row_ptr,
    /// breaking downstream CSR walkers that assume `row_ptr[0] = 0`.
    #[test]
    fn empty_graph_yields_singleton_row_ptr() {
        let (row_ptr, col_idx) = build_ifds_csr(0, 0, 0, &[], &[], &[], &[]);
        assert_eq!(row_ptr, vec![0u32]);
        assert!(col_idx.is_empty());
    }

    /// Adversarial: KILL must suppress fact propagation along an
    /// intra edge. (proc 0, block 0, fact 1) is killed → no edge
    /// emitted from (0, 0, 1) to (0, 1, 1).
    #[test]
    fn kill_suppresses_fact_propagation() {
        let intra = vec![(0, 0, 1)];
        let kill = vec![(0, 0, 1)];
        let (row_ptr, col_idx) = build_ifds_csr(1, 2, 2, &intra, &[], &[], &kill);
        // Node (0, 0, 1) is at dense index 0 * 4 + 0 * 2 + 1 = 1.
        let src = 1usize;
        let row_start = row_ptr[src] as usize;
        let row_end = row_ptr[src + 1] as usize;
        let neighbors = &col_idx[row_start..row_end];
        // Should have NO edge to (0, 1, 1) (= dense 0*4 + 1*2 + 1 = 3).
        assert!(!neighbors.contains(&3), "killed fact must not propagate");
    }

    /// Adversarial: GEN must inject the new fact along the intra
    /// edge. (proc 0, block 0, gen fact 1) → edge from (0, 0, 0)
    /// (the 0-fact) to (0, 1, 1).
    #[test]
    fn gen_injects_new_fact() {
        let intra = vec![(0, 0, 1)];
        let gen = vec![(0, 0, 1)];
        let (row_ptr, col_idx) = build_ifds_csr(1, 2, 2, &intra, &[], &gen, &[]);
        // 0-fact at (0, 0, 0) → dense index 0.
        let row_start = row_ptr[0] as usize;
        let row_end = row_ptr[1] as usize;
        let neighbors = &col_idx[row_start..row_end];
        // Edge to (0, 1, 1) → dense 3.
        assert!(neighbors.contains(&3), "gen must emit edge to new fact");
    }

    /// Round-trip dense ↔ encoded must be identity for valid indices.
    #[test]
    fn round_trip_dense_is_identity() {
        let blocks_per_proc = 4;
        let facts_per_proc = 8;
        for dense in 0..32 {
            assert_eq!(
                round_trip_dense(dense, blocks_per_proc, facts_per_proc),
                Some(dense)
            );
        }
    }

    /// Adversarial: inter-procedural edge propagates EVERY fact
    /// (IFDS upper bound). For 2 facts, expect 2 edges from
    /// (sp, sb, *) to (dp, db, *).
    #[test]
    fn inter_edge_propagates_every_fact() {
        let inter = vec![(0, 0, 1, 1)];
        let (row_ptr, col_idx) = build_ifds_csr(2, 2, 2, &[], &inter, &[], &[]);
        let dense_src_f0 = 0; // (0, 0, 0)
        let dense_src_f1 = 1; // (0, 0, 1)
        let row0 = &col_idx[row_ptr[dense_src_f0] as usize..row_ptr[dense_src_f0 + 1] as usize];
        let row1 = &col_idx[row_ptr[dense_src_f1] as usize..row_ptr[dense_src_f1 + 1] as usize];
        // (1, 1, 0) = 1*4 + 1*2 + 0 = 6
        // (1, 1, 1) = 1*4 + 1*2 + 1 = 7
        assert!(row0.contains(&6), "fact 0 must propagate via inter edge");
        assert!(row1.contains(&7), "fact 1 must propagate via inter edge");
    }
}
