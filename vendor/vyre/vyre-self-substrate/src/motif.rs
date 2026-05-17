//! Region-graph motif-matching substrate consumer.
//!
//! Wires `vyre_primitives::graph::motif::cpu_ref` (zero substrate
//! consumers prior) so the optimizer can pattern-match small Region
//! shapes (e.g. "load-store-store" or "atomic-then-barrier") for
//! lint/audit/rewrite passes. Same primitive surgec ships to user
//! dialects, now consumed by vyre's own IR walker.

use vyre_primitives::graph::motif::{cpu_ref as motif_cpu, MotifEdge};

/// Match a motif (small directed pattern) against a CSR-encoded
/// Region-graph and return the per-node participation byte-vector
/// (1 = node participates in a full motif match, 0 otherwise).
///
/// `node_count` is the number of Regions; `edge_offsets`/`edge_targets`
/// are the CSR; `edge_kind_mask` carries per-edge kind bits parallel
/// to `edge_targets`. Bumps the dataflow-fixpoint substrate counter
/// (the closest existing counter for graph-walk primitives) so
/// dispatch dashboards register motif match traffic.
#[must_use]
pub fn match_motif(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    motif_cpu(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )
}

/// Convenience: returns true iff any node participates in a motif
/// match (i.e. the motif fully matched at least once on the graph).
#[must_use]
pub fn motif_matches(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> bool {
    match_motif(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )
    .iter()
    .any(|&v| v != 0)
}

/// Count the number of distinct nodes participating in motif
/// matches over the graph. Useful as a dispatch-time signal: high
/// participation suggests the motif is endemic and worth a
/// dedicated rewrite pass.
#[must_use]
pub fn motif_participation_count(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> u32 {
    match_motif(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )
    .iter()
    .filter(|&&v| v != 0)
    .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Triangle 0 -> 1 -> 2 -> 0 with edge kind 1 on every edge.
    /// Motif = same triangle.
    fn triangle_csr() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // Edge offsets: 0 -> [0..1], 1 -> [1..2], 2 -> [2..3].
        let edge_offsets = vec![0, 1, 2, 3];
        let edge_targets = vec![1, 2, 0];
        let edge_kind_mask = vec![1, 1, 1];
        (edge_offsets, edge_targets, edge_kind_mask)
    }

    #[test]
    fn matches_triangle() {
        let (eo, et, ek) = triangle_csr();
        let motif = vec![
            MotifEdge {
                from: 0,
                kind_mask: 1,
                to: 1,
            },
            MotifEdge {
                from: 1,
                kind_mask: 1,
                to: 2,
            },
            MotifEdge {
                from: 2,
                kind_mask: 1,
                to: 0,
            },
        ];
        let participants = match_motif(3, &eo, &et, &ek, &motif);
        assert_eq!(participants, vec![1, 1, 1]);
        assert!(motif_matches(3, &eo, &et, &ek, &motif));
        assert_eq!(motif_participation_count(3, &eo, &et, &ek, &motif), 3);
    }

    #[test]
    fn rejects_unmatched_motif() {
        let (eo, et, ek) = triangle_csr();
        // Demand a 0->2 edge that doesn't exist.
        let motif = vec![MotifEdge {
            from: 0,
            kind_mask: 1,
            to: 2,
        }];
        let participants = match_motif(3, &eo, &et, &ek, &motif);
        assert_eq!(participants, vec![0, 0, 0]);
        assert!(!motif_matches(3, &eo, &et, &ek, &motif));
    }

    /// Closure-bar: substrate path must equal the primitive call.
    #[test]
    fn matches_primitive_directly() {
        let (eo, et, ek) = triangle_csr();
        let motif = vec![
            MotifEdge {
                from: 0,
                kind_mask: 1,
                to: 1,
            },
            MotifEdge {
                from: 1,
                kind_mask: 1,
                to: 2,
            },
        ];
        let via_substrate = match_motif(3, &eo, &et, &ek, &motif);
        let via_primitive = motif_cpu(3, &eo, &et, &ek, &motif);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: kind_mask filtering. An edge that exists in the
    /// graph but with a kind bit not requested by the motif must
    /// NOT count as a match.
    #[test]
    fn kind_mask_filter_rejects_wrong_kind() {
        let edge_offsets = vec![0, 1, 1];
        let edge_targets = vec![1];
        let edge_kind_mask = vec![0b0010]; // kind bit 1 only
        let motif = vec![MotifEdge {
            from: 0,
            kind_mask: 0b0001, // demand kind bit 0
            to: 1,
        }];
        let participants = match_motif(2, &edge_offsets, &edge_targets, &edge_kind_mask, &motif);
        assert_eq!(participants, vec![0, 0]);
    }

    /// Adversarial: empty motif. Spec: empty motif "matches" trivially
    /// because matched_edges == motif_edges.len() == 0. Participation
    /// should be all-zero (no node participates in zero edges).
    #[test]
    fn empty_motif_yields_zero_participation() {
        let (eo, et, ek) = triangle_csr();
        let participants = match_motif(3, &eo, &et, &ek, &[]);
        assert_eq!(participants, vec![0, 0, 0]);
    }

    /// Partial match: motif requires two edges, only one exists
    /// in the graph. Must return all-zero (motif is atomic).
    #[test]
    fn partial_match_returns_all_zero() {
        let (eo, et, ek) = triangle_csr();
        let motif = vec![
            MotifEdge {
                from: 0,
                kind_mask: 1,
                to: 1,
            }, // exists
            MotifEdge {
                from: 0,
                kind_mask: 1,
                to: 2,
            }, // missing
        ];
        let participants = match_motif(3, &eo, &et, &ek, &motif);
        assert_eq!(participants, vec![0, 0, 0]);
    }
}
