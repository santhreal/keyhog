//! Region-graph motif-matching substrate consumer.
//!
//! Wires `vyre_primitives::graph::motif` so the optimizer can
//! pattern-match small Region shapes (e.g. "load-store-store" or
//! "atomic-then-barrier") for lint/audit/rewrite passes. Same
//! primitive downstream analyzer ships to user dialects, now consumed by vyre's own
//! IR walker.

use vyre_primitives::graph::motif::{
    count_witness_participants, motif as primitive_motif, validate_motif_inputs, MotifEdge,
};
#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::motif::{
    cpu_ref as reference_motif, cpu_ref_matches as reference_motif_matches,
    cpu_ref_participation_count as reference_motif_participation_count,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, u32_word_bytes, write_u32_slice_le_bytes,
    write_u32_slice_or_zero_words, write_zero_bytes,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned GPU dispatch scratch for motif matching.
#[derive(Debug, Default)]
pub struct MotifGpuScratch {
    nodes: Vec<u32>,
    node_tags: Vec<u32>,
    inputs: Vec<Vec<u8>>,
    motif_hits: Vec<u32>,
}

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
#[cfg(any(test, feature = "cpu-parity"))]
pub fn match_motif(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reference_motif(
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
#[cfg(any(test, feature = "cpu-parity"))]
pub fn motif_matches(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> bool {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reference_motif_matches(edge_offsets, edge_targets, edge_kind_mask, motif_edges)
        && reference_motif_participation_count(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            motif_edges,
        ) != 0
}

/// Count the number of distinct nodes participating in motif
/// matches over the graph. Useful as a dispatch-time signal: high
/// participation suggests the motif is endemic and worth a
/// dedicated rewrite pass.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn motif_participation_count(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> u32 {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reference_motif_participation_count(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )
}

/// Dispatcher-backed motif match.
///
/// # Errors
///
/// Propagates dispatch failures and rejects malformed CSR or
/// truncated readback.
pub fn match_motif_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Result<Vec<u32>, DispatchError> {
    let mut out = Vec::new();
    match_motif_via_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
        &mut out,
    )?;
    Ok(out)
}

/// Dispatcher-backed motif match into caller-owned storage.
pub fn match_motif_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
    witness_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = MotifGpuScratch::default();
    match_motif_via_with_scratch_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
        &mut scratch,
        witness_out,
    )
}

/// Dispatcher-backed motif match into caller-owned dispatch and output storage.
pub fn match_motif_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
    scratch: &mut MotifGpuScratch,
    witness_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_motif_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )
    .map_err(DispatchError::BadInputs)?;
    if layout.node_count == 0 {
        witness_out.clear();
        return Ok(());
    }
    scratch.nodes.clear();
    scratch.nodes.resize(layout.output_words, 0);
    scratch.node_tags.clear();
    scratch.node_tags.resize(layout.output_words, 0);

    let program = primitive_motif(
        ProgramGraphShape::new(layout.node_count, layout.edge_count.max(1)),
        motif_edges,
        "witness_out",
    );
    let output_bytes = u32_word_bytes(layout.output_words, "match_motif_via output")?;
    ensure_input_slots(&mut scratch.inputs, 7);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], &scratch.nodes);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], edge_offsets);
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[2],
        edge_targets,
        layout.edge_storage_words,
        "match_motif_via edge_targets",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[3],
        edge_kind_mask,
        layout.edge_storage_words,
        "match_motif_via edge_kind_mask",
    )?;
    write_u32_slice_le_bytes(&mut scratch.inputs[4], &scratch.node_tags);
    write_zero_bytes(&mut scratch.inputs[5], output_bytes);
    write_zero_bytes(&mut scratch.inputs[6], output_bytes);
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([1, 1, 1]))?;
    if outputs.len() != 2 {
        return Err(DispatchError::BackendError(format!(
            "Fix: match_motif_via expected exactly 2 output buffers (motif_hits, witness_out), got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        layout.output_words,
        "match_motif_via motif_hits",
        &mut scratch.motif_hits,
    )?;
    decode_u32_output_exact(
        &outputs[1],
        layout.output_words,
        "match_motif_via witness_out",
        witness_out,
    )
}

/// Dispatcher-backed motif existence predicate.
///
/// # Errors
///
/// Returns [`DispatchError`] when graph validation or backend execution fails.
pub fn motif_matches_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Result<bool, DispatchError> {
    Ok(match_motif_via(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )?
    .iter()
    .any(|&value| value != 0))
}

/// Dispatcher-backed motif participation count.
///
/// # Errors
///
/// Returns [`DispatchError`] when graph validation or backend execution fails.
pub fn motif_participation_count_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    motif_edges: &[MotifEdge],
) -> Result<u32, DispatchError> {
    let witness = match_motif_via(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        motif_edges,
    )?;
    count_witness_participants(&witness).map_err(DispatchError::BackendError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

    struct MotifDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for MotifDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([1, 1, 1]));
            if inputs.len() != 7 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: motif test dispatcher expected 7 inputs, got {}.",
                    inputs.len()
                )));
            }
            Ok(self.outputs.clone())
        }
    }

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
        let via_primitive = reference_motif(3, &eo, &et, &ek, &motif);
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
        assert!(
            !motif_matches(3, &eo, &et, &ek, &[]),
            "substrate existence predicate means at least one participating node"
        );
        assert_eq!(motif_participation_count(3, &eo, &et, &ek, &[]), 0);
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

    #[test]
    fn via_decodes_exact_witness_into_reused_buffer() {
        let dispatcher = MotifDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[1, 1, 1]),
                u32_slice_to_le_bytes(&[1, 0, 1]),
            ],
        };
        let (eo, et, ek) = triangle_csr();
        let motif = vec![MotifEdge {
            from: 0,
            kind_mask: 1,
            to: 1,
        }];
        let mut out = Vec::with_capacity(8);
        let ptr = out.as_ptr();
        match_motif_via_into(&dispatcher, 3, &eo, &et, &ek, &motif, &mut out)
            .expect("dispatch succeeds");
        assert_eq!(out, vec![1, 0, 1]);
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn via_with_scratch_reuses_dispatch_split_decode_and_output_storage() {
        let dispatcher = MotifDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[1, 1, 1]),
                u32_slice_to_le_bytes(&[1, 0, 1]),
            ],
        };
        let (eo, et, ek) = triangle_csr();
        let motif = vec![MotifEdge {
            from: 0,
            kind_mask: 1,
            to: 1,
        }];
        let mut scratch = MotifGpuScratch::default();
        let mut out = Vec::with_capacity(3);

        match_motif_via_with_scratch_into(
            &dispatcher,
            3,
            &eo,
            &et,
            &ek,
            &motif,
            &mut scratch,
            &mut out,
        )
        .expect("dispatch succeeds");

        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let nodes_capacity = scratch.nodes.capacity();
        let hits_capacity = scratch.motif_hits.capacity();
        let out_capacity = out.capacity();

        match_motif_via_with_scratch_into(
            &dispatcher,
            3,
            &eo,
            &et,
            &ek,
            &motif,
            &mut scratch,
            &mut out,
        )
        .expect("dispatch succeeds");

        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(scratch.nodes.capacity(), nodes_capacity);
        assert_eq!(scratch.motif_hits.capacity(), hits_capacity);
        assert_eq!(out.capacity(), out_capacity);
        assert_eq!(out, vec![1, 0, 1]);
    }

    #[test]
    fn via_rejects_extra_outputs() {
        let dispatcher = MotifDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[1, 1, 1]),
                u32_slice_to_le_bytes(&[1, 0, 1]),
                u32_slice_to_le_bytes(&[0, 0, 0]),
            ],
        };
        let (eo, et, ek) = triangle_csr();
        let err = match_motif_via(&dispatcher, 3, &eo, &et, &ek, &[])
            .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_rejects_trailing_witness_bytes() {
        let dispatcher = MotifDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[1, 1, 1]), vec![1, 0, 0, 0, 2]],
        };
        let (eo, et, ek) = triangle_csr();
        let err = match_motif_via(&dispatcher, 3, &eo, &et, &ek, &[])
            .expect_err("trailing witness bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_convenience_predicates_match_witness() {
        let dispatcher = MotifDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[1, 1, 1]),
                u32_slice_to_le_bytes(&[1, 0, 1]),
            ],
        };
        let (eo, et, ek) = triangle_csr();
        let motif = vec![MotifEdge {
            from: 0,
            kind_mask: 1,
            to: 1,
        }];
        assert!(
            motif_matches_via(&dispatcher, 3, &eo, &et, &ek, &motif).expect("dispatch succeeds")
        );
        assert_eq!(
            motif_participation_count_via(&dispatcher, 3, &eo, &et, &ek, &motif)
                .expect("dispatch succeeds"),
            2
        );
    }

    #[test]
    fn via_rejects_mismatched_edge_arrays() {
        let dispatcher = MotifDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[1, 1]),
                u32_slice_to_le_bytes(&[1, 0]),
            ],
        };
        let err = match_motif_via(&dispatcher, 2, &[0, 1, 1], &[1], &[], &[])
            .expect_err("mismatched edge arrays must be rejected");
        assert!(matches!(err, DispatchError::BadInputs(_)));
    }

    #[test]
    fn via_empty_graph_is_validated_by_primitive_and_does_not_dispatch() {
        struct NoDispatch;

        impl OptimizerDispatcher for NoDispatch {
            fn dispatch(
                &self,
                _program: &Program,
                _inputs: &[Vec<u8>],
                _grid_override: Option<[u32; 3]>,
            ) -> Result<Vec<Vec<u8>>, DispatchError> {
                panic!("empty motif graph must not dispatch");
            }
        }

        let mut out = vec![u32::MAX];
        match_motif_via_into(&NoDispatch, 0, &[0], &[], &[], &[], &mut out)
            .expect("canonical empty graph is valid");
        assert!(out.is_empty());
    }

    #[test]
    fn release_via_path_does_not_call_cpu_or_reference_helpers() {
        let source = include_str!("motif.rs");
        let start = source
            .find("pub fn match_motif_via")
            .expect("via path marker must exist");
        let end = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must exist");
        let release_path = &source[start..end];
        assert!(!release_path.contains("reference_motif"));
        assert!(!release_path.contains("reference_"));
        assert!(!release_path.contains("cpu_ref"));
    }
}
