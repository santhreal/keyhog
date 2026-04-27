//! `taint_flow` — Tier-3 shim over the primitive traversal step,
//! restricted to dataflow edge kinds.

use vyre::ir::Program;
use vyre_primitives::graph::csr_forward_traverse::csr_forward_traverse;
use vyre_primitives::graph::program_graph::ProgramGraphShape;
use vyre_primitives::predicate::edge_kind;

use crate::security::flows_to::FLOWS_TO_MASK;

const OP_ID: &str = "vyre-libs::security::taint_flow";

/// Build one forward-traversal step over DATAFLOW edges only. The
/// stdlib rule composes this with `bitset_fixpoint` to reach the
/// full taint-flow matrix.
///
/// Pre-AUDIT_2026-04-24 this used `0xFFFF_FFFF` which let taint
/// cross CONTROL+DOMINANCE edges; zero-FP rules that consumed
/// taint_flow inherited that over-approximation and drowned in
/// false positives at internet scale. Restricted now to the same
/// dataflow-only mask as `flows_to`.
#[must_use]
pub fn taint_flow(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_forward_traverse(shape, frontier_in, frontier_out, FLOWS_TO_MASK)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || taint_flow(ProgramGraphShape::new(4, 3), "fin", "fout"),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Linear 0 → 1 → 2 → 3 along ASSIGNMENT edges. Starting
            // frontier {0}; `fout` starts as the accumulator.
            vec![vec![
                to_bytes(&[0, 0, 0, 0]),          // pg_nodes
                to_bytes(&[0, 1, 2, 3, 3]),       // pg_edge_offsets
                to_bytes(&[1, 2, 3]),             // pg_edge_targets
                to_bytes(&[
                    edge_kind::ASSIGNMENT,
                    edge_kind::ASSIGNMENT,
                    edge_kind::ASSIGNMENT,
                ]),                               // pg_edge_kind_mask — dataflow
                to_bytes(&[0, 0, 0, 0]),          // pg_node_tags
                to_bytes(&[0b0001]),              // fin = {0}
                to_bytes(&[0b0001]),              // fout accumulator seed = {0}
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // One forward step writes {1} into the accumulator.
            vec![vec![to_bytes(&[0b0011])]]
        }),
    }
}

inventory::submit! {
    // AUDIT_2026-04-24 F-TF-03: max_iterations matches flows_to at
    // 4096 so deep taint paths don't hit a silent 64-step truncation.
    crate::harness::ConvergenceContract {
        op_id: OP_ID,
        max_iterations: 4096,
    }
}
