//! `arg_of` — reverse-traverse along `CALL_ARG` edges.
//!
//! Frontier = callers. Emits the NodeSet of the argument-expression
//! predecessors. Uses [`crate::graph::csr_backward_traverse`].

use vyre_foundation::ir::Program;

use crate::graph::csr_backward_traverse::csr_backward_traverse;
use crate::graph::program_graph::ProgramGraphShape;
use crate::predicate::edge_kind;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::arg_of";

/// Build a Program.
#[must_use]
pub fn arg_of(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_backward_traverse(shape, frontier_in, frontier_out, edge_kind::CALL_ARG)
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
) -> Vec<u32> {
    crate::graph::csr_backward_traverse::cpu_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        edge_kind::CALL_ARG,
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || arg_of(ProgramGraphShape::new(4, 2), "fin", "fout"),
        Some(|| {
            use super::inventory_u32_le_bytes as b;
            vec![vec![
                b(&[2, 1, 1, 1]),       // pg_nodes
                b(&[0, 1, 2, 2, 2]),    // pg_edge_offsets
                b(&[1, 2]),              // pg_edge_targets
                b(&[2, 2]),              // pg_edge_kind_mask (CALL_ARG)
                b(&[0, 0, 0, 0]),       // pg_node_tags
                b(&[0b0010]),            // frontier_in = {1}
                b(&[0]),                 // frontier_out
            ]]
        }),
        Some(|| {
            use super::inventory_u32_le_bytes as b;
            vec![vec![b(&[0b0001])]]   // {0} is predecessor via CALL_ARG
        }),
    )
}
