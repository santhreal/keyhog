//! `return_value_of` — forward-traverse along `RETURN` edges.

use vyre_foundation::ir::Program;

use crate::graph::csr_forward_traverse::csr_forward_traverse;
use crate::graph::program_graph::ProgramGraphShape;
use crate::predicate::edge_kind;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::return_value_of";

/// Build a Program that emits the NodeSet of return-value bindings
/// reached from the caller frontier via `Return` edges.
#[must_use]
pub fn return_value_of(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_forward_traverse(shape, frontier_in, frontier_out, edge_kind::RETURN)
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
    crate::graph::csr_forward_traverse::cpu_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        edge_kind::RETURN,
    )
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || return_value_of(ProgramGraphShape::new(4, 1), "fin", "fout"),
        Some(|| {
            use super::inventory_u32_le_bytes as b;
            vec![vec![
                b(&[2, 1, 1, 1]),       // pg_nodes
                b(&[0, 1, 1, 1, 1]),    // pg_edge_offsets
                b(&[1]),                // pg_edge_targets
                b(&[4]),                // pg_edge_kind_mask (RETURN)
                b(&[0, 0, 0, 0]),       // pg_node_tags
                b(&[0b0001]),            // frontier_in = {0}
                b(&[0]),                 // frontier_out
            ]]
        }),
        Some(|| {
            use super::inventory_u32_le_bytes as b;
            vec![vec![b(&[0b0010])]]   // {1} reached via RETURN
        }),
    )
}
