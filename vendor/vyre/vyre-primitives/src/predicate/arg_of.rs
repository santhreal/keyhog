//! `arg_of` — reverse-traverse along `CALL_ARG` edges.
//!
//! Frontier = callers. Emits the NodeSet of the argument-expression
//! predecessors. Uses [`crate::graph::csr_backward_traverse`].
//!
//! Slot-precise variants restrict the traversal to a single argument
//! slot via the per-slot CALL_ARG_N edge subkind the walker stamps.
//! `arg_of_unspecified` (legacy alias) returns every CALL_ARG
//! predecessor regardless of position — recall-safe but
//! precision-loose.

use vyre_foundation::ir::Program;

use crate::graph::csr_backward_traverse::csr_backward_traverse;
use crate::graph::program_graph::ProgramGraphShape;
use crate::predicate::edge_kind;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::arg_of";

/// Build a Program traversing CALL_ARG edges restricted to argument
/// slot `slot`. Slot 0 catches the first arg, slot 1 the second, etc.
/// Beyond `edge_kind::CALL_ARG_MAX_SLOT` (7) the mask falls back to
/// the generic CALL_ARG bit — recall-safe but precision-loose; widen
/// the substrate to u64 edge_kind_mask before relying on slot N>7.
#[must_use]
pub fn arg_of_slot(
    shape: ProgramGraphShape,
    frontier_in: &str,
    frontier_out: &str,
    slot: u32,
) -> Program {
    csr_backward_traverse(
        shape,
        frontier_in,
        frontier_out,
        edge_kind::call_arg_slot(slot),
    )
}

/// Build a Program traversing every CALL_ARG edge regardless of
/// argument position. Recall-safe over-approximation; only use when
/// the slot is genuinely unknown.
#[must_use]
pub fn arg_of(shape: ProgramGraphShape, frontier_in: &str, frontier_out: &str) -> Program {
    csr_backward_traverse(shape, frontier_in, frontier_out, edge_kind::CALL_ARG)
}

/// CPU reference for the legacy unspecified-slot form.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
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

/// Slot-precise CPU reference. Mirrors `arg_of_slot`'s GPU semantics.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_slot(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    slot: u32,
) -> Vec<u32> {
    crate::graph::csr_backward_traverse::cpu_ref(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        edge_kind::call_arg_slot(slot),
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
