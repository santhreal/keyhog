//! `literal_of` — `NodeSet = { v : nodes[v] == Literal AND
//!                                  literal_values[v] == probe }`.
//!
//! The IR-level primitive filters by NodeKind only; surgec's
//! type-inference ensures `literal_of(probe)` is only lowered against
//! literal-typed frontiers. A runtime match on the literal value can
//! be composed by re-filtering with a dedicated literal-payload
//! comparison primitive in Tier 3.

use vyre_foundation::ir::Program;

use crate::predicate::node_kind;
use crate::predicate::node_kind_eq::node_kind_eq;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::literal_of";

/// Build a Program that emits every node whose kind is Literal.
#[must_use]
pub fn literal_of(nodes: &str, nodeset_out: &str, node_count: u32) -> Program {
    node_kind_eq(nodes, nodeset_out, node_count, node_kind::LITERAL)
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(nodes: &[u32]) -> Vec<u32> {
    crate::predicate::node_kind_eq::cpu_ref(nodes, node_kind::LITERAL)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || literal_of("nodes", "nodeset", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[1, 2, 1, 4]), // nodes: VARIABLE, CALL, VARIABLE, LITERAL
                to_bytes(&[0]),          // nodeset_out
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1000])]] // node 3 (LITERAL)
        }),
    )
}
