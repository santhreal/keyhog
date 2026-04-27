//! `in_function` — `NodeSet = { v : node_tags[v] & TAG_FAMILY_FUNCTION != 0 }`.

use vyre_foundation::ir::Program;

use crate::label::resolve_family::resolve_family;
use crate::predicate::tag_family;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::in_function";

/// Build a Program that emits the NodeSet of function-tagged nodes.
#[must_use]
pub fn in_function(node_tags: &str, nodeset_out: &str, node_count: u32) -> Program {
    resolve_family(node_tags, nodeset_out, node_count, tag_family::FUNCTION)
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(node_tags: &[u32]) -> Vec<u32> {
    crate::label::resolve_family::cpu_ref(node_tags, tag_family::FUNCTION)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || in_function("tags", "nodeset", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[1, 0, 1, 0]), // node_tags: FUNCTION, _, FUNCTION, _
                to_bytes(&[0]),          // nodeset_out
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0101])]] // nodes 0 and 2
        }),
    )
}
