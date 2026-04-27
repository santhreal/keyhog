//! `in_file` — `NodeSet = { v : node_tags[v] & TAG_FAMILY_FILE != 0 }`.

use vyre_foundation::ir::Program;

use crate::label::resolve_family::resolve_family;
use crate::predicate::tag_family;

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::predicate::in_file";

/// Build a Program.
#[must_use]
pub fn in_file(node_tags: &str, nodeset_out: &str, node_count: u32) -> Program {
    resolve_family(node_tags, nodeset_out, node_count, tag_family::FILE)
}

/// CPU reference.
#[must_use]
pub fn cpu_ref(node_tags: &[u32]) -> Vec<u32> {
    crate::label::resolve_family::cpu_ref(node_tags, tag_family::FILE)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || in_file("tags", "nodeset", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[2, 2, 0, 0]), // node_tags: FILE, FILE, _, _
                to_bytes(&[0]),          // nodeset_out
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0011])]] // nodes 0 and 1
        }),
    )
}
