//! `label_by_family` — Tier-3 shim over
//! [`vyre_primitives::label::resolve_family`].

use vyre::ir::Program;
use vyre_primitives::label::resolve_family::resolve_family;

const OP_ID: &str = "vyre-libs::security::label_by_family";

/// Resolve every node whose tag bitmap intersects `family_mask`.
#[must_use]
pub fn label_by_family(
    node_tags: &str,
    nodeset_out: &str,
    node_count: u32,
    family_mask: u32,
) -> Program {
    resolve_family(node_tags, nodeset_out, node_count, family_mask)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || label_by_family("node_tags", "out", 4, 0b0010),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0x01, 0x02, 0x06, 0x04]),
                to_bytes(&[0]),
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b0110])]]
        }),
    }
}
