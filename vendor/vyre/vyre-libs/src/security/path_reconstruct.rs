//! `path_reconstruct` — Tier-3 shim over
//! [`vyre_primitives::graph::path_reconstruct`].

use vyre::ir::Program;
use vyre_primitives::graph::path_reconstruct::path_reconstruct as primitive_path_reconstruct;

const OP_ID: &str = "vyre-libs::security::path_reconstruct";

/// Signature retained for ABI compatibility.
#[must_use]
pub fn path_reconstruct(
    parent: &str,
    target: &str,
    path_out: &str,
    path_len: &str,
    max_depth: u32,
) -> Program {
    primitive_path_reconstruct(parent, target, path_out, path_len, max_depth)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || path_reconstruct("parent", "target", "path_out", "path_len", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0, 0, 1, 2]),
                to_bytes(&[3]),
                to_bytes(&[0, 0, 0, 0]),
                to_bytes(&[0]),
            ]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[3, 2, 1, 0]), to_bytes(&[4])]]
        }),
    }
}
