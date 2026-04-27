//! FNV-1a 32-bit non-cryptographic hash.
//!
//! Category A composition — the kernel body is
//! [`vyre_primitives::hash::fnv1a::fnv1a32_program_dyn`]; the Tier-3
//! wrapper stamps the `vyre-libs::hash::fnv1a32` op id, carries the
//! `OpEntry` fixtures, and exposes the universal `(input, out)`
//! signature the harness uses.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::hash::fnv1a::{fnv1a32_program_dyn, FNV1A32_OP_ID};

#[cfg(test)]
use crate::buffer_names::fixed_name;
use crate::buffer_names::scoped_generic_name;

const OP_ID: &str = "vyre-libs::hash::fnv1a32";
const FAMILY_PREFIX: &str = "hash_fnv1a32";

fn scoped_input_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "input", name, &["input"])
}

fn scoped_output_buffer(name: &str) -> String {
    scoped_generic_name(FAMILY_PREFIX, "out", name, &["out", "output"])
}

/// Build a Program that computes FNV-1a 32-bit over `input` bytes,
/// writing the result to `out[0]`.
///
/// `input` is a u32 buffer with one byte per slot (upper 24 bits zero).
/// `out` is a single-slot u32 buffer.
#[must_use]
pub fn fnv1a32(input: &str, out: &str) -> Program {
    let input = scoped_input_buffer(input);
    let out = scoped_output_buffer(out);
    let primitive = fnv1a32_program_dyn(&input, &out);
    let parent = GeneratorRef {
        name: OP_ID.to_string(),
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(&input, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output(&out, 1, DataType::U32).with_count(1),
        ],
        primitive.workgroup_size(),
        vec![crate::region::wrap_anonymous(
            OP_ID,
            vec![crate::region::wrap_child(
                FNV1A32_OP_ID,
                parent,
                primitive.entry().to_vec(),
            )],
        )],
    )
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || fnv1a32("input", "out"),
        test_inputs: Some(|| vec![vec![
            vec![0x61, 0, 0, 0, 0x62, 0, 0, 0, 0x63, 0, 0, 0],
            vec![0, 0, 0, 0],
        ]]),
        expected_output: Some(|| vec![{
            let hash = 0x1a47_e90bu32;
            vec![hash.to_le_bytes().to_vec()]
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_default_names_are_family_scoped() {
        let program = fnv1a32("input", "out");
        assert_eq!(
            program.buffers()[0].name(),
            fixed_name(FAMILY_PREFIX, "input")
        );
        assert_eq!(
            program.buffers()[1].name(),
            fixed_name(FAMILY_PREFIX, "out")
        );
    }
}
