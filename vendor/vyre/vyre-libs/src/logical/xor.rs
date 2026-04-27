use crate::builder::BuildOptions;
use crate::tensor_ref::TensorRef;
use vyre::ir::{Expr, Program};

const OP_ID: &str = "vyre-libs::logical::xor";

/// Bitwise XOR operation.
#[must_use]
pub fn xor(a: &str, b: &str, out: &str, size: u32) -> Program {
    crate::builder::build_elementwise_binary(
        OP_ID,
        TensorRef::u32_1d(a, size),
        TensorRef::u32_1d(b, size),
        TensorRef::u32_1d(out, size),
        BuildOptions::default(),
        Expr::bitxor,
    )
    .unwrap_or_else(|err| panic!("Fix: {OP_ID} build failed: {err}"))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || xor("a", "b", "out", 4),
        test_inputs: Some(|| {
            let a = [0xFF00_FF00u32, 0x00FF_00FF, 0xFFFF_FFFF, 0x0000_0000];
            let b = [0xF0F0_F0F0u32, 0x0F0F_0F0F, 0xFFFF_FFFF, 0x0000_0000];
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&a), to_bytes(&b), vec![0u8; 16]]]
        }),
        expected_output: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            // Elementwise a ^ b on the 4-lane fixture.
            vec![vec![to_bytes(&[0x0FF0_0FF0, 0x0FF0_0FF0, 0x0000_0000, 0x0000_0000])]]
        }),
    }
}
