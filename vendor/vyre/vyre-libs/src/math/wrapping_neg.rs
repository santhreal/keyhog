use crate::builder::BuildOptions;
use crate::tensor_ref::TensorRef;
use vyre::ir::{DataType, Expr, Program};

const OP_ID: &str = "vyre-libs::math::wrapping_neg";

/// Computes wrapping negation.
#[must_use]
pub fn wrapping_neg(a: &str, out: &str, size: u32) -> Program {
    crate::builder::build_elementwise_unary(
        OP_ID,
        TensorRef::u32_1d(a, size),
        TensorRef::u32_1d(out, size),
        BuildOptions::default(),
        |lx| Expr::sub(Expr::u32(0), lx),
    )
    .unwrap_or_else(|err| {
        crate::builder::invalid_output_program(OP_ID, out, DataType::U32, format!("Fix: {err}"))
    })
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || wrapping_neg("a", "out", 4),
        test_inputs: Some(|| {
            let a = [0u32, 1, u32::MAX, 42];
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&a)]]
        }),
        expected_output: Some(|| {
            let expected = [
                0u32.wrapping_neg(),
                1u32.wrapping_neg(),
                u32::MAX.wrapping_neg(),
                42u32.wrapping_neg(),
            ];
            let bytes = expected
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
        category: Some("math"),
    }
}
