use crate::builder::BuildOptions;
use crate::tensor_ref::TensorRef;
use vyre::ir::{Expr, Program};

const OP_ID: &str = "vyre-libs::math::avg_floor";

/// Computes average floor.
#[must_use]
pub fn avg_floor(a: &str, b: &str, out: &str, size: u32) -> Program {
    crate::builder::build_elementwise_binary(
        OP_ID,
        TensorRef::u32_1d(a, size),
        TensorRef::u32_1d(b, size),
        TensorRef::u32_1d(out, size),
        BuildOptions::default(),
        |lx, rx| {
            Expr::add(
                Expr::bitand(lx.clone(), rx.clone()),
                Expr::shr(Expr::bitxor(lx, rx), Expr::u32(1)),
            )
        },
    )
    .unwrap_or_else(|err| panic!("Fix: {OP_ID} build failed: {err}"))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || avg_floor("a", "b", "out", 4),
        test_inputs: Some(|| {
            let a = [10u32, u32::MAX, 7, 100];
            let b = [20u32, u32::MAX, 12, 0];
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&a), to_bytes(&b), vec![0u8; 16]]]
        }),
        expected_output: Some(|| {
            // HD-style floor((a+b)/2) that never overflows:
            //   (a & b) + ((a ^ b) >> 1). For the fixture
            //   (10,20)->15, (MAX,MAX)->MAX, (7,12)->9, (100,0)->50.
            let a = [10u32, u32::MAX, 7, 100];
            let b = [20u32, u32::MAX, 12, 0];
            let expected: Vec<u32> = a
                .iter()
                .zip(b.iter())
                .map(|(&x, &y)| (x & y).wrapping_add((x ^ y) >> 1))
                .collect();
            let bytes = expected
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
    }
}
