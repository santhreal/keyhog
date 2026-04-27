//! Cat-A `lzcnt_u32` — count leading zeros per u32 lane.
//!
//! Migration target per `docs/migration-vyre-ops-to-intrinsics.md`:
//! `Expr::clz` is an existing UnOp primitive; no dedicated Naga emitter
//! arm needed. Therefore the op lives in `vyre-libs`, not
//! `vyre-intrinsics`.
//!
//! CPU reference: `u32::leading_zeros` bit-exact.

use vyre::ir::{Expr, Program};

use crate::builder::{build_elementwise_unary, BuildOptions};
use crate::tensor_ref::TensorRef;

const OP_ID: &str = "vyre-libs::math::lzcnt_u32";

/// Map `input[i] -> input[i].leading_zeros()` into `out[i]`.
#[must_use]
pub fn lzcnt_u32(input: &str, out: &str, size: u32) -> Program {
    build_elementwise_unary(
        OP_ID,
        TensorRef::u32_1d(input, size),
        TensorRef::u32_1d(out, size),
        BuildOptions::default(),
        Expr::clz,
    )
    .unwrap_or_else(|err| panic!("Fix: {OP_ID} build failed: {err}"))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || lzcnt_u32("input", "out", 4),
        test_inputs: Some(|| {
            let input = [0u32, 1, 0x8000_0000, 0x00F0_0000];
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&input), vec![0u8; 16]]]
        }),
        expected_output: Some(|| {
            // u32::leading_zeros: 0 -> 32, 1 -> 31, 0x80000000 -> 0, 0x00F00000 -> 8.
            let expected = [32u32, 31, 0, 8];
            let bytes = expected
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![bytes]]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn run(input: &[u32]) -> Vec<u32> {
        let n = input.len() as u32;
        let program = lzcnt_u32("input", "out", n.max(1));
        let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
        let inputs = vec![
            Value::Bytes(to_bytes(input).into()),
            Value::Bytes(vec![0u8; (n.max(1) * 4) as usize].into()),
        ];
        let outputs =
            vyre_reference::reference_eval(&program, &inputs).expect("lzcnt_u32 must run");
        let raw = outputs[0].to_bytes();
        raw.chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    #[test]
    fn matches_rust_ref_on_small_samples() {
        let input = [0u32, 1, 0x8000_0000, 0x00F0_0000];
        let got = run(&input);
        let expected: Vec<u32> = input.iter().map(|v| v.leading_zeros()).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn max_value() {
        let input = [u32::MAX];
        let got = run(&input);
        assert_eq!(got, vec![0]);
    }
}
