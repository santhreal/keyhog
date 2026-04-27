//! Cat-C `popcount_u32` — count of set bits in each u32 lane.
//! CPU reference: `u32::count_ones` bit-exact.
//!
//! # Backend fallback
//!
//! `popcount_u32` lowers to the Naga `MathFunction::CountOneBits` intrinsic.
//! On backends that do not expose `countOneBits` (e.g. very old GLSL
//! targets), the lowering must emit a clear `BackendError::Unsupported`
//! rather than silently producing incorrect results.  There is no portable
//! software fallback at the vyre-intrinsics layer because the bit-exact
//! contract would require a multi-instruction sequence that differs per
//! target; callers needing universal portability should use a Category-A
//! composition over shifts and masks instead.

use vyre_foundation::ir::{Expr, Program};

use crate::hardware::{pack_u32, unary_u32_program};

/// Map `input[i] -> popcount(input[i])` into `out[i]`.
#[must_use]
pub fn popcount_u32(input: &str, out: &str, n: u32) -> Program {
    unary_u32_program(input, out, n, Expr::popcount)
}

fn cpu_ref(input: &[u32]) -> Vec<u8> {
    pack_u32(&input.iter().map(|v| v.count_ones()).collect::<Vec<_>>())
}

fn test_inputs() -> Vec<Vec<Vec<u8>>> {
    let input = vec![0u32, 1, 0xFFFF_FFFF, 0x1234_5678];
    let len = input.len() * 4;
    vec![vec![pack_u32(&input), vec![0u8; len]]]
}

fn expected_output() -> Vec<Vec<Vec<u8>>> {
    let input = vec![0u32, 1, 0xFFFF_FFFF, 0x1234_5678];
    vec![vec![cpu_ref(&input)]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-intrinsics::hardware::popcount_u32",
        build: || popcount_u32("input", "out", 4),
        test_inputs: Some(test_inputs),
        expected_output: Some(expected_output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{lcg_u32, run_program};

    fn assert_case(input: &[u32]) {
        let n = input.len() as u32;
        let program = popcount_u32("input", "out", n.max(1));
        let outputs = run_program(
            &program,
            vec![pack_u32(input), vec![0u8; (n.max(1) * 4) as usize]],
        );
        assert_eq!(outputs, vec![cpu_ref(input)]);
    }

    #[test]
    fn one_element() {
        assert_case(&[1]);
    }

    #[test]
    fn max_value() {
        assert_case(&[u32::MAX]);
    }

    #[test]
    fn random_sixty_four() {
        let input = lcg_u32(0xC0FF_EE11, 64);
        assert_case(&input);
    }
}
