//! Cat-C `bit_reverse_u32` — reverse the bit order within each u32.
//! CPU reference: `u32::reverse_bits` bit-exact.

use vyre_foundation::ir::{Expr, Program};

use crate::hardware::{pack_u32, unary_u32_program};

/// Build a Program that computes `out[i] = input[i].reverse_bits()` over `n` u32 lanes.
#[must_use]
pub fn bit_reverse_u32(input: &str, out: &str, n: u32) -> Program {
    unary_u32_program(input, out, n, Expr::reverse_bits)
}

fn cpu_ref(input: &[u32]) -> Vec<u8> {
    pack_u32(&input.iter().map(|v| v.reverse_bits()).collect::<Vec<_>>())
}

fn test_inputs() -> Vec<Vec<Vec<u8>>> {
    let input = vec![0u32, 1, 0x8000_0000, 0x1234_5678];
    let len = input.len() * 4;
    vec![vec![pack_u32(&input), vec![0u8; len]]]
}

fn expected_output() -> Vec<Vec<Vec<u8>>> {
    let input = vec![0u32, 1, 0x8000_0000, 0x1234_5678];
    vec![vec![cpu_ref(&input)]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-intrinsics::hardware::bit_reverse_u32",
        build: || bit_reverse_u32("input", "out", 4),
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
        let program = bit_reverse_u32("input", "out", n.max(1));
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
        let input = lcg_u32(0x1EA0_7733, 64);
        assert_case(&input);
    }
}
