//! Prefix-sum scan  -  inclusive scan over a u32 buffer.
//!
//! Category A composition backed by the Tier-2.5 workgroup scan
//! primitive for one-workgroup inputs.

use vyre::ir::Program;
use vyre_primitives::math::prefix_scan::{
    prefix_scan_large_with_op_id, prefix_scan_with_op_id, ScanKind,
};

const OP_ID: &str = "vyre-libs::math::scan_prefix_sum";

/// Build a Program that computes the inclusive prefix sum of `input`
/// into `output`, both sized `n`.
///
/// **Overflow semantics** (V7-CORR-018): all accumulator additions
/// use `u32::wrapping_add`. For inputs whose cumulative sum exceeds
/// `u32::MAX`, the output wraps modulo 2^32.
#[must_use]
pub fn scan_prefix_sum(input: &str, output: &str, n: u32) -> Program {
    if n == 0 {
        return crate::builder::invalid_output_program(
            OP_ID,
            output,
            vyre::ir::DataType::U32,
            "Fix: scan_prefix_sum requires n > 0.".to_string(),
        );
    }
    if (1..=1024).contains(&n) {
        prefix_scan_with_op_id(input, output, n, ScanKind::InclusiveSum, OP_ID)
    } else {
        prefix_scan_large_with_op_id(input, output, n, OP_ID)
    }
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || scan_prefix_sum("input", "output", 4),
        test_inputs: Some(|| vec![vec![
            vyre_primitives::wire::pack_u32_slice(&[1u32, 2, 3, 4]),
        ]]),
        expected_output: Some(|| vec![vec![
            // Only ReadWrite buffer: prefix sum [1, 3, 6, 10]
            vyre_primitives::wire::pack_u32_slice(&[1u32, 3, 6, 10]),
        ]]),
        category: Some("math"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::byte_pack::{bytes_to_u32 as decode_u32_words, u32_bytes};
    use vyre_reference::value::Value;

    fn run_scan(n: u32, input: &[u32]) -> Vec<u32> {
        let program = scan_prefix_sum("input", "output", n);
        let outputs = vyre_reference::reference_eval(
            &program,
            &[
                Value::from(u32_bytes(input)),
                Value::from(vec![0u8; (n as usize).saturating_mul(4)]),
            ],
        )
        .expect("Fix: prefix sum must execute");
        decode_u32_words(&outputs[0].to_bytes())
    }

    #[test]
    fn prefix_sum_single_element() {
        let input = [42u32];
        let actual = run_scan(1, &input);
        assert_eq!(actual, vec![42u32]);
    }

    #[test]
    fn prefix_sum_empty_n_zero_should_trap() {
        let program = scan_prefix_sum("input", "output", 0);
        let error = vyre_reference::reference_eval(
            &program,
            &[Value::from(vec![0u8; 0]), Value::from(vec![0u8; 0])],
        )
        .expect_err("n=0 prefix_sum must trap instead of returning empty");
        let msg = error.to_string();
        assert!(
            msg.contains("trap") || msg.contains("Fix:"),
            "n=0 prefix_sum error must be actionable: {msg}"
        );
    }

    #[test]
    fn prefix_sum_boundary_small_path() {
        let input: Vec<u32> = (1..=1024).collect();
        let actual = run_scan(1024, &input);
        let expected: Vec<u32> = input
            .iter()
            .scan(0u32, |acc, &x| {
                *acc = acc.wrapping_add(x);
                Some(*acc)
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn prefix_sum_boundary_large_path() {
        let input: Vec<u32> = (1..=1025).collect();
        let actual = run_scan(1025, &input);
        let expected: Vec<u32> = input
            .iter()
            .scan(0u32, |acc, &x| {
                *acc = acc.wrapping_add(x);
                Some(*acc)
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn prefix_sum_overflow_wraps() {
        let input = [u32::MAX, 1u32, 1u32];
        let actual = run_scan(3, &input);
        assert_eq!(actual[0], u32::MAX);
        assert_eq!(actual[1], 0u32, "u32::MAX + 1 must wrap to 0");
        assert_eq!(actual[2], 1u32, "0 + 1 must be 1");
    }
}
