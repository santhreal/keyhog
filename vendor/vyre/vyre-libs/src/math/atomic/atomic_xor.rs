//! Cat-B `atomic_xor_u32`. CPU ref: sequential bitwise XOR.

use vyre::ir::{AtomicOp, Program};

use super::build_atomic_serial;

const OP_ID: &str = "vyre-libs::math::atomic::atomic_xor_u32";

/// Sequential atomic-XOR over `values[0..n]` into one-slot `state`.
#[must_use]
pub fn atomic_xor_u32(values: &str, state: &str, trace: &str, n: u32) -> Program {
    build_atomic_serial(OP_ID, AtomicOp::Xor, values, state, trace, n)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || atomic_xor_u32("values", "state", "trace", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0xF0u32, 0x0F, 0xFF, 0x55]),
                to_bytes(&[0u32]),
                vec![0u8; 16],
            ]]
        }),
        expected_output: Some(|| {
            // Serial ^= starting at 0:
            //   0 ^ 0xF0 = 0xF0, 0xF0 ^ 0x0F = 0xFF,
            //   0xFF ^ 0xFF = 0x00, 0x00 ^ 0x55 = 0x55
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0x55u32]),
                to_bytes(&[0u32, 0xF0, 0xFF, 0x00]),
            ]]
        }),
    }
}

register_atomic_serial_op!(OP_ID, || atomic_xor_u32("values", "state", "trace", 4));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::atomic::testutil::run_serial;

    #[test]
    fn matches_bitwise_xor() {
        let values = vec![0xF0u32, 0x0F, 0xFF, 0x55];
        let initial = 0u32;
        let program = atomic_xor_u32("values", "state", "trace", values.len() as u32);
        let (final_state, trace) = run_serial(&program, &values, initial);

        let mut cpu_state = initial;
        let mut cpu_trace = Vec::new();
        for &v in &values {
            cpu_trace.push(cpu_state);
            cpu_state ^= v;
        }

        assert_eq!(final_state, cpu_state);
        assert_eq!(trace, cpu_trace);
    }
}
