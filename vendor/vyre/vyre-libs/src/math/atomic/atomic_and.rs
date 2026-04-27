//! Cat-B `atomic_and_u32`. CPU ref: sequential bitwise AND.

use vyre::ir::{AtomicOp, Program};

use super::build_atomic_serial;

const OP_ID: &str = "vyre-libs::math::atomic::atomic_and_u32";

/// Sequential atomic-AND over `values[0..n]` into one-slot `state`.
#[must_use]
pub fn atomic_and_u32(values: &str, state: &str, trace: &str, n: u32) -> Program {
    build_atomic_serial(OP_ID, AtomicOp::And, values, state, trace, n)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || atomic_and_u32("values", "state", "trace", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0xFFu32, 0xF0, 0x0F, 0x33]),
                to_bytes(&[u32::MAX]),
                vec![0u8; 16],
            ]]
        }),
        expected_output: Some(|| {
            // Serial &= walk starting at u32::MAX:
            //   0xFFFFFFFF & 0xFF = 0xFF
            //   0xFF       & 0xF0 = 0xF0
            //   0xF0       & 0x0F = 0x00
            //   0x00       & 0x33 = 0x00
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0x00u32]),
                to_bytes(&[u32::MAX, 0xFF, 0xF0, 0x00]),
            ]]
        }),
    }
}

register_atomic_serial_op!(OP_ID, || atomic_and_u32("values", "state", "trace", 4));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::atomic::testutil::run_serial;

    #[test]
    fn matches_bitwise_and() {
        let values = vec![0xFFu32, 0xF0, 0x0F, 0x33];
        let initial = u32::MAX;
        let program = atomic_and_u32("values", "state", "trace", values.len() as u32);
        let (final_state, trace) = run_serial(&program, &values, initial);

        let mut cpu_state = initial;
        let mut cpu_trace = Vec::new();
        for &v in &values {
            cpu_trace.push(cpu_state);
            cpu_state &= v;
        }

        assert_eq!(final_state, cpu_state);
        assert_eq!(trace, cpu_trace);
    }
}
