//! Cat-B `atomic_or_u32`. CPU ref: sequential bitwise OR.

use vyre::ir::{AtomicOp, Program};

use super::build_atomic_serial;

const OP_ID: &str = "vyre-libs::math::atomic::atomic_or_u32";

/// Sequential atomic-OR over `values[0..n]` into one-slot `state`.
#[must_use]
pub fn atomic_or_u32(values: &str, state: &str, trace: &str, n: u32) -> Program {
    build_atomic_serial(OP_ID, AtomicOp::Or, values, state, trace, n)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || atomic_or_u32("values", "state", "trace", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0x01u32, 0x02, 0x04, 0x08]),
                to_bytes(&[0u32]),
                vec![0u8; 16],
            ]]
        }),
        expected_output: Some(|| {
            // Serial |= walk starting at 0:
            //   0 | 1 = 1, 1 | 2 = 3, 3 | 4 = 7, 7 | 8 = 15
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0x0Fu32]), to_bytes(&[0u32, 1, 3, 7])]]
        }),
    }
}

register_atomic_serial_op!(OP_ID, || atomic_or_u32("values", "state", "trace", 4));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::atomic::testutil::run_serial;

    #[test]
    fn matches_bitwise_or() {
        let values = vec![0x01u32, 0x02, 0x04, 0x08];
        let initial = 0u32;
        let program = atomic_or_u32("values", "state", "trace", values.len() as u32);
        let (final_state, trace) = run_serial(&program, &values, initial);

        let mut cpu_state = initial;
        let mut cpu_trace = Vec::new();
        for &v in &values {
            cpu_trace.push(cpu_state);
            cpu_state |= v;
        }

        assert_eq!(final_state, cpu_state);
        assert_eq!(trace, cpu_trace);
    }
}
