//! Cat-B `atomic_add_u32` — sequential `Expr::Atomic { op: Add, ... }`.
//! CPU ref: `state = state.wrapping_add(value); trace[i] = pre-op state`.

use vyre::ir::{AtomicOp, Program};

use super::build_atomic_serial;

const OP_ID: &str = "vyre-libs::math::atomic::atomic_add_u32";

/// Sequential atomic-add over `values[0..n]` into one-slot `state`.
#[must_use]
pub fn atomic_add_u32(values: &str, state: &str, trace: &str, n: u32) -> Program {
    build_atomic_serial(OP_ID, AtomicOp::Add, values, state, trace, n)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || atomic_add_u32("values", "state", "trace", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[1u32, 5, u32::MAX, 3]),
                to_bytes(&[7u32]),
                vec![0u8; 16],
            ]]
        }),
        expected_output: Some(|| {
            // Serial CPU ref: trace[i] = pre-op state before
            // wrapping-adding values[i]. Starts at state=7.
            //   i=0: pre=7, state=8
            //   i=1: pre=8, state=13
            //   i=2: pre=13, state=12 (wrap past u32::MAX)
            //   i=3: pre=12, state=15
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[15u32]), to_bytes(&[7u32, 8, 13, 12])]]
        }),
    }
}

register_atomic_serial_op!(OP_ID, || atomic_add_u32("values", "state", "trace", 4));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::atomic::testutil::run_serial;

    #[test]
    fn matches_wrapping_add() {
        let values = vec![1u32, 5, u32::MAX, 3];
        let initial = 7u32;
        let program = atomic_add_u32("values", "state", "trace", values.len() as u32);
        let (final_state, trace) = run_serial(&program, &values, initial);

        let mut cpu_state = initial;
        let mut cpu_trace = Vec::new();
        for &v in &values {
            cpu_trace.push(cpu_state);
            cpu_state = cpu_state.wrapping_add(v);
        }

        assert_eq!(final_state, cpu_state);
        assert_eq!(trace, cpu_trace);
    }

    #[test]
    fn single_addition() {
        let program = atomic_add_u32("values", "state", "trace", 1);
        let (s, t) = run_serial(&program, &[10], 32);
        assert_eq!(t, vec![32]);
        assert_eq!(s, 42);
    }
}
