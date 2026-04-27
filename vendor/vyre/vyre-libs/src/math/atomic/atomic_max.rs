//! Cat-B `atomic_max_u32`. CPU ref: sequential `u32::max`.

use vyre::ir::{AtomicOp, Program};

use super::build_atomic_serial;

const OP_ID: &str = "vyre-libs::math::atomic::atomic_max_u32";

/// Sequential atomic-max over `values[0..n]` into one-slot `state`.
#[must_use]
pub fn atomic_max_u32(values: &str, state: &str, trace: &str, n: u32) -> Program {
    build_atomic_serial(OP_ID, AtomicOp::Max, values, state, trace, n)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: OP_ID,
        build: || atomic_max_u32("values", "state", "trace", 4),
        test_inputs: Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[50u32, 20, 80, 10]),
                to_bytes(&[0u32]),
                vec![0u8; 16],
            ]]
        }),
        expected_output: Some(|| {
            // max(0,50)=50, max(50,20)=50, max(50,80)=80, max(80,10)=80
            let to_bytes = |w: &[u32]| w.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[80u32]), to_bytes(&[0u32, 50, 50, 80])]]
        }),
    }
}

register_atomic_serial_op!(OP_ID, || atomic_max_u32("values", "state", "trace", 4));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::atomic::testutil::run_serial;

    #[test]
    fn matches_u32_max() {
        let values = vec![50u32, 20, 80, 10];
        let initial = 0u32;
        let program = atomic_max_u32("values", "state", "trace", values.len() as u32);
        let (final_state, trace) = run_serial(&program, &values, initial);

        let mut cpu_state = initial;
        let mut cpu_trace = Vec::new();
        for &v in &values {
            cpu_trace.push(cpu_state);
            cpu_state = cpu_state.max(v);
        }

        assert_eq!(final_state, cpu_state);
        assert_eq!(trace, cpu_trace);
    }
}
