//! K-FAC step inside vyre's natural-gradient autotuner.
//!
//! Replaces standard gradient descent on dispatch-graph continuous
//! variables (e.g. tile sizes, fusion probabilities) with Fisher-
//! preconditioned updates.
//!
//! Dispatches the `vyre_primitives::math::kfac_block_inverse` primitive
//! to invert the block-diagonal Fisher information matrix of the
//! autotuner's policy network.

use vyre_foundation::ir::Program;
use vyre_primitives::math::kfac_block_inverse::kfac_block_inverse;

/// Canonical op ID for the autotune step.
pub const OP_ID: &str = "vyre-libs::self_substrate::kfac_autotune_step";

/// Compile a Program that inverts the Fisher block-diagonal matrix.
///
/// `n` is the size of each block (e.g. number of parameters in a layer).
/// `num_blocks` is the number of independent layers/blocks.
#[must_use]
pub fn kfac_autotune_step_program(
    blocks_out: &str,
    blocks_in: &str,
    scratch: &str,
    num_blocks: u32,
    n: u32,
) -> Program {
    use crate::observability::{bump, kfac_autotune_step_calls};
    bump(&kfac_autotune_step_calls);
    kfac_block_inverse(blocks_out, blocks_in, scratch, num_blocks, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::math::kfac_block_inverse::cpu_ref;

    #[test]
    fn test_kfac_program_shape() {
        let p = kfac_autotune_step_program("bo", "bi", "s", 10, 16);
        assert_eq!(p.buffers().len(), 3, "Expects exactly 3 buffers");
        assert!(p.buffers().iter().any(|b| b.name() == "bi"));
    }

    #[test]
    fn test_kfac_autotune_fisher_block() {
        // Non-trivial vyre IR shape: 2 blocks of size 2x2.
        // Block 1: Identity
        // Block 2: Diagonal [2, 4] -> inverse is [0.5, 0.25]
        let num_blocks = 2;
        let n = 2;
        let blocks_in = vec![
            1.0, 0.0, 0.0, 1.0, // block 0
            2.0, 0.0, 0.0, 4.0, // block 1
        ];

        let out = cpu_ref(&blocks_in, num_blocks, n);

        assert_eq!(out[0..4], vec![1.0, 0.0, 0.0, 1.0]);
        assert_eq!(out[4..8], vec![0.5, 0.0, 0.0, 0.25]);
    }

    #[test]
    fn test_kfac_autotune_dense_block() {
        // Dense block
        let num_blocks = 1;
        let n = 2;
        let blocks_in = vec![4.0, 3.0, 3.0, 2.0];
        // determinant = 4*2 - 3*3 = 8 - 9 = -1
        // inverse = [-2, 3; 3, -4]

        let out = cpu_ref(&blocks_in, num_blocks, n);

        assert_eq!(out, vec![-2.0, 3.0, 3.0, -4.0]);
    }

    #[test]
    fn test_multi_layer_kfac_composition() {
        let p1 = kfac_autotune_step_program("bo1", "bi1", "s1", 1, 4);
        let p2 = kfac_autotune_step_program("bo2", "bi2", "s2", 1, 4);
        let p3 = kfac_autotune_step_program("bo3", "bi3", "s3", 1, 4);

        let mut entry = p1.entry().to_vec();
        entry.extend(p2.entry().to_vec());
        entry.extend(p3.entry().to_vec());

        let mut buffers = p1.buffers().to_vec();
        buffers.extend(p2.buffers().to_vec());
        buffers.extend(p3.buffers().to_vec());

        let final_p = Program::wrapped(buffers, [256, 1, 1], entry);
        let region_count = final_p
            .entry()
            .iter()
            .filter(|n| matches!(n, vyre_foundation::ir::Node::Region { .. }))
            .count();
        assert!(region_count >= 3);
    }

    #[test]
    fn test_end_to_end_kfac_parity() {
        let blocks_in = vec![2.0, 0.0, 0.0, 4.0];
        let p = kfac_autotune_step_program("bo", "bi", "s", 1, 2);

        use std::sync::Arc;
        use vyre_reference::reference_eval;
        use vyre_reference::value::Value;

        let to_value = |data: &[f32]| {
            let bytes: Vec<u8> = data.iter().flat_map(|v| v.to_le_bytes()).collect();
            Value::Bytes(Arc::from(bytes))
        };

        let inputs = vec![
            to_value(&[0.0; 4]),
            to_value(&blocks_in),
            to_value(&[0.0; 4]),
        ];

        let results = reference_eval(&p, &inputs).expect("Fix: interpreter failed");
        let actual_bytes = results[0].to_bytes();
        let actual_out: Vec<f32> = actual_bytes
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(actual_out, vec![0.5, 0.0, 0.0, 0.25]);
    }
}
