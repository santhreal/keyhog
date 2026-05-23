//! `reduce_max` — unsigned maximum over a u32 ValueSet.

use vyre_foundation::ir::Program;

use super::atomic_scalar::{atomic_reduce_u32, AtomicReduceKind};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::max";

/// Build a Program: `out[0] = max(values)`.
#[must_use]
pub fn reduce_max(values: &str, out: &str, count: u32) -> Program {
    atomic_reduce_u32(values, out, count, AtomicReduceKind::Max, OP_ID)
}

/// CPU reference.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(values: &[u32]) -> u32 {
    values.iter().copied().max().unwrap_or(0)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || reduce_max("values", "out", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[9, 3, 7, 5]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[9])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_maximum() {
        assert_eq!(cpu_ref(&[9, 3, 7, 5]), 9);
    }

    #[test]
    fn program_uses_parallel_grid_stride() {
        let program = reduce_max("values", "out", 513);
        assert_eq!(
            program.workgroup_size(),
            [crate::reduce::atomic_scalar::WORKGROUP_SIZE, 1, 1]
        );
    }
}
