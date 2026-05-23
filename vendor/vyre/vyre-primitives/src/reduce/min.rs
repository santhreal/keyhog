//! `reduce_min` — unsigned minimum over a u32 ValueSet.

use vyre_foundation::ir::Program;

use super::atomic_scalar::{atomic_reduce_u32, AtomicReduceKind};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::reduce::min";

/// Build a Program: `out[0] = min(values)`.
#[must_use]
pub fn reduce_min(values: &str, out: &str, count: u32) -> Program {
    atomic_reduce_u32(values, out, count, AtomicReduceKind::Min, OP_ID)
}

/// CPU reference.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(values: &[u32]) -> u32 {
    values.iter().copied().min().unwrap_or(u32::MAX)
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || reduce_min("values", "out", 4),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[9, 3, 7, 5]), to_bytes(&[0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[3])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_minimum() {
        assert_eq!(cpu_ref(&[9, 3, 7, 5]), 3);
    }

    #[test]
    fn empty_returns_u32_max() {
        assert_eq!(cpu_ref(&[]), u32::MAX);
    }

    #[test]
    fn program_uses_parallel_grid_stride() {
        let program = reduce_min("values", "out", 513);
        assert_eq!(
            program.workgroup_size(),
            [crate::reduce::atomic_scalar::WORKGROUP_SIZE, 1, 1]
        );
    }
}
