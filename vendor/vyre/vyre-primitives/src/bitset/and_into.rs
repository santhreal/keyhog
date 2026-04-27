//! `bitset_and_into` — in-place per-word bitwise AND (`target &= mask`).
//!
//! Same-buffer-as-input-and-output composition that `bitset_and`
//! cannot express because its three-binding signature would declare
//! the same buffer name twice with different access modes (ReadOnly +
//! ReadWrite), triggering merge-time deduplication that silently
//! drops the ReadWrite half. This in-place variant exposes ONE
//! binding for the accumulator and a separate binding for the mask.
//!
//! Used by surgec to mask a flowing frontier against an allow set
//! without allocating a fresh output buffer per step — the same
//! pattern the `flows_to_not_via` lowering uses to subtract waypoint
//! nodes can be expressed in fewer dispatches when the caller is
//! happy to mutate its accumulator.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::and_into";

/// Build a Program: `target[w] = target[w] & mask[w]`.
#[must_use]
pub fn bitset_and_into(target: &str, mask: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        target,
        t.clone(),
        Expr::bitand(Expr::load(target, t.clone()), Expr::load(mask, t.clone())),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(target, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(mask, 1, BufferAccess::ReadOnly, DataType::U32).with_count(words),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(t.clone(), Expr::u32(words)),
                body,
            )]),
        }],
    )
}

/// CPU reference. Mutates `target` in place.
pub fn cpu_ref(target: &mut [u32], mask: &[u32]) {
    let n = target.len().min(mask.len());
    for i in 0..n {
        target[i] &= mask[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_place_and_shrinks_monotonically() {
        let mut acc = vec![0xFFFFu32, 0xF0F0u32];
        cpu_ref(&mut acc, &[0xFF00, 0xFFFF]);
        assert_eq!(acc, vec![0xFF00, 0xF0F0]);
        cpu_ref(&mut acc, &[0x0F00, 0x0F0F]);
        assert_eq!(acc, vec![0x0F00, 0x0000]);
        // Idempotent on repeat.
        cpu_ref(&mut acc, &[0x0F00, 0x0F0F]);
        assert_eq!(acc, vec![0x0F00, 0x0000]);
    }

    #[test]
    fn full_mask_is_identity() {
        let mut acc = vec![0xDEAD_BEEFu32, 0x1234_5678u32];
        cpu_ref(&mut acc, &[0xFFFF_FFFF, 0xFFFF_FFFF]);
        assert_eq!(acc, vec![0xDEAD_BEEF, 0x1234_5678]);
    }

    #[test]
    fn empty_mask_zeros_target() {
        let mut acc = vec![0xDEAD_BEEFu32, 0x1234_5678u32];
        cpu_ref(&mut acc, &[0, 0]);
        assert_eq!(acc, vec![0, 0]);
    }
}
