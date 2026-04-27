//! `bitset_and_not_into` — in-place per-word `target &= !subtrahend`.
//!
//! Set-difference accumulator: subtract `subtrahend` from `target` in
//! place. Used by surgec's `flows_to_not_via` lowering to drop
//! waypoint nodes from a frontier as it grows, without allocating a
//! fresh output buffer per masking step.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::and_not_into";

/// Build a Program: `target[w] = target[w] & !subtrahend[w]`.
#[must_use]
pub fn bitset_and_not_into(target: &str, subtrahend: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        target,
        t.clone(),
        Expr::bitand(
            Expr::load(target, t.clone()),
            Expr::UnOp {
                op: UnOp::BitNot,
                operand: Box::new(Expr::load(subtrahend, t.clone())),
            },
        ),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(target, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(subtrahend, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
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
pub fn cpu_ref(target: &mut [u32], subtrahend: &[u32]) {
    let n = target.len().min(subtrahend.len());
    for i in 0..n {
        target[i] &= !subtrahend[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtraction_drops_waypoint_bits() {
        let mut acc = vec![0xFFFFu32, 0xF0F0u32];
        cpu_ref(&mut acc, &[0xFF00, 0x00F0]);
        assert_eq!(acc, vec![0x00FF, 0xF000]);
    }

    #[test]
    fn empty_subtrahend_is_identity() {
        let mut acc = vec![0xDEAD_BEEFu32, 0x1234_5678u32];
        cpu_ref(&mut acc, &[0, 0]);
        assert_eq!(acc, vec![0xDEAD_BEEF, 0x1234_5678]);
    }

    #[test]
    fn full_subtrahend_zeros_target() {
        let mut acc = vec![0xDEAD_BEEFu32, 0x1234_5678u32];
        cpu_ref(&mut acc, &[0xFFFF_FFFF, 0xFFFF_FFFF]);
        assert_eq!(acc, vec![0, 0]);
    }

    #[test]
    fn idempotent_on_repeat() {
        let mut acc = vec![0xFFFFu32];
        cpu_ref(&mut acc, &[0xFF00]);
        assert_eq!(acc, vec![0x00FF]);
        cpu_ref(&mut acc, &[0xFF00]);
        assert_eq!(acc, vec![0x00FF]);
    }
}
