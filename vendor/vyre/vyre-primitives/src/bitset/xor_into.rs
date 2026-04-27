//! `bitset_xor_into` — in-place per-word `target ^= addend`.
//!
//! Symmetric difference accumulator. Same in-place pattern as
//! `or_into` and `and_into` — single binding for the accumulator,
//! separate read-only binding for the operand. Used by fixpoint
//! drivers that need to detect "did anything change" without
//! allocating a fresh output buffer per step.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::xor_into";

/// Build a Program: `target[w] = target[w] ^ addend[w]`.
#[must_use]
pub fn bitset_xor_into(target: &str, addend: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        target,
        t.clone(),
        Expr::bitxor(Expr::load(target, t.clone()), Expr::load(addend, t.clone())),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(target, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::storage(addend, 1, BufferAccess::ReadOnly, DataType::U32).with_count(words),
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
pub fn cpu_ref(target: &mut [u32], addend: &[u32]) {
    let n = target.len().min(addend.len());
    for i in 0..n {
        target[i] ^= addend[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_with_self_zeros() {
        let mut acc = vec![0xDEAD_BEEFu32, 0x1234_5678u32];
        let copy = acc.clone();
        cpu_ref(&mut acc, &copy);
        assert_eq!(acc, vec![0, 0]);
    }

    #[test]
    fn xor_with_zero_is_identity() {
        let mut acc = vec![0xFFFFu32, 0x0F0Fu32];
        cpu_ref(&mut acc, &[0, 0]);
        assert_eq!(acc, vec![0xFFFF, 0x0F0F]);
    }

    #[test]
    fn xor_is_self_inverse() {
        let mut acc = vec![0xAAAAu32];
        cpu_ref(&mut acc, &[0xFF00]);
        cpu_ref(&mut acc, &[0xFF00]);
        assert_eq!(acc, vec![0xAAAA]);
    }

    #[test]
    fn xor_distributes_per_word() {
        let mut acc = vec![0x00FFu32, 0xFF00u32];
        cpu_ref(&mut acc, &[0x0F0F, 0xF0F0]);
        assert_eq!(acc, vec![0x0FF0, 0x0FF0]);
    }
}
