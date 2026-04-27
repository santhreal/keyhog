//! `bitset_or_into` — in-place per-word bitwise OR (`target |= addend`).
//!
//! Same-buffer-as-input-and-output composition that `bitset_or` cannot
//! express because its three-binding signature would declare the same
//! buffer name twice with different access modes (ReadOnly + ReadWrite),
//! triggering merge-time deduplication that silently drops the
//! ReadWrite half on the merged Program. This in-place variant exposes
//! ONE binding for the accumulator and a separate binding for the
//! addend, matching the WGSL contract for fixpoint composition. Used
//! by the surgec rule lowering to grow a reachability accumulator
//! across persistent-dispatch iterations.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::or_into";

/// Build a Program: `target[w] = target[w] | addend[w]`.
#[must_use]
pub fn bitset_or_into(target: &str, addend: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        target,
        t.clone(),
        Expr::bitor(Expr::load(target, t.clone()), Expr::load(addend, t.clone())),
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
        target[i] |= addend[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_place_or_grows_monotonically() {
        let mut acc = vec![0u32, 0u32];
        cpu_ref(&mut acc, &[0xFF00, 0x0F0F]);
        assert_eq!(acc, vec![0xFF00, 0x0F0F]);
        cpu_ref(&mut acc, &[0x00FF, 0xF0F0]);
        assert_eq!(acc, vec![0xFFFF, 0xFFFF]);
        // Idempotent on repeat.
        cpu_ref(&mut acc, &[0x00FF, 0xF0F0]);
        assert_eq!(acc, vec![0xFFFF, 0xFFFF]);
    }
}
