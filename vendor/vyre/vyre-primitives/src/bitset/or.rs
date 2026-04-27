//! `bitset_or` — per-word bitwise OR over two packed bitsets.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::or";

/// Build a Program: `out[w] = lhs[w] | rhs[w]`.
#[must_use]
pub fn bitset_or(lhs: &str, rhs: &str, out: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        out,
        t.clone(),
        Expr::bitor(Expr::load(lhs, t.clone()), Expr::load(rhs, t.clone())),
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(lhs, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(rhs, 1, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out, 2, BufferAccess::ReadWrite, DataType::U32).with_count(words),
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

/// CPU reference.
#[must_use]
pub fn cpu_ref(lhs: &[u32], rhs: &[u32]) -> Vec<u32> {
    lhs.iter().zip(rhs.iter()).map(|(a, b)| a | b).collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_or("lhs", "rhs", "out", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0xFF00, 0x0F0F]),
                to_bytes(&[0x00FF, 0xF0F0]),
                to_bytes(&[0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0xFFFF, 0xFFFF])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_word_or() {
        assert_eq!(
            cpu_ref(&[0xFF00, 0x0F0F], &[0x00FF, 0xF0F0]),
            vec![0xFFFF, 0xFFFF]
        );
    }
}
