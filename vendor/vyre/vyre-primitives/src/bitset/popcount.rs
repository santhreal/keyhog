//! `bitset_popcount` — per-word population count over a packed bitset.
//!
//! Produces a parallel `count_words[w]` array whose sum reduction
//! yields the total bit count. Reductions to a single scalar live
//! under [`crate::reduce`]; this primitive handles just the per-word
//! popcount so it can be composed.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::popcount";

/// Build a Program: `count_words[w] = popcount(input[w])`.
#[must_use]
pub fn bitset_popcount(input: &str, count_words: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        count_words,
        t.clone(),
        Expr::UnOp {
            op: UnOp::Popcount,
            operand: Box::new(Expr::load(input, t.clone())),
        },
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(count_words, 1, BufferAccess::ReadWrite, DataType::U32)
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

/// CPU reference.
#[must_use]
pub fn cpu_ref(input: &[u32]) -> Vec<u32> {
    input.iter().map(|w| w.count_ones()).collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_popcount("input", "count", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[0b1111, 0xFFFF_FFFF]), to_bytes(&[0, 0])]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[4, 32])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popcount_per_word() {
        assert_eq!(cpu_ref(&[0b1111, 0xFFFF_FFFF]), vec![4, 32]);
    }
}
