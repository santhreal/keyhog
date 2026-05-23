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
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref(input: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    cpu_ref_into(input, &mut out);
    out
}

/// CPU reference into caller-owned storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn cpu_ref_into(input: &[u32], out: &mut Vec<u32>) {
    out.clear();
    out.reserve(input.len());
    out.extend(input.iter().map(|w| w.count_ones()));
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

    #[test]
    fn popcount_into_reuses_output() {
        let mut out = Vec::with_capacity(4);
        cpu_ref_into(&[0b1111, 0xFFFF_FFFF], &mut out);
        let capacity = out.capacity();
        assert_eq!(out, vec![4, 32]);

        cpu_ref_into(&[0b1010], &mut out);
        assert_eq!(out.capacity(), capacity);
        assert_eq!(out, vec![2]);
    }

    // ------------------------------------------------------------------
    // Adversarial fixtures — empty, all-zeros, all-ones, alternating, cross-word.
    // ------------------------------------------------------------------

    #[test]
    fn empty_bitset() {
        assert_eq!(cpu_ref(&[]), Vec::<u32>::new());
    }

    #[test]
    fn single_word_all_zeros() {
        assert_eq!(cpu_ref(&[0]), vec![0]);
    }

    #[test]
    fn single_word_all_ones() {
        assert_eq!(cpu_ref(&[0xFFFF_FFFF]), vec![32]);
    }

    #[test]
    fn alternating_pattern() {
        // 0xAAAA_AAAA = 1010...1010 → 16 ones
        assert_eq!(cpu_ref(&[0xAAAA_AAAA]), vec![16]);
        // 0x5555_5555 = 0101...0101 → 16 ones
        assert_eq!(cpu_ref(&[0x5555_5555]), vec![16]);
    }

    #[test]
    fn cross_word_boundary() {
        // Two words: one with bit 31 set, one with bit 0 set.
        assert_eq!(cpu_ref(&[0x8000_0000, 0x0000_0001]), vec![1, 1]);
    }
}
