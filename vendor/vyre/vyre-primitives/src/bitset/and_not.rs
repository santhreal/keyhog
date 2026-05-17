//! `bitset_and_not` — per-word `lhs AND NOT rhs` over packed bitsets.
//!
//! Produced as a first-class primitive so set-difference (subtract
//! `rhs` from `lhs`) is one Region instead of the two-op compose
//! `bitset_not(rhs)` → `bitset_and(lhs, allow)`. Surgec's
//! `flows_to_not_via` lowering uses this to subtract waypoint nodes
//! from the source frontier, making the `not_via` path one fewer
//! buffer + one fewer dispatch than the manual compose.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::and_not";

/// Build a Program: `out[w] = lhs[w] & !rhs[w]`.
///
/// Per-thread per-word implementation. Equivalent CPU oracle:
/// `lhs.iter().zip(rhs).map(|(a,b)| a & !b).collect()`.
#[must_use]
pub fn bitset_and_not(lhs: &str, rhs: &str, out: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![Node::store(
        out,
        t.clone(),
        Expr::bitand(
            Expr::load(lhs, t.clone()),
            Expr::bitnot(Expr::load(rhs, t.clone())),
        ),
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

/// CPU reference: `out[i] = lhs[i] & !rhs[i]` per word.
#[must_use]
pub fn cpu_ref(lhs: &[u32], rhs: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    cpu_ref_into(lhs, rhs, &mut out);
    out
}

/// CPU reference into caller-owned storage.
pub fn cpu_ref_into(lhs: &[u32], rhs: &[u32], out: &mut Vec<u32>) {
    out.clear();
    out.reserve(lhs.len().min(rhs.len()));
    out.extend(lhs.iter().zip(rhs.iter()).map(|(a, b)| a & !b));
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_and_not("lhs", "rhs", "out", 2),
        Some(|| {
            let to_bytes = |words: &[u32]| {
                words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<u8>>()
            };
            vec![vec![
                to_bytes(&[0xFF00, 0xAAAA_AAAA]),
                to_bytes(&[0xF0F0, 0x5555_5555]),
                to_bytes(&[0, 0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |words: &[u32]| {
                words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<u8>>()
            };
            vec![vec![to_bytes(&[0x0F00, 0xAAAA_AAAA])]]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_word_and_not() {
        // 0xFF00 with 0xF0F0 removed = 0x0F00.
        assert_eq!(cpu_ref(&[0xFF00], &[0xF0F0]), vec![0x0F00]);
    }

    #[test]
    fn empty_rhs_passes_lhs_through() {
        assert_eq!(cpu_ref(&[0xDEAD_BEEF], &[0]), vec![0xDEAD_BEEF]);
    }

    #[test]
    fn full_rhs_zeros_output() {
        assert_eq!(cpu_ref(&[0xDEAD_BEEF], &[0xFFFF_FFFF]), vec![0]);
    }

    #[test]
    fn distributes_over_multiple_words() {
        let lhs = [0xFFFF_FFFF, 0x0F0F_0F0F, 0xAAAA_AAAA];
        let rhs = [0x0000_FFFF, 0xF0F0_F0F0, 0x5555_5555];
        let want = [0xFFFF_0000, 0x0F0F_0F0F, 0xAAAA_AAAA];
        assert_eq!(cpu_ref(&lhs, &rhs), want);
    }

    // ------------------------------------------------------------------
    // Adversarial fixtures — empty, single-word, cross-word, A==B, B=all-1s.
    // ------------------------------------------------------------------

    #[test]
    fn empty_bitset() {
        assert_eq!(cpu_ref(&[], &[]), Vec::<u32>::new());
    }

    #[test]
    fn single_word_all_bits() {
        let lhs = vec![0xFFFF_FFFF];
        let rhs = vec![0x0000_FFFF];
        assert_eq!(cpu_ref(&lhs, &rhs), vec![0xFFFF_0000]);
    }

    #[test]
    fn cross_word_boundary() {
        // Word 0 bit 31 and word 1 bit 0 are adjacent nodes.
        let lhs = vec![0x8000_0000, 0x0000_0001];
        let rhs = vec![0x0000_0000, 0x0000_0000];
        assert_eq!(cpu_ref(&lhs, &rhs), vec![0x8000_0000, 0x0000_0001]);
    }

    #[test]
    fn a_eq_b_produces_all_zeros() {
        let a = vec![0xDEAD_BEEF, 0x0F0F_0F0F];
        assert_eq!(cpu_ref(&a, &a), vec![0, 0]);
    }

    #[test]
    fn b_all_ones_produces_zeros() {
        let lhs = vec![0xFFFF_FFFF, 0xFFFF_FFFF];
        let rhs = vec![0xFFFF_FFFF, 0xFFFF_FFFF];
        assert_eq!(cpu_ref(&lhs, &rhs), vec![0, 0]);
    }
}
