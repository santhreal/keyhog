//! `bitset_equal` — exact-equality check, writes 1 to `out_scalar`
//! iff every word of `lhs` equals the corresponding word of `rhs`.
//!
//! Used by fixpoint convergence checks: "did the frontier change?"
//! is `bitset_equal(prev, current, out_scalar)` then "if out == 1 stop."

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::equal";

/// Build a Program: `out_scalar[0] = (forall w: lhs[w] == rhs[w]) ? 1 : 0`.
///
/// One-shot reduction: each thread tests one word; thread 0 then
/// reduces by reading a `__bitset_equal_diff` flag that all threads
/// AtomicOr into.
#[must_use]
pub fn bitset_equal(lhs: &str, rhs: &str, out_scalar: &str, words: u32) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![
        // Each thread atomically OR-s the per-word inequality flag
        // into out_scalar[0]. After the dispatch, out_scalar[0] = 1
        // means "at least one word differed"; we then complement to
        // produce equality.
        Node::if_then(
            Expr::lt(t.clone(), Expr::u32(words)),
            vec![Node::let_bind(
                "_diff",
                Expr::atomic_or(
                    out_scalar,
                    Expr::u32(0),
                    Expr::ne(Expr::load(lhs, t.clone()), Expr::load(rhs, t.clone())),
                ),
            )],
        ),
        // Thread 0 finalizes: equality = !diff.
        Node::if_then(
            Expr::eq(t.clone(), Expr::u32(0)),
            vec![Node::store(
                out_scalar,
                Expr::u32(0),
                Expr::eq(Expr::load(out_scalar, Expr::u32(0)), Expr::u32(0)),
            )],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(lhs, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(rhs, 1, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out_scalar, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: returns 1 iff every word matches, 0 otherwise.
#[must_use]
pub fn cpu_ref(lhs: &[u32], rhs: &[u32]) -> u32 {
    if lhs.len() != rhs.len() {
        return 0;
    }
    if lhs.iter().zip(rhs.iter()).all(|(a, b)| a == b) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_returns_one() {
        assert_eq!(cpu_ref(&[0xDEAD, 0xBEEF], &[0xDEAD, 0xBEEF]), 1);
    }

    #[test]
    fn differs_in_first_word_returns_zero() {
        assert_eq!(cpu_ref(&[0xDEAD, 0xBEEF], &[0xDEAE, 0xBEEF]), 0);
    }

    #[test]
    fn differs_in_last_word_returns_zero() {
        assert_eq!(cpu_ref(&[0, 0, 1], &[0, 0, 0]), 0);
    }

    #[test]
    fn empty_pair_returns_one() {
        assert_eq!(cpu_ref(&[], &[]), 1);
    }

    #[test]
    fn length_mismatch_returns_zero() {
        assert_eq!(cpu_ref(&[0], &[0, 0]), 0);
    }
}
