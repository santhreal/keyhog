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
const WORKGROUP_SIZE: u32 = 256;

/// Build a Program: `out_scalar[0] = (forall w: lhs[w] == rhs[w]) ? 1 : 0`.
///
/// One-dispatch reduction: lane 0 initializes the output to true, then
/// every lane scans its chunk-strided words and atomically ANDs its
/// equality predicate into the scalar.
#[must_use]
pub fn bitset_equal(lhs: &str, rhs: &str, out_scalar: &str, words: u32) -> Program {
    let lane = Expr::InvocationId { axis: 0 };
    let chunk_count = Expr::div(
        Expr::add(Expr::u32(words), Expr::u32(WORKGROUP_SIZE - 1)),
        Expr::u32(WORKGROUP_SIZE),
    );
    let body = vec![
        Node::if_then(
            Expr::eq(lane.clone(), Expr::u32(0)),
            vec![Node::store(out_scalar, Expr::u32(0), Expr::u32(1))],
        ),
        Node::Barrier {
            ordering: vyre_foundation::MemoryOrdering::SeqCst,
        },
        Node::loop_for(
            "chunk",
            Expr::u32(0),
            chunk_count,
            vec![
                Node::let_bind(
                    "w",
                    Expr::add(
                        Expr::mul(Expr::var("chunk"), Expr::u32(WORKGROUP_SIZE)),
                        lane.clone(),
                    ),
                ),
                Node::if_then(
                    Expr::lt(Expr::var("w"), Expr::u32(words)),
                    vec![Node::let_bind(
                        "_eq_prev",
                        Expr::atomic_and(
                            out_scalar,
                            Expr::u32(0),
                            Expr::select(
                                Expr::eq(
                                    Expr::load(lhs, Expr::var("w")),
                                    Expr::load(rhs, Expr::var("w")),
                                ),
                                Expr::u32(1),
                                Expr::u32(0),
                            ),
                        ),
                    )],
                ),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(lhs, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(rhs, 1, BufferAccess::ReadOnly, DataType::U32).with_count(words),
            BufferDecl::storage(out_scalar, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [WORKGROUP_SIZE, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(body),
        }],
    )
}

/// CPU reference: returns 1 iff every word matches, 0 otherwise.
#[cfg(any(test, feature = "cpu-parity"))]
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

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_equal("lhs", "rhs", "out", 2),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![
                to_bytes(&[0xFFFF, 0xF0F0]),
                to_bytes(&[0xFFFF, 0xF0F0]),
                to_bytes(&[0]),
            ]]
        }),
        Some(|| {
            let to_bytes = |w: &[u32]| w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
            vec![vec![to_bytes(&[1])]]
        }),
    )
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
