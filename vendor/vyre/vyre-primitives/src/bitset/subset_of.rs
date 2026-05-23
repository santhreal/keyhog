//! `bitset_subset_of` — write 1 to `out_scalar` iff `lhs ⊆ rhs`.
//!
//! Equivalent: `(lhs & !rhs) == 0` per word for every word.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program, UnOp};

/// Canonical op id.
pub const OP_ID: &str = "vyre-primitives::bitset::subset_of";
const WORKGROUP_SIZE: u32 = 256;

/// Build a Program: `out_scalar[0] = (forall w: (lhs[w] & !rhs[w]) == 0) ? 1 : 0`.
#[must_use]
pub fn bitset_subset_of(lhs: &str, rhs: &str, out_scalar: &str, words: u32) -> Program {
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
                        "_subset_prev",
                        Expr::atomic_and(
                            out_scalar,
                            Expr::u32(0),
                            Expr::select(
                                Expr::eq(
                                    Expr::bitand(
                                        Expr::load(lhs, Expr::var("w")),
                                        Expr::UnOp {
                                            op: UnOp::BitNot,
                                            operand: Box::new(Expr::load(rhs, Expr::var("w"))),
                                        },
                                    ),
                                    Expr::u32(0),
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

/// CPU reference.
#[cfg(any(test, feature = "cpu-parity"))]
#[must_use]
pub fn cpu_ref(lhs: &[u32], rhs: &[u32]) -> u32 {
    let n = lhs.len().min(rhs.len());
    for i in 0..n {
        if (lhs[i] & !rhs[i]) != 0 {
            return 0;
        }
    }
    if lhs.len() > rhs.len() {
        for &word in &lhs[n..] {
            if word != 0 {
                return 0;
            }
        }
    }
    1
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || bitset_subset_of("lhs", "rhs", "out", 2),
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
    fn proper_subset_returns_one() {
        assert_eq!(cpu_ref(&[0b0011], &[0b1111]), 1);
    }

    #[test]
    fn equal_sets_are_subsets() {
        assert_eq!(cpu_ref(&[0xDEAD], &[0xDEAD]), 1);
    }

    #[test]
    fn superset_returns_zero() {
        assert_eq!(cpu_ref(&[0b1111], &[0b0011]), 0);
    }

    #[test]
    fn disjoint_nonempty_returns_zero() {
        assert_eq!(cpu_ref(&[0b1100], &[0b0011]), 0);
    }

    #[test]
    fn empty_lhs_is_subset_of_anything() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF_FFFF]), 1);
    }
}
