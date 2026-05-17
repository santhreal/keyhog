//! `may_alias` — Andersen-style may-alias query packed as a bitset.
//!
//! Given two pointer expressions `p` and `q`, return 1 iff their
//! points-to sets overlap (`pts(p) ∩ pts(q) ≠ ∅`). Implementation:
//! per-node bitset AND of pts(p) and pts(q), then any-reduce.
//!
//! Soundness: `MayOver`.

use std::sync::Arc;

use vyre::ir::model::expr::Ident;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_primitives::graph::csr_forward_traverse::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::may_alias";

/// Build a may-alias Program. Inputs:
/// - `pts_p`, `pts_q`: per-node points-to bitsets.
/// - `intersect_buf`: scratch.
/// - `out_scalar`: 1 if the points-to sets overlap, else 0.
#[must_use]
pub fn may_alias(
    node_count: u32,
    pts_p: &str,
    pts_q: &str,
    intersect_buf: &str,
    out_scalar: &str,
) -> Program {
    let words = bitset_words(node_count);
    let t = Expr::InvocationId { axis: 0 };
    let body = vec![
        Node::let_bind("p", Expr::load(pts_p, t.clone())),
        Node::let_bind("q", Expr::load(pts_q, t.clone())),
        Node::let_bind("intersect", Expr::bitand(Expr::var("p"), Expr::var("q"))),
        Node::store(intersect_buf, t.clone(), Expr::var("intersect")),
        Node::if_then(
            Expr::ne(Expr::var("intersect"), Expr::u32(0)),
            vec![Node::let_bind(
                "_",
                Expr::atomic_or(out_scalar, Expr::u32(0), Expr::u32(1)),
            )],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(pts_p, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
            BufferDecl::storage(pts_q, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
            BufferDecl::storage(intersect_buf, 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(words),
            BufferDecl::output(out_scalar, 3, DataType::U32).with_count(1),
        ],
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(Expr::lt(t.clone(), Expr::u32(words)), body)]),
        }],
    )
}

/// CPU oracle.
#[must_use]
pub fn cpu_ref(pts_p: &[u32], pts_q: &[u32]) -> u32 {
    let inter = vyre_primitives::bitset::and::cpu_ref(pts_p, pts_q);
    u32::from(inter.iter().any(|w| *w != 0))
}

/// Soundness marker for [`may_alias`].
pub struct MayAlias;
impl super::soundness::SoundnessTagged for MayAlias {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_pts_alias() {
        assert_eq!(cpu_ref(&[0b1010], &[0b0011]), 1);
    }

    #[test]
    fn disjoint_pts_dont_alias() {
        assert_eq!(cpu_ref(&[0b1010], &[0b0101]), 0);
    }

    #[test]
    fn empty_pts_dont_alias() {
        assert_eq!(cpu_ref(&[0], &[0xFFFF]), 0);
    }

    #[test]
    fn identical_pts_alias() {
        assert_eq!(cpu_ref(&[0xDEAD], &[0xDEAD]), 1);
    }
}
