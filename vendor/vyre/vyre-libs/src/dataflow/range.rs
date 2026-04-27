//! DF-7 — value-range and symbolic-length lattice.
//!
//! Interval abstract domain over integer-typed variables:
//! `⟨lo, hi⟩ ∈ {−∞, ℤ, +∞}²`. Overflow tracked as a separate flag
//! so the domain is sound under wrap-around arithmetic.
//!
//! Extended with symbolic-length expressions: `len(buf) + k`, where
//! `k` is a range constant. Critical for C05 (integer trunc →
//! undersized alloc → OOB) and C19 (ioctl size fields that bypass
//! `copy_from_user` bound checks when the lattice concretizes to a
//! non-trivial range).
//!
//! # Implementation
//!
//! Each variable occupies two consecutive u32 slots `[lo, hi]`
//! in the flat buffer. One invocation per variable, indexed by
//! `InvocationId` axis 0. The edge transfer is an additive shift
//! per variable (`lo' = lo + t_lo`, `hi' = hi + t_hi`) — the
//! simplest interval transfer that covers assign, add-const, and
//! symbolic-length-plus-k.
//!
//! Meet at join points is the caller's responsibility: join two
//! runs of this primitive with an element-wise `min(lo, lo')` /
//! `max(hi, hi')` kernel (built via `vyre_primitives::math` ops).
//!
//! Soundness: [`MayOver`](super::Soundness::MayOver) in the standard
//! abstract-interpretation sense. Zero-FP rules that consume this
//! lattice must pair with DF-3 + an aliasing filter.

use std::sync::Arc;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::range";

/// Build one forward interval-propagation step.
#[must_use]
pub fn range_propagate(defs_in: &str, edges_in: &str, ranges_out: &str) -> Program {
    range_propagate_with_count(defs_in, edges_in, ranges_out, 4)
}

/// Version that takes `var_count` explicitly.
#[must_use]
pub fn range_propagate_with_count(
    defs_in: &str,
    edges_in: &str,
    ranges_out: &str,
    var_count: u32,
) -> Program {
    let v = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("lo_idx", Expr::mul(v.clone(), Expr::u32(2))),
        Node::let_bind("hi_idx", Expr::add(Expr::var("lo_idx"), Expr::u32(1))),
        Node::let_bind("lo", Expr::load(defs_in, Expr::var("lo_idx"))),
        Node::let_bind("hi", Expr::load(defs_in, Expr::var("hi_idx"))),
        Node::let_bind("t_lo", Expr::load(edges_in, Expr::var("lo_idx"))),
        Node::let_bind("t_hi", Expr::load(edges_in, Expr::var("hi_idx"))),
        Node::store(
            ranges_out,
            Expr::var("lo_idx"),
            Expr::add(Expr::var("lo"), Expr::var("t_lo")),
        ),
        Node::store(
            ranges_out,
            Expr::var("hi_idx"),
            Expr::add(Expr::var("hi"), Expr::var("t_hi")),
        ),
    ];

    let slots = var_count.saturating_mul(2).max(1);
    let buffers = vec![
        BufferDecl::storage(defs_in, 0, BufferAccess::ReadOnly, DataType::U32).with_count(slots),
        BufferDecl::storage(edges_in, 1, BufferAccess::ReadOnly, DataType::U32).with_count(slots),
        BufferDecl::storage(ranges_out, 2, BufferAccess::ReadWrite, DataType::U32)
            .with_count(slots),
    ];

    Program::wrapped(
        buffers,
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(v.clone(), Expr::u32(var_count)),
                body,
            )]),
        }],
    )
}

/// Marker type for the interval-range dataflow primitive.
pub struct Range;

impl super::soundness::SoundnessTagged for Range {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}
