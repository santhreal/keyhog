//! DF-10 — loop summarization (stratified fixpoint acceleration).
//!
//! Widening + narrowing over loops so range / taint analyses
//! terminate in finitely many iterations on unbounded loops.
//! Required for decode-chain detection (C10 decompression bomb, C11
//! parser differential, C15 path traversal decode chain) where the
//! vuln only manifests after N iterations of a loop that reads a
//! length-prefixed field.
//!
//! # Implementation
//!
//! Standard Cousot widening on the interval lattice: at a loop
//! header, the new summary is `widen(prev, new)` where
//! `widen(⟨a, b⟩, ⟨c, d⟩)` keeps `a` if it was finite and reduced
//! else jumps to `-∞`, and keeps `b` if it was finite and grew
//! else jumps to `+∞`. The u32 lattice uses `0` as `-∞` sentinel
//! and `u32::MAX` as `+∞` sentinel.
//!
//! Each invocation handles one variable's `[lo, hi]` pair,
//! identical buffer layout to DF-7 `range`.
//!
//! Soundness: [`MayOver`](super::Soundness::MayOver) under the standard
//! widening-narrowing correctness argument.

use std::sync::Arc;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};

pub(crate) const OP_ID: &str = "weir::loop_sum";

/// One widening step. `cfg_in` holds the previous-iteration
/// intervals `[prev_lo_v, prev_hi_v, …]`; `ranges_in` holds the
/// new iteration's intervals; `summary_out` receives the widened
/// result per variable.
#[must_use]
pub fn loop_summarize(cfg_in: &str, ranges_in: &str, summary_out: &str) -> Program {
    loop_summarize_with_count(cfg_in, ranges_in, summary_out, 4)
}

/// Version that takes `var_count` explicitly.
#[must_use]
pub fn loop_summarize_with_count(
    cfg_in: &str,
    ranges_in: &str,
    summary_out: &str,
    var_count: u32,
) -> Program {
    let v = Expr::InvocationId { axis: 0 };
    const NEG_INF: u32 = 0;
    const POS_INF: u32 = u32::MAX;

    let body = vec![
        Node::let_bind("lo_idx", Expr::mul(v.clone(), Expr::u32(2))),
        Node::let_bind("hi_idx", Expr::add(Expr::var("lo_idx"), Expr::u32(1))),
        Node::let_bind("prev_lo", Expr::load(cfg_in, Expr::var("lo_idx"))),
        Node::let_bind("prev_hi", Expr::load(cfg_in, Expr::var("hi_idx"))),
        Node::let_bind("new_lo", Expr::load(ranges_in, Expr::var("lo_idx"))),
        Node::let_bind("new_hi", Expr::load(ranges_in, Expr::var("hi_idx"))),
        // widen lo: if new_lo < prev_lo (lower bound decreasing),
        // jump to -∞ (NEG_INF); else keep prev_lo.
        Node::let_bind(
            "wide_lo",
            Expr::select(
                Expr::lt(Expr::var("new_lo"), Expr::var("prev_lo")),
                Expr::u32(NEG_INF),
                Expr::var("prev_lo"),
            ),
        ),
        // widen hi: if new_hi > prev_hi (upper bound increasing),
        // jump to +∞ (POS_INF); else keep prev_hi.
        Node::let_bind(
            "wide_hi",
            Expr::select(
                Expr::lt(Expr::var("prev_hi"), Expr::var("new_hi")),
                Expr::u32(POS_INF),
                Expr::var("prev_hi"),
            ),
        ),
        Node::store(summary_out, Expr::var("lo_idx"), Expr::var("wide_lo")),
        Node::store(summary_out, Expr::var("hi_idx"), Expr::var("wide_hi")),
    ];

    let slots = var_count.saturating_mul(2).max(1);
    let buffers = vec![
        BufferDecl::storage(cfg_in, 0, BufferAccess::ReadOnly, DataType::U32).with_count(slots),
        BufferDecl::storage(ranges_in, 1, BufferAccess::ReadOnly, DataType::U32).with_count(slots),
        BufferDecl::storage(summary_out, 2, BufferAccess::ReadWrite, DataType::U32)
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

/// Marker type for the loop-summarization dataflow primitive.
pub struct LoopSum;

impl super::soundness::SoundnessTagged for LoopSum {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}
