//! DF-9 — persistent procedure summaries.
//!
//! Bottom-up fixpoint: compute a summary for each function describing
//! its effect on caller state (inputs tainted → outputs tainted,
//! inputs ranged → outputs ranged, etc.). Persist to the pipeline
//! cache keyed by function AST hash so unchanged functions are not
//! reanalysed across scans.
//!
//! This is the performance gate for the whole dataflow stack — Linux
//! has ~450k functions; reanalysing per-rule is infeasible without
//! summaries.
//!
//! # Implementation
//!
//! Two-layer composition:
//!
//!   1. **Kernel:** a single-dispatch Program that reads the
//!      per-function input-bitset (`fn_ast_in`), unions callee
//!      summaries from the callgraph (`callgraph_in`), falls back
//!      to the previous iteration's cached summary
//!      (`cached_summary_in`), and writes the new summary.
//!
//!   2. **Host loop:** the caller drives this Program in a
//!      bottom-up order (callees before callers) using the topsort
//!      primitive; once a function's summary is unchanged across two
//!      consecutive passes it is written to the pipeline cache
//!      (G8's blake3-keyed content cache) keyed by AST hash +
//!      callee-summary hash.
//!
//! Soundness: inherited from the underlying primitives.

use std::sync::Arc;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};
use vyre_primitives::bitset::bitset_words;

pub(crate) const OP_ID: &str = "weir::summary";

/// One summary-update step for a single function.
///
/// Bit `i` of `summary_out` is set iff any of: the AST-derived bit
/// was set, the callgraph-aggregated bit from callee summaries was
/// set, or the cached summary from the previous scan was set. That
/// is a three-way OR — same kernel shape as `escape`, different
/// buffer names.
#[must_use]
pub fn summarize_function(
    fn_ast_in: &str,
    callgraph_in: &str,
    cached_summary_in: &str,
    summary_out: &str,
) -> Program {
    summarize_function_with_count(fn_ast_in, callgraph_in, cached_summary_in, summary_out, 64)
}

/// Version that takes the bit-lane count explicitly.
#[must_use]
pub fn summarize_function_with_count(
    fn_ast_in: &str,
    callgraph_in: &str,
    cached_summary_in: &str,
    summary_out: &str,
    bit_count: u32,
) -> Program {
    let words = bitset_words(bit_count).max(1);
    let w = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("ast", Expr::load(fn_ast_in, w.clone())),
        Node::let_bind("cg", Expr::load(callgraph_in, w.clone())),
        Node::let_bind("cached", Expr::load(cached_summary_in, w.clone())),
        Node::store(
            summary_out,
            w.clone(),
            Expr::bitor(
                Expr::bitor(Expr::var("ast"), Expr::var("cg")),
                Expr::var("cached"),
            ),
        ),
    ];

    let buffers = vec![
        BufferDecl::storage(fn_ast_in, 0, BufferAccess::ReadOnly, DataType::U32).with_count(words),
        BufferDecl::storage(callgraph_in, 1, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(cached_summary_in, 2, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(summary_out, 3, BufferAccess::ReadWrite, DataType::U32)
            .with_count(words),
    ];

    Program::wrapped(
        buffers,
        [256, 1, 1],
        vec![Node::Region {
            generator: Ident::from(OP_ID),
            source_region: None,
            body: Arc::new(vec![Node::if_then(
                Expr::lt(w.clone(), Expr::u32(words)),
                body,
            )]),
        }],
    )
}

/// Marker type for the persistent-summary dataflow primitive.
pub struct Summary;

impl super::soundness::SoundnessTagged for Summary {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}
