//! DF-8 — escape analysis.
//!
//! Does this pointer leave its defining frame / cross a trust
//! boundary? Closure over assignments to parameters, return values,
//! heap fields reachable from globals, and indirect-call arguments.
//!
//! # Implementation
//!
//! Escape is a reachability fixpoint in bitset space:
//!   * `escapes[v]` is set iff any of:
//!     - `v` is a root (written to global, parameter, return value,
//!        indirect-call argument — seeded by caller),
//!     - `v` points to an escaped object (propagated through
//!        `points_to`),
//!     - `v` is passed to an escaped callee (propagated through
//!        `callgraph`).
//!
//! Per invocation we OR-union both channels and AND-mask against the
//! current escape-status to emit the new escape set. The caller
//! drives the fixpoint via `bitset_fixpoint` and stops when the
//! bitset is unchanged.
//!
//! Soundness: [`MayOver`](super::Soundness::MayOver).
//!
//! Required for C03 (double-free on concurrent path), C17 (fd
//! passing confused-deputy).

use std::sync::Arc;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};
use vyre_primitives::bitset::bitset_words;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::escape";

/// One escape-propagation step. Output bit `v` is set iff any of
/// `points_to_in[v]`, `callgraph_in[v]`, or prior `escape_out[v]`
/// was set. Host runs this in a fixpoint until the bitset is
/// unchanged.
#[must_use]
pub fn escape_analyze(points_to_in: &str, callgraph_in: &str, escape_out: &str) -> Program {
    escape_analyze_with_count(points_to_in, callgraph_in, escape_out, 64)
}

/// Version that takes the lane count explicitly.
#[must_use]
pub fn escape_analyze_with_count(
    points_to_in: &str,
    callgraph_in: &str,
    escape_out: &str,
    node_count: u32,
) -> Program {
    let words = bitset_words(node_count).max(1);
    let w = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("pts", Expr::load(points_to_in, w.clone())),
        Node::let_bind("cg", Expr::load(callgraph_in, w.clone())),
        Node::let_bind("prev", Expr::load(escape_out, w.clone())),
        Node::store(
            escape_out,
            w.clone(),
            Expr::bitor(
                Expr::bitor(Expr::var("pts"), Expr::var("cg")),
                Expr::var("prev"),
            ),
        ),
    ];

    let buffers = vec![
        BufferDecl::storage(points_to_in, 0, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(callgraph_in, 1, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(escape_out, 2, BufferAccess::ReadWrite, DataType::U32)
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

/// Marker type for the escape-analysis dataflow primitive.
pub struct Escape;

impl super::soundness::SoundnessTagged for Escape {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}
