//! DF-5 — call graph with indirect dispatch resolution.
//!
//! Direct calls are trivial — the graph is built during AP-2 lowering.
//! Indirect calls (fnptr tables, vtables, kernel ops-struct dispatch —
//! `file_operations`, `net_proto_ops`, `proto_ops`, etc.) require
//! points-to (DF-3) to resolve the callee set.
//!
//! The kernel ops-struct pattern is the largest source of false
//! negatives in competing tools. We track every struct literal whose
//! fields are function pointers, index by the struct's type, and when
//! `x->f(...)` appears with `x : struct T *` the callee set is
//! `{ s.f | s is a struct T literal in the program }`.
//!
//! # Implementation
//!
//! The final call-graph bitset per call-site is
//! `direct ∪ (indirect_sites × points_to_closure)`. Both operands are
//! bitsets in the CSR-frontier shape we already own, so the kernel
//! is a per-invocation bitwise OR of two loads plus a bounds check.
//!
//! Soundness: [`MayOver`](super::Soundness::MayOver) — may-analysis.
//!
//! Gate for C19.

use std::sync::Arc;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};
use vyre_primitives::bitset::bitset_words;

pub(crate) const OP_ID: &str = "weir::callgraph";

/// Build a single-dispatch Program that OR-merges a direct call-edge
/// bitset with the transitive-closure bitset produced by
/// [`crate::points_to::andersen_points_to`] into the final
/// callgraph edge bitset.
///
/// `direct_edges_in` and `indirect_sites_in` are read-only bitsets
/// over `node_count` call-site lanes. `pts_closure_in` is the
/// points-to closure for each indirect call-site. `callgraph_out` is
/// the final bitset written lane-by-lane.
///
/// `node_count` is the number of call sites (one bit per site).
#[must_use]
pub fn callgraph_build(
    direct_edges_in: &str,
    indirect_sites_in: &str,
    pts_closure_in: &str,
    callgraph_out: &str,
) -> Program {
    callgraph_build_with_count(
        direct_edges_in,
        indirect_sites_in,
        pts_closure_in,
        callgraph_out,
        4,
    )
}

/// Version that takes the number of call-site lanes explicitly.
#[must_use]
pub fn callgraph_build_with_count(
    direct_edges_in: &str,
    indirect_sites_in: &str,
    pts_closure_in: &str,
    callgraph_out: &str,
    node_count: u32,
) -> Program {
    let words = bitset_words(node_count);
    let w = Expr::InvocationId { axis: 0 };

    let body = vec![
        Node::let_bind("direct", Expr::load(direct_edges_in, w.clone())),
        Node::let_bind(
            "indirect",
            Expr::bitand(
                Expr::load(indirect_sites_in, w.clone()),
                Expr::load(pts_closure_in, w.clone()),
            ),
        ),
        Node::store(
            callgraph_out,
            w.clone(),
            Expr::bitor(Expr::var("direct"), Expr::var("indirect")),
        ),
    ];

    let buffers = vec![
        BufferDecl::storage(direct_edges_in, 0, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(indirect_sites_in, 1, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(pts_closure_in, 2, BufferAccess::ReadOnly, DataType::U32)
            .with_count(words),
        BufferDecl::storage(callgraph_out, 3, BufferAccess::ReadWrite, DataType::U32)
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

/// Marker type for the callgraph dataflow primitive.
pub struct Callgraph;

impl super::soundness::SoundnessTagged for Callgraph {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::MayOver
    }
}
