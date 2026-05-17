//! Linear-type discipline checker (P-1.0-V2.2).
//!
//! Walks every `Node` and `Expr` in a `Program`, counts reads and
//! writes per buffer, and reports violations against each
//! `BufferDecl::linear_type()` declaration:
//!
//! * `Linear`     — exactly one use; reject if `uses == 0` or `uses > 1`.
//! * `Affine`     — at most one use; reject if `uses > 1`.
//! * `Relevant`   — at least one use; reject if `uses == 0`.
//! * `Unrestricted` — anything (default).
//!
//! "Use" here means any reference: `Expr::Load`, `Expr::BufLen`,
//! `Expr::Atomic`, `Node::Store`, `Node::AsyncLoad`, `Node::AsyncStore`,
//! `Node::IndirectDispatch`. The checker is conservative: it counts
//! every occurrence in source order, so a buffer appearing inside an
//! `If::then` *and* `If::otherwise` is two uses even though only one
//! path runs at dispatch time.
//!
//! Wired into `validate::validate` so backends never see a program
//! that violates declared discipline.

use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::node::Node;
use crate::ir_inner::model::program::{BufferDecl, LinearType, Program};
use crate::transform::visit::{walk_nodes_and_exprs, ExprVisitor, NodeVisitor};
use crate::validate::{err, ValidationError};
use rustc_hash::FxHashMap;

/// Walk `program` and return a list of validation errors describing
/// every buffer whose declared `linear_type` is violated.
#[must_use]
pub fn check_linear_types(program: &Program) -> Vec<ValidationError> {
    let mut counts: FxHashMap<&str, u32> = FxHashMap::default();
    for buffer in program.buffers() {
        if buffer.linear_type() != LinearType::Unrestricted {
            counts.insert(buffer.name(), 0);
        }
    }
    if counts.is_empty() {
        return Vec::new();
    }

    struct Counter<'counts, 'program> {
        counts: &'counts mut FxHashMap<&'program str, u32>,
    }

    impl Counter<'_, '_> {
        #[inline]
        fn bump(&mut self, buffer: &str) {
            if let Some(count) = self.counts.get_mut(buffer) {
                *count += 1;
            }
        }
    }

    impl NodeVisitor for Counter<'_, '_> {
        fn visit_node(&mut self, node: &Node) {
            match node {
                Node::Store { buffer, .. } => self.bump(buffer.as_str()),
                Node::IndirectDispatch { count_buffer, .. } => self.bump(count_buffer.as_str()),
                Node::AsyncLoad {
                    source,
                    destination,
                    ..
                }
                | Node::AsyncStore {
                    source,
                    destination,
                    ..
                } => {
                    self.bump(source.as_str());
                    self.bump(destination.as_str());
                }
                _ => {}
            }
        }
    }

    impl ExprVisitor for Counter<'_, '_> {
        fn visit_expr(&mut self, expr: &Expr) {
            match expr {
                Expr::Load { buffer, .. }
                | Expr::BufLen { buffer }
                | Expr::Atomic { buffer, .. } => self.bump(buffer.as_str()),
                _ => {}
            }
        }
    }

    {
        let mut counter = Counter {
            counts: &mut counts,
        };
        walk_nodes_and_exprs(program, &mut counter);
    }
    let mut errors = Vec::new();
    for buffer in program.buffers() {
        let lt = buffer.linear_type();
        if lt == LinearType::Unrestricted {
            continue;
        }
        let uses = counts.get(buffer.name()).copied().unwrap_or(0);
        if let Some(message) = violation_message(buffer, lt, uses) {
            errors.push(err(message));
        }
    }
    errors
}

fn violation_message(buffer: &BufferDecl, lt: LinearType, uses: u32) -> Option<String> {
    match lt {
        LinearType::Linear => {
            if uses != 1 {
                Some(format!(
                    "buffer `{}` declared `LinearType::Linear` must be used exactly once but was used {uses} time(s). Fix: ensure the program reads or writes this buffer exactly once on every path, or change the discipline to Affine / Relevant / Unrestricted.",
                    buffer.name()
                ))
            } else {
                None
            }
        }
        LinearType::Affine => {
            if uses > 1 {
                Some(format!(
                    "buffer `{}` declared `LinearType::Affine` must be used at most once but was used {uses} time(s). Fix: drop the redundant references, or change the discipline to Relevant / Unrestricted to allow re-use.",
                    buffer.name()
                ))
            } else {
                None
            }
        }
        LinearType::Relevant => {
            if uses == 0 {
                Some(format!(
                    "buffer `{}` declared `LinearType::Relevant` must be used at least once but was unused. Fix: add a read or write of this buffer, or change the discipline to Affine / Unrestricted.",
                    buffer.name()
                ))
            } else {
                None
            }
        }
        LinearType::Unrestricted => None,
    }
}
