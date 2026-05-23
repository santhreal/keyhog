//! Min/Max idempotence — fold `Min(x, x) → x`, `Max(x, x) → x`,
//! and the absorbing-bound cases `Min(x, MAX) → x`, `Max(x, MIN) → x`
//! when the bound is a U32 literal at the natural extreme.
//!
//! Source-of-truth: `PERF_ROADMAP_2026-05-01.md` section A.4
//! (algebraic simplification family). identity_elim already handles
//! `Min(x, MAX_U32) → x` for U32 literals at U32::MAX; this pass
//! adds the symmetric self-cases that don't depend on literal-value
//! introspection.
//!
//! Patterns rewritten:
//! - `Min(x, x)` → `Copy(x)`
//! - `Max(x, x)` → `Copy(x)`
//!
//! Out of scope:
//! - `Min(x, MIN_U32)` → `Lit(0)` (absorbing) — handled by const_fold
//!   when both sides are literal; otherwise needs literal-value
//!   introspection that identity_elim already provides.
//! - Float Min/Max — semantically distinct under NaN propagation;
//!   we operate on the descriptor IR which is dtype-untyped, so we
//!   only fold the case that's safe regardless of operand dtype
//!   (self-comparison: Min(x, x) = x for any total order).
//!
//! Recurses into nested control flow. Idempotent. Wired into
//! `CANONICAL_REWRITE_PASSES` immediately after `select_fold` in the
//! algebraic-simplification cluster.

use crate::{KernelBody, KernelDescriptor, KernelOpKind};
use vyre_foundation::ir::BinOp;

#[must_use]
pub fn min_max_idemp(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = min_max_idemp_body(out.body);
    out
}

fn min_max_idemp_body(mut body: KernelBody) -> KernelBody {
    let mut rewrites: Vec<(usize, u32)> = Vec::new();
    for (idx, op) in body.ops.iter().enumerate() {
        let bin = match &op.kind {
            KernelOpKind::BinOpKind(b) => *b,
            _ => continue,
        };
        if !matches!(bin, BinOp::Min | BinOp::Max) {
            continue;
        }
        if op.operands.len() != 2 {
            continue;
        }
        if op.operands[0] == op.operands[1] {
            rewrites.push((idx, op.operands[0]));
        }
    }
    for (op_idx, replace_id) in rewrites {
        body.ops[op_idx].kind = KernelOpKind::Copy;
        body.ops[op_idx].operands = vec![replace_id];
    }
    body.child_bodies = body
        .child_bodies
        .into_iter()
        .map(min_max_idemp_body)
        .collect();
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindingLayout, Dispatch, KernelOp, LiteralValue};
    use vyre_foundation::ir::BinOp;

    fn empty_body() -> KernelBody {
        KernelBody {
            ops: Vec::new(),
            child_bodies: Vec::new(),
            literals: Vec::new(),
        }
    }

    fn descriptor_with(body: KernelBody) -> KernelDescriptor {
        KernelDescriptor {
            id: "min_max_idemp_test".into(),
            bindings: BindingLayout { slots: Vec::new() },
            dispatch: Dispatch::new(1, 1, 1),
            body,
        }
    }

    fn lit_u32(body: &mut KernelBody, value: u32, result: u32) {
        let pool_idx = body.literals.len() as u32;
        body.literals.push(LiteralValue::U32(value));
        body.ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![pool_idx],
            result: Some(result),
        });
    }

    fn binop(body: &mut KernelBody, op: BinOp, lhs: u32, rhs: u32, result: u32) {
        body.ops.push(KernelOp {
            kind: KernelOpKind::BinOpKind(op),
            operands: vec![lhs, rhs],
            result: Some(result),
        });
    }

    fn copied_source(desc: &KernelDescriptor, result: u32) -> u32 {
        let op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(result))
            .unwrap();
        assert!(matches!(op.kind, KernelOpKind::Copy));
        op.operands[0]
    }

    #[test]
    fn min_self_collapses() {
        let mut body = empty_body();
        lit_u32(&mut body, 42, 0);
        binop(&mut body, BinOp::Min, 0, 0, 1);
        let desc = min_max_idemp(&descriptor_with(body));
        assert_eq!(copied_source(&desc, 1), 0);
    }

    #[test]
    fn max_self_collapses() {
        let mut body = empty_body();
        lit_u32(&mut body, 42, 0);
        binop(&mut body, BinOp::Max, 0, 0, 1);
        let desc = min_max_idemp(&descriptor_with(body));
        assert_eq!(copied_source(&desc, 1), 0);
    }

    #[test]
    fn min_with_distinct_operands_unchanged() {
        let mut body = empty_body();
        lit_u32(&mut body, 1, 0);
        lit_u32(&mut body, 2, 1);
        binop(&mut body, BinOp::Min, 0, 1, 2);
        let desc = min_max_idemp(&descriptor_with(body));
        let op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(2))
            .unwrap();
        assert!(matches!(op.kind, KernelOpKind::BinOpKind(BinOp::Min)));
    }

    #[test]
    fn non_min_max_ops_unchanged() {
        let mut body = empty_body();
        lit_u32(&mut body, 5, 0);
        binop(&mut body, BinOp::Add, 0, 0, 1);
        let desc = min_max_idemp(&descriptor_with(body));
        let op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(1))
            .unwrap();
        assert!(
            matches!(op.kind, KernelOpKind::BinOpKind(BinOp::Add)),
            "Fix: Add(x, x) is NOT min/max idempotence — leave alone"
        );
    }

    #[test]
    fn rewrite_is_idempotent() {
        let mut body = empty_body();
        lit_u32(&mut body, 7, 0);
        binop(&mut body, BinOp::Min, 0, 0, 1);
        let desc = descriptor_with(body);
        let once = min_max_idemp(&desc);
        let twice = min_max_idemp(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn recurses_into_child_bodies() {
        let mut child = empty_body();
        lit_u32(&mut child, 9, 10);
        binop(&mut child, BinOp::Max, 10, 10, 11);
        let mut body = empty_body();
        body.child_bodies.push(child);
        let desc = min_max_idemp(&descriptor_with(body));
        let op = desc.body.child_bodies[0]
            .ops
            .iter()
            .find(|op| op.result == Some(11))
            .unwrap();
        assert!(matches!(op.kind, KernelOpKind::Copy));
        assert_eq!(op.operands[0], 10);
    }
}
