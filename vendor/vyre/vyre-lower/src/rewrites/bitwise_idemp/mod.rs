//! Bitwise idempotence — fold `BitAnd(x, x)` → `Copy(x)` and
//! `BitOr(x, x)` → `Copy(x)`. Companion to `boolean_simplify`'s
//! `And(x, x)` / `Or(x, x)` patterns — that pass handles the
//! boolean logical ops, this one handles the integer bitwise ops.
//!
//! Source-of-truth: `PERF_ROADMAP_2026-05-01.md` section A.4
//! (algebraic simplification family).
//!
//! Patterns rewritten:
//! - `BitAnd(x, x)` → `Copy(x)`
//! - `BitOr(x, x)`  → `Copy(x)`
//!
//! The `BitXor(x, x) → 0` case is handled by `boolean_simplify`
//! (which already covers self-cancellation; that's the analogue of
//! the non-idempotent self case).
//!
//! Recurses. Idempotent. Wired into `CANONICAL_REWRITE_PASSES`
//! immediately after `min_max_idemp` in the algebraic-simplification
//! cluster.

use crate::{KernelBody, KernelDescriptor, KernelOpKind};
use vyre_foundation::ir::BinOp;

#[must_use]
pub fn bitwise_idemp(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = bitwise_idemp_body(out.body);
    out
}

fn bitwise_idemp_body(mut body: KernelBody) -> KernelBody {
    let mut rewrites: Vec<(usize, u32)> = Vec::new();
    for (idx, op) in body.ops.iter().enumerate() {
        let bin = match &op.kind {
            KernelOpKind::BinOpKind(b) => *b,
            _ => continue,
        };
        if !matches!(bin, BinOp::BitAnd | BinOp::BitOr) {
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
        .map(bitwise_idemp_body)
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
            id: "bitwise_idemp_test".into(),
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
    fn bitand_self_collapses() {
        let mut body = empty_body();
        lit_u32(&mut body, 0xCAFE, 0);
        binop(&mut body, BinOp::BitAnd, 0, 0, 1);
        let desc = bitwise_idemp(&descriptor_with(body));
        assert_eq!(copied_source(&desc, 1), 0);
    }

    #[test]
    fn bitor_self_collapses() {
        let mut body = empty_body();
        lit_u32(&mut body, 0xBABE, 0);
        binop(&mut body, BinOp::BitOr, 0, 0, 1);
        let desc = bitwise_idemp(&descriptor_with(body));
        assert_eq!(copied_source(&desc, 1), 0);
    }

    #[test]
    fn bitand_distinct_unchanged() {
        let mut body = empty_body();
        lit_u32(&mut body, 0xFF, 0);
        lit_u32(&mut body, 0x0F, 1);
        binop(&mut body, BinOp::BitAnd, 0, 1, 2);
        let desc = bitwise_idemp(&descriptor_with(body));
        let op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(2))
            .unwrap();
        assert!(matches!(op.kind, KernelOpKind::BinOpKind(BinOp::BitAnd)));
    }

    #[test]
    fn bitxor_self_left_to_boolean_simplify() {
        // BitXor(x, x) → 0 is the SELF-CANCELLATION case already
        // owned by boolean_simplify; this pass should not touch it.
        let mut body = empty_body();
        lit_u32(&mut body, 7, 0);
        binop(&mut body, BinOp::BitXor, 0, 0, 1);
        let desc = bitwise_idemp(&descriptor_with(body));
        let op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(1))
            .unwrap();
        assert!(
            matches!(op.kind, KernelOpKind::BinOpKind(BinOp::BitXor)),
            "Fix: BitXor(x, x) handled by boolean_simplify, not bitwise_idemp."
        );
    }

    #[test]
    fn rewrite_is_idempotent() {
        let mut body = empty_body();
        lit_u32(&mut body, 1, 0);
        binop(&mut body, BinOp::BitAnd, 0, 0, 1);
        let desc = descriptor_with(body);
        let once = bitwise_idemp(&desc);
        let twice = bitwise_idemp(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn recurses_into_child_bodies() {
        let mut child = empty_body();
        lit_u32(&mut child, 9, 10);
        binop(&mut child, BinOp::BitOr, 10, 10, 11);
        let mut body = empty_body();
        body.child_bodies.push(child);
        let desc = bitwise_idemp(&descriptor_with(body));
        let op = desc.body.child_bodies[0]
            .ops
            .iter()
            .find(|op| op.result == Some(11))
            .unwrap();
        assert!(matches!(op.kind, KernelOpKind::Copy));
        assert_eq!(op.operands[0], 10);
    }
}
