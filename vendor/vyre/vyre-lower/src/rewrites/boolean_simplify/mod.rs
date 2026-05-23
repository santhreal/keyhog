//! Boolean simplification rewrite.
//!
//! Source-of-truth: `PERF_ROADMAP_2026-05-01.md` section A.4 — boolean
//! simplification is one of the 20 classical compiler passes named in
//! the perf roadmap. Patterns rewritten:
//!
//! - `LogicalNot(LogicalNot(x))` → `x` (double-negation elimination)
//! - `LogicalNot(BoolLit)` → opposite `BoolLit` (constant fold over Bool)
//! - `And(x, x)` → `x` (idempotence)
//! - `Or(x, x)` → `x` (idempotence)
//! - `BitXor(x, x)` → `Literal(0)` (self-cancellation, integer-only)
//! - `Eq(LitU32(a), LitU32(b))` → `BoolLit(a == b)` (literal compare)
//! - `Ne(LitU32(a), LitU32(b))` → `BoolLit(a != b)`
//!
//! What this pass does NOT do (out of scope, deliberately):
//! - De Morgan's laws — they don't reduce op count, just rebalance
//!   structure; downstream CSE handles the equality cases this would
//!   produce.
//! - `Eq(x, x)` → `true` — unsafe under f32 because NaN != NaN.
//! - Float `Add(x, 0.0)` / `Mul(x, 1.0)` — those are wrong under
//!   strict-FP (they affect signed zero / NaN propagation); identity_elim
//!   handles the integer cases.
//!
//! Recurses into nested control flow. Idempotent. Wired into
//! `CANONICAL_REWRITE_PASSES` after `identity_elim` (which handles the
//! left/right-identity rules this leans on for stable input).

use crate::{KernelBody, KernelDescriptor, KernelOp, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;
use vyre_foundation::ir::{BinOp, UnOp};

#[must_use]
pub fn boolean_simplify(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = boolean_simplify_body(out.body);
    out
}

fn boolean_simplify_body(mut body: KernelBody) -> KernelBody {
    // Map result-id → op index. SSA shape so each id has exactly one
    // producer.
    let result_to_idx: FxHashMap<u32, usize> = body
        .ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| op.result.map(|r| (r, i)))
        .collect();

    // Pre-allocate next free result-id for synthesized literals.
    let mut next_id: u32 = body
        .ops
        .iter()
        .filter_map(|o| o.result)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

    enum Rewrite {
        ReplaceWithExisting { op_idx: usize, replace_id: u32 },
        ReplaceWithBoolLit { op_idx: usize, value: bool },
        ReplaceWithU32Lit { op_idx: usize, value: u32 },
    }
    let mut rewrites: Vec<Rewrite> = Vec::new();

    for (idx, op) in body.ops.iter().enumerate() {
        match &op.kind {
            KernelOpKind::UnOpKind(UnOp::LogicalNot) => {
                if op.operands.len() != 1 {
                    continue;
                }
                let inner = op.operands[0];
                let producer = match result_to_idx.get(&inner) {
                    Some(p) => *p,
                    None => continue,
                };
                let producer_op = &body.ops[producer];
                // LogicalNot(LogicalNot(x)) → x
                if matches!(producer_op.kind, KernelOpKind::UnOpKind(UnOp::LogicalNot))
                    && producer_op.operands.len() == 1
                {
                    rewrites.push(Rewrite::ReplaceWithExisting {
                        op_idx: idx,
                        replace_id: producer_op.operands[0],
                    });
                    continue;
                }
                // LogicalNot(BoolLit) → opposite BoolLit
                if matches!(producer_op.kind, KernelOpKind::Literal)
                    && producer_op.operands.len() == 1
                {
                    let pool_idx = producer_op.operands[0] as usize;
                    if let Some(LiteralValue::Bool(value)) = body.literals.get(pool_idx) {
                        rewrites.push(Rewrite::ReplaceWithBoolLit {
                            op_idx: idx,
                            value: !value,
                        });
                    }
                }
            }
            KernelOpKind::BinOpKind(bin) => {
                if op.operands.len() != 2 {
                    continue;
                }
                let lhs = op.operands[0];
                let rhs = op.operands[1];
                match bin {
                    // Idempotent: And(x, x) / Or(x, x) → x.
                    BinOp::And | BinOp::Or if lhs == rhs => {
                        rewrites.push(Rewrite::ReplaceWithExisting {
                            op_idx: idx,
                            replace_id: lhs,
                        });
                    }
                    // Self-cancellation: BitXor(x, x) → 0.
                    BinOp::BitXor if lhs == rhs => {
                        rewrites.push(Rewrite::ReplaceWithU32Lit {
                            op_idx: idx,
                            value: 0,
                        });
                    }
                    // Literal compare: Eq/Ne over two U32 literals.
                    BinOp::Eq | BinOp::Ne => {
                        if let Some((lhs_lit, rhs_lit)) =
                            u32_lit_pair(&body, &result_to_idx, lhs, rhs)
                        {
                            let value = match bin {
                                BinOp::Eq => lhs_lit == rhs_lit,
                                BinOp::Ne => lhs_lit != rhs_lit,
                                _ => unreachable!(),
                            };
                            rewrites.push(Rewrite::ReplaceWithBoolLit { op_idx: idx, value });
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Apply: rewrites that produce a literal allocate a new Literal op
    // (and patch the original to a Copy of the new id); rewrites that
    // replace with an existing id patch the op to a Copy.
    for r in rewrites {
        match r {
            Rewrite::ReplaceWithExisting { op_idx, replace_id } => {
                body.ops[op_idx].kind = KernelOpKind::Copy;
                body.ops[op_idx].operands = vec![replace_id];
            }
            Rewrite::ReplaceWithBoolLit { op_idx, value } => {
                let pool_idx = push_lit(&mut body.literals, LiteralValue::Bool(value));
                let synth_id = next_id;
                next_id += 1;
                body.ops.push(KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![pool_idx],
                    result: Some(synth_id),
                });
                body.ops[op_idx].kind = KernelOpKind::Copy;
                body.ops[op_idx].operands = vec![synth_id];
            }
            Rewrite::ReplaceWithU32Lit { op_idx, value } => {
                let pool_idx = push_lit(&mut body.literals, LiteralValue::U32(value));
                let synth_id = next_id;
                next_id += 1;
                body.ops.push(KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![pool_idx],
                    result: Some(synth_id),
                });
                body.ops[op_idx].kind = KernelOpKind::Copy;
                body.ops[op_idx].operands = vec![synth_id];
            }
        }
    }

    body.child_bodies = body
        .child_bodies
        .into_iter()
        .map(boolean_simplify_body)
        .collect();
    body
}

fn u32_lit_pair(
    body: &KernelBody,
    result_to_idx: &FxHashMap<u32, usize>,
    lhs: u32,
    rhs: u32,
) -> Option<(u32, u32)> {
    let lhs_value = u32_lit(body, result_to_idx, lhs)?;
    let rhs_value = u32_lit(body, result_to_idx, rhs)?;
    Some((lhs_value, rhs_value))
}

fn u32_lit(body: &KernelBody, result_to_idx: &FxHashMap<u32, usize>, id: u32) -> Option<u32> {
    let producer_idx = *result_to_idx.get(&id)?;
    let producer = body.ops.get(producer_idx)?;
    if !matches!(producer.kind, KernelOpKind::Literal) {
        return None;
    }
    let pool_idx = *producer.operands.first()? as usize;
    match body.literals.get(pool_idx) {
        Some(LiteralValue::U32(v)) => Some(*v),
        _ => None,
    }
}

fn push_lit(literals: &mut Vec<LiteralValue>, value: LiteralValue) -> u32 {
    // Reuse an existing literal slot if one already holds the same value
    // — shrinks the literal pool when many rewrites synthesize the same
    // constant (e.g. Bool(true)).
    if let Some(idx) = literals.iter().position(|lit| lit == &value) {
        return idx as u32;
    }
    let idx = literals.len() as u32;
    literals.push(value);
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindingLayout, Dispatch, KernelOp};
    use vyre_foundation::ir::{BinOp, UnOp};

    fn empty_body() -> KernelBody {
        KernelBody {
            ops: Vec::new(),
            child_bodies: Vec::new(),
            literals: Vec::new(),
        }
    }

    fn descriptor_with(body: KernelBody) -> KernelDescriptor {
        KernelDescriptor {
            id: "boolean_simplify_test".into(),
            bindings: BindingLayout { slots: Vec::new() },
            dispatch: Dispatch::new(1, 1, 1),
            body,
        }
    }

    fn lit_bool(body: &mut KernelBody, value: bool, result: u32) {
        let pool_idx = body.literals.len() as u32;
        body.literals.push(LiteralValue::Bool(value));
        body.ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![pool_idx],
            result: Some(result),
        });
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

    fn unop(body: &mut KernelBody, op: UnOp, operand: u32, result: u32) {
        body.ops.push(KernelOp {
            kind: KernelOpKind::UnOpKind(op),
            operands: vec![operand],
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

    fn op_kind_for_result(desc: &KernelDescriptor, result: u32) -> &KernelOpKind {
        &desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(result))
            .expect("Fix: target result op must survive the rewrite")
            .kind
    }

    fn copied_source(desc: &KernelDescriptor, result: u32) -> u32 {
        let op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(result))
            .expect("Fix: result op must exist");
        assert!(
            matches!(op.kind, KernelOpKind::Copy),
            "Fix: expected Copy at result {result}, got {:?}",
            op.kind
        );
        op.operands[0]
    }

    #[test]
    fn double_logical_not_eliminated() {
        let mut body = empty_body();
        lit_bool(&mut body, true, 0);
        unop(&mut body, UnOp::LogicalNot, 0, 1); // !true
        unop(&mut body, UnOp::LogicalNot, 1, 2); // !!true → true
        let desc = boolean_simplify(&descriptor_with(body));
        assert_eq!(
            copied_source(&desc, 2),
            0,
            "must alias to the inner Bool literal"
        );
    }

    #[test]
    fn logical_not_of_bool_literal_folds_to_opposite() {
        let mut body = empty_body();
        lit_bool(&mut body, false, 0);
        unop(&mut body, UnOp::LogicalNot, 0, 1); // !false → true
        let desc = boolean_simplify(&descriptor_with(body));
        let copied = copied_source(&desc, 1);
        let copied_op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(copied))
            .unwrap();
        assert!(matches!(copied_op.kind, KernelOpKind::Literal));
        let pool_idx = copied_op.operands[0] as usize;
        assert_eq!(desc.body.literals[pool_idx], LiteralValue::Bool(true));
    }

    #[test]
    fn and_idempotent_collapses_to_self() {
        let mut body = empty_body();
        lit_bool(&mut body, true, 0); // dummy bool source
        binop(&mut body, BinOp::And, 0, 0, 1);
        let desc = boolean_simplify(&descriptor_with(body));
        assert_eq!(copied_source(&desc, 1), 0);
    }

    #[test]
    fn or_idempotent_collapses_to_self() {
        let mut body = empty_body();
        lit_bool(&mut body, false, 0);
        binop(&mut body, BinOp::Or, 0, 0, 1);
        let desc = boolean_simplify(&descriptor_with(body));
        assert_eq!(copied_source(&desc, 1), 0);
    }

    #[test]
    fn xor_self_collapses_to_zero() {
        let mut body = empty_body();
        lit_u32(&mut body, 7, 0);
        binop(&mut body, BinOp::BitXor, 0, 0, 1);
        let desc = boolean_simplify(&descriptor_with(body));
        let zero_id = copied_source(&desc, 1);
        let zero_op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(zero_id))
            .unwrap();
        assert!(matches!(zero_op.kind, KernelOpKind::Literal));
        let pool_idx = zero_op.operands[0] as usize;
        assert_eq!(desc.body.literals[pool_idx], LiteralValue::U32(0));
    }

    #[test]
    fn eq_of_two_distinct_u32_literals_folds_to_false() {
        let mut body = empty_body();
        lit_u32(&mut body, 3, 0);
        lit_u32(&mut body, 5, 1);
        binop(&mut body, BinOp::Eq, 0, 1, 2);
        let desc = boolean_simplify(&descriptor_with(body));
        let folded = copied_source(&desc, 2);
        let folded_op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(folded))
            .unwrap();
        let pool_idx = folded_op.operands[0] as usize;
        assert_eq!(desc.body.literals[pool_idx], LiteralValue::Bool(false));
    }

    #[test]
    fn ne_of_two_equal_u32_literals_folds_to_false() {
        let mut body = empty_body();
        lit_u32(&mut body, 7, 0);
        lit_u32(&mut body, 7, 1);
        binop(&mut body, BinOp::Ne, 0, 1, 2);
        let desc = boolean_simplify(&descriptor_with(body));
        let folded = copied_source(&desc, 2);
        let folded_op = desc
            .body
            .ops
            .iter()
            .find(|op| op.result == Some(folded))
            .unwrap();
        let pool_idx = folded_op.operands[0] as usize;
        assert_eq!(desc.body.literals[pool_idx], LiteralValue::Bool(false));
    }

    #[test]
    fn no_change_when_pattern_does_not_match() {
        let mut body = empty_body();
        lit_bool(&mut body, true, 0);
        lit_bool(&mut body, false, 1);
        binop(&mut body, BinOp::And, 0, 1, 2); // distinct operands → not idempotent
        let original = descriptor_with(body);
        let desc = boolean_simplify(&original);
        assert_eq!(
            op_kind_for_result(&desc, 2),
            &KernelOpKind::BinOpKind(BinOp::And)
        );
    }

    #[test]
    fn rewrite_is_idempotent() {
        let mut body = empty_body();
        lit_bool(&mut body, true, 0);
        unop(&mut body, UnOp::LogicalNot, 0, 1);
        unop(&mut body, UnOp::LogicalNot, 1, 2);
        let desc = descriptor_with(body);
        let once = boolean_simplify(&desc);
        let twice = boolean_simplify(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn recurses_into_child_bodies() {
        let mut child = empty_body();
        lit_bool(&mut child, true, 0);
        unop(&mut child, UnOp::LogicalNot, 0, 1);
        unop(&mut child, UnOp::LogicalNot, 1, 2);

        let mut body = empty_body();
        body.child_bodies.push(child);
        let desc = boolean_simplify(&descriptor_with(body));
        let child_out = &desc.body.child_bodies[0];
        let copy_op = child_out
            .ops
            .iter()
            .find(|op| op.result == Some(2))
            .unwrap();
        assert!(matches!(copy_op.kind, KernelOpKind::Copy));
        assert_eq!(copy_op.operands[0], 0);
    }
}
