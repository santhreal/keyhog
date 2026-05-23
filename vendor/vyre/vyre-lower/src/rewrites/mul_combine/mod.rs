//! Mul-chain combine — fold `Mul(Mul(x, Lit(a)), Lit(b))` to
//! `Mul(x, Lit(a*b))` (wrap-checked) and the symmetric forms.
//! Companion to `add_combine` for the multiplicative monoid.
//!
//! Source-of-truth: `PERF_ROADMAP_2026-05-01.md` section A.4
//! (algebraic simplification family). Companion to
//! `descriptor_const_fold` (which folds `Mul(Lit, Lit)` when both
//! operands are literal but doesn't combine across an intermediate
//! Mul) and `strength_reduce` (which converts `Mul(x, lit_pow2)` to
//! shifts — that runs FIRST, so `mul_combine` sees Mul-Mul chains
//! whose constants are non-pow2).
//!
//! Patterns rewritten (when both Lits are U32 and a * b doesn't
//! wrap):
//! - `Mul(Mul(x, Lit(a)), Lit(b))` → `Mul(x, Lit(a * b))`
//! - `Mul(Lit(b), Mul(x, Lit(a)))` → `Mul(x, Lit(a * b))`
//! - `Mul(Lit(b), Mul(Lit(a), x))` → `Mul(x, Lit(a * b))`
//! - `Mul(Mul(Lit(a), x), Lit(b))` → `Mul(x, Lit(a * b))`
//!
//! Same out-of-scope set as `add_combine`: wrapping multiplication,
//! multi-consumer inner Muls.
//!
//! Recurses. Idempotent. Wired into `CANONICAL_REWRITE_PASSES`
//! immediately after `add_combine`.

use crate::{KernelBody, KernelDescriptor, KernelOp, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;
use vyre_foundation::ir::BinOp;

#[must_use]
pub fn mul_combine(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = mul_combine_body(out.body);
    out
}

fn mul_combine_body(mut body: KernelBody) -> KernelBody {
    let result_to_idx: FxHashMap<u32, usize> = body
        .ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| op.result.map(|r| (r, i)))
        .collect();

    let mut use_count: FxHashMap<u32, u32> = FxHashMap::default();
    for op in &body.ops {
        for operand in &op.operands {
            *use_count.entry(*operand).or_insert(0) += 1;
        }
    }

    let mut rewrites: Vec<(usize, u32, u32)> = Vec::new();
    for (idx, op) in body.ops.iter().enumerate() {
        if !matches!(op.kind, KernelOpKind::BinOpKind(BinOp::Mul)) {
            continue;
        }
        if op.operands.len() != 2 {
            continue;
        }
        let lhs = op.operands[0];
        let rhs = op.operands[1];

        if let Some((x, a)) = candidate_mul_with_lit(&body, &result_to_idx, &use_count, lhs) {
            if let Some(b) = u32_lit(&body, &result_to_idx, rhs) {
                if let Some(prod) = a.checked_mul(b) {
                    rewrites.push((idx, x, prod));
                    continue;
                }
            }
        }
        if let Some((x, a)) = candidate_mul_with_lit(&body, &result_to_idx, &use_count, rhs) {
            if let Some(b) = u32_lit(&body, &result_to_idx, lhs) {
                if let Some(prod) = a.checked_mul(b) {
                    rewrites.push((idx, x, prod));
                }
            }
        }
    }

    let mut next_id: u32 = body
        .ops
        .iter()
        .filter_map(|o| o.result)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

    for (op_idx, x_id, prod) in rewrites {
        let pool_idx = push_lit(&mut body.literals, LiteralValue::U32(prod));
        let synth_id = next_id;
        next_id += 1;
        body.ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![pool_idx],
            result: Some(synth_id),
        });
        body.ops[op_idx].kind = KernelOpKind::BinOpKind(BinOp::Mul);
        body.ops[op_idx].operands = vec![x_id, synth_id];
    }

    body.child_bodies = body
        .child_bodies
        .into_iter()
        .map(mul_combine_body)
        .collect();
    body
}

fn candidate_mul_with_lit(
    body: &KernelBody,
    result_to_idx: &FxHashMap<u32, usize>,
    use_count: &FxHashMap<u32, u32>,
    result_id: u32,
) -> Option<(u32, u32)> {
    let producer_idx = *result_to_idx.get(&result_id)?;
    let producer = body.ops.get(producer_idx)?;
    if !matches!(producer.kind, KernelOpKind::BinOpKind(BinOp::Mul)) {
        return None;
    }
    if producer.operands.len() != 2 {
        return None;
    }
    if use_count.get(&result_id).copied().unwrap_or(0) != 1 {
        return None;
    }
    let lhs = producer.operands[0];
    let rhs = producer.operands[1];
    if let Some(c) = u32_lit(body, result_to_idx, rhs) {
        return Some((lhs, c));
    }
    if let Some(c) = u32_lit(body, result_to_idx, lhs) {
        return Some((rhs, c));
    }
    None
}

fn u32_lit(body: &KernelBody, result_to_idx: &FxHashMap<u32, usize>, id: u32) -> Option<u32> {
    let producer_idx = *result_to_idx.get(&id)?;
    let producer = body.ops.get(producer_idx)?;
    if !matches!(producer.kind, KernelOpKind::Literal) {
        return None;
    }
    let pool_idx = *producer.operands.first()? as usize;
    match body.literals.get(pool_idx)? {
        LiteralValue::U32(v) => Some(*v),
        _ => None,
    }
}

fn push_lit(literals: &mut Vec<LiteralValue>, value: LiteralValue) -> u32 {
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
            id: "mul_combine_test".into(),
            bindings: BindingLayout { slots: Vec::new() },
            dispatch: Dispatch::new(1, 1, 1),
            body,
        }
    }

    fn nonliteral_source(body: &mut KernelBody, result: u32) {
        body.ops.push(KernelOp {
            kind: KernelOpKind::GlobalInvocationId,
            operands: vec![0],
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

    fn binop(body: &mut KernelBody, op: BinOp, lhs: u32, rhs: u32, result: u32) {
        body.ops.push(KernelOp {
            kind: KernelOpKind::BinOpKind(op),
            operands: vec![lhs, rhs],
            result: Some(result),
        });
    }

    fn op_at(desc: &KernelDescriptor, result: u32) -> &KernelOp {
        desc.body
            .ops
            .iter()
            .find(|op| op.result == Some(result))
            .expect("Fix: target op must exist")
    }

    fn lit_value_at(desc: &KernelDescriptor, id: u32) -> u32 {
        let op = op_at(desc, id);
        assert!(matches!(op.kind, KernelOpKind::Literal));
        let pool_idx = op.operands[0] as usize;
        match desc.body.literals[pool_idx] {
            LiteralValue::U32(v) => v,
            _ => panic!("Fix: expected U32 literal"),
        }
    }

    #[test]
    fn mul_chain_combines_when_no_wrap() {
        // (x * 3) * 5 → x * 15
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 3, 1);
        binop(&mut body, BinOp::Mul, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Mul, 2, 3, 4);
        let desc = mul_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert!(matches!(outer.kind, KernelOpKind::BinOpKind(BinOp::Mul)));
        assert_eq!(outer.operands[0], 0);
        assert_eq!(lit_value_at(&desc, outer.operands[1]), 15);
    }

    #[test]
    fn wrapping_product_left_alone() {
        // (x * 0x1_0000) * 0x1_0000 = x * 0x1_0000_0000 (overflow)
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 0x1_0000, 1);
        binop(&mut body, BinOp::Mul, 0, 1, 2);
        lit_u32(&mut body, 0x1_0000, 3);
        binop(&mut body, BinOp::Mul, 2, 3, 4);
        let desc = mul_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(
            outer.operands[0], 2,
            "Fix: refuse to combine when product overflows u32."
        );
    }

    #[test]
    fn inner_mul_with_multiple_consumers_left_alone() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 3, 1);
        binop(&mut body, BinOp::Mul, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Mul, 2, 3, 4);
        binop(&mut body, BinOp::Mul, 2, 0, 5);
        let desc = mul_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(outer.operands[0], 2);
    }

    #[test]
    fn rewrite_is_idempotent() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 3, 1);
        binop(&mut body, BinOp::Mul, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Mul, 2, 3, 4);
        let desc = descriptor_with(body);
        let once = mul_combine(&desc);
        let twice = mul_combine(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn recurses_into_child_bodies() {
        let mut child = empty_body();
        child.ops.push(KernelOp {
            kind: KernelOpKind::GlobalInvocationId,
            operands: vec![0],
            result: Some(10),
        });
        lit_u32(&mut child, 4, 11);
        binop(&mut child, BinOp::Mul, 10, 11, 12);
        lit_u32(&mut child, 6, 13);
        binop(&mut child, BinOp::Mul, 12, 13, 14);
        let mut body = empty_body();
        body.child_bodies.push(child);
        let desc = mul_combine(&descriptor_with(body));
        let outer = desc.body.child_bodies[0]
            .ops
            .iter()
            .find(|op| op.result == Some(14))
            .unwrap();
        assert_eq!(outer.operands[0], 10);
        let lit_idx = desc.body.child_bodies[0]
            .ops
            .iter()
            .find(|op| op.result == Some(outer.operands[1]))
            .unwrap()
            .operands[0] as usize;
        assert_eq!(
            desc.body.child_bodies[0].literals[lit_idx],
            LiteralValue::U32(24)
        );
    }
}
