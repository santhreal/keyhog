//! Div-chain combine — fold `Div(Div(x, Lit(a)), Lit(b))` to
//! `Div(x, Lit(a * b))` (wrap-checked, divisor non-zero) for unsigned
//! floor division. Identity:
//!     ⌊⌊x / a⌋ / b⌋ = ⌊x / (a * b)⌋ for x ≥ 0, a > 0, b > 0.
//!
//! Source-of-truth: `PERF_ROADMAP_2026-05-01.md` section A.4
//! (algebraic simplification family). Companion to `add_combine`,
//! `sub_combine`, `mul_combine`, `bitwise_combine`.
//!
//! Pattern rewritten (when both Lits are U32, both > 0, and a * b
//! doesn't wrap, and the inner Div has exactly one consumer):
//! - `Div(Div(x, Lit(a)), Lit(b))` → `Div(x, Lit(a * b))`
//!
//! Out-of-scope: zero divisors (preserved unchanged so the runtime
//! div-by-zero trap stays observable), wrapping product, multi-consumer
//! inner Div, signed division (I32 left to a future pass), and the
//! rotated forms `Div(Lit, Div(...))` which require non-trivial
//! reasoning over partial quotients.
//!
//! Recurses. Idempotent. Wired immediately after `sub_combine` in
//! `CANONICAL_REWRITE_PASSES`.

use crate::{KernelBody, KernelDescriptor, KernelOp, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;
use vyre_foundation::ir::BinOp;

#[must_use]
pub fn div_combine(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = div_combine_body(out.body);
    out
}

fn div_combine_body(mut body: KernelBody) -> KernelBody {
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
        if !matches!(op.kind, KernelOpKind::BinOpKind(BinOp::Div)) {
            continue;
        }
        if op.operands.len() != 2 {
            continue;
        }
        let lhs = op.operands[0];
        let rhs = op.operands[1];

        // Only the right-chain canonical form: Div(Div(x, Lit(a)), Lit(b)).
        if let Some((x, a)) = candidate_div_with_rhs_lit(&body, &result_to_idx, &use_count, lhs) {
            if let Some(b) = u32_lit(&body, &result_to_idx, rhs) {
                if a == 0 || b == 0 {
                    continue;
                }
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
        body.ops[op_idx].kind = KernelOpKind::BinOpKind(BinOp::Div);
        body.ops[op_idx].operands = vec![x_id, synth_id];
    }

    body.child_bodies = body
        .child_bodies
        .into_iter()
        .map(div_combine_body)
        .collect();
    body
}

fn candidate_div_with_rhs_lit(
    body: &KernelBody,
    result_to_idx: &FxHashMap<u32, usize>,
    use_count: &FxHashMap<u32, u32>,
    result_id: u32,
) -> Option<(u32, u32)> {
    let producer_idx = *result_to_idx.get(&result_id)?;
    let producer = body.ops.get(producer_idx)?;
    if !matches!(producer.kind, KernelOpKind::BinOpKind(BinOp::Div)) {
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
    let c = u32_lit(body, result_to_idx, rhs)?;
    if c == 0 {
        return None;
    }
    Some((lhs, c))
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
            id: "div_combine_test".into(),
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
    fn div_chain_combines_when_no_wrap_and_nonzero() {
        // (x / 3) / 5 → x / 15
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 3, 1);
        binop(&mut body, BinOp::Div, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Div, 2, 3, 4);
        let desc = div_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert!(matches!(outer.kind, KernelOpKind::BinOpKind(BinOp::Div)));
        assert_eq!(outer.operands[0], 0);
        assert_eq!(lit_value_at(&desc, outer.operands[1]), 15);
    }

    #[test]
    fn wrapping_product_left_alone() {
        // (x / 0x1_0000) / 0x1_0000 — product 0x1_0000_0000 overflows u32.
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 0x1_0000, 1);
        binop(&mut body, BinOp::Div, 0, 1, 2);
        lit_u32(&mut body, 0x1_0000, 3);
        binop(&mut body, BinOp::Div, 2, 3, 4);
        let desc = div_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(outer.operands[0], 2, "Fix: refuse on overflow.");
    }

    #[test]
    fn zero_divisor_left_alone() {
        // Div by zero must remain observable — the runtime trap is part
        // of the program's semantics.
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 0, 1);
        binop(&mut body, BinOp::Div, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Div, 2, 3, 4);
        let desc = div_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(
            outer.operands[0], 2,
            "Fix: never absorb a div-by-zero into a fold."
        );
    }

    #[test]
    fn outer_zero_divisor_left_alone() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 5, 1);
        binop(&mut body, BinOp::Div, 0, 1, 2);
        lit_u32(&mut body, 0, 3);
        binop(&mut body, BinOp::Div, 2, 3, 4);
        let desc = div_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(outer.operands[0], 2);
    }

    #[test]
    fn inner_div_with_multiple_consumers_left_alone() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 3, 1);
        binop(&mut body, BinOp::Div, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Div, 2, 3, 4);
        binop(&mut body, BinOp::Add, 2, 0, 5);
        let desc = div_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(outer.operands[0], 2);
    }

    #[test]
    fn rewrite_is_idempotent() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 3, 1);
        binop(&mut body, BinOp::Div, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Div, 2, 3, 4);
        let desc = descriptor_with(body);
        let once = div_combine(&desc);
        let twice = div_combine(&once);
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
        binop(&mut child, BinOp::Div, 10, 11, 12);
        lit_u32(&mut child, 6, 13);
        binop(&mut child, BinOp::Div, 12, 13, 14);
        let mut body = empty_body();
        body.child_bodies.push(child);
        let desc = div_combine(&descriptor_with(body));
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
