//! Add-chain combine — fold `Add(Add(x, Lit(a)), Lit(b))` to
//! `Add(x, Lit(a+b))` and the symmetric forms. Saves one op per
//! combine and exposes more constant-fold opportunities downstream.
//!
//! Source-of-truth: `PERF_ROADMAP_2026-05-01.md` section A.4
//! (algebraic simplification family). Companion to
//! `descriptor_const_fold` (which folds `Add(Lit, Lit)` when both
//! operands are literal but doesn't combine across an intermediate
//! Add).
//!
//! Patterns rewritten (when both Lits are U32 and a + b doesn't
//! wrap):
//! - `Add(Add(x, Lit(a)), Lit(b))` → `Add(x, Lit(a + b))`
//! - `Add(Lit(b), Add(x, Lit(a)))` → `Add(x, Lit(a + b))`
//! - `Add(Lit(b), Add(Lit(a), x))` → `Add(x, Lit(a + b))`
//! - `Add(Add(Lit(a), x), Lit(b))` → `Add(x, Lit(a + b))`
//!
//! Out of scope:
//! - Wrapping addition (`a + b` overflows u32) — refuse to combine
//!   so the wrap semantics of the original chain are preserved
//!   under both interpretations. A future const_fold extension can
//!   handle the wrap case once the saturating-vs-wrapping contract
//!   is explicit on each `BinOp::Add` op.
//! - The inner Add must have exactly one consumer (this outer Add).
//!   Otherwise eliminating it would orphan its other use.
//! - Sub-Sub chains and mixed Add-Sub chains — symmetric in spirit
//!   but each direction has its own inverse; out of scope to keep
//!   the proof obligations small.
//!
//! Recurses. Idempotent. Wired into `CANONICAL_REWRITE_PASSES`
//! after `descriptor_const_fold` so any newly-foldable `Add(Lit,
//! Lit)` produced by this pass gets folded by the post-saturation
//! const_fold rerun.

use crate::{KernelBody, KernelDescriptor, KernelOp, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;
use vyre_foundation::ir::BinOp;

#[must_use]
pub fn add_combine(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = add_combine_body(out.body);
    out
}

fn add_combine_body(mut body: KernelBody) -> KernelBody {
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

    // (op_idx, x_id, combined_lit)
    let mut rewrites: Vec<(usize, u32, u32)> = Vec::new();
    for (idx, op) in body.ops.iter().enumerate() {
        if !matches!(op.kind, KernelOpKind::BinOpKind(BinOp::Add)) {
            continue;
        }
        if op.operands.len() != 2 {
            continue;
        }
        let lhs = op.operands[0];
        let rhs = op.operands[1];

        // Try lhs as the inner-Add side.
        if let Some((x, a)) = candidate_add_with_lit(&body, &result_to_idx, &use_count, lhs) {
            if let Some(b) = u32_lit(&body, &result_to_idx, rhs) {
                if let Some(sum) = a.checked_add(b) {
                    rewrites.push((idx, x, sum));
                    continue;
                }
            }
        }
        // Try rhs as the inner-Add side.
        if let Some((x, a)) = candidate_add_with_lit(&body, &result_to_idx, &use_count, rhs) {
            if let Some(b) = u32_lit(&body, &result_to_idx, lhs) {
                if let Some(sum) = a.checked_add(b) {
                    rewrites.push((idx, x, sum));
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

    for (op_idx, x_id, sum) in rewrites {
        let pool_idx = push_lit(&mut body.literals, LiteralValue::U32(sum));
        let synth_id = next_id;
        next_id += 1;
        body.ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![pool_idx],
            result: Some(synth_id),
        });
        body.ops[op_idx].kind = KernelOpKind::BinOpKind(BinOp::Add);
        body.ops[op_idx].operands = vec![x_id, synth_id];
    }

    body.child_bodies = body
        .child_bodies
        .into_iter()
        .map(add_combine_body)
        .collect();
    body
}

/// If `result_id` was produced by `Add(x, Lit(c))` (or `Add(Lit(c), x)`)
/// with exactly one consumer, return `(x, c)`.
fn candidate_add_with_lit(
    body: &KernelBody,
    result_to_idx: &FxHashMap<u32, usize>,
    use_count: &FxHashMap<u32, u32>,
    result_id: u32,
) -> Option<(u32, u32)> {
    let producer_idx = *result_to_idx.get(&result_id)?;
    let producer = body.ops.get(producer_idx)?;
    if !matches!(producer.kind, KernelOpKind::BinOpKind(BinOp::Add)) {
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

    /// Create a non-literal source op (so candidate_add_with_lit
    /// reliably treats it as the "x" side).
    fn nonliteral_source(body: &mut KernelBody, result: u32) {
        body.ops.push(KernelOp {
            kind: KernelOpKind::GlobalInvocationId,
            operands: vec![0],
            result: Some(result),
        });
    }

    fn descriptor_with(body: KernelBody) -> KernelDescriptor {
        KernelDescriptor {
            id: "add_combine_test".into(),
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
    fn add_chain_combines_when_no_wrap() {
        // (x + 2) + 3 → x + 5; x is GlobalInvocationId (non-literal).
        let mut body = empty_body();
        nonliteral_source(&mut body, 0); // x
        lit_u32(&mut body, 2, 1);
        binop(&mut body, BinOp::Add, 0, 1, 2);
        lit_u32(&mut body, 3, 3);
        binop(&mut body, BinOp::Add, 2, 3, 4);
        let desc = add_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert!(matches!(outer.kind, KernelOpKind::BinOpKind(BinOp::Add)));
        assert_eq!(outer.operands[0], 0, "x should now be operand 0");
        assert_eq!(lit_value_at(&desc, outer.operands[1]), 5);
    }

    #[test]
    fn add_chain_with_lit_on_left_combines() {
        // 3 + (x + 2) → x + 5
        let mut body = empty_body();
        nonliteral_source(&mut body, 0); // x
        lit_u32(&mut body, 2, 1);
        binop(&mut body, BinOp::Add, 0, 1, 2);
        lit_u32(&mut body, 3, 3);
        binop(&mut body, BinOp::Add, 3, 2, 4);
        let desc = add_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert!(matches!(outer.kind, KernelOpKind::BinOpKind(BinOp::Add)));
        assert_eq!(lit_value_at(&desc, outer.operands[1]), 5);
    }

    #[test]
    fn wrapping_sum_left_alone() {
        // (x + 0xFFFFFFFE) + 5 → would wrap; refuse to combine.
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 0xFFFF_FFFE, 1);
        binop(&mut body, BinOp::Add, 0, 1, 2);
        lit_u32(&mut body, 5, 3);
        binop(&mut body, BinOp::Add, 2, 3, 4);
        let desc = add_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(
            outer.operands[0], 2,
            "Fix: refuse to fold when the sum would wrap; chain stays as-is."
        );
    }

    #[test]
    fn inner_add_with_multiple_consumers_left_alone() {
        // (x + 2) appears in BOTH (x + 2) + 3 AND another consumer.
        // Cannot fold — the inner Add must stay live for the second
        // consumer.
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 2, 1);
        binop(&mut body, BinOp::Add, 0, 1, 2);
        lit_u32(&mut body, 3, 3);
        binop(&mut body, BinOp::Add, 2, 3, 4);
        // Second consumer of result-2:
        binop(&mut body, BinOp::Add, 2, 0, 5);
        let desc = add_combine(&descriptor_with(body));
        let outer = op_at(&desc, 4);
        assert_eq!(
            outer.operands[0], 2,
            "Fix: inner Add must have exactly one consumer for the fold to fire."
        );
    }

    #[test]
    fn non_literal_outer_unchanged() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 2, 1);
        binop(&mut body, BinOp::Add, 0, 1, 2);
        // outer rhs is the result of another Add (not a literal)
        lit_u32(&mut body, 1, 3);
        lit_u32(&mut body, 1, 4);
        binop(&mut body, BinOp::Add, 3, 4, 5);
        binop(&mut body, BinOp::Add, 2, 5, 6);
        let desc = add_combine(&descriptor_with(body));
        let outer = op_at(&desc, 6);
        assert_eq!(outer.operands[0], 2);
        assert_eq!(outer.operands[1], 5);
    }

    #[test]
    fn rewrite_is_idempotent() {
        let mut body = empty_body();
        nonliteral_source(&mut body, 0);
        lit_u32(&mut body, 2, 1);
        binop(&mut body, BinOp::Add, 0, 1, 2);
        lit_u32(&mut body, 3, 3);
        binop(&mut body, BinOp::Add, 2, 3, 4);
        let desc = descriptor_with(body);
        let once = add_combine(&desc);
        let twice = add_combine(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn recurses_into_child_bodies() {
        let mut child = empty_body();
        // Use a non-literal source via a synthesised GlobalInvocationId.
        child.ops.push(KernelOp {
            kind: KernelOpKind::GlobalInvocationId,
            operands: vec![0],
            result: Some(10),
        });
        lit_u32(&mut child, 4, 11);
        binop(&mut child, BinOp::Add, 10, 11, 12);
        lit_u32(&mut child, 6, 13);
        binop(&mut child, BinOp::Add, 12, 13, 14);
        let mut body = empty_body();
        body.child_bodies.push(child);
        let desc = add_combine(&descriptor_with(body));
        let outer = desc.body.child_bodies[0]
            .ops
            .iter()
            .find(|op| op.result == Some(14))
            .unwrap();
        assert!(matches!(outer.kind, KernelOpKind::BinOpKind(BinOp::Add)));
        assert_eq!(outer.operands[0], 10);
        let pool_idx = desc.body.child_bodies[0]
            .ops
            .iter()
            .find(|op| op.result == Some(outer.operands[1]))
            .unwrap()
            .operands[0] as usize;
        assert_eq!(
            desc.body.child_bodies[0].literals[pool_idx],
            LiteralValue::U32(10)
        );
    }
}
