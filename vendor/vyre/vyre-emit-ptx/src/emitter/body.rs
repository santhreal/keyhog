use std::fmt::Write as _;

use smallvec::SmallVec;
use vyre_foundation::ir::BinOp;
use vyre_lower::{KernelBody, KernelOp, KernelOpKind};

use super::facts::EmitFacts;
use super::schedule::{
    is_latency_load, is_schedulable_pure_op, is_scheduling_fence, op_reads_operand,
    operand_is_immediate,
};
use super::BodyCtx;
use crate::reg::PtxType;
use crate::EmitError;

const MAX_LOAD_GAP_FILLERS: usize = 3;

impl BodyCtx<'_> {
    pub(super) fn emit_body(&mut self, body: &KernelBody) -> Result<(), EmitError> {
        let facts = EmitFacts::new(body);
        let mut skip = vec![false; body.ops.len()];
        let mut idx = 0;
        while idx < body.ops.len() {
            if skip[idx] {
                idx += 1;
                continue;
            }
            if let Some(chain) = self.collect_vec_load_chain(body, &facts, idx)? {
                self.emit_vec_load_chain(body, &chain)?;
                for &op_idx in chain.iter().skip(1) {
                    skip[op_idx] = true;
                }
                self.mark_dead_vec_index_ops(body, &facts, &chain, &mut skip)?;
                let blocked_results = chain
                    .iter()
                    .filter_map(|op_idx| body.ops.get(*op_idx).and_then(|op| op.result))
                    .collect::<SmallVec<[u32; 4]>>();
                for _ in 0..MAX_LOAD_GAP_FILLERS {
                    let Some(filler_idx) = self.find_latency_filler_avoiding_results(
                        body,
                        idx,
                        &blocked_results,
                        &skip,
                    ) else {
                        break;
                    };
                    let _ = writeln!(
                        self.text,
                        "    // schedule: hoist independent op#{filler_idx} into vector-load gap after op#{idx}"
                    );
                    self.emit_op(body, &body.ops[filler_idx])?;
                    skip[filler_idx] = true;
                }
                idx += 1;
                continue;
            }
            if let Some(chain) = self.collect_vec_store_chain(body, &facts, idx)? {
                self.emit_vec_store_chain(body, &chain)?;
                for &op_idx in chain.iter().skip(1) {
                    skip[op_idx] = true;
                }
                self.mark_dead_vec_index_ops(body, &facts, &chain, &mut skip)?;
                idx += 1;
                continue;
            }
            if self.should_defer_integer_mul_for_mad(body, &facts, idx) {
                skip[idx] = true;
                idx += 1;
                continue;
            }
            if self.emit_integer_mad_from_add(body, &facts, &body.ops[idx])? {
                idx += 1;
                continue;
            }
            self.emit_op(body, &body.ops[idx])?;
            if is_latency_load(&body.ops[idx]) {
                let blocked_results = body.ops[idx]
                    .result
                    .into_iter()
                    .collect::<SmallVec<[u32; 1]>>();
                for _ in 0..MAX_LOAD_GAP_FILLERS {
                    let Some(filler_idx) = self.find_latency_filler_avoiding_results(
                        body,
                        idx,
                        &blocked_results,
                        &skip,
                    ) else {
                        break;
                    };
                    let _ = writeln!(
                        self.text,
                        "    // schedule: hoist independent op#{filler_idx} into load-use gap after op#{idx}"
                    );
                    self.emit_op(body, &body.ops[filler_idx])?;
                    skip[filler_idx] = true;
                }
            }
            idx += 1;
        }
        Ok(())
    }

    fn find_latency_filler_avoiding_results(
        &self,
        body: &KernelBody,
        anchor_idx: usize,
        blocked_results: &[u32],
        skip: &[bool],
    ) -> Option<usize> {
        if blocked_results.is_empty() {
            return None;
        }
        let upper = body.ops.len().min(anchor_idx.saturating_add(10));
        for candidate_idx in anchor_idx + 1..upper {
            if skip.get(candidate_idx).copied().unwrap_or(false) {
                continue;
            }
            let candidate = &body.ops[candidate_idx];
            if is_scheduling_fence(candidate) {
                break;
            }
            if blocked_results
                .iter()
                .any(|result| op_reads_operand(candidate, *result))
            {
                continue;
            }
            if self.is_ready_pure_op(candidate) {
                return Some(candidate_idx);
            }
        }
        None
    }

    fn is_ready_pure_op(&self, op: &KernelOp) -> bool {
        if !is_schedulable_pure_op(op) {
            return false;
        }
        if let Some(result) = op.result {
            if self.operand_to_reg.contains_key(&result) {
                return false;
            }
        }
        op.operands.iter().all(|operand| {
            operand_is_immediate(op, *operand) || self.operand_to_reg.contains_key(operand)
        })
    }

    /// Skip emitting a standalone integer `mul` when its result is consumed
    /// by exactly one `add`/`wrapping_add` that `emit_integer_mad_from_add`
    /// will fuse into a `mad` - otherwise the `mul` is dead (the `mad`
    /// recomputes the product from the same operands). Delegating to
    /// `integer_mad_parts` keeps this predicate in lock-step with the actual
    /// fusion: we only defer when the `mad` provably fires, so a live `mul`
    /// is never dropped (worst case the opt is missed, leaving the prior
    /// behaviour).
    fn should_defer_integer_mul_for_mad(
        &self,
        body: &KernelBody,
        facts: &EmitFacts,
        op_idx: usize,
    ) -> bool {
        let Some(op) = body.ops.get(op_idx) else {
            return false;
        };
        if !matches!(op.kind, KernelOpKind::BinOpKind(BinOp::Mul)) || op.operands.len() != 2 {
            return false;
        }
        let Some(result) = op.result else {
            return false;
        };
        let consumer_idx = match facts.consumer_indices(result) {
            Some([idx]) => *idx,
            _ => return false,
        };
        let Some(consumer) = body.ops.get(consumer_idx) else {
            return false;
        };
        if !matches!(
            consumer.kind,
            KernelOpKind::BinOpKind(BinOp::Add | BinOp::WrappingAdd)
        ) || consumer.operands.len() != 2
        {
            return false;
        }
        let lhs = consumer.operands[0];
        let rhs = consumer.operands[1];
        self.integer_mad_parts(body, facts, lhs, rhs).is_some()
            || self.integer_mad_parts(body, facts, rhs, lhs).is_some()
    }

    fn emit_integer_mad_from_add(
        &mut self,
        body: &KernelBody,
        facts: &EmitFacts,
        op: &KernelOp,
    ) -> Result<bool, EmitError> {
        if !matches!(
            op.kind,
            KernelOpKind::BinOpKind(BinOp::Add | BinOp::WrappingAdd)
        ) || op.operands.len() != 2
        {
            return Ok(false);
        }

        let lhs = op.operands[0];
        let rhs = op.operands[1];
        let mad = self
            .integer_mad_parts(body, facts, lhs, rhs)
            .or_else(|| self.integer_mad_parts(body, facts, rhs, lhs));
        let Some((a, b, c, ptx_suffix, out_ty)) = mad else {
            return Ok(false);
        };

        let out = self.alloc(out_ty);
        let _ = writeln!(
            self.text,
            "    mad.lo.{ptx_suffix}    {out}, {a}, {b}, {c};"
        );
        self.bind_result(op, out)?;
        Ok(true)
    }

    fn integer_mad_parts(
        &self,
        body: &KernelBody,
        facts: &EmitFacts,
        mul_result_id: u32,
        addend_id: u32,
    ) -> Option<(
        crate::reg::Reg,
        crate::reg::Reg,
        crate::reg::Reg,
        &'static str,
        PtxType,
    )> {
        if facts.result_use_count(mul_result_id) != 1 {
            return None;
        }
        let producer_idx = facts.producer_idx(mul_result_id)?;
        let producer = body.ops.get(producer_idx)?;
        if !matches!(producer.kind, KernelOpKind::BinOpKind(BinOp::Mul))
            || producer.operands.len() != 2
            || producer.result != Some(mul_result_id)
        {
            return None;
        }
        let a = self.operand_to_reg.get(&producer.operands[0]).copied()?;
        let b = self.operand_to_reg.get(&producer.operands[1]).copied()?;
        let c = self.operand_to_reg.get(&addend_id).copied()?;
        if a.0 != b.0 || a.0 != c.0 {
            return None;
        }
        match a.0 {
            PtxType::U32 => Some((a, b, c, "u32", PtxType::U32)),
            PtxType::I32 => Some((a, b, c, "s32", PtxType::I32)),
            _ => None,
        }
    }
}
