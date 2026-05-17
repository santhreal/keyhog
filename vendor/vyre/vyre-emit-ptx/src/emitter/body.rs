use std::fmt::Write as _;

use smallvec::SmallVec;
use vyre_lower::{KernelBody, KernelOp};

use super::facts::EmitFacts;
use super::schedule::{
    is_latency_load, is_schedulable_pure_op, is_scheduling_fence, op_reads_operand,
    operand_is_immediate,
};
use super::BodyCtx;
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
                    let Some(filler_idx) =
                        self.find_latency_filler_avoiding_results(body, idx, &blocked_results, &skip)
                    else {
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
            self.emit_op(body, &body.ops[idx])?;
            if is_latency_load(&body.ops[idx]) {
                let blocked_results = body.ops[idx].result.into_iter().collect::<SmallVec<[u32; 1]>>();
                for _ in 0..MAX_LOAD_GAP_FILLERS {
                    let Some(filler_idx) =
                        self.find_latency_filler_avoiding_results(body, idx, &blocked_results, &skip)
                    else {
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
}
