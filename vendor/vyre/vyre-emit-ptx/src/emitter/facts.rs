use rustc_hash::FxHashMap;
use vyre_foundation::ir::BinOp;
use vyre_lower::{KernelBody, KernelOpKind, LiteralValue};

pub(super) struct EmitFacts {
    producer: FxHashMap<u32, usize>,
    lit_u32: FxHashMap<u32, u32>,
}

impl EmitFacts {
    pub(super) fn new(body: &KernelBody) -> Self {
        let mut producer = FxHashMap::with_capacity_and_hasher(body.ops.len(), Default::default());
        let mut lit_u32 = FxHashMap::with_capacity_and_hasher(body.ops.len(), Default::default());
        for (idx, op) in body.ops.iter().enumerate() {
            let Some(result_id) = op.result else {
                continue;
            };
            producer.insert(result_id, idx);
            if !matches!(op.kind, KernelOpKind::Literal) {
                continue;
            }
            let Some(&pool_idx) = op.operands.first() else {
                continue;
            };
            let Some(lit) = body.literals.get(pool_idx as usize) else {
                continue;
            };
            let value = match lit {
                LiteralValue::U32(value) => Some(*value),
                LiteralValue::I32(value) => Some(*value as u32),
                _ => None,
            };
            if let Some(value) = value {
                lit_u32.insert(result_id, value);
            }
        }
        Self { producer, lit_u32 }
    }

    pub(super) fn is_index_plus_one(
        &self,
        body: &KernelBody,
        candidate_id: u32,
        prev_id: u32,
    ) -> bool {
        let Some(&op_idx) = self.producer.get(&candidate_id) else {
            return false;
        };
        let op = &body.ops[op_idx];
        let KernelOpKind::BinOpKind(BinOp::Add) = op.kind else {
            return false;
        };
        if op.operands.len() != 2 {
            return false;
        }
        let lhs = op.operands[0];
        let rhs = op.operands[1];
        let is_one = |id: u32| self.lit_u32.get(&id) == Some(&1);
        (lhs == prev_id && is_one(rhs)) || (rhs == prev_id && is_one(lhs))
    }

    pub(super) fn producer_idx(&self, result_id: u32) -> Option<usize> {
        self.producer.get(&result_id).copied()
    }
}
