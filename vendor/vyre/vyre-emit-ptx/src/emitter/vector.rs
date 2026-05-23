use std::fmt::Write as _;

use smallvec::SmallVec;
use vyre_foundation::ir::BinOp;
use vyre_lower::{KernelBody, KernelOpKind};

use super::facts::EmitFacts;
use super::format::{is_ptx_vectorizable_dtype, write_reg_tuple};
use super::operands::{read_store_operands, read_two_operands};
use super::BodyCtx;
use crate::reg::PtxType;
use crate::EmitError;

type VectorChain = SmallVec<[usize; 4]>;
const PTX_VECTOR_WIDTH_V2: usize = 2;
const PTX_VECTOR_WIDTH_V4: usize = 4;
const PTX_VECTOR_LOAD_GLOBAL_PREFIX: &str = "ld.global";
const PTX_VECTOR_LOAD_SHARED_PREFIX: &str = "ld.shared";

impl BodyCtx<'_> {
    pub(super) fn collect_vec_load_chain(
        &self,
        body: &KernelBody,
        facts: &EmitFacts,
        start_idx: usize,
    ) -> Result<Option<VectorChain>, EmitError> {
        let op = &body.ops[start_idx];
        if !matches!(op.kind, KernelOpKind::LoadGlobal) {
            return Ok(None);
        }
        let (slot, base_idx_id) = read_two_operands(op, "LoadGlobal")?;
        let binding = self.binding_for_slot(slot)?;
        if !is_ptx_vectorizable_dtype(&binding.element_type) || op.result.is_none() {
            return Ok(None);
        }

        let mut chain = SmallVec::from_buf([start_idx, 0, 0, 0]);
        chain.truncate(1);
        let mut prev_idx_id = base_idx_id;
        let mut scan_idx = start_idx + 1;
        while scan_idx < body.ops.len() && chain.len() < PTX_VECTOR_WIDTH_V4 {
            let mut next_idx = scan_idx;
            let next = &body.ops[next_idx];
            if matches!(next.kind, KernelOpKind::BinOpKind(BinOp::Add)) {
                let Some(result_id) = next.result else {
                    break;
                };
                if !facts.is_index_plus_one(body, result_id, prev_idx_id) {
                    break;
                }
                next_idx += 1;
                if next_idx >= body.ops.len() {
                    break;
                }
            }

            let next = &body.ops[next_idx];
            if !matches!(next.kind, KernelOpKind::LoadGlobal) || next.result.is_none() {
                break;
            }
            let (next_slot, next_index_id) = read_two_operands(next, "LoadGlobal")?;
            if next_slot != slot || !facts.is_index_plus_one(body, next_index_id, prev_idx_id) {
                break;
            }
            chain.push(next_idx);
            prev_idx_id = next_index_id;
            scan_idx = next_idx + 1;
        }

        truncate_vector_chain(chain)
    }

    pub(super) fn collect_vec_store_chain(
        &self,
        body: &KernelBody,
        facts: &EmitFacts,
        start_idx: usize,
    ) -> Result<Option<VectorChain>, EmitError> {
        let op = &body.ops[start_idx];
        if !matches!(op.kind, KernelOpKind::StoreGlobal) {
            return Ok(None);
        }
        let (slot, base_idx_id, _) = read_store_operands(op)?;
        let binding = self.binding_for_slot(slot)?;
        if !is_ptx_vectorizable_dtype(&binding.element_type) {
            return Ok(None);
        }

        let mut chain = SmallVec::from_buf([start_idx, 0, 0, 0]);
        chain.truncate(1);
        let mut prev_idx_id = base_idx_id;
        let mut scan_idx = start_idx + 1;
        while scan_idx < body.ops.len() && chain.len() < PTX_VECTOR_WIDTH_V4 {
            let mut next_idx = scan_idx;
            let next = &body.ops[next_idx];
            if matches!(next.kind, KernelOpKind::BinOpKind(BinOp::Add)) {
                let Some(result_id) = next.result else {
                    break;
                };
                if !facts.is_index_plus_one(body, result_id, prev_idx_id) {
                    break;
                }
                next_idx += 1;
                if next_idx >= body.ops.len() {
                    break;
                }
            }

            let next = &body.ops[next_idx];
            if !matches!(next.kind, KernelOpKind::StoreGlobal) {
                break;
            }
            let (next_slot, next_index_id, _) = read_store_operands(next)?;
            if next_slot != slot || !facts.is_index_plus_one(body, next_index_id, prev_idx_id) {
                break;
            }
            chain.push(next_idx);
            prev_idx_id = next_index_id;
            scan_idx = next_idx + 1;
        }

        truncate_vector_chain(chain)
    }

    pub(super) fn emit_vec_load_chain(
        &mut self,
        body: &KernelBody,
        chain: &[usize],
    ) -> Result<(), EmitError> {
        let first = &body.ops[chain[0]];
        let (binding_slot, index_op_id) = read_two_operands(first, "LoadGlobal")?;
        let element_type = self.binding_for_slot(binding_slot)?.element_type.clone();
        let memory_class = self.binding_for_slot(binding_slot)?.memory_class;
        let elem_ty = PtxType::from_dtype(&element_type)?;
        let final_addr =
            self.emit_global_address_operand(binding_slot, index_op_id, &element_type)?;
        let load_space = self.load_space_for(binding_slot, memory_class);
        let mut regs: SmallVec<[crate::reg::Reg; 4]> = SmallVec::new();
        for &op_idx in chain {
            let reg = self.alloc(elem_ty);
            regs.push(reg);
            self.bind_result(&body.ops[op_idx], reg)?;
        }
        let (mnemonic_prefix, cache_suffix) =
            vector_load_mnemonic_parts(load_space).ok_or_else(|| {
                EmitError::InvalidDescriptor(format!(
                    "unsupported PTX vector load space `{load_space}` for fused vector load"
                ))
            })?;
        let _ = write!(
            self.text,
            "    {mnemonic_prefix}{cache_suffix}.v{}.{}    ",
            chain.len(),
            elem_ty.ptx_type_str()
        );
        write_reg_tuple(&mut self.text, &regs);
        self.text.push_str(", ");
        self.write_mem_operand(final_addr)?;
        self.text.push_str(";\n");
        Ok(())
    }

    pub(super) fn emit_vec_store_chain(
        &mut self,
        body: &KernelBody,
        chain: &[usize],
    ) -> Result<(), EmitError> {
        let first = &body.ops[chain[0]];
        let (binding_slot, index_op_id, _) = read_store_operands(first)?;
        let element_type = self.binding_for_slot(binding_slot)?.element_type.clone();
        let elem_ty = PtxType::from_dtype(&element_type)?;
        let final_addr =
            self.emit_global_address_operand(binding_slot, index_op_id, &element_type)?;
        let mut regs: SmallVec<[crate::reg::Reg; 4]> = SmallVec::new();
        for &op_idx in chain {
            let (_, _, value_op_id) = read_store_operands(&body.ops[op_idx])?;
            regs.push(self.lookup_operand(value_op_id)?);
        }
        let _ = write!(
            self.text,
            "    st.global.v{}.{}    ",
            chain.len(),
            elem_ty.ptx_type_str()
        );
        self.write_mem_operand(final_addr)?;
        self.text.push_str(", ");
        write_reg_tuple(&mut self.text, &regs);
        self.text.push_str(";\n");
        Ok(())
    }

    pub(super) fn mark_dead_vec_index_ops(
        &self,
        body: &KernelBody,
        facts: &EmitFacts,
        chain: &[usize],
        skip: &mut [bool],
    ) -> Result<(), EmitError> {
        let mut index_adds: SmallVec<[(usize, u32); 3]> = SmallVec::new();
        for pair in chain.windows(2) {
            let prev = &body.ops[pair[0]];
            let next = &body.ops[pair[1]];
            let prev_index = vector_index_operand(prev)?;
            let next_index = vector_index_operand(next)?;
            if !facts.is_index_plus_one(body, next_index, prev_index) {
                continue;
            }
            let Some(add_idx) = facts.producer_idx(next_index) else {
                continue;
            };
            index_adds.push((add_idx, next_index));
        }
        if index_adds.is_empty() {
            return Ok(());
        }
        if index_adds.iter().any(|(idx, _)| {
            !matches!(
                body.ops.get(*idx).map(|op| &op.kind),
                Some(KernelOpKind::BinOpKind(BinOp::Add))
            )
        }) {
            return Ok(());
        }
        let internal_use = |consumer_idx: usize| {
            chain.contains(&consumer_idx) || index_adds.iter().any(|(idx, _)| *idx == consumer_idx)
        };
        for (_, result_id) in &index_adds {
            for (consumer_idx, op) in body.ops.iter().enumerate() {
                if internal_use(consumer_idx) {
                    continue;
                }
                if op.operands.iter().any(|operand| operand == result_id) {
                    return Ok(());
                }
            }
        }
        for (idx, _) in index_adds {
            if let Some(slot) = skip.get_mut(idx) {
                *slot = true;
            }
        }
        Ok(())
    }
}

fn truncate_vector_chain(mut chain: VectorChain) -> Result<Option<VectorChain>, EmitError> {
    if chain.len() >= PTX_VECTOR_WIDTH_V4 {
        chain.truncate(PTX_VECTOR_WIDTH_V4);
        Ok(Some(chain))
    } else if chain.len() >= PTX_VECTOR_WIDTH_V2 {
        chain.truncate(PTX_VECTOR_WIDTH_V2);
        Ok(Some(chain))
    } else {
        Ok(None)
    }
}

fn vector_load_mnemonic_parts(load_space: &str) -> Option<(&'static str, &'static str)> {
    match load_space {
        "global" => Some((PTX_VECTOR_LOAD_GLOBAL_PREFIX, "")),
        "global.nc" => Some((PTX_VECTOR_LOAD_GLOBAL_PREFIX, ".nc")),
        "shared" => Some((PTX_VECTOR_LOAD_SHARED_PREFIX, "")),
        _ => None,
    }
}

fn vector_index_operand(op: &vyre_lower::KernelOp) -> Result<u32, EmitError> {
    match op.kind {
        KernelOpKind::LoadGlobal => read_two_operands(op, "LoadGlobal").map(|(_, index)| index),
        KernelOpKind::StoreGlobal => read_store_operands(op).map(|(_, index, _)| index),
        _ => Err(EmitError::UnsupportedOp(op.clone())),
    }
}
