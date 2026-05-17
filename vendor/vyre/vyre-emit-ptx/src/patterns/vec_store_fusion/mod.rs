//! PERF B1 (PTX-side): vector-store fusion candidate detection.
//!
//! Mirror of [`super::vec_load_fusion`] for `StoreGlobal`. NVIDIA
//! GPUs support `st.global.v2.u32` and `st.global.v4.u32` for packed
//! stores — same throughput benefits as the load side.
//!
//! Same chain shape: `Store(slot, base_idx, val0); Add(base, 1);
//! Store(slot, idx1, val1); Add(idx1, 1); Store(slot, idx2, val2); ...`
//! up to 4 stores. The PTX emitter lowers the same chain to packed
//! `st.global.v2/v4` instructions.
//!
//! Differences from the load-side analysis:
//! - Stores have no result-id (the chain check looks at the index
//!   operand instead of the result).
//! - The "value" operands of the chained stores are independent —
//!   they go into the v2/v4 register the way they appear.
//! - Same alignment requirement: `group_size * elem_size` bytes.

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use vyre_foundation::ir::{BinOp, DataType};
use vyre_lower::{BindingSlot, KernelBody, KernelDescriptor, KernelOpKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionCandidate {
    /// Op-index of the FIRST store in the group.
    pub first_store_idx: usize,
    /// Number of stores in the group (2 or 4 — PTX has no v3).
    pub group_size: u8,
    /// Binding slot all stores share.
    pub binding_slot: u32,
    /// Element type from the binding.
    pub element_type: DataType,
    /// Required base-pointer alignment in bytes.
    pub alignment_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FusionPlan {
    pub candidates: Vec<FusionCandidate>,
}

#[must_use]
pub fn analyze(desc: &KernelDescriptor) -> FusionPlan {
    let mut plan = FusionPlan::default();
    let binding_by_slot: FxHashMap<u32, &BindingSlot> = desc
        .bindings
        .slots
        .iter()
        .map(|binding| (binding.slot, binding))
        .collect();
    walk(&desc.body, &binding_by_slot, &mut plan);
    plan
}

fn walk(body: &KernelBody, binding_by_slot: &FxHashMap<u32, &BindingSlot>, plan: &mut FusionPlan) {
    let mut producer: FxHashMap<u32, usize> =
        FxHashMap::with_capacity_and_hasher(body.ops.len(), Default::default());
    for (idx, op) in body.ops.iter().enumerate() {
        if let Some(rid) = op.result {
            producer.insert(rid, idx);
        }
    }

    let mut lit_value: FxHashMap<u32, u32> =
        FxHashMap::with_capacity_and_hasher(body.literals.len(), Default::default());
    for op in &body.ops {
        if matches!(op.kind, KernelOpKind::Literal) {
            if let (Some(rid), Some(&pool_idx)) = (op.result, op.operands.first()) {
                if let Some(lit) = body.literals.get(pool_idx as usize) {
                    use vyre_lower::LiteralValue;
                    let v = match lit {
                        LiteralValue::U32(v) => Some(*v),
                        LiteralValue::I32(v) => Some(*v as u32),
                        _ => None,
                    };
                    if let Some(v) = v {
                        lit_value.insert(rid, v);
                    }
                }
            }
        }
    }

    let mut i = 0;
    while i < body.ops.len() {
        let op = &body.ops[i];
        if !matches!(op.kind, KernelOpKind::StoreGlobal) {
            i += 1;
            continue;
        }
        let Some((slot, base_idx_id)) = store_slot_and_index(op) else {
            i += 1;
            continue;
        };
        let Some(binding) = binding_by_slot.get(&slot).copied() else {
            i += 1;
            continue;
        };

        let mut chain_len: u8 = 1;
        let mut prev_idx_id = base_idx_id;
        let mut j = i + 1;
        while j < body.ops.len() && chain_len < 4 {
            let mut next = &body.ops[j];
            if matches!(next.kind, KernelOpKind::BinOpKind(BinOp::Add)) {
                if let Some(rid) = next.result {
                    if is_index_plus_one(rid, prev_idx_id, body, &producer, &lit_value) {
                        j += 1;
                        if j >= body.ops.len() {
                            break;
                        }
                        next = &body.ops[j];
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            if !matches!(next.kind, KernelOpKind::StoreGlobal) {
                break;
            }
            let Some((next_slot, next_idx_id)) = store_slot_and_index(next) else {
                break;
            };
            if next_slot != slot {
                break;
            }
            if !is_index_plus_one(next_idx_id, prev_idx_id, body, &producer, &lit_value) {
                break;
            }
            chain_len += 1;
            prev_idx_id = next_idx_id;
            j += 1;
        }

        if chain_len >= 2 {
            let group_size = if chain_len >= 4 { 4 } else { 2 };
            let elem_size = binding.element_type.size_bytes().unwrap_or(0) as u32;
            plan.candidates.push(FusionCandidate {
                first_store_idx: i,
                group_size,
                binding_slot: slot,
                element_type: binding.element_type.clone(),
                alignment_bytes: group_size as u32 * elem_size,
            });
            i += (group_size as usize) * 2 - 1;
        } else {
            i += 1;
        }
    }

    for child in &body.child_bodies {
        walk(child, binding_by_slot, plan);
    }
}

fn store_slot_and_index(op: &vyre_lower::KernelOp) -> Option<(u32, u32)> {
    if op.operands.len() < 3 {
        return None;
    }
    Some((op.operands[0], op.operands[1]))
}

fn is_index_plus_one(
    candidate_id: u32,
    prev_id: u32,
    body: &KernelBody,
    producer: &FxHashMap<u32, usize>,
    lit_value: &FxHashMap<u32, u32>,
) -> bool {
    let Some(&op_idx) = producer.get(&candidate_id) else {
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
    let one_check = |id: u32| lit_value.get(&id) == Some(&1);
    (lhs == prev_id && one_check(rhs)) || (rhs == prev_id && one_check(lhs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::ir::DataType;
    use vyre_lower::{
        BindingLayout, BindingSlot, BindingVisibility, Dispatch, KernelBody, KernelDescriptor,
        KernelOp, KernelOpKind, LiteralValue, MemoryClass,
    };

    fn slot() -> BindingSlot {
        BindingSlot {
            slot: 0,
            element_type: DataType::U32,
            element_count: None,
            memory_class: MemoryClass::Global,
            visibility: BindingVisibility::WriteOnly,
            name: "out".into(),
        }
    }

    fn build(ops: Vec<KernelOp>, lits: Vec<LiteralValue>) -> KernelDescriptor {
        KernelDescriptor {
            id: "k".into(),
            bindings: BindingLayout {
                slots: vec![slot()],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops,
                child_bodies: vec![],
                literals: lits,
            },
        }
    }

    #[test]
    fn no_stores_no_candidates() {
        assert!(analyze(&build(vec![], vec![])).candidates.is_empty());
    }

    #[test]
    fn two_consecutive_stores_with_idx_plus_one_form_v2_candidate() {
        // r0 = Lit(0)            // base idx
        // r1 = Lit(1)            // stride
        // r2 = Lit(7)            // val0
        // r3 = Lit(8)            // val1
        // Store(slot=0, idx=r0, val=r2)
        // r4 = Add(r0, r1)       // idx+1
        // Store(slot=0, idx=r4, val=r3)
        let desc = build(
            vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![3],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 0, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 4, 3],
                    result: None,
                },
            ],
            vec![
                LiteralValue::U32(0),
                LiteralValue::U32(1),
                LiteralValue::U32(7),
                LiteralValue::U32(8),
            ],
        );
        let plan = analyze(&desc);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].group_size, 2);
        assert_eq!(plan.candidates[0].alignment_bytes, 8);
    }

    #[test]
    fn four_stores_form_v4_candidate() {
        let desc = build(
            vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                }, // base
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                }, // stride
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                }, // val
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 0, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 3, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![3, 1],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 4, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![4, 1],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 5, 2],
                    result: None,
                },
            ],
            vec![
                LiteralValue::U32(0),
                LiteralValue::U32(1),
                LiteralValue::U32(7),
            ],
        );
        let plan = analyze(&desc);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].group_size, 4);
        assert_eq!(plan.candidates[0].alignment_bytes, 16);
    }

    #[test]
    fn single_store_no_candidate() {
        let desc = build(
            vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 0, 1],
                    result: None,
                },
            ],
            vec![LiteralValue::U32(0), LiteralValue::U32(7)],
        );
        let plan = analyze(&desc);
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn stores_to_different_slots_dont_chain() {
        let mut s2 = slot();
        s2.slot = 1;
        s2.name = "out2".into();
        let desc = KernelDescriptor {
            id: "k".into(),
            bindings: BindingLayout {
                slots: vec![slot(), s2],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![2],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    },
                    KernelOp {
                        kind: KernelOpKind::BinOpKind(BinOp::Add),
                        operands: vec![0, 1],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![1, 3, 2],
                        result: None,
                    },
                ],
                child_bodies: vec![],
                literals: vec![
                    LiteralValue::U32(0),
                    LiteralValue::U32(1),
                    LiteralValue::U32(7),
                ],
            },
        };
        assert!(analyze(&desc).candidates.is_empty());
    }

    #[test]
    fn three_stores_only_yields_v2() {
        let desc = build(
            vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 0, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 3, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![3, 1],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 4, 2],
                    result: None,
                },
            ],
            vec![
                LiteralValue::U32(0),
                LiteralValue::U32(1),
                LiteralValue::U32(7),
            ],
        );
        let plan = analyze(&desc);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].group_size, 2);
    }
}
