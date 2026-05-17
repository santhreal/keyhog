//! PERF B1 (PTX-side): vector-load fusion candidate detection.
//!
//! NVIDIA GPUs support packed vector loads: `ld.global.v2.u32` and
//! `ld.global.v4.u32` move 8 or 16 bytes per transaction with one
//! memory request, instead of 2 or 4 scalar 4-byte loads. On
//! memory-bound kernels this is up to 4× throughput AND reduces
//! per-load address-arithmetic instructions (mul.wide / add.u64).
//!
//! This pattern detects fusion candidates: groups of 2 or 4
//! consecutive `LoadGlobal` ops in the body's flat op stream that:
//!
//! 1. Read from the same `binding_slot`.
//! 2. Have indices `i, i+1, i+2, [i+3]` for the same base — detected
//!    when consecutive load's index_id is the result of an `Add(prev_index_id, Lit(1))`
//!    op present in the body.
//! 3. Have no intervening op (other than the index-increment Adds).
//! 4. The base index is naturally aligned for the vector width
//!    (alignment_required is reported; the host may need to verify
//!    this against the runtime allocation alignment).
//!
//! The PTX emitter consumes the same chain shape directly and emits a
//! packed vector load while binding every scalar result id to the
//! registers returned by the vector instruction.
//!
//! Same shape as `vyre-emit-naga::patterns::vec_pack` but PTX-aware:
//! reports vector widths PTX supports (`v2`, `v4`), alignment in
//! bytes, and the expected register class.

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use vyre_foundation::ir::{BinOp, DataType};
use vyre_lower::{BindingSlot, KernelBody, KernelDescriptor, KernelOpKind};

/// One fusion candidate: a group of consecutive scalar loads that
/// could be merged into a single PTX vector load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionCandidate {
    /// Op-index of the FIRST load in the group.
    pub first_load_idx: usize,
    /// Number of loads in the group (2 or 4 only — PTX doesn't have
    /// `v3` loads).
    pub group_size: u8,
    /// Binding slot all loads share.
    pub binding_slot: u32,
    /// Element type all loads share — must be same.
    pub element_type: DataType,
    /// Required base-pointer alignment in bytes for the fused load
    /// to be valid: `group_size * element_size`. Host-side allocator
    /// must guarantee this.
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
    // Build a result-id → producer-op map for index-arithmetic lookup.
    // We need to recognize index_n+1 = Add(index_n, Lit(1)).
    let mut producer: FxHashMap<u32, usize> =
        FxHashMap::with_capacity_and_hasher(body.ops.len(), Default::default());
    for (idx, op) in body.ops.iter().enumerate() {
        if let Some(rid) = op.result {
            producer.insert(rid, idx);
        }
    }

    // Result-id → constant-int value (only for ops produced by
    // `Literal` whose pool entry is U32 or I32).
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

    // Walk consecutive loads.
    let mut i = 0;
    while i < body.ops.len() {
        let op = &body.ops[i];
        if !matches!(op.kind, KernelOpKind::LoadGlobal) {
            i += 1;
            continue;
        }
        let Some((slot, base_idx_id)) = load_slot_and_index(op) else {
            i += 1;
            continue;
        };
        let Some(binding) = binding_by_slot.get(&slot).copied() else {
            i += 1;
            continue;
        };

        // How many loads form a chain from this point? The natural
        // pattern is `Load; Add(prev_idx, Lit(1)); Load; Add(...); ...`.
        // We allow ONLY index-increment Add ops between the loads —
        // anything else (Mul, Store, Barrier, etc.) breaks the chain.
        let mut chain_len: u8 = 1;
        let mut prev_idx_id = base_idx_id;
        let mut j = i + 1;
        while j < body.ops.len() && chain_len < 4 {
            // Skip exactly one index-increment Add op if present.
            let mut next = &body.ops[j];
            if matches!(next.kind, KernelOpKind::BinOpKind(BinOp::Add)) {
                if let Some(rid) = next.result {
                    if is_index_plus_one(rid, prev_idx_id, body, &producer, &lit_value) {
                        // This Add produces the next index — skip it
                        // and look at the following op.
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
            if !matches!(next.kind, KernelOpKind::LoadGlobal) {
                break;
            }
            let Some((next_slot, next_idx_id)) = load_slot_and_index(next) else {
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

        // PTX supports v2 and v4 loads only.
        if chain_len >= 2 {
            let group_size = if chain_len >= 4 { 4 } else { 2 };
            let elem_size = binding.element_type.size_bytes().unwrap_or(0) as u32;
            plan.candidates.push(FusionCandidate {
                first_load_idx: i,
                group_size,
                binding_slot: slot,
                element_type: binding.element_type.clone(),
                alignment_bytes: group_size as u32 * elem_size,
            });
            // Skip past the loads we just claimed (and the Adds between them).
            // Each load (except the first) is preceded by one Add → 2*group_size - 1
            // ops in total cover the chain. Advance by that many.
            i += (group_size as usize) * 2 - 1;
        } else {
            i += 1;
        }
    }

    // Recurse into children.
    for child in &body.child_bodies {
        walk(child, binding_by_slot, plan);
    }
}

fn load_slot_and_index(op: &vyre_lower::KernelOp) -> Option<(u32, u32)> {
    if op.operands.len() < 2 {
        return None;
    }
    Some((op.operands[0], op.operands[1]))
}

/// True iff `candidate_id` is produced by an op of the form
/// `BinOpKind(Add)` with one operand `prev_id` and the other a
/// Literal U32/I32 with value 1.
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
            visibility: BindingVisibility::ReadWrite,
            name: "buf".into(),
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
    fn no_loads_no_candidates() {
        let plan = analyze(&build(vec![], vec![]));
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn single_load_no_candidate() {
        let desc = build(
            vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(1),
                },
            ],
            vec![LiteralValue::U32(0)],
        );
        let plan = analyze(&desc);
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn two_consecutive_loads_with_idx_plus_one_form_v2_candidate() {
        // r0 = Lit(0), r1 = Lit(1)
        // r2 = Load(slot=0, idx=r0)
        // r3 = Add(r0, r1)  ; idx+1
        // r4 = Load(slot=0, idx=r3)
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
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 3],
                    result: Some(4),
                },
            ],
            vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        );
        let plan = analyze(&desc);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].group_size, 2);
        assert_eq!(plan.candidates[0].binding_slot, 0);
        assert_eq!(plan.candidates[0].alignment_bytes, 8); // 2 * 4
    }

    #[test]
    fn four_consecutive_chained_loads_form_v4_candidate() {
        // r0 = Lit(0), r1 = Lit(1)
        // r2 = Load(0)
        // r3 = Add(0, 1)
        // r4 = Load(3)
        // r5 = Add(3, 1)
        // r6 = Load(5)
        // r7 = Add(5, 1)
        // r8 = Load(7)
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
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 3],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![3, 1],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 5],
                    result: Some(6),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![5, 1],
                    result: Some(7),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 7],
                    result: Some(8),
                },
            ],
            vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        );
        let plan = analyze(&desc);
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].group_size, 4);
        assert_eq!(plan.candidates[0].alignment_bytes, 16); // 4 * 4
    }

    #[test]
    fn loads_to_different_slots_dont_chain() {
        let mut s2 = slot();
        s2.slot = 1;
        s2.name = "buf2".into();
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
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![0, 0],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::BinOpKind(BinOp::Add),
                        operands: vec![0, 1],
                        result: Some(3),
                    },
                    // Different slot — chain breaks.
                    KernelOp {
                        kind: KernelOpKind::LoadGlobal,
                        operands: vec![1, 3],
                        result: Some(4),
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(0), LiteralValue::U32(1)],
            },
        };
        let plan = analyze(&desc);
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn non_unit_stride_doesnt_chain() {
        // Add by 2 instead of 1 — not a v-load candidate.
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
                }, // 2
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 3],
                    result: Some(4),
                },
            ],
            vec![LiteralValue::U32(0), LiteralValue::U32(2)],
        );
        let plan = analyze(&desc);
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn intervening_non_add_op_breaks_chain() {
        // Load r2; non-Add intervening op; Add; Load.
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
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Mul),
                    operands: vec![2, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 4],
                    result: Some(5),
                },
            ],
            vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        );
        // The Mul between the two loads breaks the consecutive-loads
        // sequence — chain detection requires loads back-to-back in
        // the op stream.
        let plan = analyze(&desc);
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn three_loads_only_yields_v2_candidate() {
        // Chain of 3 — PTX has no v3, so we report v2 (covers first 2).
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
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 3],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![3, 1],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 5],
                    result: Some(6),
                },
            ],
            vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        );
        let plan = analyze(&desc);
        // First 2 loads form a v2 candidate; the 3rd is left as scalar.
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].group_size, 2);
    }
}
