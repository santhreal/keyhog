//! B1 substrate: adjacent-load packing analysis.
//!
//! Detects chains of `LoadGlobal` ops on the same binding slot whose
//! literal indices are consecutive (`i`, `i+1`, `i+2`, `i+3`). Such
//! chains are candidates for vec2/vec4 packed loads  -  one wide
//! transaction instead of N narrow ones, saving (N-1) memory
//! request slots and improving coalescing.
//!
//! Pure analysis on a [`KernelDescriptor`]. The actual rewrite
//! (collapse N adjacent Loads into one wide Load + N AccessIndex
//! projections) is downstream work in `vyre-lower::rewrites`. This
//! substrate just produces the per-body chain inventory.

use crate::{KernelBody, KernelDescriptor, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;

/// One detected adjacent-load chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecPackChain {
    /// The binding slot all loads in the chain target.
    pub slot: u32,
    /// Op indices in the body, in chain order. Length is the
    /// chain length (always >= 2  -  single loads are not a chain).
    pub op_indices: Vec<usize>,
    /// Starting literal index. Subsequent loads target
    /// `start_index + 1`, `+ 2`, ...
    pub start_index: u32,
}

impl VecPackChain {
    /// The width of the packed load this chain enables (2, 3, or
    /// 4 depending on chain length, capped at 4).
    #[must_use]
    pub fn pack_width(&self) -> u32 {
        let len = self.op_indices.len() as u32;
        len.min(4)
    }
}

/// Per-body inventory of vec-pack chains.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VecPackReport {
    /// All chains in the body, sorted by `(slot, start_index)`.
    pub chains: Vec<VecPackChain>,
    /// Total ops eliminated if every chain were packed at its
    /// maximum width.
    pub total_ops_eliminated: u32,
}

impl VecPackReport {
    /// True iff at least one chain was detected.
    #[must_use]
    pub fn has_chains(&self) -> bool {
        !self.chains.is_empty()
    }
}

/// Analyse `desc.body` and return the vec-pack chain inventory.
///
/// O(ops + candidates log candidates) per body. Pure: no allocation outside
/// analysis-local tables and the returned report.
#[must_use]
pub fn analyze(desc: &KernelDescriptor) -> VecPackReport {
    let mut report = VecPackReport::default();
    walk_body(&desc.body, &mut report);
    report.chains.sort_by_key(|c| (c.slot, c.start_index));
    report.total_ops_eliminated = report
        .chains
        .iter()
        .map(|c| (c.op_indices.len() as u32).saturating_sub(1))
        .sum();
    report
}

fn walk_body(body: &KernelBody, report: &mut VecPackReport) {
    detect_chains_in_body(body, report);
    for child in &body.child_bodies {
        walk_body(child, report);
    }
}

fn detect_chains_in_body(body: &KernelBody, report: &mut VecPackReport) {
    let literal_indices = literal_index_by_result(body);
    let mut by_slot: FxHashMap<u32, Vec<(u32, usize)>> =
        FxHashMap::with_capacity_and_hasher(body.ops.len(), Default::default());

    for (op_idx, op) in body.ops.iter().enumerate() {
        let Some((slot, literal_index)) = load_with_literal_index(op, &literal_indices) else {
            continue;
        };
        by_slot
            .entry(slot)
            .or_default()
            .push((literal_index, op_idx));
    }

    for (slot, mut candidates) in by_slot {
        candidates.sort_unstable_by_key(|(literal_index, op_idx)| (*literal_index, *op_idx));
        let mut run_start = 0usize;
        while run_start < candidates.len() {
            let mut run_end = run_start + 1;
            while run_end < candidates.len()
                && candidates[run_end].0 == candidates[run_end - 1].0.saturating_add(1)
            {
                run_end += 1;
            }

            if run_end - run_start >= 2 {
                report.chains.push(VecPackChain {
                    slot,
                    op_indices: candidates[run_start..run_end]
                        .iter()
                        .map(|(_, op_idx)| *op_idx)
                        .collect(),
                    start_index: candidates[run_start].0,
                });
            }
            run_start = run_end;
        }
    }
}

fn literal_index_by_result(body: &KernelBody) -> FxHashMap<u32, u32> {
    let mut out = FxHashMap::with_capacity_and_hasher(body.ops.len(), Default::default());
    for op in &body.ops {
        if !matches!(op.kind, KernelOpKind::Literal) {
            continue;
        }
        let Some(result) = op.result else {
            continue;
        };
        let Some(pool_idx) = op.operands.first() else {
            continue;
        };
        let Some(LiteralValue::U32(value)) = body.literals.get(*pool_idx as usize) else {
            continue;
        };
        out.insert(result, *value);
    }
    out
}

/// Returns `Some((slot, literal_index))` when `op` is a `LoadGlobal` whose
/// index operand resolves to a `LiteralValue::U32`. Otherwise `None`.
fn load_with_literal_index(
    op: &crate::KernelOp,
    literal_indices: &FxHashMap<u32, u32>,
) -> Option<(u32, u32)> {
    if !matches!(op.kind, KernelOpKind::LoadGlobal) {
        return None;
    }
    let slot = *op.operands.first()?;
    let index_op_id = *op.operands.get(1)?;
    literal_indices
        .get(&index_op_id)
        .map(|literal_index| (slot, *literal_index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BindingLayout, BindingSlot, BindingVisibility, Dispatch, KernelBody, KernelDescriptor,
        KernelOp, KernelOpKind, MemoryClass,
    };
    use vyre_foundation::ir::DataType;

    fn input_slot(id: u32, name: &str) -> BindingSlot {
        BindingSlot {
            slot: id,
            element_type: DataType::U32,
            element_count: None,
            memory_class: MemoryClass::Global,
            visibility: BindingVisibility::ReadOnly,
            name: name.into(),
        }
    }

    /// Build a body with N consecutive LoadGlobal(slot, Literal(i)) ops.
    fn linear_load_body(slot: u32, n: u32) -> KernelBody {
        let mut ops = Vec::new();
        let mut literals = Vec::new();
        for i in 0..n {
            literals.push(LiteralValue::U32(i));
            ops.push(KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![i],
                result: Some(i),
            });
        }
        for i in 0..n {
            ops.push(KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![slot, i],
                result: Some(n + i),
            });
        }
        KernelBody {
            ops,
            child_bodies: vec![],
            literals,
        }
    }

    fn desc_with_body(body: KernelBody) -> KernelDescriptor {
        KernelDescriptor {
            id: "k".into(),
            bindings: BindingLayout {
                slots: vec![input_slot(0, "in")],
            },
            dispatch: Dispatch::new(1, 1, 1),
            body,
        }
    }

    #[test]
    fn empty_body_has_no_chains() {
        let desc = desc_with_body(KernelBody {
            ops: vec![],
            child_bodies: vec![],
            literals: vec![],
        });
        let report = analyze(&desc);
        assert!(!report.has_chains());
        assert_eq!(report.total_ops_eliminated, 0);
    }

    #[test]
    fn single_load_is_not_a_chain() {
        let desc = desc_with_body(linear_load_body(0, 1));
        assert!(!analyze(&desc).has_chains());
    }

    #[test]
    fn two_adjacent_loads_form_a_chain() {
        let desc = desc_with_body(linear_load_body(0, 2));
        let report = analyze(&desc);
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].op_indices.len(), 2);
        assert_eq!(report.chains[0].slot, 0);
        assert_eq!(report.chains[0].start_index, 0);
        assert_eq!(report.chains[0].pack_width(), 2);
        assert_eq!(report.total_ops_eliminated, 1);
    }

    #[test]
    fn four_adjacent_loads_form_one_chain_at_pack_width_4() {
        let desc = desc_with_body(linear_load_body(0, 4));
        let report = analyze(&desc);
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].pack_width(), 4);
        assert_eq!(report.total_ops_eliminated, 3);
    }

    #[test]
    fn five_adjacent_loads_pack_width_capped_at_4() {
        // 5 consecutive loads still form one chain of length 5;
        // pack_width caps at 4 (vec4 is the widest WGSL/PTX
        // primitive load). Total ops eliminated = 4 (5 → 1 wide
        // load gives 4 saved transactions).
        let desc = desc_with_body(linear_load_body(0, 5));
        let report = analyze(&desc);
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].op_indices.len(), 5);
        assert_eq!(report.chains[0].pack_width(), 4);
        assert_eq!(report.total_ops_eliminated, 4);
    }

    #[test]
    fn loads_on_different_slots_form_separate_chains() {
        let mut body = linear_load_body(0, 3);
        // Append two more loads on slot 1 with consecutive indices.
        body.literals.push(LiteralValue::U32(0));
        body.literals.push(LiteralValue::U32(1));
        let lit_a = body.literals.len() as u32 - 2;
        let lit_b = body.literals.len() as u32 - 1;
        let result_a = body.ops.len() as u32 + 100;
        let result_b = result_a + 1;
        body.ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![lit_a],
            result: Some(result_a),
        });
        body.ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![lit_b],
            result: Some(result_b),
        });
        body.ops.push(KernelOp {
            kind: KernelOpKind::LoadGlobal,
            operands: vec![1, result_a],
            result: Some(200),
        });
        body.ops.push(KernelOp {
            kind: KernelOpKind::LoadGlobal,
            operands: vec![1, result_b],
            result: Some(201),
        });
        let mut desc = desc_with_body(body);
        desc.bindings.slots.push(input_slot(1, "in2"));
        let report = analyze(&desc);
        // Chain on slot 0 (length 3) + chain on slot 1 (length 2).
        assert_eq!(report.chains.len(), 2);
        assert_eq!(report.chains[0].slot, 0);
        assert_eq!(report.chains[0].op_indices.len(), 3);
        assert_eq!(report.chains[1].slot, 1);
        assert_eq!(report.chains[1].op_indices.len(), 2);
    }

    #[test]
    fn non_consecutive_indices_break_the_chain() {
        // Loads at indices 0, 1, 3 (skip 2) → only 0,1 chain;
        // index 3 is a singleton.
        let mut body = KernelBody {
            ops: vec![],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::U32(0),
                LiteralValue::U32(1),
                LiteralValue::U32(3),
            ],
        };
        for (i, _) in [0, 1, 3].iter().enumerate() {
            body.ops.push(KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![i as u32],
                result: Some(i as u32),
            });
        }
        for (offset, lit_id) in [0, 1, 2].iter().enumerate() {
            body.ops.push(KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, *lit_id as u32],
                result: Some(10 + offset as u32),
            });
        }
        let report = analyze(&desc_with_body(body));
        // Only 0, 1 form a chain (length 2). Index 3 is a singleton.
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].op_indices.len(), 2);
        assert_eq!(report.total_ops_eliminated, 1);
    }

    #[test]
    fn non_literal_index_is_not_chainable() {
        // LoadGlobal whose index is the result of an Add op (not a
        // literal) should not count as a chain candidate.
        let body = KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(vyre_foundation::ir::BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(2),
                },
                // LoadGlobal(slot=0, index=result_of_Add_op_id_2)
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 2],
                    result: Some(3),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0)],
        };
        let report = analyze(&desc_with_body(body));
        assert!(!report.has_chains());
    }

    #[test]
    fn chains_in_child_bodies_are_detected_too() {
        let child = linear_load_body(0, 3);
        let parent = KernelBody {
            ops: vec![KernelOp {
                kind: KernelOpKind::StructuredBlock,
                operands: vec![0],
                result: None,
            }],
            child_bodies: vec![child],
            literals: vec![],
        };
        let report = analyze(&desc_with_body(parent));
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].op_indices.len(), 3);
    }
}
