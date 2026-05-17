//! Branch collapse — `StructuredIfThen`/`StructuredIfThenElse` whose
//! condition is a Literal(bool) collapses to the appropriate arm.
//!
//! This pairs naturally with `descriptor_const_fold`: descriptor_const_fold turns boolean
//! arithmetic chains into Literal(true)/Literal(false), then this
//! pass eliminates the dead branches.
//!
//! Conditions like `Eq(lit_5, lit_5)` get folded to Literal(true) by
//! descriptor_const_fold first; then this pass picks them up.

use crate::{KernelBody, KernelDescriptor, KernelOp, KernelOpKind, LiteralValue};
use rustc_hash::FxHashMap;

#[must_use]
pub fn branch_collapse(desc: &KernelDescriptor) -> KernelDescriptor {
    let mut out = desc.clone();
    out.body = collapse_body(out.body);
    out
}

fn collapse_body(mut body: KernelBody) -> KernelBody {
    // Map result-id → bool literal value (only when the producing op
    // is a Literal of a Bool value).
    let bool_lits: FxHashMap<u32, bool> = body
        .ops
        .iter()
        .filter_map(|op| match (&op.kind, op.result, op.operands.first()) {
            (KernelOpKind::Literal, Some(r), Some(pool_idx)) => {
                match body.literals.get(*pool_idx as usize) {
                    Some(LiteralValue::Bool(v)) => Some((r, *v)),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect();

    // Pre-compute every result id referenced by any op in this body
    // (including nested children). If a candidate-for-drop body
    // produces an id in this set, we MUST NOT drop the body — its
    // result is consumed elsewhere and dropping creates dangling refs.
    let parent_referenced_ids = collect_all_referenced_ids(&body);
    let original_children = std::mem::take(&mut body.child_bodies);
    let mut new_ops: Vec<KernelOp> = Vec::with_capacity(body.ops.len());
    let mut new_children = original_children.clone();
    let old_ops = std::mem::take(&mut body.ops);

    for op in old_ops {
        match &op.kind {
            KernelOpKind::StructuredIfThen => {
                let cond_id = op.operands.first().copied();
                let body_id = op.operands.get(1).copied();
                if let (Some(cond_id), Some(body_id)) = (cond_id, body_id) {
                    if let Some(cond_lit) = bool_lits.get(&cond_id).copied() {
                        if cond_lit {
                            if let Some(child) = original_children.get(body_id as usize) {
                                if can_collapse_safely(child, &parent_referenced_ids) {
                                    inline_child_body(child, &mut new_ops, &mut new_children);
                                    continue;
                                }
                                // Fall through — leave the IfThen
                                // intact rather than yank refs out
                                // of scope.
                            }
                        } else {
                            // Drop the if op entirely IF the dropped
                            // body produces no id consumed elsewhere
                            // in the parent body.
                            if let Some(child) = original_children.get(body_id as usize) {
                                if dropping_body_is_safe(child, &parent_referenced_ids) {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }
            KernelOpKind::StructuredIfThenElse => {
                let cond_id = op.operands.first().copied();
                let then_id = op.operands.get(1).copied();
                let else_id = op.operands.get(2).copied();
                if let (Some(cond_id), Some(then_id), Some(else_id)) = (cond_id, then_id, else_id) {
                    if let Some(cond_lit) = bool_lits.get(&cond_id).copied() {
                        let pick_id = if cond_lit { then_id } else { else_id };
                        let drop_id = if cond_lit { else_id } else { then_id };
                        let pick = original_children.get(pick_id as usize);
                        let drop = original_children.get(drop_id as usize);
                        if let Some(pick) = pick {
                            if can_collapse_safely(pick, &parent_referenced_ids)
                                && drop
                                    .map(|d| dropping_body_is_safe(d, &parent_referenced_ids))
                                    .unwrap_or(true)
                            {
                                inline_child_body(pick, &mut new_ops, &mut new_children);
                                continue;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        // Pass through: also recursively collapse any nested
        // structured-control-flow children even if the outer op isn't
        // collapsable.
        match &op.kind {
            KernelOpKind::StructuredIfThen
            | KernelOpKind::StructuredIfThenElse
            | KernelOpKind::StructuredForLoop { .. }
            | KernelOpKind::StructuredBlock
            | KernelOpKind::Region { .. } => {
                for child_id in op.operands.iter() {
                    if let Some(child) = original_children.get(*child_id as usize) {
                        let recursed = collapse_body(child.clone());
                        new_children[*child_id as usize] = recursed;
                    }
                }
            }
            _ => {}
        }
        new_ops.push(op);
    }

    body.ops = new_ops;
    body.child_bodies = new_children;
    body
}

fn inline_child_body(child: &KernelBody, ops: &mut Vec<KernelOp>, children: &mut Vec<KernelBody>) {
    let inlined = collapse_body(child.clone());
    let child_base = children.len() as u32;
    children.extend(inlined.child_bodies);
    ops.extend(
        inlined
            .ops
            .into_iter()
            .map(|op| rebase_child_body_refs(op, child_base)),
    );
}

/// Conservative pre-collapse safety check used by the IfThen and
/// IfThenElse handlers.
///
/// Inlining a child body into its grandparent is only safe when every
/// SSA result-reference inside the child resolves to an id produced
/// inside the child itself. If the child body references ids defined
/// in the body that contained the if-then (i.e. ids the inlining
/// would yank out of scope), refuse to collapse — the IfThen stays
/// intact and the verifier stays clean. This is the fix for
/// `DanglingResultRef { ref_id: 13 }` on shunting_yard descriptors.
fn can_collapse_safely(child: &KernelBody, _parent_refs: &rustc_hash::FxHashSet<u32>) -> bool {
    let mut produced = rustc_hash::FxHashSet::default();
    collect_produced_ids_inclusive(child, &mut produced);
    body_refs_only(child, &produced)
}

/// Conservative drop safety: dropping the child body is safe only
/// when none of its produced result ids are referenced anywhere in
/// the parent body (which would dangle if the producing ops vanished).
fn dropping_body_is_safe(child: &KernelBody, parent_refs: &rustc_hash::FxHashSet<u32>) -> bool {
    let mut produced = rustc_hash::FxHashSet::default();
    collect_produced_ids_inclusive(child, &mut produced);
    produced.is_disjoint(parent_refs)
}

fn collect_all_referenced_ids(body: &KernelBody) -> rustc_hash::FxHashSet<u32> {
    let mut out = rustc_hash::FxHashSet::default();
    collect_refs(body, &mut out);
    out
}

fn collect_refs(body: &KernelBody, out: &mut rustc_hash::FxHashSet<u32>) {
    for op in &body.ops {
        for (pos, &operand) in op.operands.iter().enumerate() {
            if operand_is_result_reference(&op.kind, pos) {
                out.insert(operand);
            }
        }
    }
    for child in &body.child_bodies {
        collect_refs(child, out);
    }
}

fn collect_produced_ids_inclusive(body: &KernelBody, out: &mut rustc_hash::FxHashSet<u32>) {
    for op in &body.ops {
        if let Some(r) = op.result {
            out.insert(r);
        }
    }
    for child in &body.child_bodies {
        collect_produced_ids_inclusive(child, out);
    }
}

fn body_refs_only(body: &KernelBody, produced: &rustc_hash::FxHashSet<u32>) -> bool {
    for op in &body.ops {
        for (pos, &operand) in op.operands.iter().enumerate() {
            if !operand_is_result_reference(&op.kind, pos) {
                continue;
            }
            if !produced.contains(&operand) {
                return false;
            }
        }
    }
    for child in &body.child_bodies {
        if !body_refs_only(child, produced) {
            return false;
        }
    }
    true
}

/// Conservative classification of operand positions that name a
/// result id (vs. a child-body index, literal-pool index, or binding
/// slot). Mirrors the shape the verifier uses.
fn operand_is_result_reference(kind: &KernelOpKind, pos: usize) -> bool {
    use KernelOpKind::*;
    match kind {
        Literal => false,
        LocalInvocationId
        | GlobalInvocationId
        | WorkgroupId
        | SubgroupLocalId
        | SubgroupSize
        | LoopIndex { .. } => false,
        LoopCarrierInit { .. } | LoopCarrier { .. } | LoopCarrierEnd { .. } => pos == 0,
        LoadGlobal
        | LoadShared
        | LoadConstant
        | StoreGlobal
        | StoreShared
        | BufferLength
        | Atomic { .. }
        | AsyncLoad { .. }
        | AsyncStore { .. } => pos != 0,
        StructuredIfThen => pos == 0,
        StructuredIfThenElse => pos == 0,
        StructuredForLoop { .. } => pos == 0 || pos == 1,
        StructuredBlock | Region { .. } => false,
        IndirectDispatch { .. } => false,
        _ => true,
    }
}

fn rebase_child_body_refs(mut op: KernelOp, child_base: u32) -> KernelOp {
    for (pos, operand) in op.operands.iter_mut().enumerate() {
        if operand_is_child_body_ref(&op.kind, pos) {
            *operand = operand.saturating_add(child_base);
        }
    }
    op
}

fn operand_is_child_body_ref(kind: &KernelOpKind, pos: usize) -> bool {
    match kind {
        KernelOpKind::StructuredIfThen => pos == 1,
        KernelOpKind::StructuredIfThenElse => pos == 1 || pos == 2,
        KernelOpKind::StructuredForLoop { .. } => pos == 2,
        KernelOpKind::StructuredBlock | KernelOpKind::Region { .. } => pos == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BindingLayout, Dispatch, KernelBody, KernelDescriptor, KernelOp, KernelOpKind, LiteralValue,
    };

    fn empty_kernel() -> KernelDescriptor {
        KernelDescriptor {
            id: "k".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![],
                child_bodies: vec![],
                literals: vec![],
            },
        }
    }

    #[test]
    fn empty_kernel_no_change() {
        let out = branch_collapse(&empty_kernel());
        assert!(out.body.ops.is_empty());
    }

    #[test]
    fn if_then_with_true_cond_inlines_body() {
        // Lit(true); if(cond=true) { Lit(7); }
        let desc = KernelDescriptor {
            id: "true_then".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThen,
                        operands: vec![0, 0],
                        result: None,
                    },
                ],
                child_bodies: vec![KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    }],
                    child_bodies: vec![],
                    literals: vec![LiteralValue::U32(7)],
                }],
                literals: vec![LiteralValue::Bool(true)],
            },
        };
        let out = branch_collapse(&desc);
        // Expected: outer ops = [Lit(true), Lit(7)] — IfThen replaced by inlined body.
        assert_eq!(out.body.ops.len(), 2);
        assert!(matches!(out.body.ops[0].kind, KernelOpKind::Literal));
        assert!(matches!(out.body.ops[1].kind, KernelOpKind::Literal));
        assert!(out
            .body
            .ops
            .iter()
            .all(|o| !matches!(o.kind, KernelOpKind::StructuredIfThen)));
    }

    #[test]
    fn if_then_with_false_cond_drops_branch() {
        // Lit(false); if(cond=false) { Lit(7); }
        let desc = KernelDescriptor {
            id: "false_then".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThen,
                        operands: vec![0, 0],
                        result: None,
                    },
                ],
                child_bodies: vec![KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    }],
                    child_bodies: vec![],
                    literals: vec![LiteralValue::U32(7)],
                }],
                literals: vec![LiteralValue::Bool(false)],
            },
        };
        let out = branch_collapse(&desc);
        // Expected: outer ops = [Lit(false)] only — IfThen dropped, body discarded.
        assert_eq!(out.body.ops.len(), 1);
        assert!(matches!(out.body.ops[0].kind, KernelOpKind::Literal));
    }

    #[test]
    fn if_then_with_non_literal_cond_unchanged() {
        // tid; if(cond=tid) { Lit(7); }
        let desc = KernelDescriptor {
            id: "runtime_cond".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(64, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::LocalInvocationId,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThen,
                        operands: vec![0, 0],
                        result: None,
                    },
                ],
                child_bodies: vec![KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(1),
                    }],
                    child_bodies: vec![],
                    literals: vec![LiteralValue::U32(7)],
                }],
                literals: vec![],
            },
        };
        let out = branch_collapse(&desc);
        // No change.
        assert_eq!(out.body.ops.len(), 2);
        assert!(out
            .body
            .ops
            .iter()
            .any(|o| matches!(o.kind, KernelOpKind::StructuredIfThen)));
    }

    #[test]
    fn if_then_else_picks_then_arm_for_true() {
        let desc = KernelDescriptor {
            id: "true_pick".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThenElse,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                ],
                child_bodies: vec![
                    KernelBody {
                        ops: vec![KernelOp {
                            kind: KernelOpKind::Literal,
                            operands: vec![1],
                            result: Some(1),
                        }],
                        child_bodies: vec![],
                        literals: vec![LiteralValue::U32(99)],
                    },
                    KernelBody {
                        ops: vec![KernelOp {
                            kind: KernelOpKind::Literal,
                            operands: vec![2],
                            result: Some(2),
                        }],
                        child_bodies: vec![],
                        literals: vec![LiteralValue::U32(88)],
                    },
                ],
                literals: vec![LiteralValue::Bool(true)],
            },
        };
        let out = branch_collapse(&desc);
        // Then-arm is at child_bodies[0]; we should see its 1 op survive.
        assert_eq!(out.body.ops.len(), 2); // [Lit(true), inlined_then_op]
        assert!(out
            .body
            .ops
            .iter()
            .all(|o| !matches!(o.kind, KernelOpKind::StructuredIfThenElse)));
    }

    #[test]
    fn if_then_else_picks_else_arm_for_false() {
        let desc = KernelDescriptor {
            id: "false_pick".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThenElse,
                        operands: vec![0, 0, 1],
                        result: None,
                    },
                ],
                child_bodies: vec![
                    KernelBody {
                        ops: vec![KernelOp {
                            kind: KernelOpKind::Literal,
                            operands: vec![1],
                            result: Some(1),
                        }],
                        child_bodies: vec![],
                        literals: vec![LiteralValue::U32(99)],
                    },
                    KernelBody {
                        ops: vec![KernelOp {
                            kind: KernelOpKind::Literal,
                            operands: vec![2],
                            result: Some(2),
                        }],
                        child_bodies: vec![],
                        literals: vec![LiteralValue::U32(88)],
                    },
                ],
                literals: vec![LiteralValue::Bool(false)],
            },
        };
        let out = branch_collapse(&desc);
        // Else-arm at child_bodies[1] — its 1 op survives.
        assert_eq!(out.body.ops.len(), 2);
        assert!(out
            .body
            .ops
            .iter()
            .all(|o| !matches!(o.kind, KernelOpKind::StructuredIfThenElse)));
    }

    #[test]
    fn inlined_nested_control_flow_rebases_child_body_refs() {
        let desc = KernelDescriptor {
            id: "nested".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThen,
                        operands: vec![0, 0],
                        result: None,
                    },
                ],
                child_bodies: vec![KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::StructuredBlock,
                        operands: vec![0],
                        result: None,
                    }],
                    child_bodies: vec![KernelBody {
                        ops: vec![KernelOp {
                            kind: KernelOpKind::Literal,
                            operands: vec![1],
                            result: Some(1),
                        }],
                        child_bodies: vec![],
                        literals: vec![LiteralValue::U32(7)],
                    }],
                    literals: vec![],
                }],
                literals: vec![LiteralValue::Bool(true)],
            },
        };

        let out = branch_collapse(&desc);
        let block = out
            .body
            .ops
            .iter()
            .find(|op| matches!(op.kind, KernelOpKind::StructuredBlock))
            .expect("nested block must survive inlined branch");
        let child_id = block.operands[0] as usize;
        assert!(
            out.body.child_bodies.get(child_id).is_some(),
            "inlined nested control-flow child id must point at a reparented child body"
        );
    }

    #[test]
    fn branch_collapse_is_idempotent() {
        let desc = KernelDescriptor {
            id: "k".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(0),
                    },
                    KernelOp {
                        kind: KernelOpKind::StructuredIfThen,
                        operands: vec![0, 0],
                        result: None,
                    },
                ],
                child_bodies: vec![KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(1),
                    }],
                    child_bodies: vec![],
                    literals: vec![LiteralValue::U32(42)],
                }],
                literals: vec![LiteralValue::Bool(true)],
            },
        };
        let once = branch_collapse(&desc);
        let twice = branch_collapse(&once);
        assert_eq!(once.body.ops.len(), twice.body.ops.len());
    }
}
