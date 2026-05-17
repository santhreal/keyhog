//! Weir-provided reaching-definition facts for rewrite legality.

use std::collections::BTreeMap;

use crate::{KernelBody, KernelDescriptor, KernelOpKind};

/// Reaching definitions for a descriptor result id.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReachingDefFactSet {
    reaching: BTreeMap<u32, Vec<u32>>,
}

impl ReachingDefFactSet {
    /// Replace the reaching-def list for `use_result`.
    pub fn set_reaching_defs(&mut self, use_result: u32, defs: Vec<u32>) {
        self.reaching.insert(use_result, defs);
    }

    /// Return the definitions known to reach `use_result`.
    #[must_use]
    pub fn reaching_defs(&self, use_result: u32) -> &[u32] {
        self.reaching.get(&use_result).map_or(&[], Vec::as_slice)
    }

    /// True when exactly one definition reaches the use.
    #[must_use]
    pub fn has_single_reaching_def(&self, use_result: u32) -> bool {
        self.reaching_defs(use_result).len() == 1
    }

    /// Number of use sites with facts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.reaching.len()
    }

    /// True when no reaching-def facts have been imported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reaching.is_empty()
    }
}

/// Build descriptor-local reaching-definition facts from SSA producer/use
/// edges. Each operand use that is known to reference a result id receives
/// the single producer id that defines it.
#[must_use]
pub fn import_descriptor_reaching_defs(desc: &KernelDescriptor) -> ReachingDefFactSet {
    let mut facts = ReachingDefFactSet::default();
    let mut copy_aliases = BTreeMap::new();
    collect_copy_aliases(&desc.body, &mut copy_aliases);
    import_body_reaching_defs(&desc.body, &mut facts, &copy_aliases);
    facts
}

fn collect_copy_aliases(body: &KernelBody, aliases: &mut BTreeMap<u32, u32>) {
    for op in &body.ops {
        if matches!(op.kind, KernelOpKind::Copy) {
            if let (Some(result), Some(source)) = (op.result, op.operands.first()) {
                aliases.insert(result, *source);
            }
        }
    }
    for child in &body.child_bodies {
        collect_copy_aliases(child, aliases);
    }
}

fn import_body_reaching_defs(
    body: &KernelBody,
    facts: &mut ReachingDefFactSet,
    copy_aliases: &BTreeMap<u32, u32>,
) {
    for op in &body.ops {
        if matches!(op.kind, KernelOpKind::Copy) {
            if let (Some(result), Some(source)) = (op.result, op.operands.first()) {
                facts.set_reaching_defs(result, vec![resolve_copy_alias(*source, copy_aliases)]);
            }
        }
        for (pos, operand) in op.operands.iter().enumerate() {
            if operand_is_result_reference(&op.kind, pos) {
                facts.set_reaching_defs(*operand, vec![resolve_copy_alias(*operand, copy_aliases)]);
            }
        }
    }
    for child in &body.child_bodies {
        import_body_reaching_defs(child, facts, copy_aliases);
    }
}

fn resolve_copy_alias(mut id: u32, copy_aliases: &BTreeMap<u32, u32>) -> u32 {
    for _ in 0..32 {
        let Some(next) = copy_aliases.get(&id).copied() else {
            return id;
        };
        if next == id {
            return id;
        }
        id = next;
    }
    id
}

fn operand_is_result_reference(kind: &KernelOpKind, pos: usize) -> bool {
    use KernelOpKind::*;
    match kind {
        Literal => false,
        LocalInvocationId | GlobalInvocationId | WorkgroupId => false,
        SubgroupLocalId | SubgroupSize | LoopIndex { .. } => false,
        LoopCarrierInit { .. } | LoopCarrier { .. } | LoopCarrierEnd { .. } => pos == 0,
        LoadGlobal | LoadShared | LoadConstant => pos != 0,
        BufferLength => false,
        StoreGlobal | StoreShared => pos != 0,
        Copy | BinOpKind(_) | UnOpKind(_) | Fma | MatrixMma { .. } | Select | Cast { .. } => true,
        Atomic { .. } => pos != 0,
        SubgroupBallot | SubgroupShuffle | SubgroupAdd => true,
        StructuredIfThen | StructuredIfThenElse => pos == 0,
        StructuredForLoop { .. } => pos != 2,
        StructuredBlock | Region { .. } => false,
        Return | Barrier { .. } => false,
        AsyncLoad { .. } | AsyncStore { .. } => pos >= 2,
        AsyncWait { .. } => false,
        Trap { .. } => pos == 0,
        Resume { .. } => false,
        IndirectDispatch { .. } => false,
        Call { .. } => true,
        OpaqueExpr(..) | OpaqueNode(..) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BindingLayout, Dispatch, KernelBody, KernelDescriptor, KernelOp, KernelOpKind,
        LiteralValue,
    };
    use vyre_foundation::ir::BinOp;

    #[test]
    fn reports_single_reaching_definition() {
        let mut facts = ReachingDefFactSet::default();
        facts.set_reaching_defs(9, vec![3]);
        assert_eq!(facts.reaching_defs(9), &[3]);
        assert!(facts.has_single_reaching_def(9));
    }

    #[test]
    fn imports_descriptor_operand_reaching_defs() {
        let desc = KernelDescriptor {
            id: "reaching".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![1],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::BinOpKind(BinOp::Add),
                        operands: vec![1, 2],
                        result: Some(3),
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(1), LiteralValue::U32(2)],
            },
        };
        let facts = import_descriptor_reaching_defs(&desc);
        assert!(facts.has_single_reaching_def(1));
        assert!(facts.has_single_reaching_def(2));
        assert_eq!(facts.reaching_defs(1), &[1]);
        assert_eq!(facts.reaching_defs(2), &[2]);
    }

    #[test]
    fn import_canonicalizes_copy_chains_for_rewrite_facts() {
        let desc = KernelDescriptor {
            id: "copy-reaching".into(),
            bindings: BindingLayout { slots: vec![] },
            dispatch: Dispatch::new(1, 1, 1),
            body: KernelBody {
                ops: vec![
                    KernelOp {
                        kind: KernelOpKind::Literal,
                        operands: vec![0],
                        result: Some(1),
                    },
                    KernelOp {
                        kind: KernelOpKind::Copy,
                        operands: vec![1],
                        result: Some(2),
                    },
                    KernelOp {
                        kind: KernelOpKind::Copy,
                        operands: vec![2],
                        result: Some(3),
                    },
                    KernelOp {
                        kind: KernelOpKind::BinOpKind(BinOp::Add),
                        operands: vec![3, 1],
                        result: Some(4),
                    },
                ],
                child_bodies: vec![],
                literals: vec![LiteralValue::U32(7)],
            },
        };
        let facts = import_descriptor_reaching_defs(&desc);
        assert_eq!(facts.reaching_defs(2), &[1]);
        assert_eq!(facts.reaching_defs(3), &[1]);
    }
}
