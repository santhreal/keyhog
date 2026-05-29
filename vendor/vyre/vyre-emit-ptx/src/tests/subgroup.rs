//! Test: subgroup.
use super::*;

#[test]
fn subgroup_ballot_emits_vote_sync_ballot() {
    let kernel = KernelDescriptor {
        id: "ballot".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::SubgroupBallot,
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::Bool(true)],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("activemask.b32"));
    assert!(s.contains("vote.sync.ballot.b32"));
}

#[test]
fn subgroup_shuffle_emits_shfl_sync_idx() {
    let kernel = KernelDescriptor {
        id: "shuffle".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
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
                    kind: KernelOpKind::SubgroupShuffle,
                    operands: vec![0, 1],
                    result: Some(2),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(7), LiteralValue::U32(3)],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("shfl.sync.idx.b32"));
}

#[test]
fn subgroup_add_emits_redux_sync() {
    let kernel = KernelDescriptor {
        id: "add".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::SubgroupAdd,
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::F32(5.0)],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("redux.sync.add.f32"));
}

#[test]
fn subgroup_local_id_emits_laneid() {
    let kernel = KernelDescriptor {
        id: "lane".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![KernelOp {
                kind: KernelOpKind::SubgroupLocalId,
                operands: vec![],
                result: Some(0),
            }],
            child_bodies: vec![],
            literals: vec![],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("%laneid"));
}

#[test]
fn subgroup_size_emits_probed_width_literal() {
    let kernel = KernelDescriptor {
        id: "wsz".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![KernelOp {
                kind: KernelOpKind::SubgroupSize,
                operands: vec![],
                result: Some(0),
            }],
            child_bodies: vec![],
            literals: vec![],
        },
    };
    let s = emit_with_options(
        &kernel,
        PtxEmitOptions {
            target: ComputeCapability::SM_70,
            subgroup_size: 16,
            ulp_budget: None,
        },
    )
    .unwrap();
    assert!(s.contains("mov.u32") && s.contains(", 16;"));
}

#[test]
fn atomic_unsupported_op_returns_error() {
    use vyre_foundation::ir::AtomicOp;
    let kernel = KernelDescriptor {
        id: "k".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: None,
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadWrite,
                name: "b".into(),
            }],
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
                    kind: KernelOpKind::Atomic {
                        op: AtomicOp::FetchNand,
                        ordering: vyre_foundation::runtime::memory_model::MemoryOrdering::SeqCst,
                    },
                    operands: vec![0, 0, 1],
                    result: Some(2),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        },
    };
    let r = emit(&kernel);
    assert!(matches!(r, Err(EmitError::UnsupportedOp(_))));
}

#[test]
fn for_loop_var_name_appears_in_comment() {
    let kernel = KernelDescriptor {
        id: "named_loop".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(64, 1, 1),
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
                    kind: KernelOpKind::StructuredForLoop {
                        loop_var: "row_idx".into(),
                    },
                    operands: vec![0, 1, 0],
                    result: None,
                },
            ],
            child_bodies: vec![empty_child_body()],
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(16)],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("// for row_idx in"));
}
