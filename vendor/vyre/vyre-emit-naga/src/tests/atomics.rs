//! Test: atomics.
use super::*;

#[test]
fn atomic_add_emits_statement() {
    use vyre_foundation::ir::AtomicOp;
    let desc = KernelDescriptor {
        id: "atomic_add".into(),
        bindings: BindingLayout {
            slots: vec![vyre_lower::BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: None,
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadWrite,
                name: "counter".into(),
            }],
        },
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
                    kind: KernelOpKind::Atomic {
                        op: AtomicOp::Add,
                        ordering: vyre_foundation::runtime::memory_model::MemoryOrdering::SeqCst,
                    },
                    operands: vec![0, 0, 1],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        },
    };
    let module = emit(&desc).unwrap();
    assert!(!module.entry_points.is_empty());
    assert!(
        module.global_variables.iter().any(|(_, global)| {
            let ty = &module.types[global.ty].inner;
            matches!(
                ty,
                TypeInner::Array { base, .. }
                    if matches!(module.types[*base].inner, TypeInner::Atomic(_))
            )
        }),
        "Fix: descriptor buffers targeted by atomics must use atomic element types, otherwise Naga rejects the emitted atomic pointer."
    );
}

#[test]
fn atomic_fetch_nand_emits_compare_exchange_loop() {
    use vyre_foundation::ir::AtomicOp;
    let desc = KernelDescriptor {
        id: "k".into(),
        bindings: BindingLayout {
            slots: vec![vyre_lower::BindingSlot {
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
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        },
    };
    let module = emit(&desc).expect("FetchNand must lower to a compare-exchange loop");
    let body = &module.entry_points[0].function.body;
    assert!(block_has_loop(body));
    assert!(block_has_atomic(body));
}

#[test]
fn atomic_compare_exchange_emits_statement() {
    use vyre_foundation::ir::AtomicOp;
    let desc = KernelDescriptor {
        id: "atomic_cx".into(),
        bindings: BindingLayout {
            slots: vec![vyre_lower::BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: None,
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadWrite,
                name: "counter".into(),
            }],
        },
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
                    kind: KernelOpKind::Atomic {
                        op: AtomicOp::CompareExchange,
                        ordering: vyre_foundation::runtime::memory_model::MemoryOrdering::SeqCst,
                    },
                    operands: vec![0, 0, 0, 1],
                    result: Some(2),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        },
    };
    let module = emit(&desc).expect("compare-exchange must lower to Naga atomic exchange");
    assert!(block_has_atomic(&module.entry_points[0].function.body));
}
