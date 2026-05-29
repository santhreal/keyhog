//! PTX fixture builders for the CUDA NVRTC compile/execute gate.

use vyre_foundation::ir::{BinOp, DataType};
use vyre_lower::{
    BindingLayout, BindingSlot, BindingVisibility, Dispatch, KernelBody, KernelDescriptor,
    KernelOp, KernelOpKind, LiteralValue, MemoryClass,
};

fn rw_slot(id: u32, name: &str) -> BindingSlot {
    rw_slot_typed(id, name, DataType::U32)
}

fn rw_slot_typed(id: u32, name: &str, element_type: DataType) -> BindingSlot {
    slot_typed(id, name, element_type, BindingVisibility::ReadWrite)
}

fn slot_typed(
    id: u32,
    name: &str,
    element_type: DataType,
    visibility: BindingVisibility,
) -> BindingSlot {
    BindingSlot {
        slot: id,
        element_type,
        element_count: None,
        memory_class: MemoryClass::Global,
        visibility,
        name: name.into(),
    }
}

pub(crate) fn ptx_for_op(op_kind: KernelOpKind) -> String {
    let result_id = 3u32;
    let idx_id = 2u32;

    let (mut ops, literals, binding) = match op_kind {
        KernelOpKind::Fma => (
            vec![
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Cast {
                        target: DataType::F32,
                    },
                    operands: vec![0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(idx_id),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::Fma,
                    operands: vec![1, 4, 5],
                    result: Some(result_id),
                },
            ],
            vec![
                LiteralValue::F32(2.0),
                LiteralValue::U32(0),
                LiteralValue::F32(3.0),
            ],
            rw_slot_typed(0, "out", DataType::F32),
        ),
        KernelOpKind::BinOpKind(BinOp::Mul) => (
            vec![
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(idx_id),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Mul),
                    operands: vec![0, 1],
                    result: Some(result_id),
                },
            ],
            vec![LiteralValue::U32(0)],
            rw_slot(0, "out"),
        ),
        other => (
            vec![
                // Use LocalInvocationId so the op survives constant folding.
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(idx_id),
                },
                KernelOp {
                    kind: other,
                    operands: vec![0, 1],
                    result: Some(result_id),
                },
            ],
            vec![LiteralValue::U32(7), LiteralValue::U32(0)],
            rw_slot(0, "out"),
        ),
    };
    ops.push(KernelOp {
        kind: KernelOpKind::StoreGlobal,
        operands: vec![0, idx_id, result_id],
        result: None,
    });

    let desc = KernelDescriptor {
        id: "test".into(),
        bindings: BindingLayout {
            slots: vec![binding],
        },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops,
            child_bodies: vec![],
            literals,
        },
    };
    vyre_emit_ptx::emit_optimized(&desc).unwrap()
}

pub(crate) fn ptx_for_vector_load_fusion() -> String {
    let desc = KernelDescriptor {
        id: "vector_load_fusion".into(),
        bindings: BindingLayout {
            slots: vec![
                slot_typed(0, "input", DataType::U32, BindingVisibility::ReadOnly),
                slot_typed(1, "output", DataType::U32, BindingVisibility::WriteOnly),
            ],
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
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![2, 4],
                    result: Some(9),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![9, 6],
                    result: Some(10),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![10, 8],
                    result: Some(11),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![1, 0, 11],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(1)],
        },
    };
    vyre_emit_ptx::emit_optimized(&desc).unwrap()
}

pub(crate) fn ptx_for_dynamic_vector_load_fusion() -> String {
    let desc = KernelDescriptor {
        id: "dynamic_vector_load_fusion".into(),
        bindings: BindingLayout {
            slots: vec![
                slot_typed(0, "input", DataType::U32, BindingVisibility::ReadOnly),
                slot_typed(1, "output", DataType::U32, BindingVisibility::WriteOnly),
            ],
        },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Mul),
                    operands: vec![0, 1],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 2],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![2, 3],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 5],
                    result: Some(6),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![5, 3],
                    result: Some(7),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 7],
                    result: Some(8),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![7, 3],
                    result: Some(9),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 9],
                    result: Some(10),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![4, 6],
                    result: Some(11),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![11, 8],
                    result: Some(12),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![12, 10],
                    result: Some(13),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![1, 0, 13],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(4), LiteralValue::U32(1)],
        },
    };
    vyre_emit_ptx::emit_optimized(&desc).unwrap()
}

pub(crate) fn ptx_for_vector_store_fusion() -> String {
    let desc = KernelDescriptor {
        id: "vector_store_fusion".into(),
        bindings: BindingLayout {
            slots: vec![slot_typed(
                0,
                "output",
                DataType::U32,
                BindingVisibility::WriteOnly,
            )],
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
                    kind: KernelOpKind::Literal,
                    operands: vec![3],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![4],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 0, 1],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![5],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 5, 2],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![6],
                    result: Some(6),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 6, 3],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![7],
                    result: Some(7),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 7, 4],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::U32(0),
                LiteralValue::U32(10),
                LiteralValue::U32(11),
                LiteralValue::U32(12),
                LiteralValue::U32(13),
                LiteralValue::U32(1),
                LiteralValue::U32(2),
                LiteralValue::U32(3),
            ],
        },
    };
    vyre_emit_ptx::emit_optimized(&desc).unwrap()
}

pub(crate) fn ptx_for_dynamic_vector_store_fusion() -> String {
    let desc = KernelDescriptor {
        id: "dynamic_vector_store_fusion".into(),
        bindings: BindingLayout {
            slots: vec![slot_typed(
                0,
                "output",
                DataType::U32,
                BindingVisibility::WriteOnly,
            )],
        },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::LocalInvocationId,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Mul),
                    operands: vec![0, 1],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(4),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![3],
                    result: Some(5),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![4],
                    result: Some(6),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 6],
                    result: Some(7),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![5],
                    result: Some(8),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 8],
                    result: Some(9),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![6],
                    result: Some(10),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 10],
                    result: Some(11),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![7],
                    result: Some(12),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 12],
                    result: Some(13),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 2, 7],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![2, 3],
                    result: Some(14),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 14, 9],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![2, 4],
                    result: Some(15),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 15, 11],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![2, 5],
                    result: Some(16),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 16, 13],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::U32(4),
                LiteralValue::U32(1),
                LiteralValue::U32(2),
                LiteralValue::U32(3),
                LiteralValue::U32(1000),
                LiteralValue::U32(1001),
                LiteralValue::U32(1002),
                LiteralValue::U32(1003),
            ],
        },
    };
    vyre_emit_ptx::emit_optimized(&desc).unwrap()
}
