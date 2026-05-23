use super::*;
use naga::{Binding, Block, BuiltIn, Statement, TypeInner};
use std::sync::Mutex;
use vyre_foundation::ir::DataType;
use vyre_foundation::memory_model::MemoryOrdering;
use vyre_lower::{
    BindingLayout, BindingSlot, BindingVisibility, Dispatch, KernelBody, KernelDescriptor,
    KernelOp, KernelOpKind, LiteralValue, MemoryClass,
};

static MODULE_CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn empty_desc() -> KernelDescriptor {
    KernelDescriptor {
        id: "empty".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![],
            child_bodies: vec![],
            literals: vec![],
        },
    }
}

fn empty_desc_with_workgroup(id: &str, x: u32) -> KernelDescriptor {
    KernelDescriptor {
        id: id.into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(x, 1, 1),
        body: KernelBody {
            ops: vec![],
            child_bodies: vec![],
            literals: vec![],
        },
    }
}

#[test]
fn module_cache_key_is_128_bit_and_descriptor_sensitive() {
    let a = descriptor_cache_key(&empty_desc_with_workgroup("a", 1));
    let b = descriptor_cache_key(&empty_desc_with_workgroup("a", 2));
    assert_eq!(a.0.len(), 16);
    assert_ne!(a, b);
}

fn u32_output_slot(slot: u32) -> BindingSlot {
    BindingSlot {
        slot,
        element_type: DataType::U32,
        element_count: Some(8),
        memory_class: MemoryClass::Global,
        visibility: BindingVisibility::ReadWrite,
        name: format!("out{slot}"),
    }
}

fn trap_sidecar_slot(slot: u32) -> BindingSlot {
    BindingSlot {
        slot,
        element_type: DataType::U32,
        element_count: Some(vyre_lower::TRAP_SIDECAR_WORDS),
        memory_class: MemoryClass::Global,
        visibility: BindingVisibility::ReadWrite,
        name: vyre_lower::TRAP_SIDECAR_NAME.to_owned(),
    }
}

fn async_copy_desc(kind: KernelOpKind) -> KernelDescriptor {
    KernelDescriptor {
        id: "async-copy".into(),
        bindings: BindingLayout {
            slots: vec![u32_output_slot(0), u32_output_slot(1)],
        },
        dispatch: Dispatch::new(64, 1, 1),
        body: KernelBody {
            literals: vec![LiteralValue::U32(0), LiteralValue::U32(16)],
            child_bodies: vec![],
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
                    kind,
                    operands: vec![0, 1, 0, 1],
                    result: None,
                },
                KernelOp {
                    kind: KernelOpKind::AsyncWait { tag: "copy".into() },
                    operands: vec![],
                    result: None,
                },
            ],
        },
    }
}

fn block_has_loop(block: &Block) -> bool {
    block.iter().any(|statement| match statement {
        Statement::Loop { .. } => true,
        Statement::Block(child) => block_has_loop(child),
        Statement::If { accept, reject, .. } => block_has_loop(accept) || block_has_loop(reject),
        _ => false,
    })
}

fn block_has_atomic(block: &Block) -> bool {
    block.iter().any(|statement| match statement {
        Statement::Atomic { .. } => true,
        Statement::Block(child) => block_has_atomic(child),
        Statement::If { accept, reject, .. } => {
            block_has_atomic(accept) || block_has_atomic(reject)
        }
        Statement::Loop {
            body, continuing, ..
        } => block_has_atomic(body) || block_has_atomic(continuing),
        _ => false,
    })
}

mod atomics;
mod byte_element_load;
mod cache_entry;
mod descriptor_control;
mod optimized_errors;
mod subgroup;
