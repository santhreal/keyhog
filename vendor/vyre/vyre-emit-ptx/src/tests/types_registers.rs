//! Test: types registers.
use super::*;

#[test]
fn capability_constants_present() {
    assert_eq!(ComputeCapability::SM_70.major, 7);
    assert_eq!(ComputeCapability::SM_90.major, 9);
    assert!(ComputeCapability::SM_80.supports_async_copy());
    assert!(!ComputeCapability::SM_70.supports_async_copy());
    assert!(ComputeCapability::SM_75.supports_ldmatrix());
    assert!(!ComputeCapability::SM_70.supports_ldmatrix());
}

#[test]
fn ptx_type_from_dtype_covers_scalars() {
    assert_eq!(PtxType::from_dtype(&DataType::Bool).unwrap(), PtxType::Bool);
    assert_eq!(PtxType::from_dtype(&DataType::U32).unwrap(), PtxType::U32);
    assert_eq!(PtxType::from_dtype(&DataType::I32).unwrap(), PtxType::I32);
    assert_eq!(PtxType::from_dtype(&DataType::F32).unwrap(), PtxType::F32);
}

#[test]
fn ptx_type_from_dtype_rejects_unsupported() {
    assert!(matches!(
        PtxType::from_dtype(&DataType::Tensor),
        Err(EmitError::UnsupportedDataType(_))
    ));
}

#[test]
fn reg_display_uses_correct_prefix() {
    assert_eq!(format!("{}", Reg(PtxType::U32, 5)), "%r5");
    assert_eq!(format!("{}", Reg(PtxType::I32, 0)), "%s0");
    assert_eq!(format!("{}", Reg(PtxType::F32, 3)), "%f3");
    assert_eq!(format!("{}", Reg(PtxType::Bool, 1)), "%p1");
    assert_eq!(format!("{}", Reg(PtxType::U64, 7)), "%rd7");
}

#[test]
fn register_declaration_sized_to_used_count() {
    // A kernel with 3 u32 ops declares those registers on top of
    // the reserved launch-ABI registers.
    let kernel = KernelDescriptor {
        id: "regs".into(),
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
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::BinOpKind(BinOp::Add),
                    operands: vec![0, 1],
                    result: Some(2),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(1), LiteralValue::U32(2)],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains(".reg .u32   %r<30>;"));
}
