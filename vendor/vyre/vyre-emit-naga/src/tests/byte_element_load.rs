//! Test: U8/I8 byte-element LoadGlobal emits the byte-extract pattern.
//!
//! WGSL has no native byte storage, so the emitter packs U8/I8 into
//! `array<u32>`. Without the byte-extract emit path a `Load(buffer: U8, addr)`
//! would return the u32 word at index `addr`, not the byte at byte address
//! `addr`. The reference evaluator treats U8 as byte-addressed; this test
//! pins the WGSL emit pattern that keeps both backends in agreement.
use super::*;

fn byte_load_desc(element_type: DataType) -> KernelDescriptor {
    KernelDescriptor {
        id: "byte_load".into(),
        bindings: BindingLayout {
            slots: vec![vyre_lower::BindingSlot {
                slot: 0,
                element_type,
                element_count: Some(64),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadOnly,
                name: "source".into(),
            }],
        },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![
                // result 0: the byte address (literal 7)
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                },
                // result 1: source[byte=7]  -  must auto-byte-extract
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(7)],
        },
    }
}

#[test]
fn u8_load_global_emits_word_indexed_byte_extract() {
    let desc = byte_load_desc(DataType::U8);
    let module = emit(&desc).unwrap();

    // The buffer must still be array<u32> (no native u8 storage).
    let global = module
        .global_variables
        .iter()
        .find(|(_, g)| g.name.as_deref() == Some("source"))
        .map(|(_, g)| g)
        .expect("source binding must be emitted");
    let TypeInner::Array { base, .. } = &module.types[global.ty].inner else {
        panic!("source binding must lower to array<u32>");
    };
    let TypeInner::Scalar(scalar) = &module.types[*base].inner else {
        panic!("source binding element type must be scalar");
    };
    assert_eq!(
        scalar.kind,
        naga::ScalarKind::Uint,
        "U8 buffer must remain backed by array<u32> in WGSL emit"
    );
    assert_eq!(scalar.width, 4, "U8 buffer storage width must be 4 bytes");

    // The body must contain the byte-extract arithmetic chain:
    //   shr(byte_index, 2)  -  word index
    //   and(byte_index, 3)  -  lane in word
    //   mul(lane, 8)        -  bit shift
    //   shr(word, shift)    -  extracted (unmasked)
    //   and(_, 0xff)        -  masked byte
    let entry = module.entry_points.first().expect("entry point");
    let arena = &entry.function.expressions;
    let mut shr_count = 0usize;
    let mut and_count = 0usize;
    let mut mul_count = 0usize;
    for (_, expr) in arena.iter() {
        if let naga::Expression::Binary { op, .. } = expr {
            match op {
                naga::BinaryOperator::ShiftRight => shr_count += 1,
                naga::BinaryOperator::And => and_count += 1,
                naga::BinaryOperator::Multiply => mul_count += 1,
                _ => {}
            }
        }
    }
    assert!(
        shr_count >= 2,
        "U8 byte-extract must emit ≥2 ShiftRight (word index + byte shift); got {shr_count}"
    );
    assert!(
        and_count >= 2,
        "U8 byte-extract must emit ≥2 And (lane mask + 0xff mask); got {and_count}"
    );
    assert!(
        mul_count >= 1,
        "U8 byte-extract must emit ≥1 Multiply (lane*8); got {mul_count}"
    );

    // The literal 0xff must be present (the byte mask).
    let has_ff_literal = arena
        .iter()
        .any(|(_, expr)| matches!(expr, naga::Expression::Literal(naga::Literal::U32(0xff))));
    assert!(
        has_ff_literal,
        "U8 byte-extract must mask with literal 0xff"
    );
}

#[test]
fn i8_load_global_emits_byte_extract_with_sign_extend() {
    let desc = byte_load_desc(DataType::I8);
    let module = emit(&desc).unwrap();

    // I8 sign-extend uses (byte << 24) cast i32 then >> 24. The cast
    // appears as Expression::As with kind = Sint.
    let entry = module.entry_points.first().expect("entry point");
    let arena = &entry.function.expressions;
    let has_as_sint = arena.iter().any(|(_, expr)| {
        matches!(
            expr,
            naga::Expression::As {
                kind: naga::ScalarKind::Sint,
                ..
            }
        )
    });
    assert!(
        has_as_sint,
        "I8 byte-extract must include u32→i32 cast for sign extension"
    );

    // ShiftLeft by 24 must appear.
    let has_shl_24 = arena.iter().any(|(_, expr)| {
        matches!(
            expr,
            naga::Expression::Binary {
                op: naga::BinaryOperator::ShiftLeft,
                ..
            }
        )
    });
    assert!(
        has_shl_24,
        "I8 byte-extract must include a left-shift to put byte in MSB before sign extension"
    );
}

fn byte_store_desc(element_type: DataType) -> KernelDescriptor {
    KernelDescriptor {
        id: "byte_store".into(),
        bindings: BindingLayout {
            slots: vec![vyre_lower::BindingSlot {
                slot: 0,
                element_type,
                element_count: Some(64),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadWrite,
                name: "out".into(),
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
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![0, 0, 1],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(7), LiteralValue::U32(0xab)],
        },
    }
}

#[test]
fn u8_store_global_emits_byte_rmw_with_clear_and_merge() {
    let desc = byte_store_desc(DataType::U8);
    let module = emit(&desc).unwrap();
    let entry = module.entry_points.first().expect("entry point");
    let arena = &entry.function.expressions;

    let has_bitwise_not = arena.iter().any(|(_, expr)| {
        matches!(
            expr,
            naga::Expression::Unary {
                op: naga::UnaryOperator::BitwiseNot,
                ..
            }
        )
    });
    assert!(
        has_bitwise_not,
        "U8 byte-store must invert the lane mask via BitwiseNot to clear the target byte"
    );
    let has_inclusive_or = arena.iter().any(|(_, expr)| {
        matches!(
            expr,
            naga::Expression::Binary {
                op: naga::BinaryOperator::InclusiveOr,
                ..
            }
        )
    });
    assert!(
        has_inclusive_or,
        "U8 byte-store must merge cleared word with new byte via InclusiveOr"
    );
    let store_count = entry
        .function
        .body
        .iter()
        .filter(|stmt| matches!(stmt, naga::Statement::Store { .. }))
        .count();
    assert_eq!(
        store_count, 1,
        "U8 byte-store must collapse to one Statement::Store on the underlying u32 word"
    );
}

#[test]
fn i8_store_global_uses_same_rmw_path_as_u8() {
    // I8 stores share the byte-mask + RMW path; sign-extension only
    // affects loads.
    let desc = byte_store_desc(DataType::I8);
    let module = emit(&desc).unwrap();
    let entry = module.entry_points.first().expect("entry point");
    let arena = &entry.function.expressions;
    let has_bitwise_not = arena.iter().any(|(_, expr)| {
        matches!(
            expr,
            naga::Expression::Unary {
                op: naga::UnaryOperator::BitwiseNot,
                ..
            }
        )
    });
    assert!(
        has_bitwise_not,
        "I8 byte-store must invert the lane mask via BitwiseNot, same as U8"
    );
}

#[test]
fn u32_store_global_unchanged_by_byte_rmw_path() {
    // Regression guard: U32 stores must NOT trigger the byte-RMW path.
    let desc = byte_store_desc(DataType::U32);
    let module = emit(&desc).unwrap();
    let entry = module.entry_points.first().expect("entry point");
    let arena = &entry.function.expressions;
    let has_bitwise_not = arena.iter().any(|(_, expr)| {
        matches!(
            expr,
            naga::Expression::Unary {
                op: naga::UnaryOperator::BitwiseNot,
                ..
            }
        )
    });
    assert!(
        !has_bitwise_not,
        "U32 StoreGlobal must NOT emit BitwiseNot; byte-store path leaked"
    );
}

#[test]
fn u32_load_global_unchanged_by_byte_extract_path() {
    // Regression guard: U32 buffers must NOT trigger the byte-extract
    // path. The emitted body must remain a single Access + Load pair.
    let desc = byte_load_desc(DataType::U32);
    let module = emit(&desc).unwrap();
    let entry = module.entry_points.first().expect("entry point");
    let arena = &entry.function.expressions;
    let mut and_count = 0usize;
    let mut shr_count = 0usize;
    for (_, expr) in arena.iter() {
        if let naga::Expression::Binary { op, .. } = expr {
            if matches!(op, naga::BinaryOperator::And) {
                and_count += 1;
            }
            if matches!(op, naga::BinaryOperator::ShiftRight) {
                shr_count += 1;
            }
        }
    }
    assert_eq!(
        and_count, 0,
        "U32 LoadGlobal must not emit any byte-mask And ops; byte-extract path leaked"
    );
    assert_eq!(
        shr_count, 0,
        "U32 LoadGlobal must not emit any byte-shift ShiftRight ops"
    );
}
