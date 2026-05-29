//! Test: data tensor.
use super::*;

#[test]
fn cast_emits_cvt_with_target_dtype() {
    let kernel = KernelDescriptor {
        id: "cast".into(),
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
                    kind: KernelOpKind::Cast {
                        target: DataType::F32,
                    },
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(7)],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("cvt.rn.f32.u32"));
}

#[test]
fn f32_to_bool_cast_uses_unordered_not_equal_for_nan_truthiness() {
    let kernel = KernelDescriptor {
        id: "cast_f32_bool".into(),
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
                    kind: KernelOpKind::Cast {
                        target: DataType::Bool,
                    },
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::F32(f32::NAN)],
        },
    };

    let s = emit(&kernel).unwrap();
    assert!(
        s.contains("setp.neu.f32"),
        "f32 truthiness must treat NaN as true to match reference casts:\n{s}"
    );
}

#[test]
fn f32_not_equal_comparison_uses_unordered_predicate_for_nan_truthiness() {
    let kernel = KernelDescriptor {
        id: "f32_ne_nan".into(),
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
                    kind: KernelOpKind::BinOpKind(BinOp::Ne),
                    operands: vec![0, 1],
                    result: Some(2),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::F32(f32::NAN), LiteralValue::F32(1.0)],
        },
    };

    let s = emit(&kernel).unwrap();
    assert!(
        s.contains("setp.neu.f32"),
        "f32 Ne must be unordered-not-equal so NaN != x matches the reference oracle:\n{s}"
    );
}

#[test]
fn bool_to_f32_cast_materializes_predicate_before_numeric_conversion() {
    let kernel = KernelDescriptor {
        id: "cast_bool_f32".into(),
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
                    kind: KernelOpKind::Cast {
                        target: DataType::F32,
                    },
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::Bool(true)],
        },
    };

    let s = emit(&kernel).unwrap();
    assert!(
        s.contains("selp.u32") && s.contains("cvt.rn.f32.u32"),
        "Bool->F32 must materialize %p as a u32 word before cvt; PTX cannot cvt directly from predicate registers:\n{s}"
    );
}

#[test]
fn bool_to_i32_cast_materializes_predicate_word() {
    let kernel = KernelDescriptor {
        id: "cast_bool_i32".into(),
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
                    kind: KernelOpKind::Cast {
                        target: DataType::I32,
                    },
                    operands: vec![0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::Bool(true)],
        },
    };

    let s = emit(&kernel).unwrap();
    assert!(
        s.contains("selp.u32"),
        "Bool->I32 must materialize %p as a 0/1 word:\n{s}"
    );
}

#[test]
fn bool_global_load_uses_word_load_then_predicate_set() {
    let kernel = KernelDescriptor {
        id: "bool_load".into(),
        bindings: BindingLayout {
            slots: vec![
                BindingSlot {
                    slot: 0,
                    element_type: DataType::Bool,
                    element_count: Some(1),
                    memory_class: MemoryClass::Global,
                    visibility: BindingVisibility::ReadOnly,
                    name: "input".into(),
                },
                BindingSlot {
                    slot: 1,
                    element_type: DataType::U32,
                    element_count: Some(1),
                    memory_class: MemoryClass::Global,
                    visibility: BindingVisibility::WriteOnly,
                    name: "out".into(),
                },
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
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::Cast {
                        target: DataType::U32,
                    },
                    operands: vec![1],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::StoreGlobal,
                    operands: vec![1, 0, 2],
                    result: None,
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0)],
        },
    };

    let s = emit(&kernel).unwrap();
    assert!(
        !s.contains("ld.global.pred"),
        "PTX cannot load predicate registers from memory:\n{s}"
    );
    assert!(
        s.contains("ld.global.u32"),
        "Bool memory load must use the physical word ABI:\n{s}"
    );
    assert!(
        s.contains("setp.ne.u32"),
        "Bool memory load must canonicalize non-zero words to predicates:\n{s}"
    );
}

#[test]
fn bool_global_store_materializes_predicate_word() {
    let kernel = KernelDescriptor {
        id: "bool_store".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::Bool,
                element_count: Some(1),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::WriteOnly,
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
            literals: vec![LiteralValue::U32(0), LiteralValue::Bool(true)],
        },
    };

    let s = emit(&kernel).unwrap();
    assert!(
        !s.contains("st.global.pred"),
        "PTX cannot store predicate registers to memory:\n{s}"
    );
    assert!(
        s.contains("selp.u32"),
        "Bool memory store must materialize a 0/1 word:\n{s}"
    );
    assert!(
        s.contains("st.global.u32"),
        "Bool memory store must use the physical word ABI:\n{s}"
    );
}

#[test]
fn select_emits_selp_with_correct_dtype() {
    let kernel = KernelDescriptor {
        id: "select".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                }, // cond bool
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                }, // u32
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                }, // u32
                KernelOp {
                    kind: KernelOpKind::Select,
                    operands: vec![0, 1, 2],
                    result: Some(3),
                },
            ],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::Bool(true),
                LiteralValue::U32(10),
                LiteralValue::U32(20),
            ],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("selp.u32"));
}

#[test]
fn atomic_compare_exchange_emits_atom_global_cas_b32() {
    use vyre_foundation::ir::{AtomicOp, MemoryOrdering};
    let kernel = KernelDescriptor {
        id: "cas".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: Some(4),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadWrite,
                name: "buf".into(),
            }],
        },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                }, // index
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                }, // cmp
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                }, // new
                KernelOp {
                    kind: KernelOpKind::Atomic {
                        op: AtomicOp::CompareExchange,
                        ordering: MemoryOrdering::SeqCst,
                    },
                    operands: vec![0, 0, 1, 2],
                    result: Some(3),
                },
            ],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::U32(0),
                LiteralValue::U32(7),
                LiteralValue::U32(8),
            ],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(
        s.contains("atom.global.cas.b32"),
        "must emit atom.global.cas.b32:\n{s}"
    );
}

#[test]
fn runtime_index_load_clamps_against_buffer_length() {
    // PTX has no built-in bounds check. Speculative loads in `Expr::select`
    // arms can read past buffer end → CUDA_ERROR_ILLEGAL_ADDRESS. The
    // backend must clamp every runtime index against the per-slot length
    // stored at `[%rd0 + 4 + slot*4]`.
    let kernel = KernelDescriptor {
        id: "idx_load".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: None,
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadOnly,
                name: "input".into(),
            }],
        },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![
                // Use GlobalInvocationId as a non-literal index so the
                // immediate fast-path is bypassed and the clamp path runs.
                KernelOp {
                    kind: KernelOpKind::GlobalInvocationId,
                    operands: vec![0],
                    result: Some(0),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(1),
                },
            ],
            child_bodies: vec![],
            literals: vec![],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(
        s.contains("ld.global.u32") && s.contains("[%rd0 + 4]"),
        "must load slot-0 length from params metadata at +4:\n{s}"
    );
    assert!(
        s.contains("setp.lt.u32") && s.contains("selp.u32"),
        "must clamp index via setp.lt + selp.u32:\n{s}"
    );
}

#[test]
fn buffer_length_registers_are_preloaded_before_branch_stores() {
    let kernel = KernelDescriptor {
        id: "preload_lengths_before_branch_store".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: Some(16),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::WriteOnly,
                name: "out".into(),
            }],
        },
        dispatch: Dispatch::new(16, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::GlobalInvocationId,
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
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(3),
                },
                KernelOp {
                    kind: KernelOpKind::StructuredIfThenElse,
                    operands: vec![1, 0, 1],
                    result: None,
                },
            ],
            child_bodies: vec![
                KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 2],
                        result: None,
                    }],
                    child_bodies: vec![],
                    literals: vec![],
                },
                KernelBody {
                    ops: vec![KernelOp {
                        kind: KernelOpKind::StoreGlobal,
                        operands: vec![0, 0, 3],
                        result: None,
                    }],
                    child_bodies: vec![],
                    literals: vec![],
                },
            ],
            literals: vec![
                LiteralValue::Bool(true),
                LiteralValue::U32(7),
                LiteralValue::U32(9),
            ],
        },
    };
    let s = emit(&kernel).unwrap();
    let length_load = s
        .find("[%rd0 + 4]")
        .expect("must load output slot length from params metadata");
    let first_store = s
        .find("st.global.u32")
        .expect("must emit predicated branch stores");
    assert!(
        length_load < first_store,
        "slot length load must dominate all branch stores:\n{s}"
    );
    assert_eq!(
        s.matches("[%rd0 + 4]").count(),
        1,
        "slot length must be preloaded once, not lazily reloaded per branch:\n{s}"
    );
}

#[test]

fn select_on_predicates_does_not_emit_selp_pred() {
    // PTX `selp` does not support `.pred` operands. ptxas rejects
    // `selp.pred` with "Unexpected instruction types specified for 'selp'".
    // When both arms are bool, lower as not/and/and/or.
    let kernel = KernelDescriptor {
        id: "select_pred".into(),
        bindings: BindingLayout { slots: vec![] },
        dispatch: Dispatch::new(1, 1, 1),
        body: KernelBody {
            ops: vec![
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![0],
                    result: Some(0),
                }, // cond bool
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![1],
                    result: Some(1),
                }, // bool true
                KernelOp {
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                }, // bool false
                KernelOp {
                    kind: KernelOpKind::Select,
                    operands: vec![0, 1, 2],
                    result: Some(3),
                },
            ],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::Bool(true),
                LiteralValue::Bool(true),
                LiteralValue::Bool(false),
            ],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(
        !s.contains("selp.pred"),
        "must not emit invalid selp.pred:\n{s}"
    );
    assert!(
        s.contains("not.pred") && s.contains("and.pred") && s.contains("or.pred"),
        "predicate select must lower to not/and/or:\n{s}"
    );
}

#[test]
fn fma_emits_fma_rn_with_dtype() {
    let kernel = KernelDescriptor {
        id: "fma".into(),
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
                    kind: KernelOpKind::Literal,
                    operands: vec![2],
                    result: Some(2),
                },
                KernelOp {
                    kind: KernelOpKind::Fma,
                    operands: vec![0, 1, 2],
                    result: Some(3),
                },
            ],
            child_bodies: vec![],
            literals: vec![
                LiteralValue::F32(1.0),
                LiteralValue::F32(2.0),
                LiteralValue::F32(3.0),
            ],
        },
    };
    let s = emit(&kernel).unwrap();
    assert!(s.contains("fma.rn.f32"));
}

#[test]
fn matrix_mma_emits_real_mma_sync_and_binds_all_four_results() {
    let mut ops = Vec::new();
    let mut literals = Vec::new();
    for id in 0..6 {
        literals.push(LiteralValue::U32(id));
        ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![id],
            result: Some(id),
        });
    }
    for id in 6..10 {
        literals.push(LiteralValue::F32(0.0));
        ops.push(KernelOp {
            kind: KernelOpKind::Literal,
            operands: vec![id],
            result: Some(id),
        });
    }
    ops.push(KernelOp {
        kind: KernelOpKind::MatrixMma {
            shape: MatrixMmaShape::M16N8K16,
            a_layout: MatrixMmaLayout::RowMajor,
            b_layout: MatrixMmaLayout::ColMajor,
            a_type: MatrixMmaElement::F16,
            b_type: MatrixMmaElement::F16,
            accum_type: MatrixMmaElement::F32,
        },
        operands: (0..10).collect(),
        result: Some(10),
    });
    ops.push(KernelOp {
        kind: KernelOpKind::Literal,
        operands: vec![10],
        result: Some(14),
    });
    literals.push(LiteralValue::U32(0));
    ops.push(KernelOp {
        kind: KernelOpKind::StoreGlobal,
        operands: vec![0, 14, 13],
        result: None,
    });

    let kernel = KernelDescriptor {
        id: "mma".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::F32,
                element_count: Some(1),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::WriteOnly,
                name: "out".into(),
            }],
        },
        dispatch: Dispatch::new(32, 1, 1),
        body: KernelBody {
            ops,
            child_bodies: vec![],
            literals,
        },
    };

    vyre_lower::verify::verify(&kernel)
        .expect("MatrixMma must publish result ids base..base+4 to verifier");
    let s = emit_with_target(&kernel, ComputeCapability::SM_70).unwrap();
    assert!(s.contains("mma.sync.aligned.m16n8k16.row.col.f32.f16.f16.f32"));
    assert!(
        s.contains("st.global.f32"),
        "fourth MatrixMma result id must be usable by later ops"
    );
}

