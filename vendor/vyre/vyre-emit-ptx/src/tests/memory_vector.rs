//! Test: memory vector.
use super::*;

fn dynamic_reassociated_vector_load_kernel(seed: u32) -> KernelDescriptor {
    let stride = seed.wrapping_mul(13).wrapping_add(1) << 2;
    two_slot_u32_kernel(
        "dynamic_reassociated_vec_load",
        vec![
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
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 2],
                result: Some(6),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![2, 3],
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
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 9],
                result: Some(10),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![2, 5],
                result: Some(11),
            },
            KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 11],
                result: Some(12),
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![4],
                result: Some(13),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 13, 12],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(stride),
            LiteralValue::U32(1),
            LiteralValue::U32(2),
            LiteralValue::U32(3),
            LiteralValue::U32(0),
        ],
    )
}

fn dynamic_reassociated_vector_store_kernel(seed: u32) -> KernelDescriptor {
    let stride = seed.wrapping_mul(17).wrapping_add(2) << 2;
    let value_base = 0x1000_0000_u32.wrapping_add(seed.rotate_left(seed % 31));
    two_slot_u32_kernel(
        "dynamic_reassociated_vec_store",
        vec![
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
                operands: vec![1, 2, 7],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![2, 3],
                result: Some(14),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 14, 9],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![2, 4],
                result: Some(15),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 15, 11],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![2, 5],
                result: Some(16),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 16, 13],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(stride),
            LiteralValue::U32(1),
            LiteralValue::U32(2),
            LiteralValue::U32(3),
            LiteralValue::U32(value_base),
            LiteralValue::U32(value_base.wrapping_add(1)),
            LiteralValue::U32(value_base.wrapping_add(2)),
            LiteralValue::U32(value_base.wrapping_add(3)),
        ],
    )
}

fn dynamic_misaligned_gather_to_vector_store_kernel() -> KernelDescriptor {
    two_slot_u32_kernel(
        "dynamic_misaligned_gather_to_vec_store",
        vec![
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
                result: Some(2),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Mul),
                operands: vec![0, 1],
                result: Some(3),
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![2],
                result: Some(4),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Mul),
                operands: vec![0, 4],
                result: Some(5),
            },
            KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 3],
                result: Some(6),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![3, 2],
                result: Some(7),
            },
            KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 7],
                result: Some(8),
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![3],
                result: Some(9),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![3, 9],
                result: Some(10),
            },
            KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 10],
                result: Some(11),
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![4],
                result: Some(12),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![3, 12],
                result: Some(13),
            },
            KernelOp {
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 13],
                result: Some(14),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 5, 6],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![5, 2],
                result: Some(15),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 15, 8],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![5, 9],
                result: Some(16),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 16, 11],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![5, 12],
                result: Some(17),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 17, 14],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(5),
            LiteralValue::U32(1),
            LiteralValue::U32(4),
            LiteralValue::U32(2),
            LiteralValue::U32(3),
        ],
    )
}

#[test]
fn emit_fuses_four_adjacent_u32_loads_to_ptx_vector_load() {
    let s = emit(&two_slot_u32_kernel(
        "vec_load",
        vec![
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
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 0, 8],
                result: None,
            },
        ],
        vec![LiteralValue::U32(0), LiteralValue::U32(1)],
    ))
    .unwrap();
    assert!(s.contains("ld.global.nc.v4.u32"));
    assert_eq!(s.matches("ld.global.u32").count(), 0);
    assert!(
        !s.contains("add.u32"),
        "fused vector load must not leave dead scalar index-increment adds:\n{s}"
    );
}

#[test]
fn generated_dynamic_reassociated_load_indices_fuse_to_v4() {
    for seed in 0..1024 {
        let s = emit(&dynamic_reassociated_vector_load_kernel(seed))
            .unwrap_or_else(|error| panic!("seed {seed} failed to emit: {error}"));
        assert!(
            s.contains("ld.global.nc.v4.u32"),
            "seed {seed} must recover v4 load fusion after affine reassociation:\n{s}"
        );
        assert_eq!(
            s.matches("ld.global.u32").count() + s.matches("ld.global.nc.u32").count(),
            0,
            "seed {seed} must not leave scalar data loads after v4 load fusion:\n{s}"
        );
    }
}

#[test]
fn misaligned_scalar_gather_values_do_not_fuse_to_vector_store() {
    let s = emit(&dynamic_misaligned_gather_to_vector_store_kernel()).unwrap();
    assert!(
        !s.contains("ld.global.nc.v4.u32") && !s.contains("ld.global.v4.u32"),
        "Fix: misaligned dynamic gather must stay scalar on the load side.\n{s}"
    );
    assert!(
        !s.contains("st.global.v2.u32") && !s.contains("st.global.v4.u32"),
        "Fix: values produced by a scalarized misaligned gather must not be repacked into a vector store on live CUDA.\n{s}"
    );
    assert!(
        s.matches("ld.global.u32").count() + s.matches("ld.global.nc.u32").count() >= 4,
        "Fix: misaligned gather fixture must emit scalar loads.\n{s}"
    );
    assert!(
        s.matches("st.global.u32").count() >= 4,
        "Fix: misaligned gather fixture must emit scalar stores.\n{s}"
    );
}

#[test]
fn emit_uniform_load_uses_readonly_global_addressing() {
    let mut desc = two_slot_u32_kernel(
        "uniform_load",
        vec![
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
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 0, 1],
                result: None,
            },
        ],
        vec![LiteralValue::U32(0)],
    );
    desc.bindings.slots[0].memory_class = MemoryClass::Uniform;
    let s = emit(&desc).unwrap();
    assert!(s.contains("ld.global"), "{s}");
    assert!(s.contains("st.global.u32"), "{s}");
}

#[test]
fn emit_hoists_ready_pure_op_into_vector_load_gap() {
    let s = emit(&two_slot_u32_kernel(
        "scheduled_vector_load_gap",
        vec![
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
                kind: KernelOpKind::Literal,
                operands: vec![2],
                result: Some(9),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![9, 1],
                result: Some(10),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 0, 8],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(0),
            LiteralValue::U32(1),
            LiteralValue::U32(11),
        ],
    ))
    .unwrap();

    let ld = s
        .find("ld.global.nc.v4.u32")
        .expect("test kernel must contain a fused vector load");
    let schedule_first = s
        .find("// schedule: hoist independent op#9 into vector-load gap after op#2")
        .expect("PTX emitter must hoist ready independent literal work after fused vector loads");
    let schedule_second = s
        .find("// schedule: hoist independent op#10 into vector-load gap after op#2")
        .expect("PTX emitter must keep filling fused vector-load gaps with newly-ready pure work");
    let store = s
        .find("st.global.u32")
        .expect("test kernel must contain the final global store");

    assert!(
        ld < schedule_first && schedule_first < schedule_second && schedule_second < store,
        "Fix: vector-load scheduling should hide packed-load latency before the visible store.\n{s}"
    );
}

#[test]
fn emit_hoists_ready_pure_op_into_load_use_gap() {
    let s = emit(&two_slot_u32_kernel(
        "scheduled_load_gap",
        vec![
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
                operands: vec![2, 1],
                result: Some(3),
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![2],
                result: Some(4),
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![4, 1],
                result: Some(5),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 0, 3],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(0),
            LiteralValue::U32(7),
            LiteralValue::U32(11),
        ],
    ))
    .unwrap();

    let ld = s
        .find("ld.global.u32")
        .expect("test kernel must contain a scalar global load");
    let schedule_first = s
        .find("// schedule: hoist independent op#4 into load-use gap after op#2")
        .expect("PTX emitter must hoist a ready independent op into the load-use gap");
    let schedule_second = s
        .find("// schedule: hoist independent op#5 into load-use gap after op#2")
        .expect("PTX emitter must keep filling the load-use gap with newly-ready independent work");
    let store = s
        .find("st.global.u32")
        .expect("test kernel must contain the final global store");

    assert!(
        ld < schedule_first && schedule_first < schedule_second && schedule_second < store,
        "Fix: B9 scheduling should place all ready independent pure work between a load and its visible memory effect.\n{s}"
    );
}

#[test]
fn emit_uses_read_only_cache_loads_for_texture_promoted_bindings() {
    let s = emit(&two_slot_u32_kernel(
        "readonly_cache_loads",
        vec![
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
                kind: KernelOpKind::LoadGlobal,
                operands: vec![0, 0],
                result: Some(2),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 0, 2],
                result: None,
            },
        ],
        vec![LiteralValue::U32(0)],
    ))
    .unwrap();

    assert!(
        s.contains("ld.global.nc.u32"),
        "Fix: repeated read-only global loads should use CUDA's read-only/non-coherent cache path.\n{s}"
    );
}

#[test]
fn emit_keeps_read_write_loads_on_coherent_global_path() {
    let desc = KernelDescriptor {
        id: "rw_global_loads".into(),
        bindings: BindingLayout {
            slots: vec![BindingSlot {
                slot: 0,
                element_type: DataType::U32,
                element_count: Some(16),
                memory_class: MemoryClass::Global,
                visibility: BindingVisibility::ReadWrite,
                name: "rw".into(),
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
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(1),
                },
                KernelOp {
                    kind: KernelOpKind::LoadGlobal,
                    operands: vec![0, 0],
                    result: Some(2),
                },
            ],
            child_bodies: vec![],
            literals: vec![LiteralValue::U32(0)],
        },
    };
    let s = emit(&desc).unwrap();

    assert!(s.contains("ld.global.u32"));
    assert!(
        !s.contains("ld.global.nc.u32"),
        "Fix: ReadWrite bindings must not use the non-coherent read-only cache path.\n{s}"
    );
}

#[test]
fn emit_fuses_four_adjacent_u32_stores_to_ptx_vector_store() {
    let s = emit(&two_slot_u32_kernel(
        "vec_store",
        vec![
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
                kind: KernelOpKind::Literal,
                operands: vec![5],
                result: Some(5),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 0, 2],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![0, 1],
                result: Some(6),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 6, 3],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![6, 1],
                result: Some(7),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 7, 4],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::BinOpKind(BinOp::Add),
                operands: vec![7, 1],
                result: Some(8),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 8, 5],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(0),
            LiteralValue::U32(1),
            LiteralValue::U32(10),
            LiteralValue::U32(11),
            LiteralValue::U32(12),
            LiteralValue::U32(13),
        ],
    ))
    .unwrap();
    assert!(s.contains("st.global.v4.u32"));
    assert!(!s.contains("st.global.u32"));
    assert!(
        !s.contains("add.u32"),
        "fused vector store must not leave dead scalar index-increment adds:\n{s}"
    );
}

#[test]
fn generated_dynamic_reassociated_store_indices_fuse_to_v4() {
    for seed in 0..1024 {
        let s = emit(&dynamic_reassociated_vector_store_kernel(seed))
            .unwrap_or_else(|error| panic!("seed {seed} failed to emit: {error}"));
        assert!(
            s.contains("st.global.v4.u32"),
            "seed {seed} must recover v4 store fusion after affine reassociation:\n{s}"
        );
        assert_eq!(
            s.matches("st.global.u32").count(),
            0,
            "seed {seed} must not leave scalar stores after v4 store fusion:\n{s}"
        );
    }
}

#[test]
fn emit_fuses_vector_store_across_folded_literal_index_gaps() {
    let s = emit(&two_slot_u32_kernel(
        "folded_literal_vec_store",
        vec![
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
                operands: vec![1, 0, 1],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![5],
                result: Some(5),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 5, 2],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![6],
                result: Some(6),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 6, 3],
                result: None,
            },
            KernelOp {
                kind: KernelOpKind::Literal,
                operands: vec![7],
                result: Some(7),
            },
            KernelOp {
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 7, 4],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(0),
            LiteralValue::U32(10),
            LiteralValue::U32(11),
            LiteralValue::U32(12),
            LiteralValue::U32(13),
            LiteralValue::U32(1),
            LiteralValue::U32(2),
            LiteralValue::U32(3),
        ],
    ))
    .unwrap();

    assert!(
        s.contains("st.global.v4.u32"),
        "Fix: folded adjacent store indices must still fuse into a vector store.\n{s}"
    );
    assert!(
        !s.contains("st.global.u32"),
        "Fix: folded-index vector store fusion must not leave scalar stores behind.\n{s}"
    );
}

#[test]
fn emit_does_not_fuse_vector_store_across_value_producer_gap() {
    let s = emit(&two_slot_u32_kernel(
        "value_gap_vec_store",
        vec![
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
                operands: vec![1, 0, 1],
                result: None,
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
                kind: KernelOpKind::StoreGlobal,
                operands: vec![1, 2, 3],
                result: None,
            },
        ],
        vec![
            LiteralValue::U32(0),
            LiteralValue::U32(10),
            LiteralValue::U32(1),
            LiteralValue::U32(11),
        ],
    ))
    .unwrap();

    assert!(
        !s.contains("st.global.v2.u32") && !s.contains("st.global.v4.u32"),
        "Fix: vector store fusion must not cross a value producer that has not emitted yet.\n{s}"
    );
    assert!(
        s.matches("st.global.u32").count() >= 2,
        "expected scalar stores when the value producer is in the fusion gap\n{s}"
    );
}
