//! Live CUDA/reference coverage for PTX vectorized memory chains.

mod common;

use common::{
    assert_f32_output_lanes, assert_u32_output_lanes, bool_bytes, cuda_reference_outputs,
    f32_bytes, i32_bytes, live_backend, u32_bytes,
};
use vyre::DispatchConfig;
use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

const VECTOR_LANE_COUNT: usize = 2048;
const VECTOR_GROUP_COUNT: usize = VECTOR_LANE_COUNT / 4;
const VECTOR_PAIR_GROUP_COUNT: usize = VECTOR_LANE_COUNT / 2;
const DYNAMIC_AFFINE_GROUP_COUNT: usize = 256;
const DYNAMIC_AFFINE_STRIDE: usize = 5;
const DYNAMIC_AFFINE_SOURCE_LANES: usize = DYNAMIC_AFFINE_GROUP_COUNT * DYNAMIC_AFFINE_STRIDE;
const DYNAMIC_AFFINE_OUTPUT_LANES: usize = DYNAMIC_AFFINE_GROUP_COUNT * 4;
const NARROW_LANE_COUNT: usize = 257;
const WORKGROUP_SIZE_X: u32 = 128;
const MAX_F32_ULP: u32 = 1;

#[test]
fn narrow_u8_scalar_copy_emits_byte_ptx_and_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let program = narrow_scalar_copy_program(DataType::U8, NARROW_LANE_COUNT as u32);
    let ptx = vyre_driver_cuda::codegen::program_to_ptx(&program, &DispatchConfig::default())
        .expect("Fix: CUDA PTX emission must support byte-wide U8 memory programs.");
    assert!(
        ptx.contains("ld.global.u8"),
        "Fix: U8 loads must use byte-wide PTX memory operations.\n{ptx}"
    );
    assert!(
        ptx.contains("st.global.u8"),
        "Fix: U8 stores must use byte-wide PTX memory operations.\n{ptx}"
    );

    let input = generated_u8_values();
    let outputs = cuda_reference_outputs(&backend, &program, &[input.clone()], "narrow_u8_copy");
    assert_eq!(
        outputs.reference[0], input,
        "Fix: U8 reference copy must preserve every byte."
    );
    assert_eq!(
        outputs.direct_cuda[0], outputs.reference[0],
        "Fix: direct CUDA U8 byte copy must match the reference path."
    );
    assert_eq!(
        outputs.compiled_cuda[0], outputs.reference[0],
        "Fix: compiled CUDA U8 byte copy must match the reference path."
    );
}

#[test]
fn vectorized_scalar_copy_emits_packed_ptx_and_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let mut checked = 0usize;

    for case in vector_cases() {
        let program = vectorized_copy_program(case.ty.clone());
        let ptx = vyre_driver_cuda::codegen::program_to_ptx(&program, &DispatchConfig::default())
            .expect("Fix: CUDA PTX emission must support unit-stride vectorized memory programs.");
        let vector_load = format!("ld.global.v4.{}", case.ptx_suffix);
        let vector_load_nc = format!("ld.global.nc.v4.{}", case.ptx_suffix);
        let vector_store = format!("st.global.v4.{}", case.ptx_suffix);
        assert!(
            ptx.contains(&vector_load) || ptx.contains(&vector_load_nc),
            "Fix: CUDA release PTX must fuse four adjacent {name} loads into a packed v4 global load.\n{ptx}",
            name = case.name
        );
        assert!(
            ptx.contains(&vector_store),
            "Fix: CUDA release PTX must fuse four adjacent {name} stores into a packed v4 global store.\n{ptx}",
            name = case.name
        );

        let input = generated_input_bytes(case.input);
        let outputs = cuda_reference_outputs(&backend, &program, &[input], case.name);
        checked += assert_case_outputs(&case, "direct", &outputs.direct_cuda, &outputs.reference);
        checked += assert_case_outputs(
            &case,
            "compiled",
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked,
        vector_cases().len() * VECTOR_LANE_COUNT * 2,
        "Fix: live CUDA vectorized memory matrix must compare every lane on direct and compiled paths."
    );
}

#[test]
fn vectorized_scalar_pair_copy_emits_packed_v2_ptx_and_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let mut checked = 0usize;

    for case in vector_cases() {
        let program = vectorized_pair_copy_program(case.ty.clone());
        let ptx = vyre_driver_cuda::codegen::program_to_ptx(&program, &DispatchConfig::default())
            .expect(
                "Fix: CUDA PTX emission must support unit-stride v2 vectorized memory programs.",
            );
        let vector_load = format!("ld.global.v2.{}", case.ptx_suffix);
        let vector_load_nc = format!("ld.global.nc.v2.{}", case.ptx_suffix);
        let vector_store = format!("st.global.v2.{}", case.ptx_suffix);
        assert!(
            ptx.contains(&vector_load) || ptx.contains(&vector_load_nc),
            "Fix: CUDA release PTX must fuse two adjacent {name} loads into a packed v2 global load.\n{ptx}",
            name = case.name
        );
        assert!(
            ptx.contains(&vector_store),
            "Fix: CUDA release PTX must fuse two adjacent {name} stores into a packed v2 global store.\n{ptx}",
            name = case.name
        );

        let input = generated_input_bytes(case.input);
        let outputs = cuda_reference_outputs(&backend, &program, &[input], case.name);
        checked +=
            assert_case_outputs(&case, "direct-v2", &outputs.direct_cuda, &outputs.reference);
        checked += assert_case_outputs(
            &case,
            "compiled-v2",
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked,
        vector_cases().len() * VECTOR_LANE_COUNT * 2,
        "Fix: live CUDA v2 vectorized memory matrix must compare every lane on direct and compiled paths."
    );
}

#[test]
fn vectorized_symbolic_affine_copy_emits_packed_v4_ptx_and_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let mut checked = 0usize;

    for case in vector_cases() {
        let program = vectorized_symbolic_affine_copy_program(case.ty.clone());
        let ptx = vyre_driver_cuda::codegen::program_to_ptx(&program, &DispatchConfig::default())
            .expect(
            "Fix: CUDA PTX emission must support symbolically-aligned vectorized memory programs.",
        );
        let vector_load = format!("ld.global.v4.{}", case.ptx_suffix);
        let vector_load_nc = format!("ld.global.nc.v4.{}", case.ptx_suffix);
        let vector_store = format!("st.global.v4.{}", case.ptx_suffix);
        assert!(
            ptx.contains(&vector_load) || ptx.contains(&vector_load_nc),
            "Fix: CUDA release PTX must fuse symbolic-affine adjacent {name} loads into a packed v4 global load.\n{ptx}",
            name = case.name
        );
        assert!(
            ptx.contains(&vector_store),
            "Fix: CUDA release PTX must fuse symbolic-affine adjacent {name} stores into a packed v4 global store.\n{ptx}",
            name = case.name
        );

        let input = generated_input_bytes(case.input);
        let outputs = cuda_reference_outputs(&backend, &program, &[input], case.name);
        checked += assert_case_outputs(
            &case,
            "direct-symbolic-v4",
            &outputs.direct_cuda,
            &outputs.reference,
        );
        checked += assert_case_outputs(
            &case,
            "compiled-symbolic-v4",
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked,
        vector_cases().len() * VECTOR_LANE_COUNT * 2,
        "Fix: live CUDA symbolic-affine vectorized memory matrix must compare every lane on direct and compiled paths."
    );
}

#[test]
fn dynamic_affine_sparse_gather_scalarizes_misaligned_loads_and_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let program = dynamic_affine_sparse_gather_program();
    let ptx = vyre_driver_cuda::codegen::program_to_ptx(&program, &DispatchConfig::default())
        .expect("Fix: CUDA PTX emission must support dynamic affine sparse gather vectorization.");
    assert!(
        !ptx.contains("ld.global.v2.u32")
            && !ptx.contains("ld.global.nc.v2.u32")
            && !ptx.contains("ld.global.v4.u32")
            && !ptx.contains("ld.global.nc.v4.u32"),
        "Fix: misaligned dynamic affine sparse gathers must not emit packed global loads.\n{ptx}"
    );
    assert!(
        !ptx.contains("st.global.v2.u32") && !ptx.contains("st.global.v4.u32"),
        "Fix: values from misaligned dynamic affine sparse gathers must not be repacked into unsafe global vector stores.\n{ptx}"
    );

    let input = generated_dynamic_u32_values(DYNAMIC_AFFINE_SOURCE_LANES, 0x3141_5926);
    let outputs = cuda_reference_outputs(
        &backend,
        &program,
        &[u32_bytes(&input)],
        "dynamic_affine_sparse_gather",
    );
    let checked = assert_u32_output_lanes(
        "dynamic_affine_sparse_gather direct",
        DYNAMIC_AFFINE_OUTPUT_LANES,
        &outputs.direct_cuda,
        &outputs.reference,
    ) + assert_u32_output_lanes(
        "dynamic_affine_sparse_gather compiled",
        DYNAMIC_AFFINE_OUTPUT_LANES,
        &outputs.compiled_cuda,
        &outputs.reference,
    );

    assert_eq!(
        checked,
        DYNAMIC_AFFINE_OUTPUT_LANES * 2,
        "Fix: live CUDA dynamic affine sparse gather must compare every output lane."
    );
}

#[test]
fn vectorized_dynamic_affine_sparse_scatter_emits_packed_v4_ptx_and_matches_reference_on_live_cuda()
{
    let backend = live_backend();
    let program = dynamic_affine_sparse_scatter_program();
    let ptx = vyre_driver_cuda::codegen::program_to_ptx(&program, &DispatchConfig::default())
        .expect("Fix: CUDA PTX emission must support dynamic affine sparse scatter vectorization.");
    assert!(
        ptx.contains("ld.global.v4.u32") || ptx.contains("ld.global.nc.v4.u32"),
        "Fix: dynamic affine sparse scatter input must emit a packed v4 global load.\n{ptx}"
    );
    assert!(
        !ptx.contains("st.global.v2.u32") && !ptx.contains("st.global.v4.u32"),
        "Fix: misaligned dynamic affine sparse scatters must not emit packed global stores.\n{ptx}"
    );

    let input = generated_dynamic_u32_values(DYNAMIC_AFFINE_OUTPUT_LANES, 0x2718_2818);
    let outputs = cuda_reference_outputs(
        &backend,
        &program,
        &[u32_bytes(&input)],
        "dynamic_affine_sparse_scatter",
    );
    let checked = assert_u32_output_lanes(
        "dynamic_affine_sparse_scatter direct",
        DYNAMIC_AFFINE_SOURCE_LANES,
        &outputs.direct_cuda,
        &outputs.reference,
    ) + assert_u32_output_lanes(
        "dynamic_affine_sparse_scatter compiled",
        DYNAMIC_AFFINE_SOURCE_LANES,
        &outputs.compiled_cuda,
        &outputs.reference,
    );

    assert_eq!(
        checked,
        DYNAMIC_AFFINE_SOURCE_LANES * 2,
        "Fix: live CUDA dynamic affine sparse scatter must compare every output lane."
    );
}

#[derive(Clone)]
struct VectorCase {
    name: &'static str,
    ty: DataType,
    input: VectorInput,
    ptx_suffix: &'static str,
}

#[derive(Clone, Copy)]
enum VectorInput {
    U32,
    I32,
    F32,
    Bool,
}

fn vector_cases() -> [VectorCase; 4] {
    [
        VectorCase {
            name: "vectorized_u32_copy",
            ty: DataType::U32,
            input: VectorInput::U32,
            ptx_suffix: "u32",
        },
        VectorCase {
            name: "vectorized_i32_copy",
            ty: DataType::I32,
            input: VectorInput::I32,
            ptx_suffix: "s32",
        },
        VectorCase {
            name: "vectorized_f32_copy",
            ty: DataType::F32,
            input: VectorInput::F32,
            ptx_suffix: "f32",
        },
        VectorCase {
            name: "vectorized_bool_copy",
            ty: DataType::Bool,
            input: VectorInput::Bool,
            ptx_suffix: "u32",
        },
    ]
}

fn vectorized_copy_program(ty: DataType) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, ty.clone()).with_count(VECTOR_LANE_COUNT as u32),
            BufferDecl::output("out", 1, ty).with_count(VECTOR_LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(VECTOR_GROUP_COUNT as u32)),
            vec![
                Node::let_bind("base", Expr::mul(Expr::gid_x(), Expr::u32(4))),
                Node::let_bind("i0", Expr::var("base")),
                Node::let_bind("i1", Expr::add(Expr::var("base"), Expr::u32(1))),
                Node::let_bind("i2", Expr::add(Expr::var("base"), Expr::u32(2))),
                Node::let_bind("i3", Expr::add(Expr::var("base"), Expr::u32(3))),
                Node::let_bind("v0", Expr::load("input", Expr::var("i0"))),
                Node::let_bind("v1", Expr::load("input", Expr::var("i1"))),
                Node::let_bind("v2", Expr::load("input", Expr::var("i2"))),
                Node::let_bind("v3", Expr::load("input", Expr::var("i3"))),
                Node::store("out", Expr::var("i0"), Expr::var("v0")),
                Node::store("out", Expr::var("i1"), Expr::var("v1")),
                Node::store("out", Expr::var("i2"), Expr::var("v2")),
                Node::store("out", Expr::var("i3"), Expr::var("v3")),
            ],
        )],
    )
}

fn narrow_scalar_copy_program(ty: DataType, count: u32) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, ty.clone()).with_count(count),
            BufferDecl::output("out", 1, ty).with_count(count),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(count)),
            vec![
                Node::let_bind("value", Expr::load("input", Expr::gid_x())),
                Node::store("out", Expr::gid_x(), Expr::var("value")),
            ],
        )],
    )
}

fn vectorized_pair_copy_program(ty: DataType) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, ty.clone()).with_count(VECTOR_LANE_COUNT as u32),
            BufferDecl::output("out", 1, ty).with_count(VECTOR_LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(VECTOR_PAIR_GROUP_COUNT as u32)),
            vec![
                Node::let_bind("base", Expr::mul(Expr::gid_x(), Expr::u32(2))),
                Node::let_bind("i0", Expr::var("base")),
                Node::let_bind("i1", Expr::add(Expr::var("base"), Expr::u32(1))),
                Node::let_bind("v0", Expr::load("input", Expr::var("i0"))),
                Node::let_bind("v1", Expr::load("input", Expr::var("i1"))),
                Node::store("out", Expr::var("i0"), Expr::var("v0")),
                Node::store("out", Expr::var("i1"), Expr::var("v1")),
            ],
        )],
    )
}

fn vectorized_symbolic_affine_copy_program(ty: DataType) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, ty.clone()).with_count(VECTOR_LANE_COUNT as u32),
            BufferDecl::output("out", 1, ty).with_count(VECTOR_LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(VECTOR_GROUP_COUNT as u32)),
            vec![
                Node::let_bind("two_x", Expr::add(Expr::gid_x(), Expr::gid_x())),
                Node::let_bind("base", Expr::add(Expr::var("two_x"), Expr::var("two_x"))),
                Node::let_bind("i0", Expr::var("base")),
                Node::let_bind("i1", Expr::add(Expr::var("base"), Expr::u32(1))),
                Node::let_bind("i2", Expr::add(Expr::var("base"), Expr::u32(2))),
                Node::let_bind("i3", Expr::add(Expr::var("base"), Expr::u32(3))),
                Node::let_bind("v0", Expr::load("input", Expr::var("i0"))),
                Node::let_bind("v1", Expr::load("input", Expr::var("i1"))),
                Node::let_bind("v2", Expr::load("input", Expr::var("i2"))),
                Node::let_bind("v3", Expr::load("input", Expr::var("i3"))),
                Node::store("out", Expr::var("i0"), Expr::var("v0")),
                Node::store("out", Expr::var("i1"), Expr::var("v1")),
                Node::store("out", Expr::var("i2"), Expr::var("v2")),
                Node::store("out", Expr::var("i3"), Expr::var("v3")),
            ],
        )],
    )
}

fn dynamic_affine_sparse_gather_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32)
                .with_count(DYNAMIC_AFFINE_SOURCE_LANES as u32),
            BufferDecl::output("out", 1, DataType::U32)
                .with_count(DYNAMIC_AFFINE_OUTPUT_LANES as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(DYNAMIC_AFFINE_GROUP_COUNT as u32)),
            vec![
                Node::let_bind(
                    "src_base",
                    Expr::mul(Expr::gid_x(), Expr::u32(DYNAMIC_AFFINE_STRIDE as u32)),
                ),
                Node::let_bind("dst_base", Expr::mul(Expr::gid_x(), Expr::u32(4))),
                Node::let_bind("s0", Expr::var("src_base")),
                Node::let_bind("s1", Expr::add(Expr::var("src_base"), Expr::u32(1))),
                Node::let_bind("s2", Expr::add(Expr::var("src_base"), Expr::u32(2))),
                Node::let_bind("s3", Expr::add(Expr::var("src_base"), Expr::u32(3))),
                Node::let_bind("d0", Expr::var("dst_base")),
                Node::let_bind("d1", Expr::add(Expr::var("dst_base"), Expr::u32(1))),
                Node::let_bind("d2", Expr::add(Expr::var("dst_base"), Expr::u32(2))),
                Node::let_bind("d3", Expr::add(Expr::var("dst_base"), Expr::u32(3))),
                Node::let_bind("v0", Expr::load("input", Expr::var("s0"))),
                Node::let_bind("v1", Expr::load("input", Expr::var("s1"))),
                Node::let_bind("v2", Expr::load("input", Expr::var("s2"))),
                Node::let_bind("v3", Expr::load("input", Expr::var("s3"))),
                Node::store("out", Expr::var("d0"), Expr::var("v0")),
                Node::store("out", Expr::var("d1"), Expr::var("v1")),
                Node::store("out", Expr::var("d2"), Expr::var("v2")),
                Node::store("out", Expr::var("d3"), Expr::var("v3")),
            ],
        )],
    )
}

fn dynamic_affine_sparse_scatter_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32)
                .with_count(DYNAMIC_AFFINE_OUTPUT_LANES as u32),
            BufferDecl::output("out", 1, DataType::U32)
                .with_count(DYNAMIC_AFFINE_SOURCE_LANES as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(DYNAMIC_AFFINE_GROUP_COUNT as u32)),
            vec![
                Node::let_bind("src_base", Expr::mul(Expr::gid_x(), Expr::u32(4))),
                Node::let_bind(
                    "dst_base",
                    Expr::mul(Expr::gid_x(), Expr::u32(DYNAMIC_AFFINE_STRIDE as u32)),
                ),
                Node::let_bind("s0", Expr::var("src_base")),
                Node::let_bind("s1", Expr::add(Expr::var("src_base"), Expr::u32(1))),
                Node::let_bind("s2", Expr::add(Expr::var("src_base"), Expr::u32(2))),
                Node::let_bind("s3", Expr::add(Expr::var("src_base"), Expr::u32(3))),
                Node::let_bind("d0", Expr::var("dst_base")),
                Node::let_bind("d1", Expr::add(Expr::var("dst_base"), Expr::u32(1))),
                Node::let_bind("d2", Expr::add(Expr::var("dst_base"), Expr::u32(2))),
                Node::let_bind("d3", Expr::add(Expr::var("dst_base"), Expr::u32(3))),
                Node::let_bind("v0", Expr::load("input", Expr::var("s0"))),
                Node::let_bind("v1", Expr::load("input", Expr::var("s1"))),
                Node::let_bind("v2", Expr::load("input", Expr::var("s2"))),
                Node::let_bind("v3", Expr::load("input", Expr::var("s3"))),
                Node::store("out", Expr::var("d0"), Expr::var("v0")),
                Node::store("out", Expr::var("d1"), Expr::var("v1")),
                Node::store("out", Expr::var("d2"), Expr::var("v2")),
                Node::store("out", Expr::var("d3"), Expr::var("v3")),
            ],
        )],
    )
}

fn assert_case_outputs(
    case: &VectorCase,
    path: &str,
    actual: &[Vec<u8>],
    expected: &[Vec<u8>],
) -> usize {
    let name = format!("{} {path}", case.name);
    if matches!(case.ty, DataType::F32) {
        assert_f32_output_lanes(&name, VECTOR_LANE_COUNT, MAX_F32_ULP, actual, expected)
    } else {
        assert_u32_output_lanes(&name, VECTOR_LANE_COUNT, actual, expected)
    }
}

fn generated_input_bytes(kind: VectorInput) -> Vec<u8> {
    match kind {
        VectorInput::U32 => u32_bytes(&generated_u32_values()),
        VectorInput::I32 => i32_bytes(&generated_i32_values()),
        VectorInput::F32 => f32_bytes(&generated_f32_values()),
        VectorInput::Bool => bool_bytes(&generated_bool_values()),
    }
}

fn generated_u8_values() -> Vec<u8> {
    (0..NARROW_LANE_COUNT)
        .map(|lane| {
            let lane = lane as u32;
            (lane.wrapping_mul(0x45d9_f3b).rotate_left((lane & 7) + 1) ^ 0xa7) as u8
        })
        .collect()
}

fn generated_u32_values() -> Vec<u32> {
    (0..VECTOR_LANE_COUNT)
        .map(|lane| {
            let lane = lane as u32;
            lane.wrapping_mul(0x9e37_79b9).rotate_left((lane & 31) + 1)
                ^ 0xa5a5_5a5a_u32.rotate_right(lane & 31)
        })
        .collect()
}

fn generated_i32_values() -> Vec<i32> {
    generated_u32_values()
        .into_iter()
        .enumerate()
        .map(|(lane, value)| match lane & 7 {
            0 => 0,
            1 => 1,
            2 => -1,
            3 => i32::MAX,
            4 => i32::MIN,
            _ => value as i32,
        })
        .collect()
}

fn generated_f32_values() -> Vec<f32> {
    (0..VECTOR_LANE_COUNT)
        .map(|lane| {
            let lane = lane as u32;
            let magnitude = (lane.wrapping_mul(37) & 0x3ff) as f32 / 8.0;
            if (lane & 1) == 0 {
                magnitude
            } else {
                -magnitude
            }
        })
        .collect()
}

fn generated_bool_values() -> Vec<bool> {
    (0..VECTOR_LANE_COUNT)
        .map(|lane| {
            let lane = lane as u32;
            ((lane.wrapping_mul(0x45d9_f3b).rotate_left(lane & 7) ^ 0x1357_9bdf) & 0b1011) == 0b0001
                || lane % 17 == 0
        })
        .collect()
}

fn generated_dynamic_u32_values(len: usize, salt: u32) -> Vec<u32> {
    (0..len)
        .map(|lane| {
            let lane = lane as u32;
            lane.wrapping_mul(0x9e37_79b9).rotate_left((lane & 31) + 1)
                ^ salt.rotate_right(lane & 31)
        })
        .collect()
}
