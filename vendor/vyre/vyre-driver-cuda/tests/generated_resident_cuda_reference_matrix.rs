//! Generated live CUDA-resident/reference differential matrix for release-path semantics.

mod common;

use common::{
    assert_f32_output_lanes, assert_u32_output_lanes, bool_bytes, bool_word, eq_word, f32_bytes,
    ge_word, generated_bool_cast_values, generated_f32_cast_values, generated_f32_fma_values,
    generated_i32_cast_values, generated_mixed_bool_values as generated_bool_values,
    generated_mixed_u32_values as generated_atomic_values, generated_u32_cast_values, gt_word,
    i32_bytes, le_word, live_backend, lt_word, ne_word, reference_outputs,
    resident_cuda_reference_outputs, u32_bytes, GENERATED_LANE_COUNT as LANE_COUNT,
    GENERATED_WORKGROUP_SIZE_X as WORKGROUP_SIZE_X,
};
use vyre_driver_cuda::CudaBackend;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

const OUTPUT_BYTES: usize = LANE_COUNT * std::mem::size_of::<u32>();
const BUCKET_COUNT: usize = 8;
const BUCKET_MASK: u32 = BUCKET_COUNT as u32 - 1;
const MAX_F32_ULP: u32 = 1;

#[derive(Clone, Copy)]
struct BoolUnaryCase {
    name: &'static str,
    build: fn(Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct BoolBinaryCase {
    name: &'static str,
    build: fn(Expr, Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct F32CompareCase {
    name: &'static str,
    build: fn(Expr, Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct F32BinaryCase {
    name: &'static str,
    rhs: F32RhsKind,
    build: fn(Expr, Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct F32UnaryCase {
    name: &'static str,
    inputs: F32InputKind,
    build: fn(Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct F32ClassifyCase {
    name: &'static str,
    build: fn(Expr) -> Expr,
}

#[derive(Clone, Copy)]
enum F32RhsKind {
    Mixed,
    NonZero,
}

#[derive(Clone, Copy)]
enum F32InputKind {
    Mixed,
    NonZero,
    SqrtDomain,
}

#[derive(Clone, Copy)]
struct ResidentAtomicCase {
    name: &'static str,
    identity: u32,
    value_salt: u32,
    build: fn(&str, Expr, Expr) -> Expr,
}

#[derive(Clone)]
struct CastCase {
    name: &'static str,
    input_type: DataType,
    output_type: DataType,
}

#[derive(Clone, Copy)]
struct ResidentBinaryCase {
    name: &'static str,
    build: fn(Expr, Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct ResidentUnaryCase {
    name: &'static str,
    build: fn(Expr) -> Expr,
}

#[derive(Clone)]
struct ResidentMemoryCase {
    name: &'static str,
    ty: DataType,
    build_value: fn(Expr) -> Expr,
    build_src: fn(Expr) -> Expr,
    build_dst: fn(Expr) -> Expr,
}

fn bool_and(lhs: Expr, rhs: Expr) -> Expr {
    Expr::and(lhs, rhs)
}

fn bool_or(lhs: Expr, rhs: Expr) -> Expr {
    Expr::or(lhs, rhs)
}

fn bool_eq(lhs: Expr, rhs: Expr) -> Expr {
    Expr::eq(lhs, rhs)
}

fn bool_ne(lhs: Expr, rhs: Expr) -> Expr {
    Expr::ne(lhs, rhs)
}

fn isnan_word(value: Expr) -> Expr {
    bool_word(Expr::is_nan(value))
}

fn isinf_word(value: Expr) -> Expr {
    bool_word(Expr::is_inf(value))
}

fn isfinite_word(value: Expr) -> Expr {
    bool_word(Expr::is_finite(value))
}

fn i32_rem_i32(lhs: Expr, rhs: Expr) -> Expr {
    Expr::cast(DataType::I32, Expr::rem(lhs, rhs))
}

fn i32_wrapping_negate(value: Expr) -> Expr {
    Expr::sub(Expr::i32(0), value)
}

fn i32_wrapping_abs(value: Expr) -> Expr {
    Expr::select(
        Expr::lt(value.clone(), Expr::i32(0)),
        i32_wrapping_negate(value.clone()),
        value,
    )
}

fn atomic_add(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_add(buffer, index, value)
}

fn atomic_or(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_or(buffer, index, value)
}

fn atomic_and(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_and(buffer, index, value)
}

fn atomic_xor(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_xor(buffer, index, value)
}

fn atomic_min(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_min(buffer, index, value)
}

fn atomic_max(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_max(buffer, index, value)
}

const BOOL_UNARY_CASES: &[BoolUnaryCase] = &[BoolUnaryCase {
    name: "resident_bool_not",
    build: Expr::not,
}];

const BOOL_BINARY_CASES: &[BoolBinaryCase] = &[
    BoolBinaryCase {
        name: "resident_bool_and",
        build: bool_and,
    },
    BoolBinaryCase {
        name: "resident_bool_or",
        build: bool_or,
    },
    BoolBinaryCase {
        name: "resident_bool_eq",
        build: bool_eq,
    },
    BoolBinaryCase {
        name: "resident_bool_ne",
        build: bool_ne,
    },
];

const F32_COMPARE_CASES: &[F32CompareCase] = &[
    F32CompareCase {
        name: "resident_f32_eq",
        build: eq_word,
    },
    F32CompareCase {
        name: "resident_f32_ne",
        build: ne_word,
    },
    F32CompareCase {
        name: "resident_f32_lt",
        build: lt_word,
    },
    F32CompareCase {
        name: "resident_f32_le",
        build: le_word,
    },
    F32CompareCase {
        name: "resident_f32_gt",
        build: gt_word,
    },
    F32CompareCase {
        name: "resident_f32_ge",
        build: ge_word,
    },
];

const F32_BINARY_CASES: &[F32BinaryCase] = &[
    F32BinaryCase {
        name: "resident_f32_add",
        rhs: F32RhsKind::Mixed,
        build: Expr::add,
    },
    F32BinaryCase {
        name: "resident_f32_sub",
        rhs: F32RhsKind::Mixed,
        build: Expr::sub,
    },
    F32BinaryCase {
        name: "resident_f32_mul",
        rhs: F32RhsKind::Mixed,
        build: Expr::mul,
    },
    F32BinaryCase {
        name: "resident_f32_div_nonzero",
        rhs: F32RhsKind::NonZero,
        build: Expr::div,
    },
    F32BinaryCase {
        name: "resident_f32_min",
        rhs: F32RhsKind::Mixed,
        build: Expr::min,
    },
    F32BinaryCase {
        name: "resident_f32_max",
        rhs: F32RhsKind::Mixed,
        build: Expr::max,
    },
];

const F32_UNARY_CASES: &[F32UnaryCase] = &[
    F32UnaryCase {
        name: "resident_f32_negate",
        inputs: F32InputKind::Mixed,
        build: Expr::negate,
    },
    F32UnaryCase {
        name: "resident_f32_abs",
        inputs: F32InputKind::Mixed,
        build: Expr::abs,
    },
    F32UnaryCase {
        name: "resident_f32_sqrt",
        inputs: F32InputKind::SqrtDomain,
        build: Expr::sqrt,
    },
    F32UnaryCase {
        name: "resident_f32_reciprocal_nonzero",
        inputs: F32InputKind::NonZero,
        build: Expr::reciprocal,
    },
];

const F32_CLASSIFY_CASES: &[F32ClassifyCase] = &[
    F32ClassifyCase {
        name: "resident_f32_is_nan",
        build: isnan_word,
    },
    F32ClassifyCase {
        name: "resident_f32_is_inf",
        build: isinf_word,
    },
    F32ClassifyCase {
        name: "resident_f32_is_finite",
        build: isfinite_word,
    },
];

const RESIDENT_ATOMIC_CASES: &[ResidentAtomicCase] = &[
    ResidentAtomicCase {
        name: "resident_atomic_add_bucketed",
        identity: 0,
        value_salt: 0x1020_3040,
        build: atomic_add,
    },
    ResidentAtomicCase {
        name: "resident_atomic_or_bucketed",
        identity: 0,
        value_salt: 0x3141_5926,
        build: atomic_or,
    },
    ResidentAtomicCase {
        name: "resident_atomic_and_bucketed",
        identity: u32::MAX,
        value_salt: 0x2718_2818,
        build: atomic_and,
    },
    ResidentAtomicCase {
        name: "resident_atomic_xor_bucketed",
        identity: 0,
        value_salt: 0x9e37_79b9,
        build: atomic_xor,
    },
    ResidentAtomicCase {
        name: "resident_atomic_min_bucketed",
        identity: u32::MAX,
        value_salt: 0xa5a5_5a5a,
        build: atomic_min,
    },
    ResidentAtomicCase {
        name: "resident_atomic_max_bucketed",
        identity: 0,
        value_salt: 0x5a5a_a5a5,
        build: atomic_max,
    },
];

const CAST_CASES: &[CastCase] = &[
    CastCase {
        name: "resident_u32_to_i32",
        input_type: DataType::U32,
        output_type: DataType::I32,
    },
    CastCase {
        name: "resident_u32_to_f32",
        input_type: DataType::U32,
        output_type: DataType::F32,
    },
    CastCase {
        name: "resident_u32_to_bool",
        input_type: DataType::U32,
        output_type: DataType::Bool,
    },
    CastCase {
        name: "resident_i32_to_u32",
        input_type: DataType::I32,
        output_type: DataType::U32,
    },
    CastCase {
        name: "resident_i32_to_f32",
        input_type: DataType::I32,
        output_type: DataType::F32,
    },
    CastCase {
        name: "resident_i32_to_bool",
        input_type: DataType::I32,
        output_type: DataType::Bool,
    },
    CastCase {
        name: "resident_f32_to_u32",
        input_type: DataType::F32,
        output_type: DataType::U32,
    },
    CastCase {
        name: "resident_f32_to_i32",
        input_type: DataType::F32,
        output_type: DataType::I32,
    },
    CastCase {
        name: "resident_f32_to_bool",
        input_type: DataType::F32,
        output_type: DataType::Bool,
    },
    CastCase {
        name: "resident_bool_to_u32",
        input_type: DataType::Bool,
        output_type: DataType::U32,
    },
    CastCase {
        name: "resident_bool_to_i32",
        input_type: DataType::Bool,
        output_type: DataType::I32,
    },
    CastCase {
        name: "resident_bool_to_f32",
        input_type: DataType::Bool,
        output_type: DataType::F32,
    },
];

const U32_BINARY_CASES: &[ResidentBinaryCase] = &[
    ResidentBinaryCase {
        name: "resident_u32_add",
        build: Expr::add,
    },
    ResidentBinaryCase {
        name: "resident_u32_sub",
        build: Expr::sub,
    },
    ResidentBinaryCase {
        name: "resident_u32_mul",
        build: Expr::mul,
    },
    ResidentBinaryCase {
        name: "resident_u32_div_total",
        build: Expr::div,
    },
    ResidentBinaryCase {
        name: "resident_u32_rem_total",
        build: Expr::rem,
    },
    ResidentBinaryCase {
        name: "resident_u32_bitand",
        build: Expr::bitand,
    },
    ResidentBinaryCase {
        name: "resident_u32_bitor",
        build: Expr::bitor,
    },
    ResidentBinaryCase {
        name: "resident_u32_bitxor",
        build: Expr::bitxor,
    },
    ResidentBinaryCase {
        name: "resident_u32_shl_masked",
        build: Expr::shl,
    },
    ResidentBinaryCase {
        name: "resident_u32_shr_masked",
        build: Expr::shr,
    },
];

const U32_UNARY_CASES: &[ResidentUnaryCase] = &[
    ResidentUnaryCase {
        name: "resident_u32_bitnot",
        build: Expr::bitnot,
    },
    ResidentUnaryCase {
        name: "resident_u32_reverse_bits",
        build: Expr::reverse_bits,
    },
    ResidentUnaryCase {
        name: "resident_u32_popcount",
        build: Expr::popcount,
    },
    ResidentUnaryCase {
        name: "resident_u32_clz",
        build: Expr::clz,
    },
    ResidentUnaryCase {
        name: "resident_u32_ctz",
        build: Expr::ctz,
    },
];


const I32_BINARY_CASES: &[ResidentBinaryCase] = &[
    ResidentBinaryCase {
        name: "resident_i32_add",
        build: Expr::add,
    },
    ResidentBinaryCase {
        name: "resident_i32_sub",
        build: Expr::sub,
    },
    ResidentBinaryCase {
        name: "resident_i32_mul",
        build: Expr::mul,
    },
    ResidentBinaryCase {
        name: "resident_i32_div_total",
        build: Expr::div,
    },
    ResidentBinaryCase {
        name: "resident_i32_rem_total",
        build: i32_rem_i32,
    },
];

const I32_UNARY_CASES: &[ResidentUnaryCase] = &[
    ResidentUnaryCase {
        name: "resident_i32_wrapping_negate",
        build: i32_wrapping_negate,
    },
    ResidentUnaryCase {
        name: "resident_i32_abs",
        build: i32_wrapping_abs,
    },
];

fn value_identity(value: Expr) -> Expr {
    value
}

fn value_bitnot(value: Expr) -> Expr {
    Expr::bitnot(value)
}

fn value_bool_not(value: Expr) -> Expr {
    Expr::not(value)
}

fn value_f32_negate(value: Expr) -> Expr {
    Expr::negate(value)
}

fn identity_index(idx: Expr) -> Expr {
    idx
}

fn reverse_index(idx: Expr) -> Expr {
    Expr::sub(Expr::u32((LANE_COUNT - 1) as u32), idx)
}

fn stride37_index(idx: Expr) -> Expr {
    Expr::bitand(
        Expr::mul(idx, Expr::u32(37)),
        Expr::u32((LANE_COUNT - 1) as u32),
    )
}

fn stride73_index(idx: Expr) -> Expr {
    Expr::bitand(
        Expr::mul(idx, Expr::u32(73)),
        Expr::u32((LANE_COUNT - 1) as u32),
    )
}

const U32_MEMORY_CASES: &[ResidentMemoryCase] = &[
    ResidentMemoryCase {
        name: "resident_u32_reverse_load_identity_store",
        ty: DataType::U32,
        build_value: value_identity,
        build_src: reverse_index,
        build_dst: identity_index,
    },
    ResidentMemoryCase {
        name: "resident_u32_dual_permutation_bitnot",
        ty: DataType::U32,
        build_value: value_bitnot,
        build_src: stride73_index,
        build_dst: stride37_index,
    },
];

const BOOL_MEMORY_CASES: &[ResidentMemoryCase] = &[
    ResidentMemoryCase {
        name: "resident_bool_reverse_load_identity_store",
        ty: DataType::Bool,
        build_value: value_identity,
        build_src: reverse_index,
        build_dst: identity_index,
    },
    ResidentMemoryCase {
        name: "resident_bool_dual_permutation_not",
        ty: DataType::Bool,
        build_value: value_bool_not,
        build_src: stride73_index,
        build_dst: stride37_index,
    },
];

const F32_MEMORY_CASES: &[ResidentMemoryCase] = &[
    ResidentMemoryCase {
        name: "resident_f32_reverse_load_identity_store",
        ty: DataType::F32,
        build_value: value_identity,
        build_src: reverse_index,
        build_dst: identity_index,
    },
    ResidentMemoryCase {
        name: "resident_f32_dual_permutation_negate",
        ty: DataType::F32,
        build_value: value_f32_negate,
        build_src: stride73_index,
        build_dst: stride37_index,
    },
];

#[test]
fn generated_resident_bool_scalar_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let lhs = generated_bool_values(0x1020_3040);
    let rhs = generated_bool_values(0xa5a5_5a5a);
    let lhs_bytes = bool_bytes(&lhs);
    let rhs_bytes = bool_bytes(&rhs);
    let mut checked_lanes = 0usize;

    for case in BOOL_BINARY_CASES {
        let program = resident_bool_binary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[lhs_bytes.clone(), rhs_bytes.clone()],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    for case in BOOL_UNARY_CASES {
        let program = resident_bool_unary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            std::slice::from_ref(&lhs_bytes),
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        (BOOL_BINARY_CASES.len() + BOOL_UNARY_CASES.len()) * LANE_COUNT,
        "Fix: resident Bool generated matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_bool_select_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let flag = generated_bool_values(0x3333_cccc);
    let lhs = generated_bool_values(0x1234_abcd);
    let rhs = generated_bool_values(0xdcba_4321);
    let inputs = vec![bool_bytes(&flag), bool_bytes(&lhs), bool_bytes(&rhs)];
    let program = resident_bool_select_program();
    let outputs = resident_cuda_reference_outputs(
        &backend,
        &program,
        &inputs,
        &[OUTPUT_BYTES],
        "resident_bool_select",
    );
    let checked_lanes = assert_u32_output_lanes(
        "resident_bool_select",
        LANE_COUNT,
        &outputs.resident_cuda,
        &outputs.reference,
    );
    assert_eq!(
        checked_lanes, LANE_COUNT,
        "Fix: resident Bool select generated matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_f32_comparison_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let lhs = generated_f32_values(0x55aa_1234);
    let rhs = generated_f32_values(0xaa55_4321);
    let lhs_bytes = f32_bytes(&lhs);
    let rhs_bytes = f32_bytes(&rhs);
    let mut checked_lanes = 0usize;

    for case in F32_COMPARE_CASES {
        let program = resident_f32_compare_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[lhs_bytes.clone(), rhs_bytes.clone()],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        F32_COMPARE_CASES.len() * LANE_COUNT,
        "Fix: resident f32 comparison matrix must compare every output lane, including NaN comparison lanes."
    );
}

#[test]
fn generated_resident_f32_binary_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let lhs = generated_f32_values(0x1357_9bdf);
    let mixed_rhs = generated_f32_values(0x2468_ace0);
    let nonzero_rhs = generated_f32_nonzero_values(0x0bad_f00d);
    let lhs_bytes = f32_bytes(&lhs);
    let mixed_rhs_bytes = f32_bytes(&mixed_rhs);
    let nonzero_rhs_bytes = f32_bytes(&nonzero_rhs);
    let mut checked_lanes = 0usize;

    for case in F32_BINARY_CASES {
        let rhs_bytes = match case.rhs {
            F32RhsKind::Mixed => &mixed_rhs_bytes,
            F32RhsKind::NonZero => &nonzero_rhs_bytes,
        };
        let program = resident_f32_binary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[lhs_bytes.clone(), rhs_bytes.clone()],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_f32_output_lanes(
            case.name,
            LANE_COUNT,
            MAX_F32_ULP,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        F32_BINARY_CASES.len() * LANE_COUNT,
        "Fix: resident f32 binary matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_f32_unary_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let mixed = generated_f32_values(0xfeed_beef);
    let nonzero = generated_f32_nonzero_values(0xabcd_1234);
    let sqrt_domain = generated_f32_sqrt_domain_values(0xdec0_ded1);
    let mixed_bytes = f32_bytes(&mixed);
    let nonzero_bytes = f32_bytes(&nonzero);
    let sqrt_domain_bytes = f32_bytes(&sqrt_domain);
    let mut checked_lanes = 0usize;

    for case in F32_UNARY_CASES {
        let input_bytes = match case.inputs {
            F32InputKind::Mixed => &mixed_bytes,
            F32InputKind::NonZero => &nonzero_bytes,
            F32InputKind::SqrtDomain => &sqrt_domain_bytes,
        };
        let program = resident_f32_unary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            std::slice::from_ref(input_bytes),
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_f32_output_lanes(
            case.name,
            LANE_COUNT,
            MAX_F32_ULP,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        F32_UNARY_CASES.len() * LANE_COUNT,
        "Fix: resident f32 unary matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_f32_classification_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let input = generated_f32_classification_values();
    let input_bytes = f32_bytes(&input);
    let mut checked_lanes = 0usize;

    for case in F32_CLASSIFY_CASES {
        let program = resident_f32_classify_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            std::slice::from_ref(&input_bytes),
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        F32_CLASSIFY_CASES.len() * LANE_COUNT,
        "Fix: resident f32 classification matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_atomic_reduction_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let mut checked_lanes = 0usize;

    for case in RESIDENT_ATOMIC_CASES {
        let program = resident_atomic_reduction_program(case);
        let initial = vec![case.identity; LANE_COUNT];
        let values = generated_atomic_values(case.value_salt);
        let inputs = vec![u32_bytes(&initial), u32_bytes(&values)];
        let (resident_cuda, reference) =
            resident_in_place_reference_outputs(&backend, &program, &inputs, &[0], case.name);
        checked_lanes += assert_u32_output_lanes(case.name, LANE_COUNT, &resident_cuda, &reference);
    }

    assert_eq!(
        checked_lanes,
        RESIDENT_ATOMIC_CASES.len() * LANE_COUNT,
        "Fix: resident atomic generated matrix must compare every accumulator lane."
    );
}

#[test]
fn generated_resident_cast_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let u32_input = generated_u32_cast_values(LANE_COUNT);
    let i32_input = generated_i32_cast_values(LANE_COUNT);
    let f32_input = generated_f32_cast_values(LANE_COUNT);
    let bool_input = generated_bool_cast_values(LANE_COUNT);
    let mut checked_lanes = 0usize;

    for case in CAST_CASES {
        let input = match &case.input_type {
            DataType::U32 => u32_bytes(&u32_input),
            DataType::I32 => i32_bytes(&i32_input),
            DataType::F32 => f32_bytes(&f32_input),
            DataType::Bool => bool_bytes(&bool_input),
            _ => unreachable!("resident generated cast matrix only covers scalar storage types"),
        };
        let program = resident_cast_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[input],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        CAST_CASES.len() * LANE_COUNT,
        "Fix: resident cast generated matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_f32_fma_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let a = generated_f32_fma_values(LANE_COUNT, 0x1234_5678);
    let b = generated_f32_fma_values(LANE_COUNT, 0x9abc_def0);
    let c = generated_f32_fma_values(LANE_COUNT, 0x0fed_cba9);
    let inputs = vec![f32_bytes(&a), f32_bytes(&b), f32_bytes(&c)];
    let program = resident_fma_program();
    let outputs = resident_cuda_reference_outputs(
        &backend,
        &program,
        &inputs,
        &[OUTPUT_BYTES],
        "resident_f32_fma",
    );
    let checked_lanes = assert_f32_output_lanes(
        "resident_f32_fma",
        LANE_COUNT,
        MAX_F32_ULP,
        &outputs.resident_cuda,
        &outputs.reference,
    );
    assert_eq!(
        checked_lanes, LANE_COUNT,
        "Fix: resident FMA generated matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_u32_scalar_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let lhs = generated_atomic_values(0x1020_3040);
    let rhs = generated_atomic_values(0xa5a5_5a5a);
    let lhs_bytes = u32_bytes(&lhs);
    let rhs_bytes = u32_bytes(&rhs);
    let mut checked_lanes = 0usize;

    for case in U32_BINARY_CASES {
        let program = resident_u32_binary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[lhs_bytes.clone(), rhs_bytes.clone()],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    for case in U32_UNARY_CASES {
        let program = resident_u32_unary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            std::slice::from_ref(&lhs_bytes),
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        (U32_BINARY_CASES.len() + U32_UNARY_CASES.len()) * LANE_COUNT,
        "Fix: resident u32 scalar generated matrix must compare every output lane."
    );
}

#[test]

fn generated_resident_i32_scalar_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let lhs = generated_i32_cast_values(LANE_COUNT);
    let rhs = generated_i32_cast_values(LANE_COUNT)
        .into_iter()
        .enumerate()
        .map(|(lane, value)| {
            let mixed = value ^ ((lane as i32).wrapping_mul(0x1f1f_0101));
            if mixed == 0 || mixed == -1 {
                ((lane as i32) & 0x3ff) + 1
            } else {
                mixed
            }
        })
        .collect::<Vec<_>>();
    let lhs_bytes = i32_bytes(&lhs);
    let rhs_bytes = i32_bytes(&rhs);
    let mut checked_lanes = 0usize;

    for case in I32_BINARY_CASES {
        let program = resident_i32_binary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[lhs_bytes.clone(), rhs_bytes.clone()],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    for case in I32_UNARY_CASES {
        let program = resident_i32_unary_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            std::slice::from_ref(&lhs_bytes),
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        (I32_BINARY_CASES.len() + I32_UNARY_CASES.len()) * LANE_COUNT,
        "Fix: resident i32 scalar generated matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_memory_permutation_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let u32_input = generated_atomic_values(0x3141_5926);
    let bool_input = generated_bool_values(0x2718_2818);
    let f32_input = generated_f32_values(0x1234_abcd);
    let mut checked_lanes = 0usize;

    for case in U32_MEMORY_CASES {
        let program = resident_memory_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[u32_bytes(&u32_input)],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    for case in BOOL_MEMORY_CASES {
        let program = resident_memory_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[bool_bytes(&bool_input)],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    for case in F32_MEMORY_CASES {
        let program = resident_memory_program(case);
        let outputs = resident_cuda_reference_outputs(
            &backend,
            &program,
            &[f32_bytes(&f32_input)],
            &[OUTPUT_BYTES],
            case.name,
        );
        checked_lanes += assert_f32_output_lanes(
            case.name,
            LANE_COUNT,
            MAX_F32_ULP,
            &outputs.resident_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_lanes,
        (U32_MEMORY_CASES.len() + BOOL_MEMORY_CASES.len() + F32_MEMORY_CASES.len()) * LANE_COUNT,
        "Fix: resident memory generated matrix must compare every output lane."
    );
}

fn resident_bool_binary_program(case: &BoolBinaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("lhs", 0, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::read("rhs", 1, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 2, DataType::Bool).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(
                    Expr::load("lhs", Expr::gid_x()),
                    Expr::load("rhs", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_u32_binary_program(case: &ResidentBinaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("lhs", 0, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::read("rhs", 1, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 2, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(
                    Expr::load("lhs", Expr::gid_x()),
                    Expr::load("rhs", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_u32_unary_program(case: &ResidentUnaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn resident_i32_binary_program(case: &ResidentBinaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("lhs", 0, DataType::I32).with_count(LANE_COUNT as u32),
            BufferDecl::read("rhs", 1, DataType::I32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 2, DataType::I32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(
                    Expr::load("lhs", Expr::gid_x()),
                    Expr::load("rhs", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_i32_unary_program(case: &ResidentUnaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::I32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::I32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn resident_memory_program(case: &ResidentMemoryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, case.ty.clone()).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, case.ty.clone()).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                (case.build_dst)(Expr::gid_x()),
                (case.build_value)(Expr::load("input", (case.build_src)(Expr::gid_x()))),
            )],
        )],
    )
}

fn resident_bool_unary_program(case: &BoolUnaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::Bool).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn resident_bool_select_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("flag", 0, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::read("lhs", 1, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::read("rhs", 2, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 3, DataType::Bool).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::select(
                    Expr::load("flag", Expr::gid_x()),
                    Expr::load("lhs", Expr::gid_x()),
                    Expr::load("rhs", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_f32_compare_program(case: &F32CompareCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("lhs", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::read("rhs", 1, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 2, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(
                    Expr::load("lhs", Expr::gid_x()),
                    Expr::load("rhs", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_f32_binary_program(case: &F32BinaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("lhs", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::read("rhs", 1, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 2, DataType::F32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(
                    Expr::load("lhs", Expr::gid_x()),
                    Expr::load("rhs", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_f32_unary_program(case: &F32UnaryCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::F32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn resident_f32_classify_program(case: &F32ClassifyCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                (case.build)(Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn resident_atomic_reduction_program(case: &ResidentAtomicCase) -> Program {
    let idx = Expr::var("idx");
    let bucket = Expr::bitand(idx.clone(), Expr::u32(BUCKET_MASK));
    let value = Expr::load("values", idx.clone());
    Program::wrapped(
        vec![
            BufferDecl::storage("acc", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(LANE_COUNT as u32),
            BufferDecl::read("values", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(LANE_COUNT as u32)),
                vec![Node::let_bind(
                    "old_value",
                    (case.build)("acc", bucket, value),
                )],
            ),
        ],
    )
}

fn resident_cast_program(case: &CastCase) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, case.input_type.clone()).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, case.output_type.clone()).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::cast(case.output_type.clone(), Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn resident_fma_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("a", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::read("b", 1, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::read("c", 2, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 3, DataType::F32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::fma(
                    Expr::load("a", Expr::gid_x()),
                    Expr::load("b", Expr::gid_x()),
                    Expr::load("c", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn resident_in_place_reference_outputs(
    backend: &CudaBackend,
    program: &Program,
    inputs: &[Vec<u8>],
    readback_indices: &[usize],
    case_name: &str,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut handles = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.iter().enumerate() {
        let handle = backend.allocate_resident(input.len()).unwrap_or_else(|error| {
            panic!(
                "Fix: CUDA resident in-place generated case `{case_name}` input {index} allocation failed: {error}"
            )
        });
        backend.upload_resident(handle, input).unwrap_or_else(|error| {
            panic!(
                "Fix: CUDA resident in-place generated case `{case_name}` input {index} upload failed: {error}"
            )
        });
        handles.push(handle);
    }
    backend
        .dispatch_resident(program, &handles, &Default::default())
        .unwrap_or_else(|error| {
            panic!(
                "Fix: CUDA resident in-place generated case `{case_name}` dispatch failed: {error}"
            )
        });

    let mut resident_cuda = Vec::with_capacity(readback_indices.len());
    for &index in readback_indices {
        resident_cuda.push(backend.download_resident(handles[index]).unwrap_or_else(|error| {
            panic!(
                "Fix: CUDA resident in-place generated case `{case_name}` readback {index} failed: {error}"
            )
        }));
    }
    for handle in handles {
        backend.free_resident(handle).unwrap_or_else(|error| {
            panic!(
                "Fix: CUDA resident in-place generated case `{case_name}` cleanup failed: {error}"
            )
        });
    }
    let reference = reference_outputs(program, inputs, case_name);
    (resident_cuda, reference)
}


fn generated_f32_values(salt: u32) -> Vec<f32> {
    const BITS: &[u32] = &[
        0x0000_0000,
        0x8000_0000,
        0x3f80_0000,
        0xbf80_0000,
        0x4000_0000,
        0xc000_0000,
        0x3f00_0000,
        0xbf00_0000,
        0x0000_0001,
        0x8000_0001,
        0x007f_ffff,
        0x807f_ffff,
        0x0080_0000,
        0x8080_0000,
        0x7f7f_ffff,
        0xff7f_ffff,
        0x7f80_0000,
        0xff80_0000,
        0x7fc0_0000,
        0xffc0_0000,
        0x7fa0_0001,
        0x7fff_ffff,
        0xffff_ffff,
    ];
    (0..LANE_COUNT)
        .map(|lane| {
            let lane_word = lane as u32;
            let seed = BITS[lane % BITS.len()];
            let mixed = seed ^ salt.rotate_left(lane_word & 31);
            f32::from_bits(if lane % 5 == 0 { seed } else { mixed })
        })
        .collect()
}

fn generated_f32_nonzero_values(salt: u32) -> Vec<f32> {
    generated_f32_values(salt)
        .into_iter()
        .enumerate()
        .map(|(lane, value)| {
            let bits = value.to_bits();
            if bits & 0x7fff_ffff == 0 {
                f32::from_bits(0x3f80_0000 | ((lane as u32) & 0x007f_ffff))
            } else {
                value
            }
        })
        .collect()
}

fn generated_f32_sqrt_domain_values(salt: u32) -> Vec<f32> {
    generated_f32_values(salt)
        .into_iter()
        .enumerate()
        .map(|(lane, value)| {
            let magnitude = value.to_bits() & 0x7fff_ffff;
            let exponent = magnitude & 0x7f80_0000;
            let mantissa = magnitude & 0x007f_ffff;
            if exponent == 0x7f80_0000 && mantissa != 0 {
                f32::from_bits(0x3f80_0000 | ((lane as u32) & 0x000f_ffff))
            } else {
                f32::from_bits(magnitude)
            }
        })
        .collect()
}

fn generated_f32_classification_values() -> Vec<f32> {
    const BITS: &[u32] = &[
        0x0000_0000,
        0x8000_0000,
        0x0000_0001,
        0x8000_0001,
        0x007f_ffff,
        0x807f_ffff,
        0x0080_0000,
        0x8080_0000,
        0x3f80_0000,
        0xbf80_0000,
        0x7f7f_ffff,
        0xff7f_ffff,
        0x7f80_0000,
        0xff80_0000,
        0x7fc0_0000,
        0xffc0_0000,
        0x7fa0_0001,
        0x7fff_ffff,
        0xffff_ffff,
    ];
    (0..LANE_COUNT)
        .map(|lane| f32::from_bits(BITS[lane % BITS.len()]))
        .collect()
}

