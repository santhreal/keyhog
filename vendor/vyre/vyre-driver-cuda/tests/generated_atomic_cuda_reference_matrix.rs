//! Generated live CUDA/reference differential matrix for atomic memory semantics.

mod common;

use common::{
    assert_u32_output_lanes, bytes_u32, cuda_reference_outputs, live_backend, u32_bytes,
    GENERATED_LANE_COUNT as LANE_COUNT, GENERATED_WORKGROUP_SIZE_X as WORKGROUP_SIZE_X,
};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

const BUCKET_COUNT: usize = 8;
const BUCKET_MASK: u32 = BUCKET_COUNT as u32 - 1;

#[derive(Clone, Copy)]
struct AtomicReductionCase {
    name: &'static str,
    identity: u32,
    value_salt: u32,
    build: fn(&str, Expr, Expr) -> Expr,
}

#[derive(Clone, Copy)]
struct AtomicReturnCase {
    name: &'static str,
    value_salt: u32,
    build: fn(&str, Expr, Expr) -> Expr,
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

fn atomic_exchange(buffer: &str, index: Expr, value: Expr) -> Expr {
    Expr::atomic_exchange(buffer, index, value)
}

const ATOMIC_REDUCTION_CASES: &[AtomicReductionCase] = &[
    AtomicReductionCase {
        name: "atomic_add_bucketed_512_lanes",
        identity: 0,
        value_salt: 0x1020_3040,
        build: atomic_add,
    },
    AtomicReductionCase {
        name: "atomic_or_bucketed_512_lanes",
        identity: 0,
        value_salt: 0x3141_5926,
        build: atomic_or,
    },
    AtomicReductionCase {
        name: "atomic_and_bucketed_512_lanes",
        identity: u32::MAX,
        value_salt: 0x2718_2818,
        build: atomic_and,
    },
    AtomicReductionCase {
        name: "atomic_xor_bucketed_512_lanes",
        identity: 0,
        value_salt: 0x9e37_79b9,
        build: atomic_xor,
    },
    AtomicReductionCase {
        name: "atomic_min_bucketed_512_lanes",
        identity: u32::MAX,
        value_salt: 0xa5a5_5a5a,
        build: atomic_min,
    },
    AtomicReductionCase {
        name: "atomic_max_bucketed_512_lanes",
        identity: 0,
        value_salt: 0x5a5a_a5a5,
        build: atomic_max,
    },
];

const ATOMIC_RETURN_CASES: &[AtomicReturnCase] = &[
    AtomicReturnCase {
        name: "atomic_add_return_single_writer",
        value_salt: 0x1111_2222,
        build: atomic_add,
    },
    AtomicReturnCase {
        name: "atomic_or_return_single_writer",
        value_salt: 0x3333_4444,
        build: atomic_or,
    },
    AtomicReturnCase {
        name: "atomic_and_return_single_writer",
        value_salt: 0x5555_6666,
        build: atomic_and,
    },
    AtomicReturnCase {
        name: "atomic_xor_return_single_writer",
        value_salt: 0x7777_8888,
        build: atomic_xor,
    },
    AtomicReturnCase {
        name: "atomic_min_return_single_writer",
        value_salt: 0x9999_aaaa,
        build: atomic_min,
    },
    AtomicReturnCase {
        name: "atomic_max_return_single_writer",
        value_salt: 0xbbbb_cccc,
        build: atomic_max,
    },
    AtomicReturnCase {
        name: "atomic_exchange_return_single_writer",
        value_salt: 0xdddd_eeee,
        build: atomic_exchange,
    },
];

#[test]
fn generated_atomic_reduction_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let mut checked_output_words = 0usize;

    for case in ATOMIC_REDUCTION_CASES {
        let program = atomic_reduction_program(case);
        let initial = vec![case.identity; LANE_COUNT];
        let values = generated_atomic_values(case.value_salt);
        let inputs = vec![u32_bytes(&initial), u32_bytes(&values)];
        let outputs = cuda_reference_outputs(&backend, &program, &inputs, case.name);
        checked_output_words += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.direct_cuda,
            &outputs.reference,
        );
        checked_output_words += assert_u32_output_lanes(
            case.name,
            LANE_COUNT,
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_output_words,
        ATOMIC_REDUCTION_CASES.len() * LANE_COUNT * 2,
        "Fix: generated CUDA atomic reduction matrix must compare every output lane across direct and compiled paths."
    );
}

#[test]
fn generated_atomic_exchange_single_writer_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let program = atomic_exchange_single_writer_program();
    let initial = generated_exchange_initial_values();
    let values = generated_atomic_values(0xabcdef01);
    let inputs = vec![u32_bytes(&initial), u32_bytes(&values)];
    let outputs =
        cuda_reference_outputs(&backend, &program, &inputs, "atomic_exchange_single_writer");
    let checked_output_words = assert_u32_output_lanes(
        "atomic_exchange_single_writer",
        BUCKET_COUNT,
        &outputs.direct_cuda,
        &outputs.reference,
    ) + assert_u32_output_lanes(
        "atomic_exchange_single_writer",
        BUCKET_COUNT,
        &outputs.compiled_cuda,
        &outputs.reference,
    );

    assert_eq!(
        checked_output_words,
        BUCKET_COUNT * 2,
        "Fix: generated CUDA atomic exchange matrix must compare every accumulator bucket across direct and compiled paths."
    );
}

#[test]
fn generated_atomic_compare_exchange_single_writer_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let initial = generated_exchange_initial_values();
    let values = generated_atomic_values(0x0bad_f00d);
    let mut checked_output_words = 0usize;

    for expected_matches in [true, false] {
        let case_name = if expected_matches {
            "atomic_compare_exchange_single_writer_match"
        } else {
            "atomic_compare_exchange_single_writer_miss"
        };
        let program = atomic_compare_exchange_single_writer_program(expected_matches);
        let inputs = vec![u32_bytes(&initial), u32_bytes(&values)];
        let outputs = cuda_reference_outputs(&backend, &program, &inputs, case_name);
        checked_output_words += assert_u32_output_lanes(
            case_name,
            BUCKET_COUNT,
            &outputs.direct_cuda,
            &outputs.reference,
        );
        checked_output_words += assert_u32_output_lanes(
            case_name,
            BUCKET_COUNT,
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_output_words,
        BUCKET_COUNT * 4,
        "Fix: generated CUDA compare-exchange matrix must compare every accumulator bucket for match and miss cases across direct and compiled paths."
    );
}

#[test]
fn generated_atomic_return_value_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let initial = generated_exchange_initial_values();
    let old_sentinel = generated_old_sentinel_values();
    let mut checked_output_words = 0usize;

    for case in ATOMIC_RETURN_CASES {
        let program = atomic_return_value_program(case);
        let values = generated_atomic_values(case.value_salt);
        let inputs = vec![
            u32_bytes(&initial),
            u32_bytes(&values),
            u32_bytes(&old_sentinel),
        ];
        let outputs = cuda_reference_outputs(&backend, &program, &inputs, case.name);
        checked_output_words += assert_two_u32_output_buffers(
            case.name,
            BUCKET_COUNT,
            &outputs.direct_cuda,
            &outputs.reference,
        );
        checked_output_words += assert_two_u32_output_buffers(
            case.name,
            BUCKET_COUNT,
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_output_words,
        ATOMIC_RETURN_CASES.len() * BUCKET_COUNT * 4,
        "Fix: generated CUDA atomic return-value matrix must compare accumulator and returned-old-value buffers across direct and compiled paths."
    );
}

#[test]
fn generated_atomic_compare_exchange_return_value_matrix_matches_reference_on_live_cuda() {
    let backend = live_backend();
    let initial = generated_exchange_initial_values();
    let values = generated_atomic_values(0xcafe_babe);
    let old_sentinel = generated_old_sentinel_values();
    let mut checked_output_words = 0usize;

    for expected_matches in [true, false] {
        let case_name = if expected_matches {
            "atomic_compare_exchange_return_single_writer_match"
        } else {
            "atomic_compare_exchange_return_single_writer_miss"
        };
        let program = atomic_compare_exchange_return_value_program(expected_matches);
        let inputs = vec![
            u32_bytes(&initial),
            u32_bytes(&values),
            u32_bytes(&old_sentinel),
        ];
        let outputs = cuda_reference_outputs(&backend, &program, &inputs, case_name);
        checked_output_words += assert_two_u32_output_buffers(
            case_name,
            BUCKET_COUNT,
            &outputs.direct_cuda,
            &outputs.reference,
        );
        checked_output_words += assert_two_u32_output_buffers(
            case_name,
            BUCKET_COUNT,
            &outputs.compiled_cuda,
            &outputs.reference,
        );
    }

    assert_eq!(
        checked_output_words,
        BUCKET_COUNT * 8,
        "Fix: generated CUDA compare-exchange return-value matrix must compare accumulator and returned-old-value buffers for match and miss cases across direct and compiled paths."
    );
}

fn atomic_reduction_program(case: &AtomicReductionCase) -> Program {
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

fn atomic_return_value_program(case: &AtomicReturnCase) -> Program {
    let idx = Expr::var("idx");
    let value = Expr::load("values", idx.clone());
    Program::wrapped(
        vec![
            BufferDecl::storage("acc", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(BUCKET_COUNT as u32),
            BufferDecl::read("values", 1, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::storage("old", 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(BUCKET_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(BUCKET_COUNT as u32)),
                vec![
                    Node::let_bind("old_value", (case.build)("acc", idx, value)),
                    Node::store("old", Expr::var("idx"), Expr::var("old_value")),
                ],
            ),
        ],
    )
}

fn atomic_compare_exchange_return_value_program(expected_matches: bool) -> Program {
    let expected = if expected_matches {
        Expr::load("acc", Expr::var("idx"))
    } else {
        Expr::bitxor(Expr::load("acc", Expr::var("idx")), Expr::u32(0xffff_ffff))
    };
    Program::wrapped(
        vec![
            BufferDecl::storage("acc", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(BUCKET_COUNT as u32),
            BufferDecl::read("values", 1, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::storage("old", 2, BufferAccess::ReadWrite, DataType::U32)
                .with_count(BUCKET_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(BUCKET_COUNT as u32)),
                vec![
                    Node::let_bind(
                        "old_value",
                        Expr::atomic_compare_exchange(
                            "acc",
                            Expr::var("idx"),
                            expected,
                            Expr::load("values", Expr::var("idx")),
                        ),
                    ),
                    Node::store("old", Expr::var("idx"), Expr::var("old_value")),
                ],
            ),
        ],
    )
}

fn atomic_compare_exchange_single_writer_program(expected_matches: bool) -> Program {
    let expected = if expected_matches {
        Expr::load("acc", Expr::var("idx"))
    } else {
        Expr::bitxor(Expr::load("acc", Expr::var("idx")), Expr::u32(0xffff_ffff))
    };
    Program::wrapped(
        vec![
            BufferDecl::storage("acc", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(BUCKET_COUNT as u32),
            BufferDecl::read("values", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(BUCKET_COUNT as u32)),
                vec![Node::let_bind(
                    "old_value",
                    Expr::atomic_compare_exchange(
                        "acc",
                        Expr::var("idx"),
                        expected,
                        Expr::load("values", Expr::var("idx")),
                    ),
                )],
            ),
        ],
    )
}

fn assert_two_u32_output_buffers(
    case_name: &str,
    lane_count: usize,
    cuda_outputs: &[Vec<u8>],
    reference_outputs: &[Vec<u8>],
) -> usize {
    assert_eq!(
        cuda_outputs.len(),
        2,
        "Fix: CUDA generated case `{case_name}` must return accumulator and old-value output buffers."
    );
    assert_eq!(
        reference_outputs.len(),
        2,
        "Fix: reference generated case `{case_name}` must return accumulator and old-value output buffers."
    );
    for output_index in 0..2 {
        let actual = bytes_u32(&cuda_outputs[output_index]);
        let expected = bytes_u32(&reference_outputs[output_index]);
        assert_eq!(
            actual.len(),
            lane_count,
            "Fix: CUDA generated case `{case_name}` output buffer {output_index} lane count changed."
        );
        assert_eq!(
            expected.len(),
            lane_count,
            "Fix: reference generated case `{case_name}` output buffer {output_index} lane count changed."
        );
        for lane in 0..lane_count {
            assert_eq!(
                actual[lane], expected[lane],
                "Fix: CUDA generated case `{case_name}` output buffer {output_index} lane {lane} diverged from reference."
            );
        }
    }
    lane_count * 2
}


fn generated_old_sentinel_values() -> Vec<u32> {
    (0..BUCKET_COUNT)
        .map(|lane| 0xf00d_cafe_u32.rotate_left(lane as u32) ^ lane as u32)
        .collect()
}

fn atomic_exchange_single_writer_program() -> Program {
    let idx = Expr::var("idx");
    Program::wrapped(
        vec![
            BufferDecl::storage("acc", 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(BUCKET_COUNT as u32),
            BufferDecl::read("values", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![
            Node::let_bind("idx", Expr::gid_x()),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::u32(BUCKET_COUNT as u32)),
                vec![Node::let_bind(
                    "old_value",
                    Expr::atomic_exchange(
                        "acc",
                        Expr::var("idx"),
                        Expr::load("values", Expr::var("idx")),
                    ),
                )],
            ),
        ],
    )
}

fn generated_atomic_values(salt: u32) -> Vec<u32> {
    (0..LANE_COUNT)
        .map(|lane| {
            let lane = lane as u32;
            let mixed = lane.wrapping_mul(0x9e37_79b9).rotate_left((lane & 31) + 1)
                ^ salt.rotate_right(lane & 31);
            match lane % 16 {
                0 => 0,
                1 => 1,
                2 => u32::MAX,
                3 => 0x8000_0000,
                4 => 0x7fff_ffff,
                5 => 0x5555_5555,
                6 => 0xaaaa_aaaa,
                7 => 0x0123_4567,
                _ => mixed,
            }
        })
        .collect()
}

fn generated_exchange_initial_values() -> Vec<u32> {
    (0..BUCKET_COUNT)
        .map(|bucket| 0xf000_0000 | bucket as u32)
        .collect()
}

