//! Generated live CUDA-resident sequence/reference differential matrix.

mod common;

use common::{
    assert_compact_ranges_match, assert_f32_output_lanes, assert_u32_output_lanes, bool_bytes,
    compact_word_ranges, f32_bytes, generated_mixed_bool_values as generated_bool_values,
    generated_mixed_u32_values as generated_u32_values, live_backend, overlapping_word_ranges,
    reference_outputs, u32_bytes, GENERATED_LANE_COUNT as LANE_COUNT,
    GENERATED_WORKGROUP_SIZE_X as WORKGROUP_SIZE_X,
};
use vyre_driver::backend::{ResidentDispatchStep, ResidentReadRange};
use vyre_driver::VyreBackend;
use vyre_driver_cuda::CudaBackendRegistration;
use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

const OUTPUT_BYTES: usize = LANE_COUNT * std::mem::size_of::<u32>();
const MAX_F32_ULP: u32 = 1;

#[test]
fn generated_resident_u32_sequence_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let input = generated_u32_values(0x1020_3040);
    let input_bytes = u32_bytes(&input);
    let first = u32_sequence_first_program();
    let second = u32_sequence_second_program();
    let expected_tmp = reference_outputs(
        &first,
        std::slice::from_ref(&input_bytes),
        "resident_u32_sequence_first",
    );
    let expected = reference_outputs(&second, &expected_tmp, "resident_u32_sequence_second");
    let actual = dispatch_two_step_sequence(
        &backend,
        &first,
        &second,
        &input_bytes,
        DataType::U32,
        "resident_u32_sequence",
    );
    let checked = assert_u32_output_lanes(
        "resident_u32_sequence",
        LANE_COUNT,
        std::slice::from_ref(&actual),
        &expected,
    );
    assert_eq!(
        checked, LANE_COUNT,
        "Fix: resident u32 sequence matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_bool_sequence_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let input = generated_bool_values(0x3141_5926);
    let input_bytes = bool_bytes(&input);
    let first = bool_sequence_first_program();
    let second = bool_sequence_second_program();
    let expected_tmp = reference_outputs(
        &first,
        std::slice::from_ref(&input_bytes),
        "resident_bool_sequence_first",
    );
    let expected = reference_outputs(&second, &expected_tmp, "resident_bool_sequence_second");
    let actual = dispatch_two_step_sequence(
        &backend,
        &first,
        &second,
        &input_bytes,
        DataType::Bool,
        "resident_bool_sequence",
    );
    let checked = assert_u32_output_lanes(
        "resident_bool_sequence",
        LANE_COUNT,
        std::slice::from_ref(&actual),
        &expected,
    );
    assert_eq!(
        checked, LANE_COUNT,
        "Fix: resident Bool sequence matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_f32_sequence_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let input = generated_f32_values(0x2718_2818);
    let input_bytes = f32_bytes(&input);
    let first = f32_sequence_first_program();
    let second = f32_sequence_second_program();
    let expected_tmp = reference_outputs(
        &first,
        std::slice::from_ref(&input_bytes),
        "resident_f32_sequence_first",
    );
    let expected = reference_outputs(&second, &expected_tmp, "resident_f32_sequence_second");
    let actual = dispatch_two_step_sequence(
        &backend,
        &first,
        &second,
        &input_bytes,
        DataType::F32,
        "resident_f32_sequence",
    );
    let checked = assert_f32_output_lanes(
        "resident_f32_sequence",
        LANE_COUNT,
        MAX_F32_ULP,
        std::slice::from_ref(&actual),
        &expected,
    );
    assert_eq!(
        checked, LANE_COUNT,
        "Fix: resident f32 sequence matrix must compare every output lane."
    );
}

#[test]
fn generated_resident_u32_sequence_compact_multi_range_readback_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let input = generated_u32_values(0x0bad_c0de);
    let input_bytes = u32_bytes(&input);
    let first = u32_sequence_first_program();
    let second = u32_sequence_second_program();
    let expected_tmp = reference_outputs(
        &first,
        std::slice::from_ref(&input_bytes),
        "resident_u32_sequence_compact_first",
    );
    let expected = reference_outputs(
        &second,
        &expected_tmp,
        "resident_u32_sequence_compact_second",
    );
    let ranges = compact_word_ranges();
    let actual = dispatch_two_step_sequence_read_ranges(
        &backend,
        &first,
        &second,
        &input_bytes,
        &ranges,
        DataType::U32,
        "resident_u32_sequence_compact_multi_range",
    );
    assert_compact_ranges_match(
        "resident_u32_sequence_compact_multi_range",
        &actual,
        &expected[0],
        &ranges,
    );
}

#[test]
fn generated_resident_bool_sequence_compact_multi_range_readback_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let input = generated_bool_values(0x5afe_b001);
    let input_bytes = bool_bytes(&input);
    let first = bool_sequence_first_program();
    let second = bool_sequence_second_program();
    let expected_tmp = reference_outputs(
        &first,
        std::slice::from_ref(&input_bytes),
        "resident_bool_sequence_compact_first",
    );
    let expected = reference_outputs(
        &second,
        &expected_tmp,
        "resident_bool_sequence_compact_second",
    );
    let ranges = compact_word_ranges();
    let actual = dispatch_two_step_sequence_read_ranges(
        &backend,
        &first,
        &second,
        &input_bytes,
        &ranges,
        DataType::Bool,
        "resident_bool_sequence_compact_multi_range",
    );
    assert_compact_ranges_match(
        "resident_bool_sequence_compact_multi_range",
        &actual,
        &expected[0],
        &ranges,
    );
}

#[test]
fn generated_resident_u32_sequence_overlapping_multi_range_readback_matches_reference_on_live_cuda()
{
    let backend = CudaBackendRegistration::new(live_backend());
    let input = generated_u32_values(0xf005_ba11);
    let input_bytes = u32_bytes(&input);
    let first = u32_sequence_first_program();
    let second = u32_sequence_second_program();
    let expected_tmp = reference_outputs(
        &first,
        std::slice::from_ref(&input_bytes),
        "resident_u32_sequence_overlap_first",
    );
    let expected = reference_outputs(
        &second,
        &expected_tmp,
        "resident_u32_sequence_overlap_second",
    );
    let ranges = overlapping_word_ranges();
    let actual = dispatch_two_step_sequence_read_ranges(
        &backend,
        &first,
        &second,
        &input_bytes,
        &ranges,
        DataType::U32,
        "resident_u32_sequence_overlapping_multi_range",
    );
    assert_compact_ranges_match(
        "resident_u32_sequence_overlapping_multi_range",
        &actual,
        &expected[0],
        &ranges,
    );
}

fn dispatch_two_step_sequence(
    backend: &CudaBackendRegistration,
    first: &Program,
    second: &Program,
    input_bytes: &[u8],
    ty: DataType,
    case_name: &str,
) -> Vec<u8> {
    let mut outputs = dispatch_two_step_sequence_read_ranges(
        backend,
        first,
        second,
        input_bytes,
        &[(0, OUTPUT_BYTES)],
        ty,
        case_name,
    );
    outputs.remove(0)
}

fn dispatch_two_step_sequence_read_ranges(
    backend: &CudaBackendRegistration,
    first: &Program,
    second: &Program,
    input_bytes: &[u8],
    ranges: &[(usize, usize)],
    ty: DataType,
    case_name: &str,
) -> Vec<Vec<u8>> {
    let input = VyreBackend::allocate_resident(backend, OUTPUT_BYTES)
        .unwrap_or_else(|error| panic!("Fix: {case_name} input allocation failed: {error}"));
    let tmp = VyreBackend::allocate_resident(backend, OUTPUT_BYTES)
        .unwrap_or_else(|error| panic!("Fix: {case_name} temporary allocation failed: {error}"));
    let output = VyreBackend::allocate_resident(backend, OUTPUT_BYTES)
        .unwrap_or_else(|error| panic!("Fix: {case_name} output allocation failed: {error}"));
    let result = (|| {
        VyreBackend::upload_resident(backend, &input, input_bytes)
            .map_err(|error| format!("Fix: {case_name} input upload failed: {error}"))?;
        let first_resources = [input.clone(), tmp.clone()];
        let second_resources = [tmp.clone(), output.clone()];
        let steps = [
            ResidentDispatchStep {
                program: first,
                resources: &first_resources,
                grid_override: None,
            },
            ResidentDispatchStep {
                program: second,
                resources: &second_resources,
                grid_override: None,
            },
        ];
        let read_ranges: Vec<_> = ranges
            .iter()
            .map(|(byte_offset, byte_len)| ResidentReadRange {
                resource: &output,
                byte_offset: *byte_offset,
                byte_len: *byte_len,
            })
            .collect();
        let mut outputs: Vec<Vec<u8>> = ranges.iter().map(|_| Vec::new()).collect();
        {
            let mut output_refs: Vec<&mut Vec<u8>> = outputs.iter_mut().collect();
            VyreBackend::dispatch_resident_sequence_read_ranges_into(
                backend,
                &steps,
                &read_ranges,
                &mut output_refs,
            )
            .map_err(|error| {
                format!("Fix: {case_name} resident sequence dispatch failed: {error}")
            })?;
        }
        for (index, (output, (_, expected_len))) in outputs.iter().zip(ranges.iter()).enumerate() {
            if output.len() != *expected_len {
                return Err(format!(
                    "Fix: {case_name} range {index} returned {} byte(s) for {:?}, expected {}.",
                    output.len(),
                    ty,
                    expected_len
                ));
            }
        }
        Ok(outputs)
    })();
    let free_input = VyreBackend::free_resident(backend, input);
    let free_tmp = VyreBackend::free_resident(backend, tmp);
    let free_output = VyreBackend::free_resident(backend, output);
    if let Err(error) = free_input {
        panic!("Fix: {case_name} input cleanup failed: {error}");
    }
    if let Err(error) = free_tmp {
        panic!("Fix: {case_name} temporary cleanup failed: {error}");
    }
    if let Err(error) = free_output {
        panic!("Fix: {case_name} output cleanup failed: {error}");
    }
    result.unwrap_or_else(|error| panic!("{error}"))
}

fn u32_sequence_first_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::output("tmp", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "tmp",
                Expr::gid_x(),
                Expr::bitxor(
                    Expr::mul(
                        Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(7)),
                        Expr::u32(3),
                    ),
                    Expr::u32(0xa5a5_5a5a),
                ),
            )],
        )],
    )
}

fn u32_sequence_second_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("tmp", 0, DataType::U32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::U32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::reverse_bits(Expr::shr(
                    Expr::load("tmp", Expr::gid_x()),
                    Expr::add(Expr::gid_x(), Expr::u32(33)),
                )),
            )],
        )],
    )
}

fn bool_sequence_first_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::output("tmp", 1, DataType::Bool).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "tmp",
                Expr::gid_x(),
                Expr::not(Expr::load("input", Expr::gid_x())),
            )],
        )],
    )
}

fn bool_sequence_second_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("tmp", 0, DataType::Bool).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::Bool).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::select(
                    Expr::eq(Expr::bitand(Expr::gid_x(), Expr::u32(1)), Expr::u32(0)),
                    Expr::load("tmp", Expr::gid_x()),
                    Expr::not(Expr::load("tmp", Expr::gid_x())),
                ),
            )],
        )],
    )
}

fn f32_sequence_first_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("input", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("tmp", 1, DataType::F32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "tmp",
                Expr::gid_x(),
                Expr::fma(
                    Expr::load("input", Expr::gid_x()),
                    Expr::f32(0.5),
                    Expr::f32(1.25),
                ),
            )],
        )],
    )
}

fn f32_sequence_second_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::read("tmp", 0, DataType::F32).with_count(LANE_COUNT as u32),
            BufferDecl::output("out", 1, DataType::F32).with_count(LANE_COUNT as u32),
        ],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "out",
                Expr::gid_x(),
                Expr::sqrt(Expr::abs(Expr::load("tmp", Expr::gid_x()))),
            )],
        )],
    )
}


fn generated_f32_values(salt: u32) -> Vec<f32> {
    (0..LANE_COUNT)
        .map(|lane| {
            let lane = lane as u32;
            let bits = match lane % 14 {
                0 => 0x0000_0000,
                1 => 0x8000_0000,
                2 => 0x3f80_0000,
                3 => 0xbf80_0000,
                4 => 0x4000_0000,
                5 => 0xc000_0000,
                6 => 0x3f00_0000,
                7 => 0xbf00_0000,
                8 => 0x0080_0000,
                9 => 0x8080_0000,
                10 => 0x7f7f_ffff,
                11 => 0xff7f_ffff,
                _ => (lane.wrapping_mul(0x0101_0101) ^ salt).rotate_left(lane & 15) & 0x7f7f_ffff,
            };
            f32::from_bits(bits)
        })
        .collect()
}

#[test]
fn generated_repeated_resident_u32_sequence_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let prefix = repeated_u32_prefix_program();
    let repeated = repeated_u32_step_program();
    let input = u32_bytes(&generated_u32_values(0xfeed_beef));
    let repeat_count = 5;
    let expected = repeated_reference_outputs(&prefix, &repeated, &input, repeat_count, "u32");
    let actual = dispatch_repeated_in_place_sequence(
        &backend,
        &prefix,
        &repeated,
        &input,
        repeat_count,
        DataType::U32,
        "repeated_resident_u32_sequence",
    );
    let checked = assert_u32_output_lanes(
        "repeated_resident_u32_sequence",
        LANE_COUNT,
        std::slice::from_ref(&actual),
        &expected,
    );
    assert_eq!(
        checked, LANE_COUNT,
        "Fix: repeated resident u32 sequence must compare every output lane."
    );
}

#[test]
fn generated_repeated_resident_bool_sequence_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let prefix = repeated_bool_prefix_program();
    let repeated = repeated_bool_step_program();
    let input = bool_bytes(&generated_bool_values(0xdec0_ded1));
    let repeat_count = 7;
    let expected = repeated_reference_outputs(&prefix, &repeated, &input, repeat_count, "bool");
    let actual = dispatch_repeated_in_place_sequence(
        &backend,
        &prefix,
        &repeated,
        &input,
        repeat_count,
        DataType::Bool,
        "repeated_resident_bool_sequence",
    );
    let checked = assert_u32_output_lanes(
        "repeated_resident_bool_sequence",
        LANE_COUNT,
        std::slice::from_ref(&actual),
        &expected,
    );
    assert_eq!(
        checked, LANE_COUNT,
        "Fix: repeated resident Bool sequence must compare every output lane."
    );
}

#[test]
fn generated_repeated_resident_f32_sequence_matches_reference_on_live_cuda() {
    let backend = CudaBackendRegistration::new(live_backend());
    let prefix = repeated_f32_prefix_program();
    let repeated = repeated_f32_step_program();
    let input = f32_bytes(&generated_f32_values(0xabcdef01));
    let repeat_count = 4;
    let expected = repeated_reference_outputs(&prefix, &repeated, &input, repeat_count, "f32");
    let actual = dispatch_repeated_in_place_sequence(
        &backend,
        &prefix,
        &repeated,
        &input,
        repeat_count,
        DataType::F32,
        "repeated_resident_f32_sequence",
    );
    let checked = assert_f32_output_lanes(
        "repeated_resident_f32_sequence",
        LANE_COUNT,
        MAX_F32_ULP,
        std::slice::from_ref(&actual),
        &expected,
    );
    assert_eq!(
        checked, LANE_COUNT,
        "Fix: repeated resident f32 sequence must compare every output lane."
    );
}

#[test]
fn generated_repeated_resident_u32_sequence_compact_multi_range_readback_matches_reference_on_live_cuda(
) {
    let backend = CudaBackendRegistration::new(live_backend());
    let prefix = repeated_u32_prefix_program();
    let repeated = repeated_u32_step_program();
    let input = u32_bytes(&generated_u32_values(0x51f7_beef));
    let repeat_count = 6;
    let expected = repeated_reference_outputs(
        &prefix,
        &repeated,
        &input,
        repeat_count,
        "u32_compact_multi_range",
    );
    let ranges = compact_word_ranges();
    let actual = dispatch_repeated_in_place_sequence_read_ranges(
        &backend,
        &prefix,
        &repeated,
        &input,
        repeat_count,
        &ranges,
        DataType::U32,
        "repeated_resident_u32_sequence_compact_multi_range",
    );
    assert_compact_ranges_match(
        "repeated_resident_u32_sequence_compact_multi_range",
        &actual,
        &expected[0],
        &ranges,
    );
}

#[test]
fn generated_repeated_resident_bool_sequence_compact_multi_range_readback_matches_reference_on_live_cuda(
) {
    let backend = CudaBackendRegistration::new(live_backend());
    let prefix = repeated_bool_prefix_program();
    let repeated = repeated_bool_step_program();
    let input = bool_bytes(&generated_bool_values(0xb001_b1a5));
    let repeat_count = 8;
    let expected = repeated_reference_outputs(
        &prefix,
        &repeated,
        &input,
        repeat_count,
        "bool_compact_multi_range",
    );
    let ranges = compact_word_ranges();
    let actual = dispatch_repeated_in_place_sequence_read_ranges(
        &backend,
        &prefix,
        &repeated,
        &input,
        repeat_count,
        &ranges,
        DataType::Bool,
        "repeated_resident_bool_sequence_compact_multi_range",
    );
    assert_compact_ranges_match(
        "repeated_resident_bool_sequence_compact_multi_range",
        &actual,
        &expected[0],
        &ranges,
    );
}

#[test]
fn generated_repeated_resident_bool_sequence_overlapping_multi_range_readback_matches_reference_on_live_cuda(
) {
    let backend = CudaBackendRegistration::new(live_backend());
    let prefix = repeated_bool_prefix_program();
    let repeated = repeated_bool_step_program();
    let input = bool_bytes(&generated_bool_values(0x0b00_1f15));
    let repeat_count = 9;
    let expected = repeated_reference_outputs(
        &prefix,
        &repeated,
        &input,
        repeat_count,
        "bool_overlapping_multi_range",
    );
    let ranges = overlapping_word_ranges();
    let actual = dispatch_repeated_in_place_sequence_read_ranges(
        &backend,
        &prefix,
        &repeated,
        &input,
        repeat_count,
        &ranges,
        DataType::Bool,
        "repeated_resident_bool_sequence_overlapping_multi_range",
    );
    assert_compact_ranges_match(
        "repeated_resident_bool_sequence_overlapping_multi_range",
        &actual,
        &expected[0],
        &ranges,
    );
}

fn repeated_reference_outputs(
    prefix: &Program,
    repeated: &Program,
    input: &[u8],
    repeat_count: u32,
    label: &str,
) -> Vec<Vec<u8>> {
    let mut state = reference_outputs(
        prefix,
        &[input.to_vec()],
        &format!("repeated_resident_{label}_prefix"),
    );
    for step in 0..repeat_count {
        state = reference_outputs(
            repeated,
            &state,
            &format!("repeated_resident_{label}_step_{step}"),
        );
    }
    state
}

fn dispatch_repeated_in_place_sequence(
    backend: &CudaBackendRegistration,
    prefix: &Program,
    repeated: &Program,
    input_bytes: &[u8],
    repeat_count: u32,
    ty: DataType,
    case_name: &str,
) -> Vec<u8> {
    let mut outputs = dispatch_repeated_in_place_sequence_read_ranges(
        backend,
        prefix,
        repeated,
        input_bytes,
        repeat_count,
        &[(0, OUTPUT_BYTES)],
        ty,
        case_name,
    );
    outputs.remove(0)
}

fn dispatch_repeated_in_place_sequence_read_ranges(
    backend: &CudaBackendRegistration,
    prefix: &Program,
    repeated: &Program,
    input_bytes: &[u8],
    repeat_count: u32,
    ranges: &[(usize, usize)],
    ty: DataType,
    case_name: &str,
) -> Vec<Vec<u8>> {
    let state = VyreBackend::allocate_resident(backend, OUTPUT_BYTES)
        .unwrap_or_else(|error| panic!("Fix: {case_name} state allocation failed: {error}"));
    let result = (|| {
        VyreBackend::upload_resident(backend, &state, input_bytes)
            .map_err(|error| format!("Fix: {case_name} state upload failed: {error}"))?;
        let prefix_resources = [state.clone()];
        let repeated_resources = [state.clone()];
        let prefix_steps = [ResidentDispatchStep {
            program: prefix,
            resources: &prefix_resources,
            grid_override: None,
        }];
        let repeated_steps = [ResidentDispatchStep {
            program: repeated,
            resources: &repeated_resources,
            grid_override: None,
        }];
        let read_ranges: Vec<_> = ranges
            .iter()
            .map(|(byte_offset, byte_len)| ResidentReadRange {
                resource: &state,
                byte_offset: *byte_offset,
                byte_len: *byte_len,
            })
            .collect();
        let mut outputs: Vec<Vec<u8>> = ranges.iter().map(|_| Vec::new()).collect();
        {
            let mut output_refs: Vec<&mut Vec<u8>> = outputs.iter_mut().collect();
            VyreBackend::dispatch_resident_repeated_sequence_read_ranges_into(
                backend,
                &prefix_steps,
                &repeated_steps,
                repeat_count,
                &read_ranges,
                &mut output_refs,
            )
            .map_err(|error| {
                format!("Fix: {case_name} repeated resident sequence dispatch failed: {error}")
            })?;
        }
        for (index, (output, (_, expected_len))) in outputs.iter().zip(ranges.iter()).enumerate() {
            if output.len() != *expected_len {
                return Err(format!(
                    "Fix: {case_name} range {index} returned {} byte(s) for {:?}, expected {}.",
                    output.len(),
                    ty,
                    expected_len
                ));
            }
        }
        Ok(outputs)
    })();
    if let Err(error) = VyreBackend::free_resident(backend, state) {
        panic!("Fix: {case_name} state cleanup failed: {error}");
    }
    result.unwrap_or_else(|error| panic!("{error}"))
}

fn repeated_u32_prefix_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(LANE_COUNT as u32)],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "state",
                Expr::gid_x(),
                Expr::bitxor(
                    Expr::add(Expr::load("state", Expr::gid_x()), Expr::u32(11)),
                    Expr::mul(Expr::gid_x(), Expr::u32(0x0101_0101)),
                ),
            )],
        )],
    )
}

fn repeated_u32_step_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(LANE_COUNT as u32)],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "state",
                Expr::gid_x(),
                Expr::reverse_bits(Expr::shl(
                    Expr::bitxor(Expr::load("state", Expr::gid_x()), Expr::u32(0x9e37_79b9)),
                    Expr::add(Expr::gid_x(), Expr::u32(65)),
                )),
            )],
        )],
    )
}

fn repeated_bool_prefix_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::Bool).with_count(LANE_COUNT as u32)],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "state",
                Expr::gid_x(),
                Expr::not(Expr::load("state", Expr::gid_x())),
            )],
        )],
    )
}

fn repeated_bool_step_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::Bool).with_count(LANE_COUNT as u32)],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "state",
                Expr::gid_x(),
                Expr::select(
                    Expr::eq(Expr::bitand(Expr::gid_x(), Expr::u32(3)), Expr::u32(0)),
                    Expr::not(Expr::load("state", Expr::gid_x())),
                    Expr::load("state", Expr::gid_x()),
                ),
            )],
        )],
    )
}

fn repeated_f32_prefix_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::F32).with_count(LANE_COUNT as u32)],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "state",
                Expr::gid_x(),
                Expr::abs(Expr::fma(
                    Expr::load("state", Expr::gid_x()),
                    Expr::f32(0.25),
                    Expr::f32(2.0),
                )),
            )],
        )],
    )
}

fn repeated_f32_step_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("state", 0, DataType::F32).with_count(LANE_COUNT as u32)],
        [WORKGROUP_SIZE_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(LANE_COUNT as u32)),
            vec![Node::store(
                "state",
                Expr::gid_x(),
                Expr::sqrt(Expr::add(
                    Expr::abs(Expr::load("state", Expr::gid_x())),
                    Expr::f32(0.5),
                )),
            )],
        )],
    )
}

