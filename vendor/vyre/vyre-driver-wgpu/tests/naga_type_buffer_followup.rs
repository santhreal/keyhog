//! Regression tests for type and buffer-lowering follow-up findings.

use vyre_driver::DispatchConfig;
use vyre_emit_naga::program::emit_module;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, MemoryKind, Node, Program};

const TEST_WORKGROUP_SIZE: [u32; 3] = [1, 1, 1];

fn emit_wgsl(program: &Program) -> String {
    let module = emit_module(program, &DispatchConfig::default(), TEST_WORKGROUP_SIZE)
        .expect("Fix: test program must lower to valid Naga.");
    let info = naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),
        naga::valid::Capabilities::all(),
    )
    .validate(&module)
    .expect("Fix: lowered test module must validate.");
    naga::back::wgsl::write_string(&module, &info, naga::back::wgsl::WriterFlags::empty())
        .expect("Fix: lowered test module must serialize to WGSL.")
}

#[test]
fn vec4_u32_buffers_lower_as_wgsl_vectors() {
    let program = Program::wrapped(
        vec![BufferDecl::storage(
            "vecs",
            0,
            BufferAccess::ReadOnly,
            DataType::Vec4U32,
        )],
        [1, 1, 1],
        vec![Node::Return],
    );

    let wgsl = emit_wgsl(&program);
    assert!(
        wgsl.contains("array<vec4<u32>>"),
        "Fix: Vec4U32 buffers must lower to vec4<u32> arrays.\n{wgsl}",
    );
}

#[test]
fn u64_buffers_lower_as_vec2_u32() {
    let program = Program::wrapped(
        vec![BufferDecl::storage(
            "wide",
            0,
            BufferAccess::ReadOnly,
            DataType::U64,
        )],
        [1, 1, 1],
        vec![Node::Return],
    );

    let wgsl = emit_wgsl(&program);
    assert!(
        wgsl.contains("array<vec2<u32>>"),
        "Fix: U64 buffers must lower through vec2<u32> emulation.\n{wgsl}",
    );
}

#[test]
fn bytes_buffers_fail_with_pack_prepass_error() {
    let program = Program::wrapped(
        vec![BufferDecl::storage(
            "bytes",
            0,
            BufferAccess::ReadOnly,
            DataType::Bytes,
        )],
        [1, 1, 1],
        vec![Node::Return],
    );

    let err = emit_module(&program, &DispatchConfig::default(), TEST_WORKGROUP_SIZE)
        .expect_err("Fix: raw byte buffers must not lower as invalid array<u32> storage.");
    assert!(
        err.to_string().contains("pack-to-u32 pre-pass"),
        "Fix: bytes-buffer rejection must explain the required pre-pass. Got {err}",
    );
}

#[test]
fn non_word_arrays_fail_with_struct_lowering_error() {
    let program = Program::wrapped(
        vec![BufferDecl::storage(
            "array16",
            0,
            BufferAccess::ReadOnly,
            DataType::Array { element_size: 16 },
        )],
        [1, 1, 1],
        vec![Node::Return],
    );

    let err = emit_module(&program, &DispatchConfig::default(), TEST_WORKGROUP_SIZE)
        .expect_err("Fix: non-4-byte arrays must not silently lower through array<u32>.");
    assert!(
        err.to_string().contains("struct-backed array"),
        "Fix: non-word array rejection must explain the struct-backed lowering requirement. Got {err}",
    );
}

#[test]
fn zero_sized_workgroup_buffers_are_rejected_at_lowering_boundary() {
    let program = Program::wrapped(
        vec![BufferDecl::workgroup("scratch", 0, DataType::U32)],
        [1, 1, 1],
        vec![Node::Return],
    );
    let err = emit_module(&program, &DispatchConfig::default(), TEST_WORKGROUP_SIZE)
        .expect_err("Fix: zero-sized workgroup buffers must not lower to Naga.");
    assert!(
        err.to_string().contains("zero static element count"),
        "Fix: zero-sized workgroup rejection must name the zero-count buffer. Got {err}",
    );
}

#[test]
fn persistent_buffers_are_rejected_before_naga_address_space_lowering() {
    let program = Program::wrapped(
        vec![
            BufferDecl::storage("persist", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_kind(MemoryKind::Persistent)
                .with_count(1),
        ],
        [1, 1, 1],
        vec![Node::Return],
    );

    let err = emit_module(&program, &DispatchConfig::default(), TEST_WORKGROUP_SIZE)
        .expect_err("Fix: persistent buffers must be stripped before wgpu lowering.");
    assert!(
        err.to_string().contains("AsyncLoad/AsyncStore"),
        "Fix: persistent-buffer rejection must point callers at the host transfer path. Got {err}",
    );
}

#[test]
fn f16_buffers_reject_until_wgsl_parser_accepts_enable_f16() {
    let program = Program::wrapped(
        vec![BufferDecl::storage(
            "half",
            0,
            BufferAccess::ReadOnly,
            DataType::F16,
        )],
        [1, 1, 1],
        vec![Node::Return],
    );

    let err = emit_module(&program, &DispatchConfig::default(), TEST_WORKGROUP_SIZE).expect_err(
        "Fix: F16 buffers must reject before emitting WGSL this Naga stack cannot parse",
    );
    assert!(
        err.to_string().contains("enable f16"),
        "Fix: F16 rejection must name the unsupported WGSL extension. Got {err}",
    );
}
