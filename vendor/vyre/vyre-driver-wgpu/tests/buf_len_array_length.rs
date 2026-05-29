//! Q3 reproducer: `Expr::buf_len(buffer)` lowers to `naga::ArrayLength`
//! on the wgpu/Vulkan path. ArrayLength must equal the bound storage
//! buffer's element count at dispatch time. The cat_a_gpu_differential
//! pass on 2026-05-02 surfaced a regression where the unbounded
//! `vyre-primitives::hash::fnv1a64` registration (loop bound = buf_len)
//! caused the GPU loop to run zero iterations, returning the unchanged
//! FNV1A64_OFFSET.
//!
//! These tests build the smallest possible Program that exercises
//! `Expr::buf_len` at runtime and assert that the dispatched output
//! reflects the actual bound buffer length. They are written to fail
//! before a Q3 fix lands and pass after, so the workaround in
//! `vyre_primitives::hash::fnv1a` (using `fnv1a64_program_n` instead of
//! `fnv1a64_program`) can be reverted with confidence.
//!
//! Lane: `driver_wgpu` (per `docs/optimization/OWNERSHIP.toml`).

use std::sync::{Arc, OnceLock};

use vyre_driver::{DispatchConfig, VyreBackend};
use vyre_driver_wgpu::WgpuBackend;
use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

fn backend() -> &'static WgpuBackend {
    static BACKEND: OnceLock<WgpuBackend> = OnceLock::new();
    BACKEND.get_or_init(|| {
        WgpuBackend::acquire().expect(
            "Fix: GPU adapter required for buf_len_array_length tests. Run on a host with a working wgpu adapter.",
        )
    })
}

/// Build a Program whose body writes `buf_len(input)` to `out[0]`.
/// `input` is declared without a static count, so the lowering uses
/// `naga::ArrayLength` to read the bound buffer's element count at
/// runtime. `out` is one u32 with explicit count = 1.
fn buf_len_writer_program() -> Program {
    let body = vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![Node::store("out", Expr::u32(0), Expr::buf_len("input"))],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output("out", 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        body,
    )
}

fn dispatch_and_read_first_word(program: &Program, input_bytes: Vec<u8>) -> u32 {
    dispatch_and_read_first_word_with_lowering(program, input_bytes, false)
}

/// Like [`dispatch_and_read_first_word`] but routes the program through
/// the same `vyre_foundation::optimizer::pre_lowering::optimize` pass
/// that `cat_a_gpu_differential::lower_for_gpu` uses. The catalog
/// failure cases hit that path; pure direct dispatch does not.
fn dispatch_and_read_first_word_lowered(program: &Program, input_bytes: Vec<u8>) -> u32 {
    dispatch_and_read_first_word_with_lowering(program, input_bytes, true)
}

fn dispatch_and_read_first_word_with_lowering(
    program: &Program,
    input_bytes: Vec<u8>,
    lower: bool,
) -> u32 {
    let lowered;
    let prog = if lower {
        lowered = vyre_foundation::optimizer::pre_lowering::optimize(program.clone());
        &lowered
    } else {
        program
    };
    let inputs = vec![input_bytes, vec![0u8; 4]];
    let outputs = backend()
        .dispatch(prog, &inputs, &DispatchConfig::default())
        .expect("Fix: backend.dispatch must succeed for the buf_len writer program");
    let raw = &outputs[0];
    assert!(
        raw.len() >= 4,
        "Fix: output buffer too small to read a u32 result"
    );
    u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
}

#[test]
fn buf_len_returns_one_element_for_four_byte_input() {
    // The fixture binds a 4-byte input → 1 u32 element. ArrayLength
    // must report 1; the IR Store writes that to out[0]. Before the
    // Q3 fix, this returned 0 on wgpu/Vulkan.
    let program = buf_len_writer_program();
    let observed = dispatch_and_read_first_word(&program, vec![0xAB, 0, 0, 0]);
    assert_eq!(
        observed, 1,
        "Q3: arrayLength on a 4-byte (1×u32) read-only storage buffer must return 1, got {observed}. \
         If this is 0, the wgpu/Vulkan path is computing the binding range wrong for small storage buffers  -  \
         see docs/optimization/ROADMAP.md Q3."
    );
}

#[test]
fn buf_len_returns_three_elements_for_twelve_byte_input() {
    // Three u32 elements. Same reasoning as the single-element case
    // but covers a non-minimal size to rule out a `max(1)` saturation
    // or similar implementation accident.
    let program = buf_len_writer_program();
    let observed =
        dispatch_and_read_first_word(&program, vec![0x01, 0, 0, 0, 0x02, 0, 0, 0, 0x03, 0, 0, 0]);
    assert_eq!(
        observed, 3,
        "Q3: arrayLength on a 12-byte (3×u32) read-only storage buffer must return 3, got {observed}."
    );
}

#[test]
fn buf_len_returns_eight_elements_for_thirty_two_byte_input() {
    // 32 bytes  -  past the 16-byte/32-byte minimum-binding-size
    // thresholds some Vulkan stacks impose. If ArrayLength is broken
    // only below a threshold, this case should pass while the smaller
    // ones fail; documenting the boundary helps Q3's root-cause search.
    let program = buf_len_writer_program();
    let bytes: Vec<u8> = (0..32).map(|i| i as u8).collect();
    let observed = dispatch_and_read_first_word(&program, bytes);
    assert_eq!(
        observed, 8,
        "Q3: arrayLength on a 32-byte (8×u32) read-only storage buffer must return 8, got {observed}."
    );
}

/// Wrap the buf_len writer body in three nested Region nodes to mirror
/// the shape `primitive_catalog::primitive_program` builds for
/// `catalog::hash::fnv1a64::consumer_a/b`. If `arrayLength` works on
/// the flat program but not on the deeply-wrapped one, the bug is in
/// region inlining or pre-lowering rather than in the wgpu binding
/// layer that Q3 was supposed to fix.
fn deep_region_wrapped_buf_len_program() -> Program {
    let inner = vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![Node::store("out", Expr::u32(0), Expr::buf_len("input"))],
    )];
    let mid = Node::Region {
        generator: Ident::from("vyre-primitives::test::buf_len_inner"),
        source_region: None,
        body: Arc::new(inner),
    };
    let outer = Node::Region {
        generator: Ident::from("vyre-primitives::test::buf_len_mid"),
        source_region: Some(GeneratorRef {
            name: "vyre-libs::catalog::test::buf_len_outer".to_string(),
        }),
        body: Arc::new(vec![mid]),
    };
    let body = Node::Region {
        generator: Ident::from("vyre-libs::catalog::test::buf_len_outer"),
        source_region: None,
        body: Arc::new(vec![outer]),
    };
    Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output("out", 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![body],
    )
}

fn loop_counting_buf_len_program() -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output("out", 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("seen", Expr::u32(0)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::buf_len("input"),
                    vec![Node::assign(
                        "seen",
                        Expr::add(Expr::var("seen"), Expr::u32(1)),
                    )],
                ),
                Node::store("out", Expr::u32(0), Expr::var("seen")),
            ],
        )],
    )
}

#[test]
fn buf_len_through_three_region_wraps_for_one_element() {
    let program = deep_region_wrapped_buf_len_program();
    let observed = dispatch_and_read_first_word(&program, vec![0x99, 0, 0, 0]);
    assert_eq!(
        observed, 1,
        "Q3: arrayLength on a triple-Region-wrapped Program must report 1 for a 4-byte input, got {observed}. \
         If this fails while the flat-program tests pass, region inlining or pre-lowering is breaking the BufLen path \
         in catalog wrappers  -  see ROADMAP.md Q3."
    );
}

#[test]
fn buf_len_through_three_region_wraps_for_three_elements() {
    let program = deep_region_wrapped_buf_len_program();
    let observed = dispatch_and_read_first_word(&program, vec![1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(
        observed, 3,
        "Q3: arrayLength on a triple-Region-wrapped Program must report 3 for a 12-byte input, got {observed}."
    );
}

#[test]
fn buf_len_through_three_region_wraps_through_pre_lowering_for_one_element() {
    // The cat_a_gpu_differential test path runs every program through
    // `vyre_foundation::optimizer::pre_lowering::optimize` before
    // dispatch. If buf_len works on the flat or shallow-wrapped path
    // but breaks here, the regression lives in the optimizer pipeline
    // (canonicalize → region_inline → const_fold → loop_unroll →
    // strength_reduce → normalize_atomics → CSE+DCE → ...).
    let program = deep_region_wrapped_buf_len_program();
    let observed = dispatch_and_read_first_word_lowered(&program, vec![0x99, 0, 0, 0]);
    assert_eq!(
        observed, 1,
        "Q3: arrayLength after pre_lowering::optimize on a triple-Region-wrapped Program must report 1 for a 4-byte input, got {observed}. \
         If this fails while the pre-lowering-skipping tests pass, an optimizer pass is folding `Expr::buf_len` to a constant  -  see ROADMAP.md Q3."
    );
}

#[test]
fn buf_len_through_three_region_wraps_through_pre_lowering_for_three_elements() {
    let program = deep_region_wrapped_buf_len_program();
    let observed =
        dispatch_and_read_first_word_lowered(&program, vec![1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(
        observed, 3,
        "Q3: arrayLength after pre_lowering::optimize on a triple-Region-wrapped Program must report 3 for a 12-byte input, got {observed}."
    );
}

#[test]
fn buf_len_loop_bound_survives_pre_lowering() {
    let program = loop_counting_buf_len_program();
    let observed =
        dispatch_and_read_first_word_lowered(&program, vec![1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(
        observed, 3,
        "Q3: a loop bounded by dynamic buf_len(input) must execute once per bound element after pre_lowering, got {observed}."
    );
}

/// Reproducer that mirrors fnv1a64's structure exactly: triple-Region
/// wrap → if-then(gid==0) → let-bind state → Loop bounded by
/// BufLen(input) → body assigns to outer state → after-loop Store.
/// fnv1a64's catalog form returns the unchanged FNV1A64_OFFSET on
/// GPU (loop body never runs), but the Q3 wgpu fix made arrayLength
/// correct for the simpler tests above. This test isolates whether
/// the bug is the loop+assign+outer-state pattern itself.
fn fnv1a64_shaped_count_program() -> Program {
    // Pattern: outer state `n` initialised to 0, loop runs `buf_len(input)`
    // iterations, each iteration does `n = n + 1`. Final n stored to out[0].
    // For a 4-byte input, expect out[0] = 1.
    let inner = vec![Node::if_then(
        Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
        vec![
            Node::let_bind("n", Expr::u32(0)),
            Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::buf_len("input"),
                vec![
                    // Mirror fnv1a64's pattern: read input[i], use it,
                    // assign back to outer state via Var.
                    Node::let_bind(
                        "byte",
                        Expr::bitand(Expr::load("input", Expr::var("i")), Expr::u32(0xFF)),
                    ),
                    Node::let_bind("next", Expr::add(Expr::var("n"), Expr::u32(1))),
                    Node::assign("n", Expr::var("next")),
                    // The byte let must survive even if unused by `n`.
                    Node::let_bind("_swallow", Expr::var("byte")),
                ],
            ),
            Node::store("out", Expr::u32(0), Expr::var("n")),
        ],
    )];
    let mid = Node::Region {
        generator: Ident::from("vyre-primitives::test::fnv_shape_inner"),
        source_region: None,
        body: Arc::new(inner),
    };
    let outer = Node::Region {
        generator: Ident::from("vyre-primitives::test::fnv_shape_mid"),
        source_region: Some(GeneratorRef {
            name: "vyre-libs::catalog::test::fnv_shape_outer".to_string(),
        }),
        body: Arc::new(vec![mid]),
    };
    let body = Node::Region {
        generator: Ident::from("vyre-libs::catalog::test::fnv_shape_outer"),
        source_region: None,
        body: Arc::new(vec![outer]),
    };
    Program::wrapped(
        vec![
            BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::output("out", 1, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![body],
    )
}

#[test]
fn fnv1a64_shaped_loop_runs_once_for_one_byte_input() {
    let program = fnv1a64_shaped_count_program();
    let observed = dispatch_and_read_first_word_lowered(&program, vec![0xAB, 0, 0, 0]);
    assert_eq!(
        observed, 1,
        "Q3: a fnv1a64-shaped loop (BufLen-bounded, with outer-state assign) must iterate once for a 4-byte input, got {observed}. \
         If this fails while the simpler buf_len tests pass, the bug is in how the loop body's outer-scope assigns interact with BufLen lowering."
    );
}

#[test]
fn fnv1a64_shaped_loop_runs_three_times_for_twelve_byte_input() {
    let program = fnv1a64_shaped_count_program();
    let observed =
        dispatch_and_read_first_word_lowered(&program, vec![1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(
        observed, 3,
        "Q3: a fnv1a64-shaped loop must iterate three times for a 12-byte input, got {observed}."
    );
}
