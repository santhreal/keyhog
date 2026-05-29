//! Smoke tests for the Rust nano-subset parser and end-to-end pipeline.

use vyre_frontend_rust::api::parse_rust_bytes;
use vyre_frontend_rust::pipeline::{RustPipeline, RustPipelineConfig};
use vyre_frontend_rust::RustFrontendError;

#[test]
fn parse_trivial_function() {
    let source = "fn main() { let x: i32 = 5; }";
    let summary = parse_rust_bytes(source.as_bytes()).unwrap();
    assert_eq!(summary.module.functions.len(), 1);
}

#[test]
fn parse_function_with_params() {
    let source = "fn add(a: i32, b: i32) -> i32 { return a + b; }";
    let summary = parse_rust_bytes(source.as_bytes()).unwrap();
    assert_eq!(summary.module.functions.len(), 1);
    assert_eq!(summary.module.functions[0].params.len(), 2);
}

#[test]
fn parse_if_else() {
    let source = "fn max(a: i32, b: i32) -> i32 { if a < b { return b; } else { return a; }; }";
    let summary = parse_rust_bytes(source.as_bytes()).unwrap();
    assert_eq!(summary.module.functions.len(), 1);
}

#[test]
fn parse_borrow() {
    let source = "fn borrow(x: &i32) -> i32 { return *x; }";
    let summary = parse_rust_bytes(source.as_bytes()).unwrap();
    assert_eq!(summary.module.functions.len(), 1);
}

#[test]
fn compile_pipeline_rejects_unwired_gpu_lex_without_silent_cpu_path() {
    let pipeline = RustPipeline::new(RustPipelineConfig { gpu_lex: true, borrow_check: false, lower: false });
    let error = pipeline
        .compile_unit(b"fn main() { let x: i32 = 5; }")
        .expect_err("Fix: GPU lexing must fail loudly until Rust GPU lexer dispatch is wired.");
    let message = error.to_string();
    assert!(message.contains("GPU backend unavailable"));
    assert!(message.contains("not wired yet"));
    assert!(message.contains("silently"));
}

#[test]
fn compile_unit_succeeds_on_well_typed_program() {
    let pipeline = RustPipeline::new(RustPipelineConfig::default());
    let unit = pipeline
        .compile_unit(b"fn add(a: i32, b: i32) -> i32 { return a + b; }")
        .expect("Fix: a well-typed nano-subset program must compile through resolve + typeck");
    assert!(unit.program.is_none(), "Fix: lowering is off by default, so there is no Program yet");
}

#[test]
fn compile_unit_rejects_type_mismatch() {
    let pipeline = RustPipeline::new(RustPipelineConfig::default());
    let error = pipeline
        .compile_unit(b"fn f() -> i32 { return true; }")
        .expect_err("Fix: a return-type mismatch must fail type checking, not compile.");
    assert!(matches!(error, RustFrontendError::Typeck(_)), "got {error:?}");
    assert!(error.to_string().contains("mismatched types"));
}

#[test]
fn compile_unit_borrow_check_catches_e0596() {
    let pipeline = RustPipeline::new(RustPipelineConfig { gpu_lex: false, borrow_check: true, lower: false });
    let error = pipeline
        .compile_unit(b"fn f() { let x: i32 = 0; let r: &mut i32 = &mut x; }")
        .expect_err("Fix: &mut of an immutable binding must fail borrow checking.");
    assert!(matches!(error, RustFrontendError::Borrow(_)), "got {error:?}");
    assert!(error.to_string().contains("cannot borrow `x` as mutable"));
}

#[test]
fn compile_unit_borrow_check_reports_incomplete_on_clean_program() {
    // Mutability passes, but the conflicting-borrow rules are not yet wired, so
    // the pipeline reports incomplete rather than faking a complete borrow check.
    let pipeline = RustPipeline::new(RustPipelineConfig { gpu_lex: false, borrow_check: true, lower: false });
    let error = pipeline
        .compile_unit(b"fn f() { let mut x: i32 = 0; let r: &mut i32 = &mut x; }")
        .expect_err("Fix: an incomplete borrow check must not report a clean pass.");
    assert!(matches!(error, RustFrontendError::Borrow(_)), "got {error:?}");
    assert!(error.to_string().contains("borrow checking is incomplete"));
}
