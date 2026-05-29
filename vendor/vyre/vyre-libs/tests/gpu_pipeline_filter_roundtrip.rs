//! End-to-end test of `gpu_filter_source_bytes`: line-splice + comment-strip
//! + AND + scan + compact, all GPU IR Programs, validated through
//! `vyre_reference::reference_eval` (avoids the GPU driver / wgpu /
//! vyre-debug dep stack  -  those are exercised by per-kernel roundtrip
//! tests in `vyre-libs`).

#![cfg(feature = "c-parser")]
#![allow(deprecated)]
use vyre::ir::Program;
use vyre_libs::parsing::c::preprocess::gpu_pipeline::{
    gpu_filter_source_bytes, FilteredBytes, GpuDispatcher,
};
use vyre_reference::value::Value;

/// Reference-eval dispatcher. Each input `Vec<u8>` becomes a `Value`,
/// `reference_eval` runs the Program through the pure-Rust interpreter,
/// each output `Value` is converted back to `Vec<u8>`.
struct RefDispatcher;

impl GpuDispatcher for RefDispatcher {
    fn dispatch(&self, program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        let values: Vec<Value> = inputs.iter().cloned().map(Value::from).collect();
        let outputs = vyre_reference::reference_eval(program, &values)
            .map_err(|e| format!("reference_eval: {e}"))?;
        Ok(outputs.into_iter().map(|v| v.to_bytes().to_vec()).collect())
    }

    fn requires_output_inputs(&self) -> bool {
        true
    }
}

struct CountingDispatcher {
    calls: std::cell::Cell<usize>,
    op_ids: std::cell::RefCell<Vec<String>>,
}

impl CountingDispatcher {
    fn new() -> Self {
        Self {
            calls: std::cell::Cell::new(0),
            op_ids: std::cell::RefCell::new(Vec::new()),
        }
    }
}

impl GpuDispatcher for CountingDispatcher {
    fn dispatch(&self, program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.calls.set(self.calls.get() + 1);
        self.op_ids.borrow_mut().push(
            program
                .entry_op_id
                .clone()
                .unwrap_or_else(|| "<anonymous>".to_string()),
        );
        RefDispatcher.dispatch(program, inputs)
    }

    fn requires_output_inputs(&self) -> bool {
        true
    }
}

fn reference_filter_source_bytes(raw: &[u8]) -> Vec<u8> {
    use vyre_libs::parsing::c::preprocess::gpu_comment_strip_mask::reference_gpu_comment_strip_mask;
    use vyre_primitives::parsing::line_splice_classify::reference_line_splice_classify;
    let splice_keep = reference_line_splice_classify(raw);
    let comment_mask = reference_gpu_comment_strip_mask(raw);
    raw.iter()
        .enumerate()
        .filter(|(i, _)| splice_keep[*i] == 1 && comment_mask[*i] != 1)
        .map(|(i, b)| if comment_mask[i] == 2 { b' ' } else { *b })
        .collect()
}

fn run(raw: &[u8]) -> FilteredBytes {
    gpu_filter_source_bytes(&RefDispatcher, raw).expect("gpu_filter_source_bytes")
}

#[test]
fn no_comments_no_splices_passes_through() {
    let src = b"int main(void) { return 0; }";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn division_slash_bypasses_serial_comment_filter() {
    let src = b"int q = a / b; char c = 'x'; const char *s = \"not a comment\";\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, src);
    assert_eq!(
        dispatcher.calls.get(),
        1,
        "ordinary slash must stop after the parallel transform preflight"
    );
}

#[test]
fn line_splice_only() {
    let src = b"int x = \\\n42;\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn line_comment_only() {
    let src = b"int x = 1; // trailing comment\nint y = 2;\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn simple_line_comments_bypass_serial_comment_state_machine() {
    let src = b"int x = 1; // trailing comment\nint y = 2; // another\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .all(|op| !op.contains("gpu_comment_strip_mask")),
        "simple line comments must not dispatch the serial comment-strip state machine"
    );
}

#[test]
fn block_comment_only() {
    let src = b"int x = /* between */ 1;\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn simple_block_comments_bypass_serial_comment_state_machine() {
    let src = b"int x = /* between */ 1; int y = /* another */ 2;\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .all(|op| !op.contains("gpu_comment_strip_mask")),
        "simple block comments must not dispatch the serial comment-strip state machine"
    );
}

#[test]
fn nested_block_marker_falls_back_to_full_comment_state_machine() {
    let src = b"int x = 1; /* outer /* inner marker */ int y = 2;\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .any(|op| op.contains("gpu_comment_strip_mask")),
        "nested block marker topology must use the full comment-state machine"
    );
}

#[test]
fn stray_block_close_falls_back_to_full_comment_state_machine() {
    let src = b"int x = 1; */ int y = /* comment */ 2;\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .any(|op| op.contains("gpu_comment_strip_mask")),
        "stray block close topology must use the full comment-state machine"
    );
}

#[test]
fn block_comment_replacement_prevents_token_concatenation() {
    let src = b"int ab = a/**/b;\n";
    assert_eq!(run(src).bytes, b"int ab = a b;\n");
}

#[test]
fn comment_markers_inside_literals_are_preserved() {
    let src = br#"char *s = "/* not comment */"; int c = '//';"#;
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
    assert_eq!(run(src).bytes, src);
}

#[test]
fn header_guard_realistic() {
    let src = b"#ifndef GUARD_H\n#define GUARD_H\n// API\nint foo(void);\n#endif\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn macro_with_continuation_and_comment() {
    let src = b"#define MAX(a,b) /* unsafe */ \\\n    ((a)>(b)?(a):(b))\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn block_comment_spanning_lines() {
    let src = b"a\n/*\n  multi-line\n  block\n*/\nb\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn dense_mixed_pattern() {
    let src = b"//c1\nint x; /*c2*/ int y; \\\nint z; // c3\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn large_filter_uses_multi_block_prefix_scan_contract() {
    let mut src = Vec::new();
    for i in 0..256u32 {
        src.extend_from_slice(format!("int keep_{i} = {i}; // strip this comment\n").as_bytes());
    }
    src.extend_from_slice(b"int joined = 1 + \\\n2; /* block */ int tail = 3;\n");
    assert!(
        src.len() > 1024,
        "fixture must exceed one prefix-scan block"
    );
    assert_eq!(run(&src).bytes, reference_filter_source_bytes(&src));
}

#[test]
fn late_transform_candidate_after_first_workgroup_is_detected() {
    let mut src = Vec::new();
    for i in 0..96u32 {
        src.extend_from_slice(format!("int keep_{i} = {i};\n").as_bytes());
    }
    assert!(src.len() > 1024, "prefix must exceed one workgroup");
    src.extend_from_slice(b"int tail = 1; // late comment\n");
    assert_eq!(run(&src).bytes, reference_filter_source_bytes(&src));
}

#[test]
fn large_simple_line_comments_bypass_serial_comment_state_machine() {
    let mut src = Vec::new();
    for i in 0..192u32 {
        src.extend_from_slice(format!("int keep_{i} = {i}; // strip\n").as_bytes());
    }
    assert!(src.len() > 1024, "fixture must exceed one workgroup");
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, &src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(&src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .all(|op| !op.contains("gpu_comment_strip_mask")),
        "large simple line comments must not dispatch the serial comment-strip state machine"
    );
}

#[test]
fn large_simple_block_comments_bypass_serial_comment_state_machine() {
    let mut src = Vec::new();
    for i in 0..192u32 {
        src.extend_from_slice(format!("int keep_{i} = /* strip */ {i};\n").as_bytes());
    }
    assert!(src.len() > 1024, "fixture must exceed one workgroup");
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, &src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(&src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .all(|op| !op.contains("gpu_comment_strip_mask")),
        "large simple block comments must not dispatch the serial comment-strip state machine"
    );
}

#[test]
fn empty_input_produces_empty_output() {
    assert!(run(b"").bytes.is_empty());
}
