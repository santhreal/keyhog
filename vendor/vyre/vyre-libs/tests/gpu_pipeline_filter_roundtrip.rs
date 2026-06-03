//! End-to-end test of `gpu_filter_source_bytes`: line-splice + comment-strip
//! + AND + scan + compact, all GPU IR Programs, validated through
//! `vyre_reference::reference_eval` (avoids the GPU driver / wgpu /
//! vyre-debug dep stack  -  those are exercised by per-kernel roundtrip
//! tests in `vyre-libs`).

#![cfg(feature = "c-parser")]
#![allow(deprecated)]
use vyre::ir::{DataType, Program};
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
    bytes_in_elements: std::cell::RefCell<Vec<DataType>>,
    bytes_in_input_lens: std::cell::RefCell<Vec<usize>>,
    preflight_flags: std::cell::RefCell<Vec<(String, u32, usize)>>,
}

impl CountingDispatcher {
    fn new() -> Self {
        Self {
            calls: std::cell::Cell::new(0),
            op_ids: std::cell::RefCell::new(Vec::new()),
            bytes_in_elements: std::cell::RefCell::new(Vec::new()),
            bytes_in_input_lens: std::cell::RefCell::new(Vec::new()),
            preflight_flags: std::cell::RefCell::new(Vec::new()),
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
        self.bytes_in_elements.borrow_mut().extend(
            program
                .buffers()
                .iter()
                .filter_map(|buffer| (buffer.name() == "bytes_in").then_some(buffer.element())),
        );
        self.bytes_in_input_lens.borrow_mut().extend(
            program
                .buffers()
                .iter()
                .position(|buffer| buffer.name() == "bytes_in")
                .and_then(|index| inputs.get(index))
                .map(Vec::len),
        );
        for (index, buffer) in program.buffers().iter().enumerate() {
            let name = buffer.name();
            if name == "transform_flag" || name == "spliced_comment_flag" {
                self.preflight_flags.borrow_mut().push((
                    name.to_string(),
                    buffer.count(),
                    inputs.get(index).map_or(0, Vec::len),
                ));
            }
        }
        RefDispatcher.dispatch(program, inputs)
    }

    fn requires_output_inputs(&self) -> bool {
        true
    }
}

fn assert_byte_source_dispatches_are_u8(dispatcher: &CountingDispatcher) {
    let elements = dispatcher.bytes_in_elements.borrow();
    assert!(
        !elements.is_empty(),
        "filter path must dispatch at least one byte-source program"
    );
    assert!(
        elements
            .iter()
            .all(|element| matches!(element, DataType::U8)),
        "filter byte-source programs must consume raw U8 source buffers, got {elements:?}"
    );
}

fn assert_byte_source_inputs_are_unpadded(dispatcher: &CountingDispatcher, raw_len: usize) {
    let input_lens = dispatcher.bytes_in_input_lens.borrow();
    assert!(
        !input_lens.is_empty(),
        "filter path must dispatch at least one byte-source program"
    );
    assert!(
        input_lens.iter().all(|len| *len == raw_len),
        "filter byte-source programs must consume the raw input length {raw_len}, got {input_lens:?}"
    );
}

fn assert_preflight_flags_are_singleton(dispatcher: &CountingDispatcher) {
    let flags = dispatcher.preflight_flags.borrow();
    assert!(
        flags.iter().any(|(name, _, _)| name == "transform_flag"),
        "filter path must dispatch the transform preflight"
    );
    for (name, count, input_len) in flags.iter() {
        assert!(
            *count == 1 && *input_len == std::mem::size_of::<u32>(),
            "{name} must stage exactly one zeroed u32, got count={count} input_len={input_len}"
        );
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

fn generated_route_source(case: u32) -> Vec<u8> {
    match case % 8 {
        0 => format!("int keep_{case} = a / b; char c_{case} = '/';\n").into_bytes(),
        1 => format!("int x_{case} = 1; // strip line {case}\nint y_{case} = 2;\n").into_bytes(),
        2 => format!("int x_{case} = /* strip block {case} */ {case};\n").into_bytes(),
        3 => format!("int joined_{case} = {case} + \\\n{};\n", case + 1).into_bytes(),
        4 => format!("int x_{case} = 1; /\\\n/ hidden {case}\nint y_{case} = 2;\n").into_bytes(),
        5 => format!("int x_{case} = 1; /\\\n* hidden {case} */ int y_{case} = 2;\n").into_bytes(),
        6 => format!("int a_{case} = 1; // line\nint b_{case} = /* block */ 2;\n").into_bytes(),
        _ => format!("int x_{case} = 1; /* outer /* inner {case} */ int y_{case} = 2;\n")
            .into_bytes(),
    }
}

#[test]
fn no_comments_no_splices_passes_through() {
    let src = b"int main(void) { return 0; }";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn generated_filter_route_matrix_uses_singleton_preflight_flags() {
    let mut route_counts = [0usize; 6];

    for case in 0..64u32 {
        let src = generated_route_source(case);
        let dispatcher = CountingDispatcher::new();
        let out = gpu_filter_source_bytes(&dispatcher, &src)
            .unwrap_or_else(|error| panic!("Fix: generated C filter case {case} failed: {error}"));
        assert_eq!(
            out.bytes,
            reference_filter_source_bytes(&src),
            "case {case}"
        );
        assert_preflight_flags_are_singleton(&dispatcher);
        assert_byte_source_dispatches_are_u8(&dispatcher);
        assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());

        let ops = dispatcher.op_ids.borrow();
        let saw_op = |needle: &str| ops.iter().any(|op| op.contains(needle));
        route_counts[0] += usize::from(ops.len() == 1);
        route_counts[1] += usize::from(saw_op("simple_line_comment_masks"));
        route_counts[2] += usize::from(saw_op("simple_block_comment_masks"));
        let saw_spliced_preflight = saw_op("filter_spliced_comment_preflight");
        route_counts[5] += usize::from(saw_spliced_preflight);
        let saw_full_comment = saw_op("gpu_comment_strip_mask");
        route_counts[4] += usize::from(saw_full_comment);
        route_counts[3] += usize::from(saw_spliced_preflight && !saw_full_comment);
    }

    assert!(
        route_counts[..5].iter().all(|count| *count > 0),
        "generated matrix route gap: {route_counts:?}"
    );
    assert!(
        route_counts[5] >= 24,
        "generated matrix must repeatedly run spliced-comment preflights"
    );
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
    assert_byte_source_dispatches_are_u8(&dispatcher);
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
}

#[test]
fn line_splice_only() {
    let src = b"int x = \\\n42;\n";
    assert_eq!(run(src).bytes, reference_filter_source_bytes(src));
}

#[test]
fn line_splice_only_bypasses_serial_comment_state_machine() {
    let src = b"int x = \\\n42;\nint y = 1 + \\\r\n2;\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .all(|op| !op.contains("gpu_comment_strip_mask")),
        "line-splice-only inputs must not dispatch the serial comment-strip state machine"
    );
    assert_byte_source_dispatches_are_u8(&dispatcher);
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
}

#[test]
fn spliced_line_comment_delimiter_uses_full_comment_state_machine() {
    let src = b"int x = 1; /\\\n/ hidden\nint y = 2;\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .any(|op| op.contains("gpu_comment_strip_mask")),
        "spliced line-comment delimiters must use the full comment-state machine"
    );
}

#[test]
fn spliced_block_comment_delimiter_uses_full_comment_state_machine() {
    let src = b"int x = 1; /\\\n* hidden *\\\n/ int y = 2;\n";
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert!(
        dispatcher
            .op_ids
            .borrow()
            .iter()
            .any(|op| op.contains("gpu_comment_strip_mask")),
        "spliced block-comment delimiters must use the full comment-state machine"
    );
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
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
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
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
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
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
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
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
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
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(src));
    assert_byte_source_dispatches_are_u8(&dispatcher);
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
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
    let dispatcher = CountingDispatcher::new();
    let out = gpu_filter_source_bytes(&dispatcher, &src).expect("gpu_filter_source_bytes");
    assert_eq!(out.bytes, reference_filter_source_bytes(&src));
    assert_preflight_flags_are_singleton(&dispatcher);
    assert_byte_source_inputs_are_unpadded(&dispatcher, src.len());
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
fn large_line_splice_only_bypasses_serial_comment_state_machine() {
    let mut src = Vec::new();
    for i in 0..192u32 {
        if i % 2 == 0 {
            src.extend_from_slice(format!("int joined_{i} = {i} + \\\n{};\n", i + 1).as_bytes());
        } else {
            src.extend_from_slice(format!("int joined_{i} = {i} + \\\r\n{};\n", i + 1).as_bytes());
        }
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
        "large line-splice-only inputs must not dispatch the serial comment-strip state machine"
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
