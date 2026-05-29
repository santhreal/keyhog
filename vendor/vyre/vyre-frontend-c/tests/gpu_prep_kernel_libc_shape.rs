//! Diagnostic: run the GPU preprocessor directly on
//! `KERNEL_LIBC_SHAPED_SOURCE` (the fixture that the headline
//! `c11_typed_object_sections` test uses) and assert the output is
//! non-empty.
//!
//! When the headline fails with `tok_types.len() = 0`, the proximate
//! cause is an empty preprocessed source (verified via lex-trace:
//! `source.len=0`). This test isolates the GPU preprocessor stage
//! from the rest of the pipeline to confirm whether the bug is in the
//! preprocessor or downstream.

#[allow(unused_imports)]
use vyre_driver_wgpu as _;

mod support;

use std::path::PathBuf;
use vyre_libs::parsing::c::preprocess::gpu_pipeline::{
    gpu_preprocess_translation_unit, BackendDispatcher, ConditionalEventKind,
    ConditionalEventResidency, IncludeAccelerationKind, IncludeEventResidency, IncludeLoader,
    MacroDef, MacroEventKind,
};

struct NullLoader;
impl IncludeLoader for NullLoader {
    fn load(
        &self,
        _path: &[u8],
        _is_system: bool,
        _is_next: bool,
        _from: &std::path::Path,
    ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
        Ok(None)
    }
}

#[test]
fn gpu_preprocess_returns_non_empty_for_kernel_libc_shaped_source() {
    let backend =
        vyre::backend::acquire_preferred_dispatch_backend().expect("preferred backend available");
    let dispatcher = BackendDispatcher(backend.as_ref());
    let loader = NullLoader;
    let path = PathBuf::from("kernel_libc_shaped.c");
    let raw = support::KERNEL_LIBC_SHAPED_SOURCE.as_bytes();

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");

    eprintln!(
        "[gpu-prep-trace] raw.len={} out.len={} first_64_bytes={:?}",
        raw.len(),
        res.bytes.len(),
        &res.bytes[..res.bytes.len().min(64)]
    );

    assert_ne!(res.bytes.len(), 0,
        "Fix: GPU preprocessor must emit non-empty output for a fixture that contains \
         no preprocessor directives. Got empty output for a {}-byte source.",
        raw.len()
    );
}

/// Reference-eval each filter pipeline STAGE individually on the
/// failing fixture, tracing what each stage produces. This isolates
/// which kernel emits the wrong output for a 734-byte input.
#[test]
fn reference_eval_filter_pipeline_stages_on_kernel_libc_shaped_source() {
    use vyre_primitives::math::prefix_scan::{prefix_scan, ScanKind};
    use vyre_primitives::parsing::line_splice_classify::line_splice_classify;
    // `byte_compact` and `comment_strip` are crate-private internals covered by
    // vyre-libs and WGPU integration tests. This frontend test isolates the
    // public splice mask and prefix-scan contract for the 734-byte fixture.

    fn cpu(prog: &vyre::ir::Program, inputs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let value_inputs: Vec<vyre_reference::value::Value> =
            inputs.into_iter().map(|b| b.into()).collect();
        let outs =
            vyre_reference::reference_eval(prog, &value_inputs).expect("reference_eval succeeds");
        outs.into_iter().map(|v| v.to_bytes()).collect()
    }

    let raw = support::KERNEL_LIBC_SHAPED_SOURCE.as_bytes();
    let n = raw.len() as u32;
    let cap = (n as usize).max(1);
    let byte_buf_pad = (cap.div_ceil(4) * 4).max(4);
    let mut padded_input = raw.to_vec();
    padded_input.resize(byte_buf_pad, 0);

    eprintln!("[stage-trace] n={n} byte_buf_pad={byte_buf_pad}");

    // ---- Stage 1: line_splice_classify ----
    let splice_prog = line_splice_classify(n);
    let splice_out = cpu(&splice_prog, vec![padded_input.clone(), vec![0u8; cap * 4]]);
    eprintln!(
        "[stage1 line_splice] reference_eval returned {} buffers",
        splice_out.len()
    );
    // reference_eval returns only OUTPUT buffers (write-side). The
    // kept_mask is the kernel's only output, so it sits at index 0.
    let kept_mask = &splice_out[0];
    let ones_kept = kept_mask.chunks_exact(4).filter(|c| c[0] == 1).count();
    eprintln!(
        "[stage1 line_splice] out_buf.len={} ones_in_kept_mask={} (expect ~{})",
        kept_mask.len(),
        ones_kept,
        n
    );

    // ---- Stage 4: prefix_scan over the kept_mask alone (assume no
    // comments in fixture) ----
    if n <= 1024 {
        let scan_prog = prefix_scan("mask_in", "offsets_out", n, ScanKind::ExclusiveSum);
        let scan_out = cpu(&scan_prog, vec![kept_mask.clone(), vec![0u8; cap * 4]]);
        let offsets = &scan_out[0];
        eprintln!(
            "[stage4 prefix_scan] offsets.len={} last_word_at_n-1={}",
            offsets.len(),
            u32::from_le_bytes([
                offsets[(cap - 1) * 4],
                offsets[(cap - 1) * 4 + 1],
                offsets[(cap - 1) * 4 + 2],
                offsets[(cap - 1) * 4 + 3],
            ])
        );
    } else {
        eprintln!(
            "[stage4 prefix_scan] SKIPPED  -  n={} > 1024 (prefix_scan rejects n > 1024)",
            n
        );
    }

    assert!(
        ones_kept > 0,
        "line_splice_classify must keep at least some bytes for non-empty source"
    );
}

/// Logging dispatcher: runs each dispatch via reference_eval and
/// prints input/output buffer sizes + first-bytes summary. Localizes
/// which sub-dispatch returns the bad data within `gpu_filter_source_bytes`.
#[test]
fn logging_filter_pipeline_for_kernel_libc_shaped_source() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::{gpu_filter_source_bytes, GpuDispatcher};
    struct LoggingDispatcher {
        idx: AtomicUsize,
    }
    impl GpuDispatcher for LoggingDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let i = self.idx.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "[dispatch#{i}] buffers={} workgroup={:?} input_lens={:?}",
                program.buffers.len(),
                program.workgroup_size(),
                inputs.iter().map(|b| b.len()).collect::<Vec<_>>(),
            );
            for (j, buf) in program.buffers.iter().enumerate() {
                eprintln!(
                    "  buf[{j}] name={:?} access={:?} count={} is_output={}",
                    buf.name(),
                    buf.access,
                    buf.count,
                    buf.is_output
                );
            }
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval[{i}]: {e}"))?;
            let out_bytes: Vec<Vec<u8>> = outs.into_iter().map(|v| v.to_bytes()).collect();
            eprintln!(
                "  -> outputs={} output_lens={:?}",
                out_bytes.len(),
                out_bytes.iter().map(|b| b.len()).collect::<Vec<_>>(),
            );
            for (j, out) in out_bytes.iter().enumerate() {
                let words: Vec<u32> = out
                    .chunks_exact(4)
                    .take(8)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
                let nonzero = out
                    .chunks_exact(4)
                    .filter(|c| c[0] != 0 || c[1] != 0 || c[2] != 0 || c[3] != 0)
                    .count();
                eprintln!(
                    "    out[{j}] first8_words={:?} nonzero_words={}",
                    words, nonzero
                );
            }
            Ok(out_bytes)
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }
    let dispatcher = LoggingDispatcher {
        idx: AtomicUsize::new(0),
    };
    let raw = support::KERNEL_LIBC_SHAPED_SOURCE.as_bytes();
    let res = gpu_filter_source_bytes(&dispatcher, raw).expect("filter pipeline succeeds");
    eprintln!(
        "[result] raw.len={} compacted.len={}",
        raw.len(),
        res.bytes.len()
    );
}

#[test]
fn gpu_preprocess_size_bisection() {
    // Bisection: at what input size does the GPU preprocessor start
    // returning empty output?
    let backend =
        vyre::backend::acquire_preferred_dispatch_backend().expect("preferred backend available");
    let dispatcher = BackendDispatcher(backend.as_ref());
    let loader = NullLoader;
    let path = PathBuf::from("bisect.c");

    // Build inputs of increasing sizes by repeating "int x;\n" (7 bytes).
    let unit = b"int x;\n";
    for size in &[7usize, 252, 256, 257] {
        let mut raw = Vec::new();
        while raw.len() < *size {
            raw.extend_from_slice(unit);
        }
        raw.truncate(*size);
        let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, &raw, &[])
            .expect("gpu preprocess succeeds");
        eprintln!(
            "[gpu-prep-bisect] input.len={} out.len={} out_first20={:?}",
            raw.len(),
            res.bytes.len(),
            std::str::from_utf8(&res.bytes[..res.bytes.len().min(20)]).unwrap_or("<non-utf8>")
        );
    }
}

#[test]
fn gpu_preprocess_returns_non_empty_for_int_main() {
    let backend =
        vyre::backend::acquire_preferred_dispatch_backend().expect("preferred backend available");
    let dispatcher = BackendDispatcher(backend.as_ref());
    let loader = NullLoader;
    let path = PathBuf::from("int_main.c");
    let raw = b"int main(void) { return 0; }\n";

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");

    eprintln!(
        "[gpu-prep-trace] raw.len={} out.len={} out_str={:?}",
        raw.len(),
        res.bytes.len(),
        std::str::from_utf8(&res.bytes).unwrap_or("<non-utf8>")
    );

    assert_ne!(res.bytes.len(), 0,
        "GPU preprocessor must emit non-empty output for int main(void) {{ return 0; }}"
    );
}

#[test]
fn gpu_preprocess_records_gpu_resident_include_request_events() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    struct HeaderLoader;
    impl IncludeLoader for HeaderLoader {
        fn load(
            &self,
            path: &[u8],
            is_system: bool,
            is_next: bool,
            _from: &std::path::Path,
        ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
            assert_eq!(path, b"h.h");
            assert!(!is_system);
            assert!(!is_next);
            Ok(Some((
                PathBuf::from("/tmp/vyrec-gpu-include-event/h.h"),
                b"int from_header;\n".to_vec().into(),
            )))
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = HeaderLoader;
    let path = PathBuf::from("/tmp/vyrec-gpu-include-event/main.c");
    let raw = b"#include \"h.h\"\nint from_source;\n";

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");

    assert!(
        std::str::from_utf8(&res.bytes)
            .expect("preprocessed bytes must be UTF-8")
            .contains("from_header"),
        "included header bytes must be materialized into preprocessed output"
    );
    assert_eq!(res.include_events.len(), 1);
    let event = &res.include_events[0];
    assert_eq!(event.includer, path);
    assert_eq!(event.requested_path, b"h.h");
    assert_eq!(event.directive_row, 0);
    assert_eq!(event.directive_byte_offset, 0);
    assert!(!event.is_system);
    assert!(!event.is_next);
    assert_eq!(
        event.request_residency,
        IncludeEventResidency::GpuResidentRequest
    );
    assert_eq!(
        event.resolution_residency,
        IncludeEventResidency::HostFilesystemMetadata
    );
}

#[test]
fn gpu_preprocess_records_nested_conditional_state_events() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = NullLoader;
    let path = PathBuf::from("nested_conditionals.c");
    let raw = concat!(
        "#define A 1\n",
        "#define LOG(fmt, ...) fmt\n",
        "#ifdef A\n",
        "#if 0\n",
        "int no_a;\n",
        "#elif 1\n",
        "int yes;\n",
        "#else\n",
        "int no_b;\n",
        "#endif\n",
        "#endif\n",
    )
    .as_bytes();

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");
    let out = std::str::from_utf8(&res.bytes).expect("preprocessed bytes must be UTF-8");

    assert!(
        out.contains("yes"),
        "expected active branch in output; out={out:?} events={:#?}",
        res.conditional_events
    );
    assert!(!out.contains("no_a"));
    assert!(!out.contains("no_b"));

    let kinds = res
        .conditional_events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            ConditionalEventKind::Ifdef,
            ConditionalEventKind::If,
            ConditionalEventKind::Elif,
            ConditionalEventKind::Else,
            ConditionalEventKind::Endif,
            ConditionalEventKind::Endif,
        ]
    );
    assert!(
        res.conditional_events
            .iter()
            .any(|event| event.depth_after == 2),
        "nested conditional depth must be recorded"
    );
    assert!(
        res.conditional_events
            .iter()
            .filter(|event| matches!(
                event.kind,
                ConditionalEventKind::Ifdef | ConditionalEventKind::If | ConditionalEventKind::Elif
            ))
            .all(|event| event.directive_residency
                == ConditionalEventResidency::GpuResidentDirective
                && event.state_residency == ConditionalEventResidency::GpuResidentTruth),
        "conditional directive payload and truth events must be GPU-resident"
    );
    let variadic = res
        .macro_events
        .iter()
        .find(|event| event.name == b"LOG")
        .expect("function-like variadic macro event must be recorded");
    assert_eq!(variadic.kind, MacroEventKind::Define);
    assert!(variadic.gpu_resident);
    assert!(variadic.is_function_like);
    assert!(variadic.is_variadic);
    assert_eq!(variadic.args, b"fmt, ...");
    assert_eq!(variadic.replacement, b"fmt");
    assert!(variadic.name_range.is_some());
    assert!(variadic.args_range.is_some());
    assert!(variadic.replacement_range.is_some());
    assert!(
        variadic.symbol_id.iter().any(|byte| *byte != 0),
        "stable macro symbol ID must not be all zeros"
    );
}

#[test]

fn gpu_preprocess_records_object_like_macro_expansion_origins() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = NullLoader;
    let path = PathBuf::from("object_macro.c");
    let raw = concat!("#define X 42\n", "int x = X;\n").as_bytes();

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");
    let out = std::str::from_utf8(&res.bytes).expect("preprocessed bytes must be UTF-8");

    assert!(
        out.contains("42"),
        "object-like macro must expand on GPU: {out:?}"
    );
    assert_eq!(res.macro_expansion_events.len(), 1);
    let event = &res.macro_expansion_events[0];
    assert_eq!(event.file, path);
    assert_eq!(event.name, b"X");
    assert_eq!(event.replacement, b"42");
    assert!(event.invocation_args.is_empty());
    assert!(event.include_stack.is_empty());
    assert_eq!(event.use_len, 1);
    assert!(!event.is_function_like);
    assert!(!event.is_variadic);
    assert!(event.gpu_resident);
    assert!(
        event.symbol_id.iter().any(|byte| *byte != 0),
        "stable macro expansion symbol ID must not be all zeros"
    );
    let provenance = res
        .token_provenance_events
        .iter()
        .find(|provenance| provenance.macro_name == b"X")
        .expect("expanded macro token provenance must be recorded");
    assert_eq!(provenance.output_len, 2);
    assert_eq!(provenance.spelling_file, path);
    assert_eq!(provenance.spelling_start, 10);
    assert_eq!(provenance.spelling_len, 2);
    assert_eq!(provenance.expansion_file, path);
    assert_eq!(provenance.expansion_len, 1);
    assert_eq!(provenance.macro_symbol_id, Some(event.symbol_id));
    assert!(provenance.include_stack.is_empty());
    assert!(provenance.gpu_resident);
}

#[test]
fn gpu_preprocess_records_function_like_macro_expansion_origins() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = NullLoader;
    let path = PathBuf::from("function_macro.c");
    let raw = concat!(
        "#define ADD(a, b) ((a)+(b))\n",
        "#define STR(x) #x\n",
        "#define CAT(a, b) a ## b\n",
        "#define LOG(fmt, ...) fmt\n",
        "int a = ADD(1, 2);\n",
        "char *s = STR(abc);\n",
        "int CAT(foo, bar);\n",
        "LOG(\"x\", 1);\n",
    )
    .as_bytes();

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");

    for name in [
        b"ADD".as_slice(),
        b"STR".as_slice(),
        b"CAT".as_slice(),
        b"LOG".as_slice(),
    ] {
        assert!(
            res.macro_expansion_events
                .iter()
                .any(|event| event.name == name
                    && event.is_function_like
                    && event.gpu_resident
                    && !event.invocation_args.is_empty()),
            "function-like macro expansion event missing for {:?}: {:#?}",
            std::str::from_utf8(name).unwrap_or("<non-utf8>"),
            res.macro_expansion_events
        );
    }
    let log = res
        .macro_expansion_events
        .iter()
        .find(|event| event.name == b"LOG")
        .expect("LOG expansion must be recorded");
    assert!(log.is_variadic);
    assert_eq!(log.invocation_args, b"\"x\", 1");
    let add_provenance: Vec<_> = res
        .token_provenance_events
        .iter()
        .filter(|provenance| provenance.macro_name == b"ADD")
        .collect();
    assert!(
        !add_provenance.is_empty(),
        "function-like macro expansion must emit token-level provenance"
    );
    assert!(add_provenance
        .iter()
        .all(|provenance| provenance.expansion_len == 9
            && provenance.expansion_file == path
            && provenance.include_stack.is_empty()
            && provenance.macro_symbol_id.is_some()
            && provenance.gpu_resident));
    let expansion_start = add_provenance[0].expansion_start;
    let arg_one = expansion_start + 4;
    let arg_two = expansion_start + 7;
    assert!(
        add_provenance
            .iter()
            .any(|provenance| provenance.spelling_start == arg_one && provenance.spelling_len == 1),
        "substituted parameter `a` must spell from invocation argument `1`: {add_provenance:#?}"
    );
    assert!(
        add_provenance
            .iter()
            .any(|provenance| provenance.spelling_start == arg_two && provenance.spelling_len == 1),
        "substituted parameter `b` must spell from invocation argument `2`: {add_provenance:#?}"
    );
    let str_provenance: Vec<_> = res
        .token_provenance_events
        .iter()
        .filter(|provenance| provenance.macro_name == b"STR")
        .collect();
    let str_expansion_start = str_provenance[0].expansion_start;
    assert!(
        str_provenance.iter().any(|provenance| {
            provenance.spelling_start == str_expansion_start + 4 && provenance.spelling_len == 3
        }),
        "stringification parameter must spell from invocation argument `abc`: {str_provenance:#?}"
    );
    let cat_provenance: Vec<_> = res
        .token_provenance_events
        .iter()
        .filter(|provenance| provenance.macro_name == b"CAT")
        .collect();
    let cat_expansion_start = cat_provenance[0].expansion_start;
    assert!(
        cat_provenance.iter().any(|provenance| {
            provenance.spelling_start == cat_expansion_start + 4 && provenance.spelling_len == 3
        }),
        "token-paste left parameter must spell from invocation argument `foo`: {cat_provenance:#?}"
    );
    assert!(
        cat_provenance.iter().any(|provenance| {
            provenance.spelling_start == cat_expansion_start + 9 && provenance.spelling_len == 3
        }),
        "token-paste right parameter must spell from invocation argument `bar`: {cat_provenance:#?}"
    );
}

#[test]
fn gpu_preprocess_records_macro_expansion_include_stack() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    struct HeaderLoader;
    impl IncludeLoader for HeaderLoader {
        fn load(
            &self,
            path: &[u8],
            _is_system: bool,
            _is_next: bool,
            _from: &std::path::Path,
        ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
            assert_eq!(path, b"h.h");
            Ok(Some((
                PathBuf::from("/tmp/vyrec-macro-stack/h.h"),
                b"#define H 7\nint y = H;\n".to_vec().into(),
            )))
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = HeaderLoader;
    let path = PathBuf::from("/tmp/vyrec-macro-stack/main.c");
    let raw = b"#include \"h.h\"\n";

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");

    let event = res
        .macro_expansion_events
        .iter()
        .find(|event| event.name == b"H")
        .expect("header macro expansion must be recorded");
    assert_eq!(
        event.include_stack,
        vec![PathBuf::from("/tmp/vyrec-macro-stack/h.h")]
    );
    let provenance = res
        .token_provenance_events
        .iter()
        .find(|provenance| provenance.macro_name == b"H")
        .expect("header macro token provenance must be recorded");
    assert_eq!(
        provenance.include_stack,
        vec![PathBuf::from("/tmp/vyrec-macro-stack/h.h")]
    );
    assert_eq!(
        provenance.spelling_file,
        PathBuf::from("/tmp/vyrec-macro-stack/h.h")
    );
    assert_eq!(
        provenance.expansion_file,
        PathBuf::from("/tmp/vyrec-macro-stack/h.h")
    );
}

#[test]
fn gpu_preprocess_records_each_replacement_token_provenance() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = NullLoader;
    let path = PathBuf::from("replacement_tokens.c");
    let raw = concat!("#define PAIR 1 + 2\n", "int x = PAIR;\n").as_bytes();

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");
    let replacement_tokens: Vec<_> = res
        .token_provenance_events
        .iter()
        .filter(|provenance| provenance.macro_name == b"PAIR")
        .collect();

    assert_eq!(replacement_tokens.len(), 3);
    assert_eq!(
        replacement_tokens
            .iter()
            .map(|provenance| (provenance.spelling_start, provenance.spelling_len))
            .collect::<Vec<_>>(),
        vec![(13, 1), (15, 1), (17, 1)]
    );
    assert!(replacement_tokens
        .iter()
        .all(|provenance| provenance.expansion_len == 4
            && provenance.expansion_file == path
            && provenance.gpu_resident));
}

#[test]
fn gpu_preprocess_records_identity_path_token_provenance() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = NullLoader;
    let path = PathBuf::from("identity_tokens.c");
    let raw = b"int x = 1;\n";

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");
    let first = res
        .token_provenance_events
        .first()
        .expect("identity path must still emit token provenance");

    assert_eq!(res.bytes, raw);
    assert_eq!(first.file, path);
    assert_eq!(first.output_start, 0);
    assert_eq!(first.spelling_file, path);
    assert_eq!(first.spelling_start, 0);
    assert_eq!(first.expansion_file, path);
    assert!(first.include_stack.is_empty());
    assert!(first.macro_symbol_id.is_none());
    assert!(first.gpu_resident);
}

#[test]
fn gpu_preprocess_skips_repeated_pragma_once_include() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    struct HeaderLoader;
    impl IncludeLoader for HeaderLoader {
        fn load(
            &self,
            path: &[u8],
            _is_system: bool,
            _is_next: bool,
            _from: &std::path::Path,
        ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
            assert_eq!(path, b"once.h");
            Ok(Some((
                PathBuf::from("/tmp/vyrec-once/once.h"),
                b"#pragma once\nint once_value;\n".to_vec().into(),
            )))
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = HeaderLoader;
    let path = PathBuf::from("/tmp/vyrec-once/main.c");
    let raw = b"#include \"once.h\"\n#include \"once.h\"\n";

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");
    let out = std::str::from_utf8(&res.bytes).expect("preprocessed bytes are UTF-8");

    assert_eq!(out.matches("once_value").count(), 1);
    assert!(res.include_acceleration_events.iter().any(|event| {
        event.kind == IncludeAccelerationKind::PragmaOnce
            && event.path == PathBuf::from("/tmp/vyrec-once/once.h")
            && event.skipped_include
            && event.gpu_directive_derived
    }));
}

#[test]
fn gpu_preprocess_skips_repeated_classic_include_guard() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    struct HeaderLoader;
    impl IncludeLoader for HeaderLoader {
        fn load(
            &self,
            path: &[u8],
            _is_system: bool,
            _is_next: bool,
            _from: &std::path::Path,
        ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
            assert_eq!(path, b"guard.h");
            Ok(Some((
                PathBuf::from("/tmp/vyrec-guard/guard.h"),
                b"#ifndef VYREC_GUARD_H\n#define VYREC_GUARD_H\nint guarded_value;\n#endif\n"
                    .to_vec()
                    .into(),
            )))
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = HeaderLoader;
    let path = PathBuf::from("/tmp/vyrec-guard/main.c");
    let raw = b"#include \"guard.h\"\n#include \"guard.h\"\n";

    let res = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, raw, &[])
        .expect("gpu preprocess succeeds");
    let out = std::str::from_utf8(&res.bytes).expect("preprocessed bytes are UTF-8");

    assert_eq!(out.matches("guarded_value").count(), 1);
    assert!(res.include_acceleration_events.iter().any(|event| {
        event.kind == IncludeAccelerationKind::IncludeGuard
            && event.path == PathBuf::from("/tmp/vyrec-guard/guard.h")
            && event.guard_macro == b"VYREC_GUARD_H"
            && event.skipped_include
            && event.gpu_directive_derived
    }));
}

#[test]

fn gpu_preprocess_reuses_header_analysis_by_path_flags_defines_and_triple() {
    use vyre_libs::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

    struct ReferenceDispatcher;
    impl GpuDispatcher for ReferenceDispatcher {
        fn dispatch(
            &self,
            program: &vyre::ir::Program,
            inputs: &[Vec<u8>],
        ) -> Result<Vec<Vec<u8>>, String> {
            let value_inputs: Vec<vyre_reference::value::Value> =
                inputs.iter().cloned().map(Into::into).collect();
            let outs = vyre_reference::reference_eval(program, &value_inputs)
                .map_err(|e| format!("reference_eval: {e}"))?;
            Ok(outs.into_iter().map(|value| value.to_bytes()).collect())
        }

        fn requires_output_inputs(&self) -> bool {
            true
        }
    }

    struct HeaderLoader;
    impl IncludeLoader for HeaderLoader {
        fn load(
            &self,
            path: &[u8],
            _is_system: bool,
            _is_next: bool,
            _from: &std::path::Path,
        ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
            assert_eq!(path, b"reuse.h");
            Ok(Some((
                PathBuf::from("/tmp/vyrec-header-reuse/reuse.h"),
                b"#ifdef FEATURE\nint feature_enabled;\n#endif\n"
                    .to_vec()
                    .into(),
            )))
        }
    }

    let dispatcher = ReferenceDispatcher;
    let loader = HeaderLoader;
    let raw = b"#include \"reuse.h\"\n";
    let enabled = [MacroDef {
        name: b"FEATURE".to_vec().into(),
        args: Vec::new(),
        body: b"1".to_vec().into(),
        is_function_like: false,
    }];
    let disabled = [MacroDef {
        name: b"OTHER_FEATURE".to_vec().into(),
        args: Vec::new(),
        body: b"1".to_vec().into(),
        is_function_like: false,
    }];

    let first = gpu_preprocess_translation_unit(
        &dispatcher,
        &loader,
        &PathBuf::from("/tmp/vyrec-header-reuse/a.c"),
        raw,
        &enabled,
    )
    .expect("first preprocess succeeds");
    let second = gpu_preprocess_translation_unit(
        &dispatcher,
        &loader,
        &PathBuf::from("/tmp/vyrec-header-reuse/b.c"),
        raw,
        &enabled,
    )
    .expect("second preprocess succeeds");
    let third = gpu_preprocess_translation_unit(
        &dispatcher,
        &loader,
        &PathBuf::from("/tmp/vyrec-header-reuse/c.c"),
        raw,
        &disabled,
    )
    .expect("third preprocess succeeds");

    let first_store = first
        .header_reuse_events
        .iter()
        .find(|event| event.stored && !event.hit)
        .expect("first include stores header analysis");
    let second_hit = second
        .header_reuse_events
        .iter()
        .find(|event| event.hit && event.gpu_analysis_reused)
        .expect("second include reuses header analysis");

    assert_eq!(
        first_store.path,
        PathBuf::from("/tmp/vyrec-header-reuse/reuse.h")
    );
    assert_eq!(second_hit.path, first_store.path);
    assert_eq!(second_hit.defines_hash, first_store.defines_hash);
    assert_eq!(second_hit.flags_hash, first_store.flags_hash);
    assert_eq!(second_hit.target_triple, first_store.target_triple);
    assert!(
        third.header_reuse_events.iter().all(|event| !event.hit),
        "changed live defines must invalidate the header cache key"
    );
    assert!(third
        .header_reuse_events
        .iter()
        .any(|event| event.stored && event.defines_hash != first_store.defines_hash));
}

