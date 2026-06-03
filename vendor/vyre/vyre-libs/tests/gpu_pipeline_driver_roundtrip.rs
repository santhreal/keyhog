//! End-to-end test of `gpu_preprocess_translation_unit`: the full
//! recursive include driver. Drives the entire 18a→18b→18c→18d chain
//! through the reference dispatcher, with an in-memory `IncludeLoader`
//! so we don't touch the filesystem.

#![cfg(feature = "c-parser")]
#![allow(deprecated)]
use std::cell::Cell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use vyre::ir::{BufferAccess, DataType, Program};
use vyre_libs::parsing::c::preprocess::gpu_pipeline::{
    gpu_preprocess_translation_unit, GpuDispatcher, IncludeEventResidency, IncludeLoader, MacroDef,
};
use vyre_reference::value::Value;

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
    dispatches: Cell<usize>,
    macro_byte_arena_elements: std::cell::RefCell<Vec<(String, DataType)>>,
    macro_byte_arena_input_lens: std::cell::RefCell<Vec<(String, usize)>>,
}

impl CountingDispatcher {
    fn new() -> Self {
        Self {
            dispatches: Cell::new(0),
            macro_byte_arena_elements: std::cell::RefCell::new(Vec::new()),
            macro_byte_arena_input_lens: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn dispatches(&self) -> usize {
        self.dispatches.get()
    }

    fn macro_byte_arena_input_lens(&self, name: &str) -> Vec<usize> {
        self.macro_byte_arena_input_lens
            .borrow()
            .iter()
            .filter_map(|(buffer, len)| (buffer == name).then_some(*len))
            .collect()
    }
}

impl GpuDispatcher for CountingDispatcher {
    fn dispatch(&self, program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.dispatches.set(self.dispatches.get() + 1);
        if program
            .entry_op_id
            .as_deref()
            .is_some_and(|op_id| op_id.contains("opt_named_macro_expansion_materialized"))
        {
            for name in [
                "source_words",
                "macro_name_words",
                "macro_replacement_words",
            ] {
                let buffer = program
                    .buffers()
                    .iter()
                    .find(|buffer| buffer.name() == name)
                    .ok_or_else(|| format!("missing materialized macro byte arena {name}"))?;
                self.macro_byte_arena_elements
                    .borrow_mut()
                    .push((name.to_string(), buffer.element()));
                let input_index = input_index_for_buffer(program, name)
                    .ok_or_else(|| format!("missing materialized macro input slot {name}"))?;
                let len = inputs.get(input_index).map(Vec::len).ok_or_else(|| {
                    format!(
                        "missing materialized macro input {name} at slot {input_index}; got {} inputs",
                        inputs.len()
                    )
                })?;
                self.macro_byte_arena_input_lens
                    .borrow_mut()
                    .push((name.to_string(), len));
            }
        }
        RefDispatcher.dispatch(program, inputs)
    }

    fn requires_output_inputs(&self) -> bool {
        true
    }
}

fn input_index_for_buffer(program: &Program, name: &str) -> Option<usize> {
    let mut input_index = 0usize;
    for buffer in program.buffers() {
        if buffer.access() == BufferAccess::Workgroup {
            continue;
        }
        if buffer.name() == name {
            return Some(input_index);
        }
        input_index += 1;
    }
    None
}

/// In-memory include loader keyed by exact path bytes.
struct MemLoader {
    files: HashMap<Vec<u8>, Vec<u8>>,
    loads: Cell<usize>,
}

impl MemLoader {
    fn new() -> Self {
        Self {
            files: HashMap::new(),
            loads: Cell::new(0),
        }
    }
    fn add(&mut self, name: &[u8], bytes: &[u8]) -> &mut Self {
        self.files.insert(name.to_vec().into(), bytes.to_vec());
        self
    }
    fn loads(&self) -> usize {
        self.loads.get()
    }
}

impl IncludeLoader for MemLoader {
    fn load(
        &self,
        path: &[u8],
        _is_system: bool,
        _is_next: bool,
        _from: &Path,
    ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
        self.loads.set(self.loads.get() + 1);
        Ok(self.files.get(path).map(|b| {
            (
                PathBuf::from(String::from_utf8_lossy(path).into_owned()),
                b.clone().into(),
            )
        }))
    }
}

fn run(src: &[u8], cli: &[MacroDef], loader: &MemLoader) -> Vec<u8> {
    gpu_preprocess_translation_unit(&RefDispatcher, loader, Path::new("<tu>"), src, cli)
        .expect("preprocess_translation_unit")
        .bytes
}

fn run_err(src: &[u8], cli: &[MacroDef], loader: &MemLoader) -> String {
    match gpu_preprocess_translation_unit(&RefDispatcher, loader, Path::new("<tu>"), src, cli) {
        Ok(_) => panic!("preprocess_translation_unit must reject malformed input"),
        Err(error) => error,
    }
}

#[test]
fn no_directives_passes_through_active_bytes() {
    let loader = MemLoader::new();
    let out = run(b"int x = 1;", &[], &loader);
    // Filtered + tokenized + reassembled.
    let out_str = String::from_utf8_lossy(&out);
    assert!(out_str.contains("int"));
    assert!(out_str.contains("x"));
    assert!(out_str.contains("1"));
}

#[test]
fn large_no_directive_unit_uses_multi_block_sparse_token_scan() {
    let loader = MemLoader::new();
    let mut src = Vec::new();
    for i in 0..48u32 {
        src.extend_from_slice(format!("int large_token_scan_{i} = {i};\n").as_bytes());
    }
    assert!(
        src.len() > 1024,
        "fixture must exceed one prefix-scan block"
    );
    let out = run(&src, &[], &loader);
    let out_str = String::from_utf8_lossy(&out);
    assert!(out_str.contains("large_token_scan_0"));
    assert!(out_str.contains("large_token_scan_47"));
}

#[test]
fn clean_translation_unit_uses_gpu_preprocessor_path() {
    let loader = MemLoader::new();
    let dispatcher = CountingDispatcher::new();
    let source = format!(
        "int already_clean_{} = 42;\nfloat also_clean = 1.0f;\n",
        std::process::id()
    );
    let path = PathBuf::from(format!("<clean-tu-{}>", std::process::id()));
    let out = gpu_preprocess_translation_unit(&dispatcher, &loader, &path, source.as_bytes(), &[])
        .expect("preprocessor-clean source must still use GPU preprocessing stages");
    assert_eq!(out.bytes, source.as_bytes());
    assert!(
        dispatcher.dispatches() > 0,
        "clean translation units must not bypass GPU preprocessing"
    );
}

#[test]
fn line_comment_is_dropped() {
    let loader = MemLoader::new();
    let out = run(b"int x;// comment here\nint y;", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("comment"));
    assert!(s.contains("int"));
}

#[test]
fn block_comment_is_dropped() {
    let loader = MemLoader::new();
    let out = run(b"int /* drop */ x;", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("drop"));
}

#[test]
fn line_splice_joins_lines() {
    let loader = MemLoader::new();
    let out = run(b"int x = 1 + \\\n2;", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    // The backslash-newline should be gone; tokens 1 + 2 should
    // appear as part of one expression.
    assert!(!s.contains("\\\n"));
}

#[test]
fn ifdef_when_macro_defined_keeps_active_block() {
    let loader = MemLoader::new();
    let out = run(
        b"#ifdef FOO\nint a;\n#endif\nint b;",
        &[MacroDef {
            name: b"FOO".to_vec().into(),
            args: Vec::new(),
            body: Vec::new(),
            is_function_like: false,
        }],
        &loader,
    );
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("a"));
    assert!(s.contains("b"));
}

#[test]
fn ifdef_when_macro_undefined_drops_inactive_block() {
    let loader = MemLoader::new();
    let out = run(b"#ifdef MISSING\nint a;\n#endif\nint b;", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("a"), "inactive #ifdef block must NOT emit 'a'");
    assert!(s.contains("b"));
}

#[test]
fn ifndef_inverts() {
    let loader = MemLoader::new();
    let out = run(b"#ifndef MISSING\nint a;\n#endif\n", &[], &loader);
    assert!(String::from_utf8_lossy(&out).contains("a"));
}

#[test]
fn else_branch_taken_when_if_false() {
    let loader = MemLoader::new();
    let out = run(b"#if 0\nint a;\n#else\nint b;\n#endif\n", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("a"));
    assert!(s.contains("b"));
}

#[test]
fn elif_else_chain_picks_first_truthy() {
    let loader = MemLoader::new();
    let out = run(
        b"#if 0\nint a;\n#elif 1\nint b;\n#elif 1\nint c;\n#else\nint d;\n#endif\n",
        &[],
        &loader,
    );
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("a"));
    assert!(s.contains("b"));
    assert!(!s.contains("c"));
    assert!(!s.contains("d"));
}

#[test]
fn if_divide_by_zero_fails_loudly() {
    let loader = MemLoader::new();
    let err = run_err(b"#if 4 / 0\nint hidden;\n#endif\n", &[], &loader);
    assert!(
        err.contains("malformed #if/#elif expression"),
        "divide-by-zero #if must fail before conditional masking; got {err}"
    );
}

#[test]
fn if_modulo_by_zero_fails_loudly() {
    let loader = MemLoader::new();
    let err = run_err(b"#if 4 % 0\nint hidden;\n#endif\n", &[], &loader);
    assert!(
        err.contains("malformed #if/#elif expression"),
        "modulo-by-zero #if must fail before conditional masking; got {err}"
    );
}

#[test]
fn nested_conditionals_inherit_parent_inactivity() {
    let loader = MemLoader::new();
    let out = run(
        b"#if 0\n#if 1\nint a;\n#endif\n#endif\nint b;\n",
        &[],
        &loader,
    );
    let s = String::from_utf8_lossy(&out);
    assert!(
        !s.contains("a"),
        "nested branch must inherit parent's inactivity"
    );
    assert!(s.contains("b"));
}

#[test]
fn simple_include_inlines_file_contents() {
    let mut loader = MemLoader::new();
    loader.add(b"foo.h", b"int from_foo;\n");
    let out = run(b"#include \"foo.h\"\nint main_tu;", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("from_foo"));
    assert!(s.contains("main_tu"));
}

#[test]
fn repeated_unguarded_include_reuses_gpu_header_analysis() {
    let pid = std::process::id();
    let mut loader = MemLoader::new();
    let header_name = format!("repeat_header_reuse_gpu_analysis_{pid}.h");
    let header_body = format!(
        "int repeated_header_{pid}; /* force gpu preprocessing without macro mutation */\n"
    );
    loader.add(header_name.as_bytes(), header_body.as_bytes());
    let source = format!("#include \"{header_name}\"\n#include \"{header_name}\"\n");
    let dispatcher = CountingDispatcher::new();
    let out = gpu_preprocess_translation_unit(
        &dispatcher,
        &loader,
        Path::new("<tu>"),
        source.as_bytes(),
        &[],
    )
    .expect("preprocess");
    let text = String::from_utf8_lossy(&out.bytes);
    let header_symbol = format!("repeated_header_{pid}");
    assert_eq!(text.matches(&header_symbol).count(), 2);
    assert!(
        out.header_reuse_events
            .iter()
            .any(|event| event.stored && !event.hit),
        "first include must store GPU-derived header analysis"
    );
    assert!(
        out.header_reuse_events
            .iter()
            .any(|event| event.hit && event.gpu_analysis_reused),
        "second include must reuse cached GPU-derived header analysis"
    );
    assert_eq!(
        loader.loads(),
        1,
        "repeated include must reuse loaded header bytes inside one translation-unit run"
    );
    assert_eq!(out.include_byte_cache_stats.hits, 1);
    assert_eq!(out.include_byte_cache_stats.misses, 1);
    assert_eq!(out.include_byte_cache_stats.entries, 1);
    assert_eq!(out.include_byte_cache_stats.evictions, 0);
    assert!(out.include_byte_cache_stats.retained_bytes >= header_body.len() as u64);
    assert_eq!(
        out.include_byte_cache_stats.loaded_bytes,
        header_body.len() as u64
    );
    assert_eq!(
        out.include_byte_cache_stats.reused_bytes,
        header_body.len() as u64
    );
    assert!(
        out.include_events
            .iter()
            .any(|event| { event.resolution_residency == IncludeEventResidency::HostMemoryCache }),
        "second include event must expose in-run header byte-cache residency"
    );
    let reused_dispatches = dispatcher.dispatches();

    let mut distinct_loader = MemLoader::new();
    let distinct_a = format!("repeat_header_reuse_gpu_analysis_{pid}_a.h");
    let distinct_b = format!("repeat_header_reuse_gpu_analysis_{pid}_b.h");
    distinct_loader.add(distinct_a.as_bytes(), header_body.as_bytes());
    distinct_loader.add(distinct_b.as_bytes(), header_body.as_bytes());
    let distinct_source = format!("#include \"{distinct_a}\"\n#include \"{distinct_b}\"\n");
    let distinct_dispatcher = CountingDispatcher::new();
    let distinct_out = gpu_preprocess_translation_unit(
        &distinct_dispatcher,
        &distinct_loader,
        Path::new("<tu-distinct>"),
        distinct_source.as_bytes(),
        &[],
    )
    .expect("distinct header preprocess");
    assert!(
        distinct_out
            .header_reuse_events
            .iter()
            .all(|event| !event.hit),
        "distinct headers must not report header-reuse hits"
    );
    assert_eq!(
        distinct_loader.loads(),
        2,
        "distinct headers must each resolve through the include loader"
    );
    assert_eq!(distinct_out.include_byte_cache_stats.hits, 0);
    assert_eq!(distinct_out.include_byte_cache_stats.misses, 2);
    assert_eq!(distinct_out.include_byte_cache_stats.entries, 2);
    assert_eq!(distinct_out.include_byte_cache_stats.evictions, 0);
    let distinct_dispatches = distinct_dispatcher.dispatches();
    assert!(
        reused_dispatches < distinct_dispatches,
        "repeated include must reduce GPU dispatch work versus two distinct headers; reused={reused_dispatches} distinct={distinct_dispatches}"
    );
}

#[test]
fn system_include_bytes_are_shared_across_includers_in_one_translation_unit() {
    let pid = std::process::id();
    let mut loader = MemLoader::new();
    let common_name = format!("shared_system_include_{pid}.h");
    let a_name = format!("shared_system_include_{pid}_a.h");
    let b_name = format!("shared_system_include_{pid}_b.h");
    let common_body = format!("int shared_system_symbol_{pid};\n");
    let a_body = format!("#include <{common_name}>\nint from_a_{pid};\n");
    let b_body = format!("#include <{common_name}>\nint from_b_{pid};\n");
    loader
        .add(common_name.as_bytes(), common_body.as_bytes())
        .add(a_name.as_bytes(), a_body.as_bytes())
        .add(b_name.as_bytes(), b_body.as_bytes());
    let source = format!("#include \"{a_name}\"\n#include \"{b_name}\"\n");

    let out = gpu_preprocess_translation_unit(
        &CountingDispatcher::new(),
        &loader,
        Path::new("<tu>"),
        source.as_bytes(),
        &[],
    )
    .expect("preprocess shared system include");
    let text = String::from_utf8_lossy(&out.bytes);

    assert_eq!(
        text.matches(&format!("shared_system_symbol_{pid}")).count(),
        2
    );
    assert_eq!(
        loader.loads(),
        3,
        "same angle-bracket include reached from two includers must load bytes once"
    );
    assert_eq!(out.include_byte_cache_stats.hits, 1);
    assert_eq!(out.include_byte_cache_stats.misses, 3);
    assert_eq!(out.include_byte_cache_stats.entries, 3);
    assert_eq!(out.include_byte_cache_stats.evictions, 0);
    assert_eq!(
        out.include_byte_cache_stats.loaded_bytes,
        (common_body.len() + a_body.len() + b_body.len()) as u64
    );
    assert!(
        out.include_byte_cache_stats.retained_bytes >= out.include_byte_cache_stats.loaded_bytes
    );
    assert_eq!(
        out.include_byte_cache_stats.reused_bytes,
        common_body.len() as u64
    );
    assert!(
        out.include_events.iter().any(|event| {
            event.requested_path == common_name.as_bytes()
                && event.resolution_residency == IncludeEventResidency::HostMemoryCache
        }),
        "second shared angle-bracket include must be served from the TU byte cache"
    );
}

#[test]
fn missing_include_fails_loudly() {
    let loader = MemLoader::new();
    let err = gpu_preprocess_translation_unit(
        &RefDispatcher,
        &loader,
        Path::new("<tu>"),
        b"#include \"missing.h\"\nint after;\n",
        &[],
    )
    .expect_err("missing include must fail loudly");
    assert!(err.contains("missing.h"));
    assert!(err.contains("Fix:"));
}

#[test]

fn nested_includes_recurse() {
    let mut loader = MemLoader::new();
    loader
        .add(b"a.h", b"int from_a;\n#include \"b.h\"\n")
        .add(b"b.h", b"int from_b;\n");
    let out = run(b"#include \"a.h\"\n", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("from_a"));
    assert!(s.contains("from_b"));
}

#[test]
fn cycle_protection_does_not_loop_forever() {
    let mut loader = MemLoader::new();
    loader.add(b"a.h", b"int from_a;\n#include \"a.h\"\n");
    let out = run(b"#include \"a.h\"\n", &[], &loader);
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("from_a"));
}

#[test]
fn macros_accumulate_across_files() {
    let mut loader = MemLoader::new();
    loader.add(b"defs.h", b"#define X 1\n");
    let res = gpu_preprocess_translation_unit(
        &RefDispatcher,
        &loader,
        Path::new("<tu>"),
        b"#include \"defs.h\"\n",
        &[],
    )
    .expect("preprocess");
    assert!(res.macros.iter().any(|m| m.name == b"X"));
}

#[test]
fn cli_define_visible_to_ifdef() {
    let loader = MemLoader::new();
    let out = run(
        b"#ifdef FROM_CLI\nint visible;\n#endif\n",
        &[MacroDef {
            name: b"FROM_CLI".to_vec().into(),
            args: Vec::new(),
            body: Vec::new(),
            is_function_like: false,
        }],
        &loader,
    );
    assert!(String::from_utf8_lossy(&out).contains("visible"));
}

#[test]
fn define_above_ifdef_in_same_file_takes_active_branch() {
    // The kernel evaluates conditionals against the macro snapshot at
    // extract time. Without a host-side re-evaluation, an in-file
    // `#define` that appears above an `#ifdef` does not influence
    // that `#ifdef`'s value. This fixture verifies the host-side
    // re-eval correctly observes the live macro table.
    let loader = MemLoader::new();
    let src = b"#define IN_FILE\n#ifdef IN_FILE\nint visible;\n#endif\nint trailing;\n";
    let out = run(src, &[], &loader);
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("visible"),
        "in-file #define must enable subsequent #ifdef; got {out_str:?}"
    );
    assert!(out_str.contains("trailing"));
}

#[test]
fn undef_above_ifdef_drops_active_branch() {
    // CLI macro defines FOO. Source #undefs it and then `#ifdef FOO`
    // must evaluate to FALSE. Verifies the dedicated gpu_undef_parse
    // kernel actually removes the macro from the live table.
    let loader = MemLoader::new();
    let out = run(
        b"#undef FOO\n#ifdef FOO\nint should_drop;\n#endif\nint after;\n",
        &[MacroDef {
            name: b"FOO".to_vec().into(),
            args: Vec::new(),
            body: Vec::new(),
            is_function_like: false,
        }],
        &loader,
    );
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        !out_str.contains("should_drop"),
        "after #undef FOO, #ifdef FOO must drop body; got {out_str:?}"
    );
    assert!(out_str.contains("after"));
}

#[test]
fn if_expr_uses_live_macro_table() {
    // `#if defined(FOO)` evaluated row-by-row should see `FOO` defined
    // by the in-file `#define` above it.
    let loader = MemLoader::new();
    let src = b"#define FOO\n#if defined(FOO)\nint visible;\n#endif\n";
    let out = run(src, &[], &loader);
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("visible"),
        "live macro table must be visible to subsequent #if; got {out_str:?}"
    );
}

#[test]
fn macro_prefilter_keeps_object_and_function_invocations_distinct() {
    let loader = MemLoader::new();
    let out = run(
        b"#define OBJ 7\n#define FN(x) x\nint a = OBJ;\nint b = FN(3);\nint c = FN;\n",
        &[],
        &loader,
    );
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("7"),
        "object-like macro use must expand after live-use prefilter; got {out_str:?}"
    );
    assert!(
        out_str.contains("3"),
        "function-like call must expand after live-use prefilter; got {out_str:?}"
    );
    assert!(
        out_str.contains("FN"),
        "bare function-like macro identifier must not be treated as an invocation; got {out_str:?}"
    );
}

#[test]
fn macro_expansion_dispatch_consumes_raw_unpadded_byte_arenas() {
    let loader = MemLoader::new();
    let dispatcher = CountingDispatcher::new();
    let active = b"int a = OBJ + FN(alpha);\n";
    let mut src = b"#define OBJ 123\n#define FN(x) x\n".to_vec();
    src.extend_from_slice(active);
    let out =
        gpu_preprocess_translation_unit(&dispatcher, &loader, Path::new("<macro-tu>"), &src, &[])
            .expect("object and function-like macros must expand through GPU materialization");
    let out_str = String::from_utf8_lossy(&out.bytes);
    assert!(
        out_str.contains("123") && out_str.contains("alpha"),
        "macro expansion must preserve object and function-like replacements; got {out_str:?}"
    );
    assert!(
        dispatcher
            .macro_byte_arena_elements
            .borrow()
            .iter()
            .all(|(_, element)| *element == DataType::U8),
        "materialized macro expansion must declare raw U8 input byte arenas"
    );
    assert!(
        dispatcher
            .macro_byte_arena_input_lens("source_words")
            .contains(&active.len()),
        "materialized macro source input must be the raw active segment length {}, got {:?}",
        active.len(),
        dispatcher.macro_byte_arena_input_lens("source_words")
    );
    assert_eq!(
        dispatcher.macro_byte_arena_input_lens("macro_name_words"),
        vec![5],
        "macro names OBJ+FN must dispatch as five raw bytes, not five padded U32 words"
    );
    assert_eq!(
        dispatcher.macro_byte_arena_input_lens("macro_replacement_words"),
        vec![4],
        "replacement bodies 123+x must dispatch as four raw bytes, not four padded U32 words"
    );
}

#[test]
fn variadic_macro_substitutes_va_args_on_gpu_expansion_path() {
    let loader = MemLoader::new();
    let out = run(
        b"#define LOG(fmt, ...) print(fmt, __VA_ARGS__)\nLOG(x, y)\n",
        &[],
        &loader,
    );
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("print"),
        "variadic macro body must be emitted through named GPU expansion; got {out_str:?}"
    );
    assert!(
        out_str.contains("x") && out_str.contains("y"),
        "fixed and variadic arguments must be substituted; got {out_str:?}"
    );
    assert!(
        !out_str.contains("LOG") && !out_str.contains("__VA_ARGS__"),
        "macro invocation and variadic parameter marker must not leak downstream; got {out_str:?}"
    );
}

#[test]
fn gnu_named_variadic_macro_substitutes_named_rest_parameter() {
    let loader = MemLoader::new();
    let out = run(
        b"#define LOG(fmt, rest...) print(fmt, rest)\nLOG(x, y)\n",
        &[],
        &loader,
    );
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("print"),
        "GNU named variadic macro body must be emitted through named GPU expansion; got {out_str:?}"
    );
    assert!(
        out_str.contains("x") && out_str.contains("y"),
        "fixed and named variadic arguments must be substituted; got {out_str:?}"
    );
    assert!(
        !out_str.contains("LOG") && !out_str.contains("rest"),
        "macro invocation and named variadic parameter marker must not leak downstream; got {out_str:?}"
    );
}
