// Integration test module for the containing Vyre package.
#![allow(deprecated)]

use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Duration;

use vyre::ir::{Expr, Program};
use vyre::VyreBackend;
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::parsing::c::lex::tokens::{
    TOK_ASSIGN, TOK_COLON, TOK_COMMA, TOK_IDENTIFIER, TOK_LBRACE, TOK_LBRACKET, TOK_LPAREN,
    TOK_RBRACE, TOK_RBRACKET, TOK_RPAREN, TOK_SEMICOLON, TOK_TYPEDEF,
};
use vyre_libs::parsing::c::lower::{
    c_lower_ast_to_pg_nodes, c_lower_ast_to_pg_semantic_graph, reference_ast_to_pg_nodes,
};
use vyre_libs::parsing::c::parse::vast::{
    c11_annotate_global_typedef_names_fast, c11_annotate_typedef_names,
    c11_annotate_typedef_names_precomputed_scope, c11_build_expression_shape_nodes,
    c11_build_vast_nodes, c11_classify_vast_node_kinds, c11_precompute_vast_scopes,
    c11_prehash_vast_identifiers, reference_c11_annotate_typedef_names,
    reference_c11_build_vast_nodes, reference_c11_classify_vast_node_kinds,
};
use vyre_libs::parsing::c::sema::c_sema_scope;

pub(crate) const VAST_STRIDE_U32: usize = 10;
pub(crate) const PG_STRIDE_U32: usize = 6;
const VAST_STRIDE_BYTES: usize = VAST_STRIDE_U32 * core::mem::size_of::<u32>();
const VAST_TYPEDEF_SYMBOL_FIELD: usize = 9;

mod common;
pub(crate) use common::c_fixture::*;

pub(crate) fn row_indices(rows: &[u8], kind: u32) -> Vec<usize> {
    row_indices_by_stride(rows, VAST_STRIDE_U32, kind)
}

pub(crate) fn row_indices_by_stride(rows: &[u8], stride_words: usize, kind: u32) -> Vec<usize> {
    rows.chunks_exact(stride_words * core::mem::size_of::<u32>())
        .enumerate()
        .filter_map(|(idx, row)| {
            let row_kind = u32::from_le_bytes(row[0..4].try_into().unwrap());
            (row_kind == kind).then_some(idx)
        })
        .collect()
}

pub(crate) fn assert_full_pipeline_parity(fix: &Fixture, label: &str) {
    let raw_cpu = reference_c11_build_vast_nodes(&fix.tok_types, &fix.tok_starts, &fix.tok_lens);
    let raw_gpu = run_gpu_vast_builder(fix);
    assert_words_eq(
        &raw_gpu,
        &raw_cpu,
        &format!("{label}: raw VAST GPU/CPU parity"),
    );

    let annotated_cpu = reference_c11_annotate_typedef_names(&raw_cpu, fix.source.as_bytes());
    let annotated_gpu = run_gpu_typedef_annotation(fix, &raw_gpu);
    assert_words_eq(
        &annotated_gpu,
        &annotated_cpu,
        &format!("{label}: annotated VAST GPU/CPU parity"),
    );

    let typed_cpu = reference_c11_classify_vast_node_kinds(&annotated_cpu);
    let typed_gpu = run_gpu_classifier(&annotated_gpu);
    assert_words_eq(
        &typed_gpu,
        &typed_cpu,
        &format!("{label}: typed VAST GPU/CPU parity"),
    );
}

pub(crate) fn classify(fix: &Fixture) -> Vec<u8> {
    let raw = reference_c11_build_vast_nodes(&fix.tok_types, &fix.tok_starts, &fix.tok_lens);
    let annotated = reference_c11_annotate_typedef_names(&raw, fix.source.as_bytes());
    reference_c11_classify_vast_node_kinds(&annotated)
}

pub(crate) fn lexeme_indices(fix: &Fixture, lexeme: &str) -> Vec<usize> {
    fix.tok_starts
        .iter()
        .zip(&fix.tok_lens)
        .enumerate()
        .filter_map(|(idx, (start, len))| {
            let start = *start as usize;
            let end = start.saturating_add(*len as usize);
            (fix.source.as_bytes().get(start..end) == Some(lexeme.as_bytes())).then_some(idx)
        })
        .collect()
}

pub(crate) fn token_indices_containing(fix: &Fixture, needle: &str) -> Vec<usize> {
    fix.tok_starts
        .iter()
        .zip(&fix.tok_lens)
        .enumerate()
        .filter_map(|(idx, (start, len))| {
            let start = *start as usize;
            let end = start.saturating_add(*len as usize);
            let token = fix.source.as_bytes().get(start..end)?;
            token
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
                .then_some(idx)
        })
        .collect()
}

fn bytes(words: &[u32]) -> Vec<u8> {
    vyre_primitives::wire::pack_u32_slice(words)
}

pub(crate) fn starts_for_lens(lens: &[u32]) -> Vec<u32> {
    let mut cursor = 0u32;
    lens.iter()
        .map(|len| {
            let start = cursor;
            cursor = cursor.saturating_add(*len).saturating_add(1);
            start
        })
        .collect()
}

pub(crate) fn word_at(buf: &[u8], word: usize) -> u32 {
    let off = word * 4;
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

pub(crate) fn pg_word_at(buf: &[u8], idx: usize, field: usize) -> u32 {
    word_at(buf, idx * PG_STRIDE_U32 + field)
}

pub(crate) fn kind_at(rows: &[u8], idx: usize) -> u32 {
    word_at(rows, idx * VAST_STRIDE_U32)
}

pub(crate) fn assert_pg_preserves_row(
    typed_vast: &[u8],
    pg: &[u8],
    tok_starts: &[u32],
    tok_lens: &[u32],
    idx: usize,
    expected_kind: u32,
) {
    assert_eq!(
        pg_word_at(pg, idx, 0),
        expected_kind,
        "PG kind mismatch at row {idx}"
    );
    assert_eq!(
        pg_word_at(pg, idx, 1),
        tok_starts[idx],
        "PG span_start mismatch at row {idx}"
    );
    assert_eq!(
        pg_word_at(pg, idx, 2),
        tok_starts[idx] + tok_lens[idx],
        "PG span_end mismatch at row {idx}"
    );
    assert_eq!(
        pg_word_at(pg, idx, 3),
        word_at(typed_vast, idx * VAST_STRIDE_U32 + 1),
        "PG parent mismatch at row {idx}"
    );
    assert_eq!(
        pg_word_at(pg, idx, 4),
        word_at(typed_vast, idx * VAST_STRIDE_U32 + 2),
        "PG first_child mismatch at row {idx}"
    );
    assert_eq!(
        pg_word_at(pg, idx, 5),
        word_at(typed_vast, idx * VAST_STRIDE_U32 + 3),
        "PG next_sibling mismatch at row {idx}"
    );
}

pub(crate) fn assert_gpu_pg_parity(fix: &Fixture, typed_vast: &[u8], label: &str) {
    let node_count = node_count_from_vast(typed_vast);
    let cpu_pg = reference_ast_to_pg_nodes(typed_vast);
    let gpu_pg = run_gpu_pg_lower_with_count(typed_vast, node_count);
    assert_eq!(
        gpu_pg,
        cpu_pg,
        "{label}: GPU PG lower output diverged from reference for {} bytes",
        fix.source.len()
    );
}

pub(crate) fn node_count_from_vast(buf: &[u8]) -> u32 {
    u32::try_from(buf.len() / VAST_STRIDE_BYTES).unwrap_or_default()
}

fn possible_declarator_follower(kind: u32) -> bool {
    matches!(
        kind,
        TOK_SEMICOLON
            | TOK_COMMA
            | TOK_ASSIGN
            | TOK_LPAREN
            | TOK_LBRACKET
            | TOK_COLON
            | TOK_RPAREN
            | TOK_RBRACKET
    )
}

fn global_typedef_hashes_from_hashed_vast(hashed_vast: &[u8]) -> Vec<u32> {
    let rows = hashed_vast.len() / VAST_STRIDE_BYTES;
    let mut hashes = Vec::new();
    let mut in_typedef_decl = false;
    let mut typedef_brace_depth = 0u32;
    for row in 0..rows {
        let kind = word_at(hashed_vast, row * VAST_STRIDE_U32);
        if kind == TOK_TYPEDEF {
            in_typedef_decl = true;
            typedef_brace_depth = 0;
            continue;
        }
        if in_typedef_decl && kind == TOK_LBRACE {
            typedef_brace_depth = typedef_brace_depth.saturating_add(1);
            continue;
        }
        if in_typedef_decl && kind == TOK_RBRACE {
            typedef_brace_depth = typedef_brace_depth.saturating_sub(1);
            continue;
        }
        if in_typedef_decl && kind == TOK_IDENTIFIER {
            let next_kind = if row + 1 < rows {
                word_at(hashed_vast, (row + 1) * VAST_STRIDE_U32)
            } else {
                TOK_SEMICOLON
            };
            if typedef_brace_depth == 0 && possible_declarator_follower(next_kind) {
                let hash = word_at(
                    hashed_vast,
                    row * VAST_STRIDE_U32 + VAST_TYPEDEF_SYMBOL_FIELD,
                );
                if hash != 0 && !hashes.contains(&hash) {
                    hashes.push(hash);
                }
            }
        }
        if in_typedef_decl && typedef_brace_depth == 0 && kind == TOK_SEMICOLON {
            in_typedef_decl = false;
        }
    }
    if hashes.is_empty() {
        hashes.push(0);
    }
    hashes
}

pub(crate) fn assert_words_eq(actual: &[u8], expected: &[u8], context: &str) {
    if actual == expected {
        return;
    }
    let limit = (actual.len() / 4).min(expected.len() / 4);
    for w in 0..limit {
        let a = word_at(actual, w);
        let e = word_at(expected, w);
        if a != e {
            let row = w / VAST_STRIDE_U32;
            let actual_row: Vec<u32> = (0..VAST_STRIDE_U32)
                .map(|field| word_at(actual, row * VAST_STRIDE_U32 + field))
                .collect();
            let expected_row: Vec<u32> = (0..VAST_STRIDE_U32)
                .map(|field| word_at(expected, row * VAST_STRIDE_U32 + field))
                .collect();
            let nearby_start = row.saturating_sub(3);
            let nearby_end = (row + 4).min(limit / VAST_STRIDE_U32);
            let nearby_actual: Vec<Vec<u32>> = (nearby_start..nearby_end)
                .map(|nearby_row| {
                    (0..VAST_STRIDE_U32)
                        .map(|field| word_at(actual, nearby_row * VAST_STRIDE_U32 + field))
                        .collect()
                })
                .collect();
            panic!(
                "{context}: word {w} differs (row={row}, field={}): actual={a}, expected={e}; actual_row={actual_row:?}; expected_row={expected_row:?}; nearby_actual_start={nearby_start}; nearby_actual={nearby_actual:?}",
                w % VAST_STRIDE_U32
            );
        }
    }
    panic!(
        "{context}: byte lengths differ: actual={}, expected={}",
        actual.len(),
        expected.len()
    );
}

pub(crate) fn gpu_backend() -> &'static WgpuBackend {
    static BACKEND: OnceLock<WgpuBackend> = OnceLock::new();
    BACKEND.get_or_init(|| {
        WgpuBackend::acquire().expect(
            "WgpuBackend::acquire failed on a machine that must have a GPU. \
             This is a configuration bug, not a graceful skip.",
        )
    })
}

pub(crate) fn dispatch_gpu_program(
    context: &'static str,
    program: Program,
    inputs: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    static DISPATCH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = DISPATCH_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let input_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        let result = gpu_backend()
            .dispatch_borrowed(&program, &input_refs, &Default::default())
            .map_err(|err| format!("{err:?}"));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(90)) {
        Ok(Ok(outputs)) => outputs,
        Ok(Err(err)) => panic!("{context}: GPU dispatch failed: {err}"),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "{context}: GPU dispatch exceeded 90s. Fix: inspect WGPU device acquisition, shader compilation, and queue completion; C parser GPU parity must fail loudly, not hang."
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{context}: GPU dispatch worker terminated before returning outputs")
        }
    }
}

fn primary_output_with_optional_empty_scratch(outputs: Vec<Vec<u8>>, context: &str) -> Vec<u8> {
    assert!(
        !outputs.is_empty(),
        "{context}: expected at least one primary GPU output"
    );
    assert!(
        outputs.iter().skip(1).all(Vec::is_empty),
        "{context}: only zero-byte scratch outputs may follow the primary output"
    );
    outputs[0].clone()
}

pub(crate) fn run_gpu_vast_builder_from_parts(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
) -> Vec<u8> {
    let program = c11_build_vast_nodes(
        "tok_types",
        "tok_starts",
        "tok_lens",
        Expr::u32(tok_types.len() as u32),
        "out_vast_nodes",
        "out_count",
    );
    let tok_type_bytes = bytes(tok_types);
    let tok_start_bytes = bytes(tok_starts);
    let tok_len_bytes = bytes(tok_lens);
    let outputs = dispatch_gpu_program(
        "GPU C VAST builder",
        program,
        vec![tok_type_bytes, tok_start_bytes, tok_len_bytes],
    );
    assert_eq!(outputs.len(), 2, "expected [vast_nodes, count]");
    outputs[0].clone()
}

fn run_gpu_vast_builder(fix: &Fixture) -> Vec<u8> {
    run_gpu_vast_builder_from_parts(&fix.tok_types, &fix.tok_starts, &fix.tok_lens)
}

fn haystack_words(bytes: &[u8]) -> Vec<u8> {
    vyre_primitives::wire::pack_bytes_as_u32_slice(bytes)
}

pub(crate) fn run_gpu_full_typedef_annotation(source: &[u8], raw_vast: &[u8]) -> Vec<u8> {
    let haystack = haystack_words(source);
    let program = c11_annotate_typedef_names(
        "vast_nodes",
        "haystack",
        Expr::u32(source.len() as u32),
        Expr::u32(node_count_from_vast(raw_vast)),
        "annotated_vast",
    );
    let inputs: Vec<&[u8]> = vec![raw_vast, &haystack];
    let outputs = gpu_backend()
        .dispatch_borrowed(&program, &inputs, &Default::default())
        .expect("GPU full typedef annotation dispatch must succeed");
    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}

pub(crate) fn run_gpu_fast_typedef_annotation(source: &[u8], raw_vast: &[u8]) -> Vec<u8> {
    let haystack = haystack_words(source);
    let node_count_value = node_count_from_vast(raw_vast);
    let node_count = Expr::u32(node_count_value);
    let hashed_program = c11_prehash_vast_identifiers(
        "vast_nodes",
        "haystack",
        Expr::u32(source.len() as u32),
        node_count.clone(),
        "hashed_vast",
    );
    let hashed = dispatch_gpu_program(
        "GPU typedef prehash",
        hashed_program,
        vec![raw_vast.to_vec(), haystack.clone(), raw_vast.to_vec()],
    );
    assert_eq!(hashed.len(), 1);

    let scoped_program =
        c11_precompute_vast_scopes("hashed_vast", node_count.clone(), "scoped_vast");
    let scope_stack = vec![0u8; node_count_value.max(1) as usize * core::mem::size_of::<u32>()];
    let scoped = dispatch_gpu_program(
        "GPU typedef scope precompute",
        scoped_program,
        vec![hashed[0].clone(), hashed[0].clone(), scope_stack],
    );
    let scoped_vast =
        primary_output_with_optional_empty_scratch(scoped, "GPU typedef scope precompute");

    let typedef_hashes = global_typedef_hashes_from_hashed_vast(&scoped_vast);
    let typedef_hash_bytes = bytes(&typedef_hashes);
    let program = c11_annotate_global_typedef_names_fast(
        "vast_nodes",
        "global_typedef_hashes",
        node_count,
        Expr::u32(typedef_hashes.len() as u32),
        "annotated_vast",
    );
    let outputs = dispatch_gpu_program(
        "GPU typedef annotation",
        program,
        vec![scoped_vast.clone(), typedef_hash_bytes, scoped_vast],
    );
    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}

pub(crate) fn run_gpu_scoped_typedef_annotation(source: &[u8], raw_vast: &[u8]) -> Vec<u8> {
    let haystack = haystack_words(source);
    let node_count_value = node_count_from_vast(raw_vast);
    let node_count = Expr::u32(node_count_value);
    let hashed_program = c11_prehash_vast_identifiers(
        "vast_nodes",
        "haystack",
        Expr::u32(source.len() as u32),
        node_count.clone(),
        "hashed_vast",
    );
    let hashed = dispatch_gpu_program(
        "GPU scoped typedef prehash",
        hashed_program,
        vec![raw_vast.to_vec(), haystack.clone(), raw_vast.to_vec()],
    );
    assert_eq!(hashed.len(), 1);

    let scoped_program =
        c11_precompute_vast_scopes("hashed_vast", node_count.clone(), "scoped_vast");
    let scope_stack = vec![0u8; node_count_value.max(1) as usize * core::mem::size_of::<u32>()];
    let scoped = dispatch_gpu_program(
        "GPU scoped typedef scope precompute",
        scoped_program,
        vec![hashed[0].clone(), hashed[0].clone(), scope_stack],
    );
    let scoped_vast =
        primary_output_with_optional_empty_scratch(scoped, "GPU scoped typedef scope precompute");

    let program = c11_annotate_typedef_names_precomputed_scope(
        "vast_nodes",
        "haystack",
        Expr::u32(source.len() as u32),
        node_count,
        "annotated_vast",
    );
    let outputs = dispatch_gpu_program(
        "GPU scoped typedef annotation",
        program,
        vec![scoped_vast, haystack],
    );
    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}

fn run_gpu_typedef_annotation(fix: &Fixture, raw_vast: &[u8]) -> Vec<u8> {
    run_gpu_fast_typedef_annotation(fix.source.as_bytes(), raw_vast)
}

pub(crate) fn run_gpu_classifier(annotated_vast: &[u8]) -> Vec<u8> {
    run_gpu_classifier_with_count(annotated_vast, node_count_from_vast(annotated_vast))
}

pub(crate) fn run_gpu_classifier_with_count(annotated_vast: &[u8], num_nodes: u32) -> Vec<u8> {
    let program =
        c11_classify_vast_node_kinds("vast_nodes", Expr::u32(num_nodes), "typed_vast_nodes");
    let outputs = dispatch_gpu_program(
        "GPU VAST classifier",
        program,
        vec![annotated_vast.to_vec()],
    );
    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}

pub(crate) fn run_gpu_expr_shape(raw_vast: &[u8], typed_vast: &[u8]) -> Vec<u8> {
    let program = c11_build_expression_shape_nodes(
        "raw_vast_nodes",
        "typed_vast_nodes",
        Expr::u32(node_count_from_vast(raw_vast)),
        "expr_shape_nodes",
    );
    let outputs = dispatch_gpu_program(
        "GPU expression-shape lower",
        program,
        vec![raw_vast.to_vec(), typed_vast.to_vec()],
    );

    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}

pub(crate) fn run_gpu_pg_lower(typed_vast: &[u8]) -> Vec<u8> {
    run_gpu_pg_lower_with_count(typed_vast, node_count_from_vast(typed_vast))
}

pub(crate) fn run_gpu_pg_lower_with_count(typed_vast: &[u8], num_nodes: u32) -> Vec<u8> {
    let program = c_lower_ast_to_pg_nodes("vast_nodes", Expr::u32(num_nodes), "out_pg_nodes");
    let outputs = dispatch_gpu_program("GPU AST-to-PG lower", program, vec![typed_vast.to_vec()]);
    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}

pub(crate) fn run_gpu_semantic_pg_lower(typed_vast: &[u8]) -> (Vec<u8>, Vec<u8>) {
    run_gpu_semantic_pg_lower_with_count(typed_vast, node_count_from_vast(typed_vast))
}

pub(crate) fn run_gpu_semantic_pg_lower_with_count(
    typed_vast: &[u8],
    num_nodes: u32,
) -> (Vec<u8>, Vec<u8>) {
    let program = c_lower_ast_to_pg_semantic_graph(
        "vast_nodes",
        Expr::u32(num_nodes),
        "out_pg_nodes",
        "out_pg_edges",
    );
    let outputs = dispatch_gpu_program(
        "GPU semantic AST-to-PG lower",
        program,
        vec![typed_vast.to_vec()],
    );
    assert_eq!(outputs.len(), 2);
    (outputs[0].clone(), outputs[1].clone())
}

pub(crate) fn run_gpu_c_sema_scope_from_parts(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
    haystack: &[u8],
) -> Vec<u8> {
    let program = c_sema_scope(
        "tok_types",
        "tok_starts",
        "tok_lens",
        "haystack",
        Expr::u32(haystack.len() as u32),
        Expr::u32(tok_types.len() as u32),
        "out_scope_tree",
    );
    let tok_type_bytes = bytes(tok_types);
    let tok_start_bytes = bytes(tok_starts);
    let tok_len_bytes = bytes(tok_lens);
    let haystack_bytes = haystack_words(haystack);
    let outputs = dispatch_gpu_program(
        "GPU C semantic scope",
        program,
        vec![
            tok_type_bytes,
            tok_start_bytes,
            tok_len_bytes,
            haystack_bytes,
        ],
    );
    assert_eq!(outputs.len(), 1);
    outputs[0].clone()
}
