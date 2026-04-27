//! End-to-end GPU C11 compilation: lex → digraphs → preproc → brackets → structure → ABI → AST → CFG → ELF.
//!
//! Host work: I/O, buffer packing, `VYRECOB2` emission, Linux ET_REL wrapper.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use vyre::ir::Expr;
use vyre::DispatchConfig;
use vyre::VyreBackend;
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::compiler::cfg::c11_build_cfg_and_gotos;
use vyre_libs::compiler::types_layout::c11_compute_alignments;
use vyre_libs::parsing::c::lex::keyword::{c_keyword, c_keyword_map_words, C_KEYWORDS};
use vyre_libs::parsing::c::lex::lexer::{c11_lex_digraphs, c11_lexer};
use vyre_libs::parsing::c::lex::tokens::{TOK_LBRACE, TOK_LPAREN, TOK_RBRACE, TOK_RPAREN};
use vyre_libs::parsing::c::parse::structure::{c11_extract_calls, c11_extract_functions};
use vyre_libs::parsing::c::pipeline::stages::C11_AST_MAX_TOK_SCAN;
use vyre_libs::parsing::c::preprocess::expansion::opt_conditional_mask;
use vyre_libs::parsing::core::ast::shunting::ast_shunting_yard;

use crate::api::VyreCompileOptions;
use crate::object_format::SectionTag;

mod buffers;
mod dispatch;
mod sema;
mod vast_pg;

use buffers::{
    build_ast_inputs, c11_statement_bounds_host, c_abi_type_table_bytes, cfg_ssa_words_from_vast,
    compiler_words_from_sections, map_bracket_kind, megakernel_section_bytes, pack_haystack,
    pad_tok_scan, read_u32_at, reject_c11_lexer_diagnostics, token_types_from_lex,
    u32_prefix_bytes, vec_u32_le_bytes,
};
use dispatch::{dispatch_bracket_match, try_dispatch_elf};
use sema::build_sema_scope;
use vast_pg::build_vast_and_pg;

const BRACKET_MAX_DEPTH: u32 = 4096;
/// Must match `ast_shunting_yard` / `vyre_libs::parsing::c::pipeline::stages::C11_AST_MAX_TOK_SCAN`.
const MAX_TOK_SCAN: u32 = C11_AST_MAX_TOK_SCAN;
/// `ast_shunting_yard` workgroup uses one lane per statement (see `vyre-libs`).
const MAX_STMT_THREADS: u32 = 256;
/// `opt_lower_elf` writes into a 4096-word object buffer with 64 words reserved
/// for ELF headers and 5 words for `.shstrtab` payload.
const ELF_LOWERING_MAX_INPUT_WORDS: usize = 4096 - 64 - 5;

/// One translation unit: GPU pipeline + ELF object at `dest`.
fn compile_translation_unit(
    backend: &WgpuBackend,
    path: &Path,
    dest: &Path,
    options: &VyreCompileOptions,
) -> Result<(), String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext != "c" && ext != "h" {
        return Err(format!(
            "vyre-cc: expected .c or .h (got {ext:?} on {}).",
            path.display()
        ));
    }

    let raw_bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let raw = String::from_utf8_lossy(&raw_bytes);
    let source = crate::tu_host::prepare_resident_translation_unit_source(path, &raw, options)?;
    let (haystack_bytes, haystack_len) = pack_haystack(&source);

    // --- A: lexer ---
    let lex_prog = c11_lexer(
        "haystack",
        "out_tok_types",
        "out_tok_starts",
        "out_tok_lens",
        "out_counts",
        haystack_len,
    );
    let lex_errors = vyre::validate(&lex_prog);
    if !lex_errors.is_empty() {
        return Err(format!("c11_lexer IR validation failed: {lex_errors:?}"));
    }
    let lex_in = vec![haystack_bytes.clone()];
    let mut dcfg = DispatchConfig::default();
    dcfg.label = Some(format!("vyre-cc lex {}", path.display()));
    let lex_out = backend
        .dispatch(&lex_prog, &lex_in, &dcfg)
        .map_err(|e| format!("c11_lexer dispatch failed: {e}"))?;
    if lex_out.len() < 4 {
        return Err("lexer: expected 4 output buffers".to_string());
    }
    let mut types = lex_out[0].clone();
    let mut starts = lex_out[1].clone();
    let mut lens = lex_out[2].clone();
    let n_tokens = read_u32_at(&lex_out[3], 0).map_err(|e| format!("lexer count: {e}"))?;

    // --- B: digraph / trigraph-style token rewriting ---
    let dig = c11_lex_digraphs("tok_types", "tok_starts", "tok_lens", haystack_len);
    if !vyre::validate(&dig).is_empty() {
        return Err("c11_lex_digraphs IR validation failed".to_string());
    }
    dcfg.label = Some(format!("vyre-cc digraph {}", path.display()));
    let dig_out = backend
        .dispatch(&dig, &[types.clone(), starts.clone(), lens.clone()], &dcfg)
        .map_err(|e| format!("c11_lex_digraphs dispatch failed: {e}"))?;
    if dig_out.len() >= 3 {
        types = dig_out[0].clone();
        starts = dig_out[1].clone();
        lens = dig_out[2].clone();
    }

    // --- B2: keyword promotion ---
    let keyword_map_words = c_keyword_map_words();
    let keyword_map_bytes = vec_u32_le_bytes(&keyword_map_words);
    let keyword_prog = c_keyword(
        "tok_types",
        "tok_starts",
        "tok_lens",
        "counts",
        "haystack",
        "keyword_map",
        haystack_len.max(1),
        C_KEYWORDS.len() as u32,
        haystack_len.max(1),
    );
    if !vyre::validate(&keyword_prog).is_empty() {
        return Err("c_keyword IR validation failed".to_string());
    }
    dcfg.label = Some(format!("vyre-cc keyword {}", path.display()));
    let keyword_out = backend
        .dispatch_borrowed(
            &keyword_prog,
            &[
                &types,
                &starts,
                &lens,
                &lex_out[3],
                &haystack_bytes,
                &keyword_map_bytes,
            ],
            &dcfg,
        )
        .map_err(|e| format!("c_keyword dispatch failed: {e}"))?;
    if let Some(keyworded_types) = keyword_out.first() {
        types = keyworded_types.clone();
    }

    let tok_types = token_types_from_lex(&types, n_tokens)?;
    let starts_logical = u32_prefix_bytes(&starts, n_tokens, "token starts")?;
    let lens_logical = u32_prefix_bytes(&lens, n_tokens, "token lengths")?;
    reject_c11_lexer_diagnostics(path, &tok_types, &starts_logical, &lens_logical)?;

    // --- C: conditional preprocessor mask for the resident token stream ---
    let mask_prog = opt_conditional_mask("tok_types", "mask", Expr::u32(n_tokens.max(1)));
    if !vyre::validate(&mask_prog).is_empty() {
        return Err("opt_conditional_mask IR validation failed".to_string());
    }
    let types_logical = u32_prefix_bytes(&types, n_tokens.max(1), "preprocessor token types")?;
    dcfg.label = Some(format!("vyre-cc cpp-mask {}", path.display()));
    let mask_out = backend
        .dispatch(&mask_prog, &[types_logical.clone()], &dcfg)
        .map_err(|e| format!("opt_conditional_mask dispatch failed: {e}"))?;
    let preproc_mask = mask_out.first().cloned().unwrap_or_default();

    // --- D: macro-token snapshot ---
    // Includes and CLI defines have been converted into one resident source stream; macro,
    // conditional, and directive semantics stay in GPU-visible token/preprocessor lanes.

    let types_logical = vec_u32_le_bytes(&tok_types);
    let macro_types_snapshot = types_logical.clone();
    let kinds_paren: Vec<u32> = tok_types
        .iter()
        .map(|&t| map_bracket_kind(t, TOK_LPAREN, TOK_RPAREN))
        .collect();
    let kinds_brace: Vec<u32> = tok_types
        .iter()
        .map(|&t| map_bracket_kind(t, TOK_LBRACE, TOK_RBRACE))
        .collect();

    let paren_pairs = dispatch_bracket_match(
        backend,
        &kinds_paren,
        &format!("vyre-cc paren {}", path.display()),
    )?;
    let brace_pairs = dispatch_bracket_match(
        backend,
        &kinds_brace,
        &format!("vyre-cc brace {}", path.display()),
    )?;

    let nt = n_tokens.max(1);
    let fn_prog = c11_extract_functions(
        "tok_types",
        "paren_pairs",
        "brace_pairs",
        Expr::u32(nt),
        "out_functions",
        "out_counts",
    );
    if !vyre::validate(&fn_prog).is_empty() {
        return Err("c11_extract_functions IR validation failed".to_string());
    }
    let fn_in = vec![
        types_logical.clone(),
        vec_u32_le_bytes(&paren_pairs),
        vec_u32_le_bytes(&brace_pairs),
    ];
    dcfg.label = Some(format!("vyre-cc functions {}", path.display()));
    let fn_out = backend
        .dispatch(&fn_prog, &fn_in, &dcfg)
        .map_err(|e| format!("c11_extract_functions dispatch failed: {e}"))?;
    if fn_out.len() < 2 {
        return Err("extract_functions: expected 2 outputs".to_string());
    }
    let fn_records = &fn_out[0];
    let fn_slot_count = read_u32_at(&fn_out[1], 0).map_err(|e| format!("function count: {e}"))?;
    let n_fn = (fn_slot_count / 3).max(1);

    let call_prog = c11_extract_calls(
        "tok_types",
        "paren_pairs",
        "functions",
        Expr::u32(nt),
        Expr::u32(n_fn),
        "out_calls",
        "out_counts",
    );
    if !vyre::validate(&call_prog).is_empty() {
        return Err("c11_extract_calls IR validation failed".to_string());
    }
    let fn_words = (n_fn * 3).max(3) as usize;
    let mut fn_buf = vec![0u8; fn_words * 4];
    let copy_len = fn_records.len().min(fn_buf.len());
    fn_buf[..copy_len].copy_from_slice(&fn_records[..copy_len]);

    let call_in = vec![
        types_logical.clone(),
        vec_u32_le_bytes(&paren_pairs),
        fn_buf,
    ];
    dcfg.label = Some(format!("vyre-cc calls {}", path.display()));
    let call_out = backend
        .dispatch(&call_prog, &call_in, &dcfg)
        .map_err(|e| format!("c11_extract_calls dispatch failed: {e}"))?;
    if call_out.is_empty() {
        return Err("extract_calls: no outputs".to_string());
    }

    // --- ABI layout ---
    let type_defs = c_abi_type_table_bytes(&tok_types);
    let type_count = u32::try_from(type_defs.len() / 4)
        .map_err(|_| "ABI type table exceeds u32 count".to_string())?
        .max(1);
    let align_prog = c11_compute_alignments("types", "sizes", "aligns", Expr::u32(type_count));
    if !vyre::validate(&align_prog).is_empty() {
        return Err("c11_compute_alignments IR validation failed".to_string());
    }
    let sz_init = vec![0u8; type_count as usize * 4];
    let al_init = vec![0u8; type_count as usize * 4];
    let mut abi_blob = Vec::new();
    dcfg.label = Some(format!("vyre-cc abi {}", path.display()));
    let abi_out = backend
        .dispatch(&align_prog, &[type_defs, sz_init, al_init], &dcfg)
        .map_err(|e| format!("c11_compute_alignments dispatch failed: {e}"))?;
    if abi_out.len() < 2 {
        return Err("c11_compute_alignments: expected sizes and alignments outputs".to_string());
    }
    abi_blob.extend_from_slice(&abi_out[0]);
    abi_blob.extend_from_slice(&abi_out[1]);

    let (stmt_pairs, num_stmt) = c11_statement_bounds_host(&tok_types, nt);
    let stmt_bytes = vec_u32_le_bytes(&stmt_pairs);
    let tok_pad = pad_tok_scan(tok_types.clone());
    let ast_prog = ast_shunting_yard(
        "tok_types",
        "statements",
        Expr::u32(num_stmt),
        "out_ast_nodes",
        "out_ast_count",
        "out_statement_roots",
        "scratch_val_stack",
        "scratch_op_stack",
    );
    let mut ast_blob = Vec::new();
    if !vyre::validate(&ast_prog).is_empty() {
        return Err("ast_shunting_yard IR validation failed".to_string());
    }
    let ast_in = build_ast_inputs(&tok_pad, &stmt_bytes, num_stmt);
    dcfg.label = Some(format!("vyre-cc ast {}", path.display()));
    let ast_out = backend
        .dispatch(&ast_prog, &ast_in, &dcfg)
        .map_err(|e| format!("ast_shunting_yard dispatch failed: {e}"))?;
    if ast_out.is_empty() {
        return Err("ast_shunting_yard: expected output buffers".to_string());
    }
    for chunk in ast_out {
        ast_blob.extend_from_slice(&chunk);
    }

    let (vast_blob, expr_shape_blob, pg_blob, semantic_pg_nodes, semantic_pg_edges) =
        build_vast_and_pg(
            backend,
            path,
            &tok_types,
            &starts_logical,
            &lens_logical,
            &haystack_bytes,
            haystack_len,
            nt,
        )?;
    let sema_blob = build_sema_scope(
        backend,
        path,
        &tok_types,
        &starts_logical,
        &lens_logical,
        &haystack_bytes,
        haystack_len,
        nt,
    )?;

    // --- CFG / goto ---
    let cfg_ssa = cfg_ssa_words_from_vast(&vast_blob)?;
    let n_ssa = u32::try_from(cfg_ssa.len())
        .map_err(|_| "CFG SSA stream exceeds u32 count".to_string())?
        .max(1);
    let ssa_buf = vec_u32_le_bytes(&cfg_ssa);
    let cfg_prog = c11_build_cfg_and_gotos("ssa", "cfg", "labels", Expr::u32(n_ssa));
    let mut cfg_blob = Vec::new();
    if !vyre::validate(&cfg_prog).is_empty() {
        return Err("c11_build_cfg_and_gotos IR validation failed".to_string());
    }
    let cfg_init = vec![0u8; n_ssa as usize * 4];
    let lbl_init = vec![0u8; n_ssa as usize * 4];
    let k_init = vec![0u8; 4096 * 4];
    let v_init = vec![0u8; 4096 * 4];
    dcfg.label = Some(format!("vyre-cc cfg {}", path.display()));
    let cfg_out = backend
        .dispatch(
            &cfg_prog,
            &[ssa_buf, cfg_init, lbl_init, k_init, v_init],
            &dcfg,
        )
        .map_err(|e| format!("c11_build_cfg_and_gotos dispatch failed: {e}"))?;
    if cfg_out.is_empty() {
        return Err("c11_build_cfg_and_gotos: expected output buffers".to_string());
    }
    for chunk in cfg_out {
        cfg_blob.extend_from_slice(&chunk);
    }

    let compiler_words = compiler_words_from_sections(
        &[
            vast_blob.as_slice(),
            pg_blob.as_slice(),
            semantic_pg_nodes.as_slice(),
            semantic_pg_edges.as_slice(),
        ],
        ELF_LOWERING_MAX_INPUT_WORDS,
    )?;
    let elf_blob = try_dispatch_elf(backend, &compiler_words)?;

    let lex_section = crate::object_format::build_vyrecob1_lex_section(
        path,
        &types_logical,
        &starts_logical,
        &lens_logical,
        n_tokens,
    )?;

    let paren_bytes = vec_u32_le_bytes(&paren_pairs);
    let brace_bytes = vec_u32_le_bytes(&brace_pairs);
    let cfg_word_count = u32::try_from(cfg_blob.len() / 4)
        .map_err(|_| "CFG section exceeds u32 count".to_string())?;
    let section_tags = [
        SectionTag::Lex as u32,
        SectionTag::ParenPairs as u32,
        SectionTag::BracePairs as u32,
        SectionTag::Functions as u32,
        SectionTag::Calls as u32,
        SectionTag::Elf as u32,
        SectionTag::PreprocMask as u32,
        SectionTag::MacroTypes as u32,
        SectionTag::AbiLayout as u32,
        SectionTag::Ast as u32,
        SectionTag::Cfg as u32,
        SectionTag::Megakernel as u32,
        SectionTag::Vast as u32,
        SectionTag::ProgramGraph as u32,
        SectionTag::SemaScope as u32,
        SectionTag::ExpressionShape as u32,
        SectionTag::SemanticProgramGraphNodes as u32,
        SectionTag::SemanticProgramGraphEdges as u32,
    ];
    let mega_bytes = megakernel_section_bytes(n_tokens, n_fn, cfg_word_count, &section_tags);
    let sections: Vec<(SectionTag, &[u8])> = vec![
        (SectionTag::Lex, lex_section.as_slice()),
        (SectionTag::ParenPairs, paren_bytes.as_slice()),
        (SectionTag::BracePairs, brace_bytes.as_slice()),
        (SectionTag::Functions, fn_records.as_slice()),
        (SectionTag::Calls, call_out[0].as_slice()),
        (SectionTag::Elf, elf_blob.as_slice()),
        (SectionTag::PreprocMask, preproc_mask.as_slice()),
        (SectionTag::MacroTypes, macro_types_snapshot.as_slice()),
        (SectionTag::AbiLayout, abi_blob.as_slice()),
        (SectionTag::Ast, ast_blob.as_slice()),
        (SectionTag::Cfg, cfg_blob.as_slice()),
        (SectionTag::Megakernel, mega_bytes.as_slice()),
        (SectionTag::Vast, vast_blob.as_slice()),
        (SectionTag::ProgramGraph, pg_blob.as_slice()),
        (SectionTag::SemaScope, sema_blob.as_slice()),
        (SectionTag::ExpressionShape, expr_shape_blob.as_slice()),
        (
            SectionTag::SemanticProgramGraphNodes,
            semantic_pg_nodes.as_slice(),
        ),
        (
            SectionTag::SemanticProgramGraphEdges,
            semantic_pg_edges.as_slice(),
        ),
    ];
    let vyrecob2 = crate::object_format::serialize_vyrecob2(&sections);
    let elf_obj = crate::elf_linux::emit_translation_unit_relocatable(&vyrecob2, path)?;
    fs::write(dest, elf_obj).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(())
}

/// Full GPU pipeline for one or more translation units; writes **ELF64 ET_REL** per TU.
pub fn compile_c11_sources(options: &VyreCompileOptions) -> Result<(), String> {
    let backend = WgpuBackend::acquire().map_err(|e| {
        format!("wgpu backend unavailable: {e}. Fix: use a machine with a supported GPU stack.")
    })?;

    if options.output_file.is_some() && options.input_files.len() > 1 {
        return Err(
            "vyre-cc: -o with multiple inputs is not supported yet; compile one TU at a time."
                .to_string(),
        );
    }

    for path in &options.input_files {
        let dest: PathBuf = if options.input_files.len() == 1 {
            options
                .output_file
                .clone()
                .unwrap_or_else(|| path.with_extension("o"))
        } else {
            path.with_extension("o")
        };
        compile_translation_unit(&backend, path, &dest, options)?;
    }

    Ok(())
}

/// Link one or more GPU-compiled `.o` files (ELF + embedded `VYRECOB2`) with `-nostdlib`.
///
/// Host-only: temp objects, startup `_start`, system `cc`. Does not add new `Program` ops.
pub fn link_c11_executable(options: &VyreCompileOptions) -> Result<(), String> {
    if options.input_files.is_empty() {
        return Err("No input files specified.".to_string());
    }

    let backend = WgpuBackend::acquire().map_err(|e| {
        format!("wgpu backend unavailable: {e}. Fix: use a machine with a supported GPU stack.")
    })?;

    let final_out = options
        .output_file
        .clone()
        .unwrap_or_else(|| PathBuf::from("a.out"));

    let tmp = std::env::temp_dir();
    let pid = std::process::id();
    let mut obj_paths: Vec<PathBuf> = Vec::new();

    for (i, path) in options.input_files.iter().enumerate() {
        let o_path = tmp.join(format!("vyrec_link_{pid}_{i}.o"));
        compile_translation_unit(&backend, path, &o_path, options)?;
        obj_paths.push(o_path);
    }

    let startup = crate::elf_linux::emit_link_startup_relocatable()?;
    let start_path = tmp.join(format!("vyrec_start_{pid}.o"));
    fs::write(&start_path, startup).map_err(|e| format!("write temp startup object: {e}"))?;

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg("-nostdlib");
    cmd.arg("-o").arg(&final_out);
    cmd.arg(&start_path);
    for o in &obj_paths {
        cmd.arg(o);
    }
    let st = cmd
        .status()
        .map_err(|e| format!("failed to spawn {cc} for link: {e}"))?;
    let _ = fs::remove_file(&start_path);
    for o in &obj_paths {
        let _ = fs::remove_file(o);
    }
    if !st.success() {
        return Err(format!(
            "{cc} -nostdlib link failed with status {st}. Fix: install a working toolchain, or set CC."
        ));
    }
    Ok(())
}
