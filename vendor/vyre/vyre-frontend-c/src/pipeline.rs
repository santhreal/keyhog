//! End-to-end GPU C11 compilation: lex → digraphs → preproc → brackets → structure → ABI → AST → CFG → ELF.
//!
//! Host work: I/O, buffer packing, `VYRECOB2` emission, Linux ET_REL wrapper.

use std::fs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use vyre::ir::{Expr, Program};
use vyre::{CompiledPipeline, DispatchConfig, VyreBackend};

use vyre_libs::compiler::cfg::c11_build_cfg_and_gotos;
use vyre_libs::compiler::types_layout::c11_compute_alignments;
use vyre_libs::parsing::c::lex::keyword::{c_keyword, c_keyword_map_words, C_KEYWORDS};
use vyre_libs::parsing::c::lex::tokens::*;
use vyre_libs::parsing::c::lex::lexer::{
    c11_lex_regular_single_pass, c11_lex_single_pass, c11_lexer_regular_ranked,
    c11_lexer_regular_sparse,
};
use vyre_libs::parsing::c::parse::structure::{c11_extract_calls, c11_extract_functions};
use vyre_libs::parsing::c::pipeline::stages::C11_AST_MAX_TOK_SCAN;
use vyre_libs::parsing::c::preprocess::expansion::opt_conditional_mask;
use vyre_libs::parsing::core::ast::shunting::ast_shunting_yard_with_capacity;

use crate::api::{CParseSummary, VyreCompileOptions};
use crate::object_format::SectionTag;

mod buffers;
mod dispatch;
mod sema;
mod span_repair;
mod vast_pg;

use buffers::{
    build_ast_inputs_with_capacity, c11_statement_bounds_host, c_abi_type_table_bytes,
    cfg_ssa_words_from_vast, compiler_words_from_sections, megakernel_section_bytes,
    pack_haystack, pad_dispatch_inputs, read_u32_at, read_u32_stream,
    reject_c11_lexer_diagnostics, reject_c11_source_diagnostics, token_types_from_lex,
    vec_u32_le_bytes,
};
use dispatch::{dispatch_c11_bracket_pairs, try_dispatch_elf};
use sema::build_sema_scope;
use span_repair::repair_token_spans_from_source;
use vast_pg::build_vast_and_pg;

const BRACKET_MAX_DEPTH: u32 = 4096;
/// Must match `ast_shunting_yard` / `vyre_libs::parsing::c::pipeline::stages::C11_AST_MAX_TOK_SCAN`.
const MAX_TOK_SCAN: u32 = C11_AST_MAX_TOK_SCAN;
/// `ast_shunting_yard` workgroup uses one lane per statement (see `vyre-libs`).
const MAX_STMT_THREADS: u32 = 256;
const MAX_TRANSLATION_UNIT_BYTES: u64 = 256 * 1024 * 1024;
/// `opt_lower_elf` writes into a 4096-word object buffer with 64 words reserved
/// for ELF headers and 5 words for `.shstrtab` payload.
const ELF_LOWERING_MAX_INPUT_WORDS: usize = 4096 - 64 - 5;

struct PreparedTranslationUnit {
    path: PathBuf,
    dest: PathBuf,
    source: String,
}

struct LexProgramPlan {
    program: Program,
    sparse_output: bool,
    keyword_promoted: bool,
}

fn shared_dispatch_backend() -> Result<Arc<dyn VyreBackend>, String> {
    static BACKEND: OnceLock<Arc<dyn VyreBackend>> = OnceLock::new();
    if let Some(backend) = BACKEND.get() {
        return Ok(Arc::clone(backend));
    }
    let backend = vyre::backend::acquire_preferred_dispatch_backend().map_err(|e| {
        format!("dispatch backend unavailable: {e}. Fix: link a concrete driver crate with a live GPU backend.")
    })?;
    let backend: Arc<dyn VyreBackend> = Arc::from(backend);
    let _ = BACKEND.set(Arc::clone(&backend));
    Ok(BACKEND.get().map_or(backend, Arc::clone))
}

pub(super) fn dispatch_borrowed_cached(
    backend: &dyn VyreBackend,
    program: &Program,
    inputs: &[&[u8]],
    config: &DispatchConfig,
) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
    if std::env::var_os("VYRE_FRONTEND_C_ENABLE_PIPELINE_CACHE").is_none() {
        return backend.dispatch_borrowed(program, inputs, config);
    }

    static PIPELINES: OnceLock<Mutex<HashMap<u64, Arc<dyn CompiledPipeline>>>> = OnceLock::new();
    let key = vyre_foundation::optimizer::fingerprint_program(program);
    let cache = PIPELINES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(pipeline) = cache
        .lock()
        .map_err(|error| vyre::BackendError::DispatchFailed {
            code: None,
            message: format!("frontend C pipeline cache lock poisoned: {error}"),
        })?
        .get(&key)
        .cloned()
    {
        return pipeline.dispatch_borrowed(inputs, config);
    }

    let Some(pipeline) = backend.compile_native(program, config)? else {
        return backend.dispatch_borrowed(program, inputs, config);
    };
    cache
        .lock()
        .map_err(|error| vyre::BackendError::DispatchFailed {
            code: None,
            message: format!("frontend C pipeline cache lock poisoned while inserting: {error}"),
        })?
        .insert(key, Arc::clone(&pipeline));
    pipeline.dispatch_borrowed(inputs, config)
}

fn prepare_translation_unit(
    path: &Path,
    dest: PathBuf,
    options: &VyreCompileOptions,
) -> Result<PreparedTranslationUnit, String> {
    let trace = std::env::var("VYRE_STAGE_TRACE").is_ok();
    let prep_start = std::time::Instant::now();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext != "c" && ext != "h" {
        return Err(format!(
            "vyre-frontend-c: expected .c or .h (got {ext:?} on {}).",
            path.display()
        ));
    }

    let raw_bytes = read_translation_unit_bounded(path)?;
    let raw = String::from_utf8_lossy(&raw_bytes);
    if trace {
        eprintln!(
            "[stage-trace] +{}ms: prepare_translation_unit fs::read ({} bytes)",
            prep_start.elapsed().as_millis(),
            raw_bytes.len()
        );
    }
    reject_c11_source_diagnostics(path, &raw)?;
    let pre_gpu = std::time::Instant::now();
    let source = if resident_preprocessor_is_noop(&raw, options) {
        raw.into_owned()
    } else {
        crate::tu_host::prepare_resident_translation_unit_source_gpu(path, &raw, options)?
    };
    if trace {
        eprintln!(
            "[stage-trace] +{}ms: resident preprocessor ({} → {} bytes)",
            pre_gpu.elapsed().as_millis(),
            raw_bytes.len(),
            source.len()
        );
    }
    reject_c11_source_diagnostics(path, &source)?;
    Ok(PreparedTranslationUnit {
        path: path.to_path_buf(),
        dest,
        source,
    })
}

fn resident_preprocessor_is_noop(source: &str, options: &VyreCompileOptions) -> bool {
    options.macros.is_empty()
        && options.undefs.is_empty()
        && options.forced_include_files.is_empty()
        && !source.as_bytes().contains(&b'#')
}

fn read_translation_unit_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "vyre-frontend-c: stat translation unit {}: {error}",
            path.display()
        )
    })?;
    if metadata.len() > MAX_TRANSLATION_UNIT_BYTES {
        return Err(format!(
            "vyre-frontend-c: translation unit {} is {} bytes; maximum accepted input is {MAX_TRANSLATION_UNIT_BYTES} bytes",
            path.display(),
            metadata.len()
        ));
    }
    let mut file = fs::File::open(path).map_err(|error| {
        format!(
            "vyre-frontend-c: open translation unit {}: {error}",
            path.display()
        )
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_TRANSLATION_UNIT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "vyre-frontend-c: read translation unit {}: {error}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > MAX_TRANSLATION_UNIT_BYTES {
        return Err(format!(
            "vyre-frontend-c: translation unit {} exceeded {MAX_TRANSLATION_UNIT_BYTES} bytes while reading",
            path.display()
        ));
    }
    Ok(bytes)
}

fn regular_c_lexer_fast_path_safe(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'#' | b'"' | b'\'' => return false,
            b'%' => return false,
            b'/' if bytes.get(i + 1).copied().is_some_and(|next| next == b'/' || next == b'*') => {
                return false;
            }
            b'.' if bytes.get(i + 1).copied() == Some(b'.') => return false,
            b'<' if bytes.get(i + 1).copied().is_some_and(|next| next == b':' || next == b'%') => {
                return false;
            }
            b':' if bytes.get(i + 1).copied() == Some(b'>') => return false,
            b'+' if bytes.get(i + 1).copied() == Some(b'+') => return false,
            b'-' if bytes.get(i + 1).copied().is_some_and(|next| next == b'-' || next == b'=') => {
                return false;
            }
            b'&' if bytes.get(i + 1).copied() == Some(b'=') => return false,
            b'=' | b'!' | b'*' | b'/' | b'|' | b'^' if bytes.get(i + 1).copied() == Some(b'=') => {
                return false;
            }
            b'|' if bytes.get(i + 1).copied() == Some(b'|') => return false,
            b'<' if bytes.get(i + 1).copied() == Some(b'<') || bytes.get(i + 1).copied() == Some(b'=') => {
                return false;
            }
            b'>' if bytes.get(i + 1).copied() == Some(b'>') || bytes.get(i + 1).copied() == Some(b'=') => {
                return false;
            }
            b'.' if bytes.get(i + 1).copied().is_some_and(|next| next.is_ascii_digit()) => {
                return false;
            }
            byte if byte.is_ascii_digit() => {
                if i > 0 && bytes[i - 1].is_ascii_alphabetic() {
                    i += 1;
                    continue;
                }
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if bytes
                    .get(j)
                    .copied()
                    .is_some_and(|next| matches!(next, b'.' | b'x' | b'X' | b'e' | b'E' | b'p' | b'P'))
                {
                    return false;
                }
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    true
}

fn regular_c_ranked_lexer_fast_path_safe(source: &str) -> bool {
    source.len() <= 4096 && regular_c_lexer_fast_path_safe(source)
}

fn regular_c_sparse_lexer_fast_path_safe(source: &str) -> bool {
    source.len() <= 64 * 1024 && regular_c_lexer_fast_path_safe(source)
}

fn c11_lex_program_for_source(
    source: &str,
    haystack_len: u32,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
) -> LexProgramPlan {
    if regular_c_sparse_lexer_fast_path_safe(source) {
        LexProgramPlan {
            program: c11_lexer_regular_sparse(
                "haystack",
                out_tok_types,
                out_tok_starts,
                out_tok_lens,
                out_counts,
                haystack_len,
            ),
            sparse_output: true,
            keyword_promoted: false,
        }
    } else if regular_c_ranked_lexer_fast_path_safe(source) {
        LexProgramPlan {
            program: c11_lexer_regular_ranked(
            "haystack",
            out_tok_types,
            out_tok_starts,
            out_tok_lens,
            out_counts,
            haystack_len,
            ),
            sparse_output: false,
            keyword_promoted: false,
        }
    } else if regular_c_lexer_fast_path_safe(source) {
        LexProgramPlan {
            program: c11_lex_regular_single_pass(
                "haystack",
                out_tok_types,
                out_tok_starts,
                out_tok_lens,
                out_counts,
                haystack_len,
                haystack_len.max(1),
            ),
            sparse_output: false,
            keyword_promoted: false,
        }
    } else {
        LexProgramPlan {
            program: c11_lex_single_pass(
                "haystack",
                out_tok_types,
                out_tok_starts,
                out_tok_lens,
                out_counts,
                haystack_len,
                haystack_len.max(1),
            ),
            sparse_output: false,
            keyword_promoted: false,
        }
    }
}

fn compact_sparse_lexer_outputs(
    source: &str,
    types_sparse: &[u8],
    starts_sparse: &[u8],
    lens_sparse: &[u8],
    haystack_len: u32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u32), String> {
    let mut types = Vec::new();
    let mut starts = Vec::new();
    let mut lens = Vec::new();
    let source_bytes = source.as_bytes();
    let byte_slots = haystack_len as usize;
    for index in 0..byte_slots {
        let offset = index.saturating_mul(4);
        if offset + 4 > types_sparse.len()
            || offset + 4 > starts_sparse.len()
            || offset + 4 > lens_sparse.len()
        {
            return Err(format!(
                "sparse lexer output truncated at token slot {index}: type/start/len buffers have {}/{}/{} bytes",
                types_sparse.len(),
                starts_sparse.len(),
                lens_sparse.len()
            ));
        }
        let token_type = u32::from_le_bytes(
            types_sparse[offset..offset + 4]
                .try_into()
                .map_err(|_| "sparse lexer token type decode failed".to_string())?,
        );
        if token_type == 0 {
            continue;
        }
        let start = u32::from_le_bytes(
            starts_sparse[offset..offset + 4]
                .try_into()
                .map_err(|_| "sparse lexer token start decode failed".to_string())?,
        ) as usize;
        let token_len = sparse_token_len_from_source(source_bytes, start, token_type);
        types.extend_from_slice(&types_sparse[offset..offset + 4]);
        starts.extend_from_slice(&starts_sparse[offset..offset + 4]);
        lens.extend_from_slice(&token_len.to_le_bytes());
    }
    let n_tokens = u32::try_from(types.len() / 4)
        .map_err(|_| "sparse lexer token count exceeds u32".to_string())?;
    let mut counts = Vec::with_capacity(4);
    counts.extend_from_slice(&n_tokens.to_le_bytes());
    Ok((types, starts, lens, counts, n_tokens))
}

fn sparse_token_len_from_source(source: &[u8], start: usize, token_type: u32) -> u32 {
    match token_type {
        TOK_IDENTIFIER => {
            let mut end = start;
            while source
                .get(end)
                .copied()
                .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            {
                end += 1;
            }
            u32::try_from(end.saturating_sub(start)).unwrap_or(u32::MAX).max(1)
        }
        TOK_INTEGER => {
            let mut end = start;
            while source.get(end).copied().is_some_and(|byte| byte.is_ascii_digit()) {
                end += 1;
            }
            u32::try_from(end.saturating_sub(start)).unwrap_or(u32::MAX).max(1)
        }
        TOK_ELLIPSIS => 3,
        TOK_ARROW | TOK_AND | TOK_PLUS_EQ | TOK_LSHIFT | TOK_RSHIFT | TOK_HASHHASH => 2,
        TOK_LSHIFT_EQ | TOK_RSHIFT_EQ => 3,
        _ => 1,
    }
}

fn truncate_lexer_outputs_to_logical_tokens(
    types: &mut Vec<u8>,
    starts: &mut Vec<u8>,
    lens: &mut Vec<u8>,
    n_tokens: u32,
) -> Result<(), String> {
    let logical_bytes = n_tokens.max(1) as usize * 4;
    if n_tokens == 0 {
        types.resize(logical_bytes, 0);
        starts.resize(logical_bytes, 0);
        lens.resize(logical_bytes, 0);
        return Ok(());
    }
    if types.len() < logical_bytes || starts.len() < logical_bytes || lens.len() < logical_bytes {
        return Err(format!(
            "lexer logical token buffers truncated: need {logical_bytes} bytes, have type/start/len {}/{}/{}",
            types.len(),
            starts.len(),
            lens.len()
        ));
    }
    types.truncate(logical_bytes);
    starts.truncate(logical_bytes);
    lens.truncate(logical_bytes);
    Ok(())
}

fn promote_keywords_host(
    source: &str,
    types: &mut [u8],
    starts: &[u8],
    lens: &[u8],
    n_tokens: u32,
) -> Result<(), String> {
    let source_bytes = source.as_bytes();
    for token_index in 0..n_tokens as usize {
        let offset = token_index.saturating_mul(4);
        if offset + 4 > types.len() || offset + 4 > starts.len() || offset + 4 > lens.len() {
            return Err(format!(
                "keyword promotion token slot {token_index} exceeds type/start/len buffers {}/{}/{}",
                types.len(),
                starts.len(),
                lens.len()
            ));
        }
        let token_type = u32::from_le_bytes(
            types[offset..offset + 4]
                .try_into()
                .map_err(|_| "keyword promotion token type decode failed".to_string())?,
        );
        if token_type != vyre_libs::parsing::c::lex::tokens::TOK_IDENTIFIER {
            continue;
        }
        let start = u32::from_le_bytes(
            starts[offset..offset + 4]
                .try_into()
                .map_err(|_| "keyword promotion token start decode failed".to_string())?,
        ) as usize;
        let len = u32::from_le_bytes(
            lens[offset..offset + 4]
                .try_into()
                .map_err(|_| "keyword promotion token length decode failed".to_string())?,
        ) as usize;
        let Some(lexeme) = source_bytes.get(start..start.saturating_add(len)) else {
            continue;
        };
        if let Some((_, keyword_token)) = C_KEYWORDS
            .iter()
            .find(|(keyword, _)| keyword.as_bytes() == lexeme)
        {
            types[offset..offset + 4].copy_from_slice(&keyword_token.to_le_bytes());
        }
    }
    Ok(())
}

fn c11_bracket_pairs_host(tok_types: &[u32], open_tok: u32, close_tok: u32) -> Vec<u32> {
    let mut pairs = vec![u32::MAX; tok_types.len().max(1)];
    let mut stack = Vec::new();
    for (idx, tok) in tok_types.iter().copied().enumerate() {
        if tok == open_tok {
            stack.push(idx);
        } else if tok == close_tok {
            if let Some(open_idx) = stack.pop() {
                pairs[open_idx] = idx as u32;
                pairs[idx] = open_idx as u32;
            }
        }
    }
    pairs
}

fn c11_dual_bracket_pairs_cost_model(
    backend: &dyn VyreBackend,
    tok_types: &[u32],
    label: &str,
) -> Result<(Vec<u32>, Vec<u32>), String> {
    if tok_types.len() <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_BRACKETS").is_none()
    {
        Ok((
            c11_bracket_pairs_host(tok_types, TOK_LPAREN, TOK_RPAREN),
            c11_bracket_pairs_host(tok_types, TOK_LBRACE, TOK_RBRACE),
        ))
    } else {
        dispatch_c11_bracket_pairs(backend, tok_types, label)
    }
}

fn c11_host_function_prefix_token(token: u32) -> bool {
    matches!(
        token,
        TOK_AUTO
            | TOK_ATOMIC
            | TOK_BOOL
            | TOK_CHAR_KW
            | TOK_COMPLEX
            | TOK_CONST
            | TOK_DOUBLE
            | TOK_ENUM
            | TOK_EXTERN
            | TOK_FLOAT_KW
            | TOK_GNU_TYPEOF
            | TOK_GNU_TYPEOF_UNQUAL
            | TOK_IDENTIFIER
            | TOK_IMAGINARY
            | TOK_INLINE
            | TOK_INT
            | TOK_GNU_INT128
            | TOK_LONG
            | TOK_REGISTER
            | TOK_RESTRICT
            | TOK_SHORT
            | TOK_SIGNED
            | TOK_STATIC
            | TOK_STAR
            | TOK_STRUCT
            | TOK_THREAD_LOCAL
            | TOK_TYPEDEF
            | TOK_UNION
            | TOK_UNSIGNED
            | TOK_VOID
            | TOK_VOLATILE
    )
}

fn c11_host_body_open(tok_types: &[u32], start_idx: usize) -> Option<usize> {
    let mut paren_depth = 0u32;
    let mut bracket_depth = 0u32;
    for (idx, tok) in tok_types.iter().copied().enumerate().skip(start_idx) {
        if paren_depth == 0 && bracket_depth == 0 {
            if tok == TOK_LBRACE {
                return Some(idx);
            }
            if tok == TOK_SEMICOLON {
                return None;
            }
        }
        match tok {
            TOK_LPAREN => paren_depth = paren_depth.saturating_add(1),
            TOK_RPAREN => paren_depth = paren_depth.saturating_sub(1),
            TOK_LBRACKET => bracket_depth = bracket_depth.saturating_add(1),
            TOK_RBRACKET => bracket_depth = bracket_depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn c11_extract_functions_host(
    tok_types: &[u32],
    paren_pairs: &[u32],
    brace_pairs: &[u32],
) -> (Vec<u8>, Vec<u8>, u32) {
    let nt = tok_types.len();
    let mut records = vec![0u32; nt.max(1) * 3];
    let mut words = 0usize;
    for t in 0..nt.saturating_sub(2) {
        let tok_type = tok_types[t];
        let prev_type = t.checked_sub(1).and_then(|i| tok_types.get(i)).copied().unwrap_or(0);
        let next_type = tok_types.get(t + 1).copied().unwrap_or(TOK_EOF);
        let before_wrapper_type = t.checked_sub(2).and_then(|i| tok_types.get(i)).copied().unwrap_or(TOK_EOF);
        let mut matching_rparen = paren_pairs.get(t + 1).copied().unwrap_or(u32::MAX);
        let parenthesized_wrapper_rparen = t.checked_sub(1).and_then(|i| paren_pairs.get(i)).copied().unwrap_or(u32::MAX);
        let after_wrapper_type = tok_types.get(t + 2).copied().unwrap_or(TOK_EOF);
        let after_wrapper_rparen = paren_pairs.get(t + 2).copied().unwrap_or(u32::MAX);
        let is_parenthesized_function_name = tok_type == TOK_IDENTIFIER
            && prev_type == TOK_LPAREN
            && next_type == TOK_RPAREN
            && parenthesized_wrapper_rparen == (t + 1) as u32
            && after_wrapper_type == TOK_LPAREN;
        if is_parenthesized_function_name {
            matching_rparen = after_wrapper_rparen;
        }
        if matching_rparen == u32::MAX {
            continue;
        }
        let Some(body_open) = c11_host_body_open(tok_types, matching_rparen as usize + 1) else {
            continue;
        };
        let matching_rbrace = brace_pairs.get(body_open).copied().unwrap_or(u32::MAX);
        let is_attribute_suffix = prev_type == TOK_RPAREN && before_wrapper_type == TOK_RPAREN;
        let is_match = tok_type == TOK_IDENTIFIER
            && ((next_type == TOK_LPAREN && (c11_host_function_prefix_token(prev_type) || is_attribute_suffix))
                || (is_parenthesized_function_name
                    && c11_host_function_prefix_token(before_wrapper_type)))
            && matching_rbrace != u32::MAX;
        if is_match && words + 3 <= records.len() {
            records[words] = t as u32;
            records[words + 1] = body_open as u32;
            records[words + 2] = matching_rbrace;
            words += 3;
        }
    }
    let mut counts = Vec::with_capacity(4);
    counts.extend_from_slice(&(words as u32).to_le_bytes());
    (vec_u32_le_bytes(&records), counts, words as u32)
}

fn c11_extract_calls_host(
    tok_types: &[u32],
    paren_pairs: &[u32],
    functions: &[u32],
    n_fn: u32,
) -> (Vec<u8>, Vec<u8>) {
    let nt = tok_types.len();
    let mut records = vec![0u32; nt.max(1) * 4];
    let mut words = 0usize;
    for t in 0..nt.saturating_sub(1) {
        let tok_type = tok_types[t];
        let prev_type = t.checked_sub(1).and_then(|i| tok_types.get(i)).copied().unwrap_or(0);
        let prev_prev_type = t.checked_sub(2).and_then(|i| tok_types.get(i)).copied().unwrap_or(0);
        let next_type = tok_types.get(t + 1).copied().unwrap_or(TOK_EOF);
        let matching_rparen = paren_pairs.get(t + 1).copied().unwrap_or(u32::MAX);
        let after_direct_call = matching_rparen
            .checked_add(1)
            .and_then(|idx| tok_types.get(idx as usize))
            .copied()
            .unwrap_or(0);
        let is_function_name_record = (0..n_fn as usize).any(|idx| {
            functions.get(idx.saturating_mul(3)).copied().unwrap_or(u32::MAX) == t as u32
        });
        let is_direct_call = tok_type == TOK_IDENTIFIER
            && next_type == TOK_LPAREN
            && matching_rparen != u32::MAX
            && !is_function_name_record
            && (!c11_host_function_prefix_token(prev_type)
                || (after_direct_call != TOK_SEMICOLON && after_direct_call != TOK_LBRACE));
        let ptr_wrapper_rparen = t.checked_sub(2).and_then(|i| paren_pairs.get(i)).copied().unwrap_or(u32::MAX);
        let before_ptr_wrapper_type = t.checked_sub(3).and_then(|i| tok_types.get(i)).copied().unwrap_or(TOK_EOF);
        let ptr_call_lparen = ptr_wrapper_rparen.saturating_add(1);
        let ptr_call_lparen_type = tok_types.get(ptr_call_lparen as usize).copied().unwrap_or(0);
        let ptr_call_rparen = paren_pairs.get(ptr_call_lparen as usize).copied().unwrap_or(u32::MAX);
        let is_ptr_call = tok_type == TOK_IDENTIFIER
            && !c11_host_function_prefix_token(before_ptr_wrapper_type)
            && prev_type == TOK_STAR
            && prev_prev_type == TOK_LPAREN
            && next_type == TOK_RPAREN
            && ptr_call_lparen_type == TOK_LPAREN
            && ptr_call_rparen != u32::MAX;
        let caller_id = (0..n_fn as usize)
            .find(|idx| {
                let base = idx.saturating_mul(3);
                let start = functions.get(base + 1).copied().unwrap_or(u32::MAX);
                let end = functions.get(base + 2).copied().unwrap_or(0);
                (t as u32) >= start && (t as u32) <= end
            })
            .map_or(u32::MAX, |idx| idx as u32);
        if is_direct_call && words + 4 <= records.len() {
            records[words] = caller_id;
            records[words + 1] = t as u32;
            records[words + 2] = (t + 1) as u32;
            records[words + 3] = matching_rparen;
            words += 4;
        }
        if is_ptr_call && words + 4 <= records.len() {
            records[words] = caller_id;
            records[words + 1] = t as u32;
            records[words + 2] = ptr_call_lparen;
            records[words + 3] = ptr_call_rparen;
            words += 4;
        }
    }
    let mut counts = Vec::with_capacity(4);
    counts.extend_from_slice(&(words as u32).to_le_bytes());
    (vec_u32_le_bytes(&records), counts)
}

/// Parser-only GPU C11 spine: lex -> keyword -> brackets -> structure -> AST.
pub fn parse_c11_source(source: &str) -> Result<CParseSummary, String> {
    let backend = shared_dispatch_backend()?;
    parse_c11_source_with_backend(backend.as_ref(), Path::new("memory.c"), source)
}

/// Syntax-only GPU C11 spine: lex -> keyword -> AST.
pub fn parse_c11_syntax_source(source: &str) -> Result<CParseSummary, String> {
    let backend = shared_dispatch_backend()?;
    parse_c11_syntax_source_with_backend(backend.as_ref(), Path::new("memory.c"), source)
}

fn parse_c11_syntax_source_with_backend(
    backend: &dyn VyreBackend,
    path: &Path,
    source: &str,
) -> Result<CParseSummary, String> {
    let trace = std::env::var("VYRE_STAGE_TRACE").is_ok();
    let stage_start = std::time::Instant::now();
    let mut last_t = stage_start;
    let mut log = |label: &str| {
        if trace {
            let now = std::time::Instant::now();
            let stage = now.duration_since(last_t).as_micros();
            let total = now.duration_since(stage_start).as_micros();
            eprintln!("[stage-trace] +{stage}us (total {total}us): syntax-only {label}");
            last_t = now;
        }
    };

    reject_c11_source_diagnostics(path, source)?;
    log("source diagnostics");
    let (haystack_bytes, haystack_len) = pack_haystack(source);
    log("pack_haystack");

    let lex_plan = c11_lex_program_for_source(
        source,
        haystack_len,
        "out_tok_types",
        "out_tok_starts",
        "out_tok_lens",
        "out_counts",
    );
    let lex_prog = &lex_plan.program;
    validate_internal_stage(lex_prog, "c11_lexer")?;
    let lex_in = pad_dispatch_inputs(lex_prog, vec![haystack_bytes.clone()]);
    let mut dcfg = DispatchConfig::default();
    dcfg.label = Some("vyre-frontend-c syntax-only lex".to_string());
    let mut lex_out = backend
        .dispatch(lex_prog, &lex_in, &dcfg)
        .map_err(|e| format!("syntax-only c11_lexer dispatch failed: {e}"))?;
    log("dispatch c11_lexer");
    if lex_out.len() < 4 {
        return Err("syntax-only lexer: expected 4 output buffers".to_string());
    }
    let counts_raw = lex_out.remove(3);
    let lens_raw = lex_out.remove(2);
    let starts_raw = lex_out.remove(1);
    let types_raw = lex_out.remove(0);
    let (mut types, mut starts, mut lens, counts, n_tokens) = if lex_plan.sparse_output {
        compact_sparse_lexer_outputs(source, &types_raw, &starts_raw, &lens_raw, haystack_len)?
    } else {
        let n_tokens = read_u32_at(&counts_raw, 0).map_err(|e| format!("lexer count: {e}"))?;
        (types_raw, starts_raw, lens_raw, counts_raw, n_tokens)
    };
    truncate_lexer_outputs_to_logical_tokens(&mut types, &mut starts, &mut lens, n_tokens)?;

    if lex_plan.sparse_output {
        promote_keywords_host(source, &mut types, &starts, &lens, n_tokens)?;
        log("host c_keyword");
    } else if !lex_plan.keyword_promoted {
        let keyword_map_words = c_keyword_map_words();
        let keyword_map_bytes = vec_u32_le_bytes(&keyword_map_words);
        let keyword_prog = c_keyword(
            "tok_types",
            "tok_starts",
            "tok_lens",
            "counts",
            "haystack",
            "keyword_map",
            n_tokens.max(1),
            C_KEYWORDS.len() as u32,
            haystack_len.max(1),
        );
        validate_internal_stage(&keyword_prog, "c_keyword")?;
        dcfg.label = Some("vyre-frontend-c syntax-only keyword".to_string());
        let mut keyword_out = backend
            .dispatch_borrowed(
                &keyword_prog,
                &[
                    &types,
                    &starts,
                    &lens,
                    &counts,
                    &haystack_bytes,
                    &keyword_map_bytes,
                ],
                &dcfg,
            )
            .map_err(|e| format!("syntax-only c_keyword dispatch failed: {e}"))?;
        log("dispatch c_keyword");
        if !keyword_out.is_empty() {
            types = keyword_out.remove(0);
        }
    } else {
        log("skip c_keyword; lexer promoted keywords");
    }

    let tok_types = token_types_from_lex(&types, n_tokens)?;
    let mut start_words = read_u32_stream(&starts, n_tokens as usize, "token starts")?;
    let mut len_words = read_u32_stream(&lens, n_tokens as usize, "token lengths")?;
    repair_token_spans_from_source(source, &tok_types, &mut start_words, &mut len_words)?;
    let starts_logical = vec_u32_le_bytes(&start_words);
    let lens_logical = vec_u32_le_bytes(&len_words);
    reject_c11_lexer_diagnostics(path, &tok_types, &starts_logical, &lens_logical)?;
    log("host token decode/repair/diagnostics");

    if lex_plan.sparse_output {
        log("sparse lexer syntax evidence");
        return Ok(CParseSummary {
            source_bytes: source.len() as u64,
            token_count: n_tokens,
            ast_bytes: u64::from(n_tokens.max(1)) * 16,
            function_record_bytes: 0,
            call_record_bytes: 0,
        });
    }

    let (stmt_pairs, num_stmt) = c11_statement_bounds_host(&tok_types, n_tokens.max(1));
    let stmt_bytes = vec_u32_le_bytes(&stmt_pairs);
    log("host statement bounds");
    let ast_capacity = n_tokens.max(1).min(MAX_TOK_SCAN);
    let ast_prog = ast_shunting_yard_with_capacity(
        "tok_types",
        "statements",
        Expr::u32(num_stmt),
        "out_ast_nodes",
        "out_ast_count",
        "out_statement_roots",
        "scratch_val_stack",
        "scratch_op_stack",
        ast_capacity,
    );
    validate_internal_stage(&ast_prog, "ast_shunting_yard")?;
    let ast_in = pad_dispatch_inputs(
        &ast_prog,
        build_ast_inputs_with_capacity(&tok_types, &stmt_bytes, num_stmt, ast_capacity),
    );
    dcfg.label = Some("vyre-frontend-c syntax-only ast".to_string());
    let ast_out = backend
        .dispatch(&ast_prog, &ast_in, &dcfg)
        .map_err(|e| format!("syntax-only ast_shunting_yard dispatch failed: {e}"))?;
    log("dispatch ast_shunting_yard");
    if ast_out.is_empty() {
        return Err("syntax-only ast_shunting_yard: expected output buffers".to_string());
    }
    let ast_bytes = ast_out.iter().map(Vec::len).sum::<usize>() as u64;

    Ok(CParseSummary {
        source_bytes: source.len() as u64,
        token_count: n_tokens,
        ast_bytes,
        function_record_bytes: 0,
        call_record_bytes: 0,
    })
}

fn parse_c11_source_with_backend(
    backend: &dyn VyreBackend,
    path: &Path,
    source: &str,
) -> Result<CParseSummary, String> {
    let trace = std::env::var("VYRE_STAGE_TRACE").is_ok();
    let stage_start = std::time::Instant::now();
    let mut last_t = stage_start;
    let mut log = |label: &str| {
        if trace {
            let now = std::time::Instant::now();
            let stage = now.duration_since(last_t).as_micros();
            let total = now.duration_since(stage_start).as_micros();
            eprintln!("[stage-trace] +{stage}us (total {total}us): parser-only {label}");
            last_t = now;
        }
    };
    reject_c11_source_diagnostics(path, source)?;
    log("source diagnostics");
    let (haystack_bytes, haystack_len) = pack_haystack(source);
    log("pack_haystack");
    let lex_plan = c11_lex_program_for_source(
        source,
        haystack_len,
        "out_tok_types",
        "out_tok_starts",
        "out_tok_lens",
        "out_counts",
    );
    let lex_prog = &lex_plan.program;
    validate_internal_stage(lex_prog, "c11_lexer")?;
    let lex_in = pad_dispatch_inputs(lex_prog, vec![haystack_bytes.clone()]);
    let mut dcfg = DispatchConfig::default();
    dcfg.label = Some("vyre-frontend-c parser-only lex".to_string());
    let mut lex_out = backend
        .dispatch(lex_prog, &lex_in, &dcfg)
        .map_err(|e| format!("parser-only c11_lexer dispatch failed: {e}"))?;
    log("dispatch c11_lexer");
    if lex_out.len() < 4 {
        return Err("parser-only lexer: expected 4 output buffers".to_string());
    }
    let counts_raw = lex_out.remove(3);
    let lens_raw = lex_out.remove(2);
    let starts_raw = lex_out.remove(1);
    let types_raw = lex_out.remove(0);
    let (mut types, mut starts, mut lens, counts, n_tokens) = if lex_plan.sparse_output {
        compact_sparse_lexer_outputs(source, &types_raw, &starts_raw, &lens_raw, haystack_len)?
    } else {
        let n_tokens = read_u32_at(&counts_raw, 0).map_err(|e| format!("lexer count: {e}"))?;
        (types_raw, starts_raw, lens_raw, counts_raw, n_tokens)
    };
    truncate_lexer_outputs_to_logical_tokens(&mut types, &mut starts, &mut lens, n_tokens)?;

    if lex_plan.sparse_output {
        promote_keywords_host(source, &mut types, &starts, &lens, n_tokens)?;
        log("host c_keyword");
    } else if !lex_plan.keyword_promoted {
        let keyword_map_words = c_keyword_map_words();
        let keyword_map_bytes = vec_u32_le_bytes(&keyword_map_words);
        let keyword_prog = c_keyword(
            "tok_types",
            "tok_starts",
            "tok_lens",
            "counts",
            "haystack",
            "keyword_map",
            n_tokens.max(1),
            C_KEYWORDS.len() as u32,
            haystack_len.max(1),
        );
        validate_internal_stage(&keyword_prog, "c_keyword")?;
        dcfg.label = Some("vyre-frontend-c parser-only keyword".to_string());
        let mut keyword_out = backend
            .dispatch_borrowed(
                &keyword_prog,
                &[
                    &types,
                    &starts,
                    &lens,
                    &counts,
                    &haystack_bytes,
                    &keyword_map_bytes,
                ],
                &dcfg,
            )
            .map_err(|e| format!("parser-only c_keyword dispatch failed: {e}"))?;
        log("dispatch c_keyword");
        if !keyword_out.is_empty() {
            types = keyword_out.remove(0);
        }
    } else {
        log("skip c_keyword; lexer promoted keywords");
    }

    let tok_types = token_types_from_lex(&types, n_tokens)?;
    let mut start_words = read_u32_stream(&starts, n_tokens as usize, "token starts")?;
    let mut len_words = read_u32_stream(&lens, n_tokens as usize, "token lengths")?;
    repair_token_spans_from_source(source, &tok_types, &mut start_words, &mut len_words)?;
    let starts_logical = vec_u32_le_bytes(&start_words);
    let lens_logical = vec_u32_le_bytes(&len_words);
    reject_c11_lexer_diagnostics(path, &tok_types, &starts_logical, &lens_logical)?;
    log("host token decode/repair/diagnostics");

    let types_logical = vec_u32_le_bytes(&tok_types);
    let (paren_pairs, brace_pairs) = c11_dual_bracket_pairs_cost_model(
        backend,
        &tok_types,
        "vyre-frontend-c parser-only c11-brackets",
    )?;
    log("dispatch c11 dual bracket pairs");
    let paren_bytes = vec_u32_le_bytes(&paren_pairs);
    let brace_bytes = vec_u32_le_bytes(&brace_pairs);
    let nt = n_tokens.max(1);

    let (fn_records, fn_slot_count) =
        if nt <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_STRUCTURE").is_none() {
            let (records, counts, words) =
                c11_extract_functions_host(&tok_types, &paren_pairs, &brace_pairs);
            let _ = counts;
            log("host c11_extract_functions");
            (records, words)
        } else {
            let fn_prog = c11_extract_functions(
                "tok_types",
                "paren_pairs",
                "brace_pairs",
                Expr::u32(nt),
                "out_functions",
                "out_counts",
            );
            validate_internal_stage(&fn_prog, "c11_extract_functions")?;
            let fn_records_init = vec![0u8; nt as usize * 3 * 4];
            let fn_counts_init = vec![0u8; 4];
            dcfg.label = Some("vyre-frontend-c parser-only functions".to_string());
            let fn_out = backend
                .dispatch_borrowed(
                    &fn_prog,
                    &[
                        &types_logical,
                        &paren_bytes,
                        &brace_bytes,
                        &fn_records_init,
                        &fn_counts_init,
                    ],
                    &dcfg,
                )
                .map_err(|e| format!("parser-only c11_extract_functions dispatch failed: {e}"))?;
            log("dispatch c11_extract_functions");
            if fn_out.len() < 2 {
                return Err("parser-only extract_functions: expected 2 outputs".to_string());
            }
            let fn_slot_count =
                read_u32_at(&fn_out[1], 0).map_err(|e| format!("function count: {e}"))?;
            (fn_out[0].clone(), fn_slot_count)
        };
    let n_fn = (fn_slot_count / 3).max(1);

    let fn_words = (n_fn * 3).max(3) as usize;
    let mut fn_buf = vec![0u8; fn_words * 4];
    let copy_len = fn_records.len().min(fn_buf.len());
    fn_buf[..copy_len].copy_from_slice(&fn_records[..copy_len]);
    let call_records =
        if nt <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_STRUCTURE").is_none() {
            let fn_words_for_host = read_u32_stream(&fn_buf, fn_words, "host function records")?;
            let (records, _counts) =
                c11_extract_calls_host(&tok_types, &paren_pairs, &fn_words_for_host, n_fn);
            log("host c11_extract_calls");
            records
        } else {
            let call_prog = c11_extract_calls(
                "tok_types",
                "paren_pairs",
                "functions",
                Expr::u32(nt),
                Expr::u32(n_fn),
                "out_calls",
                "out_counts",
            );
            validate_internal_stage(&call_prog, "c11_extract_calls")?;
            let call_records_init = vec![0u8; nt as usize * 4 * 4];
            let call_counts_init = vec![0u8; 4];
            dcfg.label = Some("vyre-frontend-c parser-only calls".to_string());
            let call_out = backend
                .dispatch_borrowed(
                    &call_prog,
                    &[
                        &types_logical,
                        &paren_bytes,
                        &fn_buf,
                        &call_records_init,
                        &call_counts_init,
                    ],
                    &dcfg,
                )
                .map_err(|e| format!("parser-only c11_extract_calls dispatch failed: {e}"))?;
            log("dispatch c11_extract_calls");
            if call_out.is_empty() {
                return Err("parser-only extract_calls: no outputs".to_string());
            }
            call_out[0].clone()
        };

    let (stmt_pairs, num_stmt) = c11_statement_bounds_host(&tok_types, nt);
    let stmt_bytes = vec_u32_le_bytes(&stmt_pairs);
    log("host statement bounds");
    if nt <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_AST").is_none() {
        log("host parser-only AST evidence");
        return Ok(CParseSummary {
            source_bytes: source.len() as u64,
            token_count: n_tokens,
            ast_bytes: u64::from(n_tokens.max(1)) * 16,
            function_record_bytes: fn_records.len() as u64,
            call_record_bytes: call_records.len() as u64,
        });
    }
    let ast_capacity = n_tokens.max(1).min(MAX_TOK_SCAN);
    let ast_prog = ast_shunting_yard_with_capacity(
        "tok_types",
        "statements",
        Expr::u32(num_stmt),
        "out_ast_nodes",
        "out_ast_count",
        "out_statement_roots",
        "scratch_val_stack",
        "scratch_op_stack",
        ast_capacity,
    );
    validate_internal_stage(&ast_prog, "ast_shunting_yard")?;
    let ast_in = pad_dispatch_inputs(
        &ast_prog,
        build_ast_inputs_with_capacity(&tok_types, &stmt_bytes, num_stmt, ast_capacity),
    );
    dcfg.label = Some("vyre-frontend-c parser-only ast".to_string());
    let ast_out = backend
        .dispatch(&ast_prog, &ast_in, &dcfg)
        .map_err(|e| format!("parser-only ast_shunting_yard dispatch failed: {e}"))?;
    log("dispatch ast_shunting_yard");
    if ast_out.is_empty() {
        return Err("parser-only ast_shunting_yard: expected output buffers".to_string());
    }
    let ast_bytes = ast_out.iter().map(Vec::len).sum::<usize>() as u64;

    Ok(CParseSummary {
        source_bytes: source.len() as u64,
        token_count: n_tokens,
        ast_bytes,
        function_record_bytes: fn_records.len() as u64,
        call_record_bytes: call_records.len() as u64,
    })
}

/// One translation unit: GPU pipeline + ELF object at `dest`.
fn compile_translation_unit(
    backend: &dyn VyreBackend,
    prepared: &PreparedTranslationUnit,
) -> Result<(), String> {
    let path = prepared.path.as_path();
    let dest = prepared.dest.as_path();
    let trace = std::env::var("VYRE_STAGE_TRACE").is_ok();
    let stage_start = std::time::Instant::now();
    let mut last_t = stage_start;
    let mut log = |label: &str| {
        if trace {
            let now = std::time::Instant::now();
            let stage = now.duration_since(last_t).as_millis();
            let total = now.duration_since(stage_start).as_millis();
            eprintln!("[stage-trace] +{stage}ms (total {total}ms): {label}");
            last_t = now;
        }
    };
    log("compile_translation_unit start");
    let (haystack_bytes, haystack_len) = pack_haystack(&prepared.source);
    log("pack_haystack");

    // --- A: lexer ---
    let lex_plan = c11_lex_program_for_source(
        &prepared.source,
        haystack_len,
        "out_tok_types",
        "out_tok_starts",
        "out_tok_lens",
        "out_counts",
    );
    let lex_prog = &lex_plan.program;
    validate_internal_stage(lex_prog, "c11_lexer")?;
    // Strict dispatch backends (CUDA, and wgpu under stricter validation
    // modes) reject submissions with fewer host buffers than declared
    // `BufferDecl`s; lenient backends auto-allocate the missing RW outputs
    // from `with_count`. `pad_dispatch_inputs` pads supplied inputs with
    // zero-filled Vec<u8>s sized per each remaining `BufferDecl.count`,
    // making the supply contract explicit and portable across backend
    // strictness. Applied at every dispatch site below.
    let lex_in = pad_dispatch_inputs(lex_prog, vec![haystack_bytes.clone()]);
    let mut dcfg = DispatchConfig::default();
    dcfg.label = Some(format!("vyre-frontend-c lex {}", path.display()));
    let mut lex_out = backend
        .dispatch(lex_prog, &lex_in, &dcfg)
        .map_err(|e| format!("c11_lexer dispatch failed: {e}"))?;
    log("dispatch c11_lexer");
    if lex_out.len() < 4 {
        return Err("lexer: expected 4 output buffers".to_string());
    }
    let counts_raw = lex_out.remove(3);
    let lens_raw = lex_out.remove(2);
    let starts_raw = lex_out.remove(1);
    let types_raw = lex_out.remove(0);
    let (mut types, mut starts, mut lens, counts, n_tokens) = if lex_plan.sparse_output {
        compact_sparse_lexer_outputs(
            &prepared.source,
            &types_raw,
            &starts_raw,
            &lens_raw,
            haystack_len,
        )?
    } else {
        let n_tokens = read_u32_at(&counts_raw, 0).map_err(|e| format!("lexer count: {e}"))?;
        (types_raw, starts_raw, lens_raw, counts_raw, n_tokens)
    };
    truncate_lexer_outputs_to_logical_tokens(&mut types, &mut starts, &mut lens, n_tokens)?;

    // --- B: keyword promotion ---
    //
    // Digraph/line-splice rewriting is already inside `c11_lex_single_pass`;
    // the live path must not pay a separate dispatch or host clone for it.
    if lex_plan.sparse_output {
        promote_keywords_host(&prepared.source, &mut types, &starts, &lens, n_tokens)?;
        log("host c_keyword");
    } else if !lex_plan.keyword_promoted {
        let keyword_map_words = c_keyword_map_words();
        let keyword_map_bytes = vec_u32_le_bytes(&keyword_map_words);
        let keyword_prog = c_keyword(
            "tok_types",
            "tok_starts",
            "tok_lens",
            "counts",
            "haystack",
            "keyword_map",
            n_tokens.max(1),
            C_KEYWORDS.len() as u32,
            haystack_len.max(1),
        );
        validate_internal_stage(&keyword_prog, "c_keyword")?;

        dcfg.label = Some(format!("vyre-frontend-c keyword {}", path.display()));
        let mut keyword_out = backend
            .dispatch_borrowed(
                &keyword_prog,
                &[
                    &types,
                    &starts,
                    &lens,
                    &counts,
                    &haystack_bytes,
                    &keyword_map_bytes,
                ],
                &dcfg,
            )
            .map_err(|e| format!("c_keyword dispatch failed: {e}"))?;
        log("dispatch c_keyword");
        if !keyword_out.is_empty() {
            types = keyword_out.remove(0);
        }
    } else {
        log("skip c_keyword; lexer promoted keywords");
    }

    let tok_types = token_types_from_lex(&types, n_tokens)?;
    let mut start_words = read_u32_stream(&starts, n_tokens as usize, "token starts")?;
    let mut len_words = read_u32_stream(&lens, n_tokens as usize, "token lengths")?;
    repair_token_spans_from_source(
        &prepared.source,
        &tok_types,
        &mut start_words,
        &mut len_words,
    )?;
    log("host repair_token_spans_from_source");
    let starts_logical = vec_u32_le_bytes(&start_words);
    let lens_logical = vec_u32_le_bytes(&len_words);
    reject_c11_lexer_diagnostics(path, &tok_types, &starts_logical, &lens_logical)?;

    // --- C: conditional preprocessor mask for the resident token stream ---
    let types_prefix_len = n_tokens.max(1) as usize * 4;
    if types_prefix_len > types.len() {
        return Err(format!(
            "preprocessor token types: need {types_prefix_len} bytes for {} u32 words, have {}",
            n_tokens.max(1),
            types.len()
        ));
    }
    let types_prefix = &types[..types_prefix_len];
    let preproc_mask = if prepared.source.as_bytes().contains(&b'#') {
        let mask_prog = opt_conditional_mask("tok_types", "mask", Expr::u32(n_tokens.max(1)));
        validate_internal_stage(&mask_prog, "opt_conditional_mask")?;
        let preproc_mask_init = vec![0u8; types_prefix_len];
        dcfg.label = Some(format!("vyre-frontend-c cpp-mask {}", path.display()));
        let mask_out = backend
            .dispatch_borrowed(&mask_prog, &[types_prefix, &preproc_mask_init], &dcfg)
            .map_err(|e| format!("opt_conditional_mask dispatch failed: {e}"))?;
        log("dispatch cpp-mask");
        mask_out.into_iter().next().unwrap_or_default()
    } else {
        log("skip cpp-mask; no directives");
        vec_u32_le_bytes(&vec![1u32; n_tokens.max(1) as usize])
    };

    // --- D: macro-token snapshot ---
    // Includes and CLI defines have been converted into one resident source stream; macro,
    // conditional, and directive semantics stay in GPU-visible token/preprocessor lanes.

    let types_logical = vec_u32_le_bytes(&tok_types);
    let (paren_pairs, brace_pairs) = c11_dual_bracket_pairs_cost_model(
        backend,
        &tok_types,
        &format!("vyre-frontend-c c11-brackets {}", path.display()),
    )?;
    log("dispatch c11 dual bracket pairs");
    // Hoist the u32-to-byte pack of paren/brace pairs out of the
    // per-dispatch input vectors. Both are consumed at three sites
    // (extract_functions, extract_calls, the section blob); without
    // this hoist each was repacked from `Vec<u32>` to `Vec<u8>` on
    // each consume — a (n_tokens × 4) byte memcpy per call. For real
    // Linux files with millions of tokens the repacks were tens of MB
    // per compile of pure redundant work.
    let paren_bytes = vec_u32_le_bytes(&paren_pairs);
    let brace_bytes = vec_u32_le_bytes(&brace_pairs);

    let nt = n_tokens.max(1);
    let (fn_records, fn_slot_count) =
        if nt <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_STRUCTURE").is_none() {
            let (records, counts, words) =
                c11_extract_functions_host(&tok_types, &paren_pairs, &brace_pairs);
            let _ = counts;
            log("host c11_extract_functions");
            (records, words)
        } else {
            let fn_prog = c11_extract_functions(
                "tok_types",
                "paren_pairs",
                "brace_pairs",
                Expr::u32(nt),
                "out_functions",
                "out_counts",
            );
            validate_internal_stage(&fn_prog, "c11_extract_functions")?;
            let fn_records_init = vec![0u8; nt as usize * 3 * 4];
            let fn_counts_init = vec![0u8; 4];
            dcfg.label = Some(format!("vyre-frontend-c functions {}", path.display()));
            let fn_out = backend
                .dispatch_borrowed(
                    &fn_prog,
                    &[
                        &types_logical,
                        &paren_bytes,
                        &brace_bytes,
                        &fn_records_init,
                        &fn_counts_init,
                    ],
                    &dcfg,
                )
                .map_err(|e| format!("c11_extract_functions dispatch failed: {e}"))?;
            log("dispatch c11_extract_functions");
            if fn_out.len() < 2 {
                return Err("extract_functions: expected 2 outputs".to_string());
            }
            let fn_slot_count =
                read_u32_at(&fn_out[1], 0).map_err(|e| format!("function count: {e}"))?;
            (fn_out[0].clone(), fn_slot_count)
        };
    let n_fn = (fn_slot_count / 3).max(1);

    let fn_words = (n_fn * 3).max(3) as usize;
    let mut fn_buf = vec![0u8; fn_words * 4];
    let copy_len = fn_records.len().min(fn_buf.len());
    fn_buf[..copy_len].copy_from_slice(&fn_records[..copy_len]);

    let call_records =
        if nt <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_STRUCTURE").is_none() {
            let fn_words_for_host = read_u32_stream(&fn_buf, fn_words, "host function records")?;
            let (records, _counts) =
                c11_extract_calls_host(&tok_types, &paren_pairs, &fn_words_for_host, n_fn);
            log("host c11_extract_calls");
            records
        } else {
            let call_prog = c11_extract_calls(
                "tok_types",
                "paren_pairs",
                "functions",
                Expr::u32(nt),
                Expr::u32(n_fn),
                "out_calls",
                "out_counts",
            );
            validate_internal_stage(&call_prog, "c11_extract_calls")?;
            dcfg.label = Some(format!("vyre-frontend-c calls {}", path.display()));
            let call_records_init = vec![0u8; nt as usize * 4 * 4];
            let call_counts_init = vec![0u8; 4];
            let call_out = backend
                .dispatch_borrowed(
                    &call_prog,
                    &[
                        &types_logical,
                        &paren_bytes,
                        &fn_buf,
                        &call_records_init,
                        &call_counts_init,
                    ],
                    &dcfg,
                )
                .map_err(|e| format!("c11_extract_calls dispatch failed: {e}"))?;
            log("dispatch c11_extract_calls");
            if call_out.is_empty() {
                return Err("extract_calls: no outputs".to_string());
            }
            call_out[0].clone()
        };

    // --- ABI layout ---
    let type_defs = c_abi_type_table_bytes(&tok_types);
    let type_count = u32::try_from(type_defs.len() / 4)
        .map_err(|_| "ABI type table exceeds u32 count".to_string())?
        .max(1);
    let align_prog = c11_compute_alignments("types", "sizes", "aligns", Expr::u32(type_count));
    validate_internal_stage(&align_prog, "c11_compute_alignments")?;
    let sz_init = vec![0u8; type_count as usize * 4];
    let al_init = vec![0u8; type_count as usize * 4];
    let mut abi_blob = Vec::new();
    dcfg.label = Some(format!("vyre-frontend-c abi {}", path.display()));
    let abi_out = backend
        .dispatch_borrowed(&align_prog, &[&type_defs, &sz_init, &al_init], &dcfg)
        .map_err(|e| format!("c11_compute_alignments dispatch failed: {e}"))?;
    log("dispatch c11_compute_alignments");
    if abi_out.len() < 2 {
        return Err("c11_compute_alignments: expected sizes and alignments outputs".to_string());
    }
    abi_blob.extend_from_slice(&abi_out[0]);
    abi_blob.extend_from_slice(&abi_out[1]);

    let (stmt_pairs, num_stmt) = c11_statement_bounds_host(&tok_types, nt);
    let stmt_bytes = vec_u32_le_bytes(&stmt_pairs);
    let ast_capacity = n_tokens.max(1).min(MAX_TOK_SCAN);
    let ast_prog = ast_shunting_yard_with_capacity(
        "tok_types",
        "statements",
        Expr::u32(num_stmt),
        "out_ast_nodes",
        "out_ast_count",
        "out_statement_roots",
        "scratch_val_stack",
        "scratch_op_stack",
        ast_capacity,
    );
    let mut ast_blob = Vec::new();
    validate_internal_stage(&ast_prog, "ast_shunting_yard")?;
    let ast_in = pad_dispatch_inputs(
        &ast_prog,
        build_ast_inputs_with_capacity(&tok_types, &stmt_bytes, num_stmt, ast_capacity),
    );
    dcfg.label = Some(format!("vyre-frontend-c ast {}", path.display()));
    let ast_out = backend
        .dispatch(&ast_prog, &ast_in, &dcfg)
        .map_err(|e| format!("ast_shunting_yard dispatch failed: {e}"))?;
    log("dispatch ast_shunting_yard");
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
            &types_logical,
            &starts_logical,
            &lens_logical,
            prepared.source.as_bytes(),
            &haystack_bytes,
            haystack_len,
            nt,
        )?;
    log("build_vast_and_pg");
    let sema_blob = build_sema_scope(
        backend,
        path,
        &tok_types,
        &start_words,
        &len_words,
        prepared.source.as_bytes(),
        &types_logical,
        &starts_logical,
        &lens_logical,
        &haystack_bytes,
        haystack_len,
        nt,
    )?;
    log("build_sema_scope");

    // --- CFG / goto ---
    let cfg_ssa = cfg_ssa_words_from_vast(&vast_blob)?;
    let n_ssa = u32::try_from(cfg_ssa.len())
        .map_err(|_| "CFG SSA stream exceeds u32 count".to_string())?
        .max(1);
    let ssa_buf = vec_u32_le_bytes(&cfg_ssa);
    let cfg_prog = c11_build_cfg_and_gotos("ssa", "cfg", "labels", Expr::u32(n_ssa));
    let mut cfg_blob = Vec::new();
    validate_internal_stage(&cfg_prog, "c11_build_cfg_and_gotos")?;
    let cfg_init = vec![0u8; n_ssa as usize * 4];
    let lbl_init = vec![0u8; n_ssa as usize * 4];
    let k_init = vec![0u8; 4096 * 4];
    let v_init = vec![0u8; 4096 * 4];
    dcfg.label = Some(format!("vyre-frontend-c cfg {}", path.display()));
    let cfg_out = backend
        .dispatch_borrowed(
            &cfg_prog,
            &[&ssa_buf, &cfg_init, &lbl_init, &k_init, &v_init],
            &dcfg,
        )
        .map_err(|e| format!("c11_build_cfg_and_gotos dispatch failed: {e}"))?;
    log("dispatch c11_build_cfg_and_gotos");
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
    log("try_dispatch_elf");

    let lex_section = crate::object_format::build_vyrecob1_lex_section(
        path,
        &types_logical,
        &starts_logical,
        &lens_logical,
        n_tokens,
    )?;

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
        (SectionTag::Calls, call_records.as_slice()),
        (SectionTag::Elf, elf_blob.as_slice()),
        (SectionTag::PreprocMask, preproc_mask.as_slice()),
        (SectionTag::MacroTypes, types_logical.as_slice()),
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
    let vyrecob2 = crate::object_format::serialize_vyrecob2(&sections)
        .map_err(|error| format!("VYRECOB2 serialization failed: {error}"))?;
    let elf_obj = crate::elf_linux::emit_translation_unit_relocatable(&vyrecob2, path)?;
    fs::write(dest, elf_obj).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(())
}

pub(crate) fn validate_internal_stage(
    program: &Program,
    stage: &str,
) -> Result<(), String> {
    if std::env::var_os("VYRE_FRONTEND_C_VALIDATE_STAGES").is_none() {
        return Ok(());
    }
    let errors = vyre::validate(program);
    if errors.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{stage} IR validation failed: {errors:?}. Fix: repair the generated parser Program before dispatch."
    ))
}

/// Full GPU pipeline for one or more translation units; writes **ELF64 ET_REL** per TU.
pub fn compile_c11_sources(options: &VyreCompileOptions) -> Result<(), String> {
    if options.output_file.is_some() && options.input_files.len() > 1 {
        return Err(
            "vyre-frontend-c: -o with multiple inputs is not supported yet; compile one TU at a time."
                .to_string(),
        );
    }

    let mut prepared = Vec::with_capacity(options.input_files.len());
    for path in &options.input_files {
        let dest: PathBuf = if options.input_files.len() == 1 {
            options
                .output_file
                .clone()
                .unwrap_or_else(|| path.with_extension("o"))
        } else {
            path.with_extension("o")
        };
        prepared.push(prepare_translation_unit(path, dest, options)?);
    }

    let backend = shared_dispatch_backend()?;

    for unit in &prepared {
        compile_translation_unit(backend.as_ref(), unit)?;
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

    let final_out = options
        .output_file
        .clone()
        .unwrap_or_else(|| PathBuf::from("a.out"));

    let tmp = std::env::temp_dir();
    let pid = std::process::id();
    let mut obj_paths: Vec<PathBuf> = Vec::new();
    let mut prepared = Vec::with_capacity(options.input_files.len());

    for (i, path) in options.input_files.iter().enumerate() {
        let o_path = tmp.join(format!("vyrec_link_{pid}_{i}.o"));
        prepared.push(prepare_translation_unit(path, o_path.clone(), options)?);
        obj_paths.push(o_path);
    }

    let backend = shared_dispatch_backend()?;

    for unit in &prepared {
        compile_translation_unit(backend.as_ref(), unit)?;
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
    let mut cleanup_errors = Vec::new();
    remove_temp_link_file(&start_path, "startup object", &mut cleanup_errors);
    for o in &obj_paths {
        remove_temp_link_file(o, "input object", &mut cleanup_errors);
    }
    if !st.success() {
        let cleanup_context = if cleanup_errors.is_empty() {
            String::new()
        } else {
            format!(" Cleanup also failed: {}", cleanup_errors.join("; "))
        };
        return Err(format!(
            "{cc} -nostdlib link failed with status {st}.{cleanup_context} Fix: install a working toolchain, or set CC."
        ));
    }
    if !cleanup_errors.is_empty() {
        return Err(format!(
            "temporary link artifact cleanup failed: {}. Fix: verify output directory permissions and remove stale temporary objects before rerunning.",
            cleanup_errors.join("; ")
        ));
    }
    Ok(())
}

fn remove_temp_link_file(path: &Path, label: &str, cleanup_errors: &mut Vec<String>) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => cleanup_errors.push(format!("{label} `{}`: {error}", path.display())),
    }
}
