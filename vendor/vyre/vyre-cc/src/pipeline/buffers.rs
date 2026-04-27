use std::path::Path;

use vyre_libs::compiler::types_layout::{C_ABI_CHAR, C_ABI_LONG, C_ABI_POINTER};
use vyre_libs::parsing::c::lex::diagnostics::{first_c11_lexer_diagnostic, C11LexerDiagnosticKind};
use vyre_libs::parsing::c::lex::tokens::{
    is_c_lexer_error_token, TOK_CHAR_KW, TOK_DOUBLE, TOK_FLOAT_KW, TOK_INT, TOK_LONG,
    TOK_SEMICOLON, TOK_SHORT, TOK_STAR, TOK_VOID,
};
use vyre_libs::parsing::c::parse::vast::{C_AST_KIND_GOTO_STMT, C_AST_KIND_LABEL_STMT};
use vyre_primitives::matching::bracket_match::{pack_u32, CLOSE_BRACE, OPEN_BRACE, OTHER};
use vyre_runtime::megakernel::protocol;

use super::{MAX_STMT_THREADS, MAX_TOK_SCAN};

pub(super) fn u32_slice_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

pub(super) fn read_u32_at(buf: &[u8], off: usize) -> Result<u32, String> {
    let end = off.saturating_add(4);
    if end > buf.len() {
        return Err(format!(
            "buffer too short for u32 read at byte {off}: need {end} bytes, have {}",
            buf.len()
        ));
    }
    let bytes: [u8; 4] = buf[off..end]
        .try_into()
        .map_err(|_| format!("failed to decode u32 at byte {off}"))?;
    Ok(u32::from_le_bytes(bytes))
}

pub(super) fn pack_haystack(source: &str) -> (Vec<u8>, u32) {
    let haystack_u32_count = u32::try_from(source.len()).unwrap_or(u32::MAX).max(1);
    let mut words = vec![0u32; haystack_u32_count as usize];
    for (i, b) in source.bytes().enumerate() {
        words[i] = u32::from(b);
    }
    (u32_slice_to_bytes(&words), haystack_u32_count)
}

pub(super) fn map_bracket_kind(tok: u32, open: u32, close: u32) -> u32 {
    if tok == open {
        OPEN_BRACE
    } else if tok == close {
        CLOSE_BRACE
    } else {
        OTHER
    }
}

pub(super) fn token_types_from_lex(types_buf: &[u8], n_tokens: u32) -> Result<Vec<u32>, String> {
    let n = n_tokens as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(
            read_u32_at(types_buf, i.saturating_mul(4))
                .map_err(|error| format!("token type buffer: {error}"))?,
        );
    }
    Ok(out)
}

pub(super) fn reject_c11_lexer_diagnostics(
    path: &Path,
    tok_types: &[u32],
    starts_buf: &[u8],
    lens_buf: &[u8],
) -> Result<(), String> {
    if !tok_types.iter().copied().any(is_c_lexer_error_token) {
        return Ok(());
    }
    let tok_starts = read_u32_stream(starts_buf, tok_types.len(), "lexer diagnostic starts")?;
    let tok_lens = read_u32_stream(lens_buf, tok_types.len(), "lexer diagnostic lengths")?;
    let diag = first_c11_lexer_diagnostic(tok_types, &tok_starts, &tok_lens).ok_or_else(|| {
        format!(
            "C lexer emitted an error token for {}, but no diagnostic decoded from token buffers. \
             Fix: keep token kind/start/length buffers aligned before parser entry.",
            path.display()
        )
    })?;
    let token_kind = tok_types
        .get(diag.token_index as usize)
        .copied()
        .unwrap_or_default();
    let detail = match diag.kind {
        C11LexerDiagnosticKind::UnterminatedString => "unterminated string literal",
        C11LexerDiagnosticKind::UnterminatedChar => "unterminated character literal",
        C11LexerDiagnosticKind::UnterminatedBlockComment => "unterminated block comment",
        C11LexerDiagnosticKind::InvalidEscape => "invalid string or character escape",
    };
    Err(format!(
        "C lexer rejected {}: {detail} ({:?}, token kind {token_kind}) at token index {}, \
         byte span [{}..{}), length {}. Fix: correct the malformed C token before parser, VAST, \
         or ProgramGraph lowering.",
        path.display(),
        diag.kind,
        diag.token_index,
        diag.byte_start,
        diag.byte_start.saturating_add(diag.byte_len),
        diag.byte_len
    ))
}

pub(super) fn u32_prefix_bytes(buf: &[u8], words: u32, label: &str) -> Result<Vec<u8>, String> {
    let bytes = words as usize * 4;
    if bytes > buf.len() {
        return Err(format!(
            "{label}: need {bytes} bytes for {words} u32 words, have {}",
            buf.len()
        ));
    }
    Ok(buf[..bytes].to_vec())
}

pub(super) fn read_u32_stream(buf: &[u8], words: usize, label: &str) -> Result<Vec<u32>, String> {
    let mut out = Vec::with_capacity(words);
    for i in 0..words {
        out.push(
            read_u32_at(buf, i.saturating_mul(4)).map_err(|error| format!("{label}: {error}"))?,
        );
    }
    Ok(out)
}

pub(super) fn vec_u32_le_bytes(words: &[u32]) -> Vec<u8> {
    pack_u32(words)
}

pub(super) fn match_none_init(n: usize) -> Vec<u8> {
    std::iter::repeat_with(|| u32::MAX.to_le_bytes())
        .take(n)
        .flatten()
        .collect()
}

pub(super) fn c_abi_type_table_bytes(tok_types: &[u32]) -> Vec<u8> {
    let mut type_kinds = Vec::with_capacity(tok_types.len().max(1));
    for tok in tok_types.iter().copied() {
        let kind = match tok {
            TOK_CHAR_KW => Some(C_ABI_CHAR),
            TOK_STAR => Some(C_ABI_POINTER),
            TOK_LONG | TOK_DOUBLE => Some(C_ABI_LONG),
            TOK_INT | TOK_SHORT | TOK_FLOAT_KW | TOK_VOID => Some(0),
            _ => None,
        };
        if let Some(kind) = kind {
            type_kinds.push(kind);
        }
    }
    if type_kinds.is_empty() {
        type_kinds.push(0);
    }
    vec_u32_le_bytes(&type_kinds)
}

pub(super) fn cfg_ssa_words_from_vast(vast_blob: &[u8]) -> Result<Vec<u32>, String> {
    const VAST_NODE_STRIDE_U32: usize = 10;
    const IDX_KIND: usize = 0;
    const IDX_NEXT_SIBLING: usize = 3;
    const IDX_SYMBOL_HASH: usize = 9;
    const SSA_LABEL_OPCODE: u32 = 0x4C41_424C;
    const SSA_GOTO_OPCODE: u32 = 0x474F_544F;

    if vast_blob.len() % 4 != 0 {
        return Err(format!(
            "typed VAST blob length must be u32-aligned before CFG lowering: {} bytes",
            vast_blob.len()
        ));
    }
    let words = read_u32_stream(vast_blob, vast_blob.len() / 4, "typed VAST words")?;
    let rows: Vec<&[u32]> = words.chunks_exact(VAST_NODE_STRIDE_U32).collect();
    let mut ssa = Vec::new();
    for row in &rows {
        match row[IDX_KIND] {
            C_AST_KIND_LABEL_STMT => {
                let hash = row[IDX_SYMBOL_HASH];
                if hash != 0 {
                    ssa.extend_from_slice(&[SSA_LABEL_OPCODE, hash]);
                }
            }
            C_AST_KIND_GOTO_STMT => {
                let target_idx = row[IDX_NEXT_SIBLING] as usize;
                let target_hash = rows
                    .get(target_idx)
                    .and_then(|target| target.get(IDX_SYMBOL_HASH))
                    .copied()
                    .unwrap_or_default();
                if target_hash != 0 {
                    ssa.extend_from_slice(&[SSA_GOTO_OPCODE, target_hash]);
                }
            }
            _ => {}
        }
    }
    if ssa.is_empty() {
        ssa.push(0);
    }
    Ok(ssa)
}

pub(super) fn compiler_words_from_sections(
    sections: &[&[u8]],
    max_words: usize,
) -> Result<Vec<u32>, String> {
    const SECTION_MARKER: u32 = 0x5659_5245; // "VYRE"
    const SECTION_HEADER_WORDS: usize = 4;

    if max_words < sections.len().saturating_mul(SECTION_HEADER_WORDS) {
        return Err(format!(
            "compiler lowering capacity {max_words} words cannot hold {} section headers. \
             Fix: increase the ELF lowering input budget or reduce section count.",
            sections.len()
        ));
    }

    let non_empty_count = sections
        .iter()
        .filter(|section| !section.is_empty())
        .count();
    if non_empty_count == 0 {
        return Err(
            "compiler lowering input has no parser/lowering section data. \
             Fix: run VAST/ProgramGraph lowering before ELF lowering."
                .to_string(),
        );
    }

    let payload_budget = max_words.saturating_sub(sections.len() * SECTION_HEADER_WORDS);
    let per_section_budget = payload_budget / non_empty_count.max(1);
    let mut payload_remainder = payload_budget % non_empty_count.max(1);
    let mut words = Vec::new();
    for (section_idx, section) in sections.iter().enumerate() {
        if section.len() % 4 != 0 {
            return Err(format!(
                "compiler section {section_idx} length is not u32-aligned: {} bytes. \
                 Fix: only feed packed parser/lowering u32 streams into ELF lowering.",
                section.len()
            ));
        }
        let section_words = read_u32_stream(section, section.len() / 4, "compiler section words")?;
        let section_hash = fnv1a32_words(&section_words);
        words.extend_from_slice(&[
            SECTION_MARKER,
            section_idx as u32,
            u32::try_from(section_words.len())
                .map_err(|_| format!("compiler section {section_idx} exceeds u32 word count"))?,
            section_hash,
        ]);

        let mut take_words = per_section_budget.min(section_words.len());
        if payload_remainder != 0 && take_words < section_words.len() {
            take_words = take_words.saturating_add(1);
            payload_remainder -= 1;
        }
        words.extend(section_words.iter().take(take_words).copied());
    }
    Ok(words)
}

fn fnv1a32_words(words: &[u32]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for word in words {
        for byte in word.to_le_bytes() {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
    }
    hash
}

pub(super) fn pad_tok_scan(mut v: Vec<u32>) -> Vec<u32> {
    v.resize(MAX_TOK_SCAN as usize, 0);
    v
}

pub(super) fn c11_statement_bounds_host(tokens: &[u32], n_tokens: u32) -> (Vec<u32>, u32) {
    let cap = n_tokens.clamp(1, MAX_TOK_SCAN);
    let n = cap as usize;
    let mut pairs: Vec<u32> = Vec::new();
    let mut start: u32 = 0;
    let mut stmt_count: u32 = 0;
    for i in 0..n {
        if tokens.get(i).copied() == Some(TOK_SEMICOLON) {
            let end = (i as u32).saturating_add(1).min(MAX_TOK_SCAN);
            pairs.push(start);
            pairs.push(end);
            start = end;
            stmt_count = stmt_count.saturating_add(1);
            if stmt_count >= MAX_STMT_THREADS {
                break;
            }
        }
    }
    if start < cap
        && stmt_count < MAX_STMT_THREADS
        && (pairs.is_empty() || pairs[pairs.len() - 1] != cap)
    {
        pairs.push(start);
        pairs.push(cap);
    }
    if pairs.is_empty() {
        return (vec![0, cap], 1);
    }
    let num_stmt = (pairs.len() / 2) as u32;
    (pairs, num_stmt.max(1))
}

pub(super) fn build_ast_inputs(tok_pad: &[u32], stmt_bytes: &[u8], num_stmt: u32) -> Vec<Vec<u8>> {
    let tok_b = pack_u32(tok_pad);
    let out_ast = vec![0u8; MAX_TOK_SCAN as usize * 4 * 4];
    let out_cnt = vec![0u8; 4];
    let roots_words = num_stmt.max(1);
    let out_roots = vec![0u8; roots_words as usize * 4];
    let scratch_words = num_stmt.saturating_mul(64).max(64);
    let scratch_v = vec![0u8; scratch_words as usize * 4];
    let scratch_o = vec![0u8; scratch_words as usize * 4];
    vec![
        tok_b,
        stmt_bytes.to_vec(),
        out_ast,
        out_cnt,
        out_roots,
        scratch_v,
        scratch_o,
    ]
}

pub(super) fn megakernel_section_bytes(
    token_count: u32,
    function_count: u32,
    cfg_word_count: u32,
    section_tags: &[u32],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MEGAKERN2");
    bytes.extend_from_slice(&protocol::SLOT_WORDS.to_le_bytes());
    bytes.extend_from_slice(&token_count.to_le_bytes());
    bytes.extend_from_slice(&function_count.to_le_bytes());
    bytes.extend_from_slice(&cfg_word_count.to_le_bytes());
    bytes.extend_from_slice(&(section_tags.len() as u32).to_le_bytes());
    for tag in section_tags {
        bytes.extend_from_slice(&tag.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_libs::parsing::c::lex::tokens::{TOK_IDENTIFIER, TOK_INT, TOK_INTEGER};

    #[test]
    fn statement_bounds_splits_on_semicolon() {
        let toks = vec![TOK_INTEGER, TOK_SEMICOLON, TOK_INTEGER, TOK_SEMICOLON];
        let (pairs, n) = c11_statement_bounds_host(&toks, 4);
        assert_eq!(n, 2);
        assert_eq!(pairs, vec![0, 2, 2, 4]);
    }

    #[test]
    fn statement_bounds_empty_tail() {
        let toks = vec![TOK_INT, TOK_IDENTIFIER, TOK_SEMICOLON];
        let (pairs, n) = c11_statement_bounds_host(&toks, 3);
        assert_eq!(n, 1);
        assert_eq!(pairs, vec![0, 3]);
    }
}
