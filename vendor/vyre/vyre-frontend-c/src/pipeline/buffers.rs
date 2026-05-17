use std::path::Path;

use vyre_libs::compiler::types_layout::{C_ABI_CHAR, C_ABI_LONG, C_ABI_POINTER};
use vyre_libs::parsing::c::lex::diagnostics::{first_c11_lexer_diagnostic, C11LexerDiagnosticKind};
use vyre_libs::parsing::c::lex::tokens::*;
use vyre_libs::parsing::c::parse::vast::{C_AST_KIND_GOTO_STMT, C_AST_KIND_LABEL_STMT};
use vyre_runtime::megakernel::protocol;

use super::{MAX_STMT_THREADS, MAX_TOK_SCAN};

pub(super) fn u32_slice_to_bytes(words: &[u32]) -> Vec<u8> {
    fast_pack_u32_le(words)
}

/// Pack a `&[u32]` as a `Vec<u8>` of little-endian bytes with one
/// up-front allocation and a 4-byte memcpy per word. Token streams in
/// this pipeline reach millions of elements on real Linux files; the
/// previous `iter().flat_map(|w| w.to_le_bytes()).collect()` pattern
/// paid per-element iterator overhead and grow-on-push amortization
/// on the output Vec. Pre-allocating the exact size and using
/// `extend_from_slice` of `to_le_bytes()` collapses both costs while
/// staying within the crate's `#![forbid(unsafe_code)]` policy.
#[inline]
pub(super) fn fast_pack_u32_le(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len().saturating_mul(4));
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Pad a dispatch input vector with zero-filled Vec<u8>s sized per the
/// program's **input** `BufferDecl` count.
///
/// The dispatcher (`vyre-driver/src/binding.rs::validate_input_lengths`)
/// expects host inputs to equal exactly the count of buffers whose role is
/// `Input` / `InputOutput` / `Uniform`. Output / WriteOnly / Shared buffers
/// are allocated by the backend, not passed in. Sites must supply input
/// buffers in declaration order (skipping non-input buffers).
///
/// Why this helper exists: strict dispatch backends (CUDA) reject
/// under-supplied OR over-supplied submissions; wgpu under earlier
/// validation modes was lenient. Wiring CUDA into vyrec exposed every
/// site's drift from the strict contract. The pipeline.rs sites supply the
/// known input buffers in source order; this helper rounds out the rest of
/// the input count with zeros sized per `with_count`. Output buffers are
/// not padded — supplying them would over-shoot the input count.
pub(super) fn pad_dispatch_inputs(
    program: &vyre_foundation::ir::Program,
    mut supplied: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let input_buffers: Vec<&vyre_foundation::ir::BufferDecl> = program
        .buffers
        .iter()
        .filter(|b| is_input_buffer(b))
        .collect();
    for buf in input_buffers.iter().skip(supplied.len()) {
        let elem_count = (buf.count as usize).max(1);
        // U32 element assumption holds for every C-parser op; non-U32 elements
        // would mis-size the zeros and the dispatcher would reject with a
        // size mismatch — loud, not silent.
        supplied.push(vec![0u8; elem_count.saturating_mul(4)]);
    }
    supplied
}

fn is_input_buffer(buf: &vyre_foundation::ir::BufferDecl) -> bool {
    use vyre_foundation::ir::BufferAccess;
    if buf.is_output {
        return false;
    }
    matches!(
        buf.access,
        BufferAccess::ReadOnly | BufferAccess::ReadWrite | BufferAccess::Uniform
    )
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
    let mut bytes = vec![0u8; haystack_u32_count as usize * 4];
    for (i, byte) in source.bytes().enumerate() {
        bytes[i * 4] = byte;
    }
    (bytes, haystack_u32_count)
}

pub(super) fn reject_c11_source_diagnostics(path: &Path, source: &str) -> Result<(), String> {
    let bytes = source.as_bytes();
    let mut token_index = 0u32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if let Some((kind, start, len)) = scan_quoted(bytes, i, b'"') {
                    return Err(format_source_diagnostic(
                        path,
                        kind,
                        token_index,
                        start,
                        len,
                    ));
                }
                token_index = token_index.saturating_add(1);
                i = skip_quoted(bytes, i, b'"');
            }
            b'\'' => {
                if let Some((kind, start, len)) = scan_quoted(bytes, i, b'\'') {
                    return Err(format_source_diagnostic(
                        path,
                        kind,
                        token_index,
                        start,
                        len,
                    ));
                }
                token_index = token_index.saturating_add(1);
                i = skip_quoted(bytes, i, b'\'');
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                if let Some(end) = find_block_comment_end(bytes, i + 2) {
                    token_index = token_index.saturating_add(1);
                    i = end;
                } else {
                    return Err(format_source_diagnostic(
                        path,
                        C11LexerDiagnosticKind::UnterminatedBlockComment,
                        token_index,
                        i,
                        bytes.len().saturating_sub(i),
                    ));
                }
            }
            byte if byte.is_ascii_whitespace() => {
                i += 1;
            }
            _ => {
                token_index = token_index.saturating_add(1);
                i += 1;
            }
        }
    }
    Ok(())
}

fn format_source_diagnostic(
    path: &Path,
    kind: C11LexerDiagnosticKind,
    token_index: u32,
    byte_start: usize,
    byte_len: usize,
) -> String {
    let detail = match kind {
        C11LexerDiagnosticKind::UnterminatedString => "unterminated string literal",
        C11LexerDiagnosticKind::UnterminatedChar => "unterminated character literal",
        C11LexerDiagnosticKind::UnterminatedBlockComment => "unterminated block comment",
        C11LexerDiagnosticKind::InvalidEscape => "invalid string or character escape",
    };
    format!(
        "C lexer rejected {}: {detail} ({kind:?}, token kind {kind:?}) at token index {}, \
         byte span [{}..{}), length {}. Fix: correct the malformed C token before parser, VAST, \
         or ProgramGraph lowering.",
        path.display(),
        token_index,
        byte_start,
        byte_start.saturating_add(byte_len),
        byte_len
    )
}

fn scan_quoted(
    bytes: &[u8],
    quote_start: usize,
    quote: u8,
) -> Option<(C11LexerDiagnosticKind, usize, usize)> {
    let mut i = quote_start + 1;
    while i < bytes.len() {
        match bytes[i] {
            byte if byte == quote => return None,
            b'\n' | b'\r' => {
                let kind = if quote == b'"' {
                    C11LexerDiagnosticKind::UnterminatedString
                } else {
                    C11LexerDiagnosticKind::UnterminatedChar
                };
                return Some((kind, quote_start, i.saturating_sub(quote_start)));
            }
            b'\\' => {
                let Some(next) = bytes.get(i + 1).copied() else {
                    return Some((C11LexerDiagnosticKind::InvalidEscape, i, 1));
                };
                match escape_width(bytes, i + 1, next) {
                    Some(width) => i += 1 + width,
                    None => return Some((C11LexerDiagnosticKind::InvalidEscape, i, 2)),
                }
            }
            _ => i += 1,
        }
    }
    let kind = if quote == b'"' {
        C11LexerDiagnosticKind::UnterminatedString
    } else {
        C11LexerDiagnosticKind::UnterminatedChar
    };
    Some((kind, quote_start, bytes.len().saturating_sub(quote_start)))
}

fn skip_quoted(bytes: &[u8], quote_start: usize, quote: u8) -> usize {
    let mut i = quote_start + 1;
    while i < bytes.len() {
        match bytes[i] {
            byte if byte == quote => return i + 1,
            b'\\' => i = i.saturating_add(2),
            _ => i += 1,
        }
    }
    bytes.len()
}

fn escape_width(bytes: &[u8], escape_start: usize, next: u8) -> Option<usize> {
    match next {
        b'\'' | b'"' | b'?' | b'\\' | b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' => Some(1),
        b'0'..=b'7' => {
            let mut width = 1usize;
            while width < 3
                && bytes
                    .get(escape_start + width)
                    .is_some_and(u8::is_ascii_digit)
            {
                if !matches!(bytes[escape_start + width], b'0'..=b'7') {
                    break;
                }
                width += 1;
            }
            Some(width)
        }
        b'x' => {
            let mut width = 1usize;
            while bytes
                .get(escape_start + width)
                .is_some_and(u8::is_ascii_hexdigit)
            {
                width += 1;
            }
            (width > 1).then_some(width)
        }
        b'u' | b'U' => {
            let required = if next == b'u' { 4 } else { 8 };
            let end = escape_start + 1 + required;
            bytes
                .get(escape_start + 1..end)
                .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))
                .map(|_| 1 + required)
        }
        _ => None,
    }
}

fn find_block_comment_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

pub(super) fn token_types_from_lex(types_buf: &[u8], n_tokens: u32) -> Result<Vec<u32>, String> {
    read_u32_stream(types_buf, n_tokens as usize, "token type buffer")
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

pub(super) fn read_u32_stream(buf: &[u8], words: usize, label: &str) -> Result<Vec<u32>, String> {
    let byte_len = words.saturating_mul(4);
    if byte_len > buf.len() {
        return Err(format!(
            "{label}: need {byte_len} bytes for {words} u32 words, have {}",
            buf.len()
        ));
    }
    let mut out = Vec::with_capacity(words);
    for chunk in buf[..byte_len].chunks_exact(4) {
        out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(out)
}

pub(super) fn vec_u32_le_bytes(words: &[u32]) -> Vec<u8> {
    // Same single-memcpy fast path as `u32_slice_to_bytes`. The
    // upstream `pack_u32` in vyre-primitives::bracket_match still
    // uses the iter/flat_map pattern; we shortcut it here on the
    // hot pipeline path. Replace the upstream when it lands.
    fast_pack_u32_le(words)
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
    let row_count = vast_blob.len() / (VAST_NODE_STRIDE_U32 * 4);
    let mut ssa = Vec::new();
    for row_index in 0..row_count {
        match packed_u32_at(vast_blob, row_index * VAST_NODE_STRIDE_U32 + IDX_KIND) {
            C_AST_KIND_LABEL_STMT => {
                let hash = packed_u32_at(vast_blob, row_index * VAST_NODE_STRIDE_U32 + IDX_SYMBOL_HASH);
                if hash != 0 {
                    ssa.extend_from_slice(&[SSA_LABEL_OPCODE, hash]);
                }
            }
            C_AST_KIND_GOTO_STMT => {
                let target_idx =
                    packed_u32_at(vast_blob, row_index * VAST_NODE_STRIDE_U32 + IDX_NEXT_SIBLING)
                        as usize;
                let target_hash = if target_idx < row_count {
                    packed_u32_at(vast_blob, target_idx * VAST_NODE_STRIDE_U32 + IDX_SYMBOL_HASH)
                } else {
                    0
                };
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

fn packed_u32_at(bytes: &[u8], word: usize) -> u32 {
    let offset = word * 4;
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
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
        let section_word_count = section.len() / 4;
        let section_hash = fnv1a32_packed_u32_bytes(section);
        words.extend_from_slice(&[
            SECTION_MARKER,
            section_idx as u32,
            u32::try_from(section_word_count)
                .map_err(|_| format!("compiler section {section_idx} exceeds u32 word count"))?,
            section_hash,
        ]);

        let mut take_words = per_section_budget.min(section_word_count);
        if payload_remainder != 0 && take_words < section_word_count {
            take_words = take_words.saturating_add(1);
            payload_remainder -= 1;
        }
        for chunk in section[..take_words * 4].chunks_exact(4) {
            words.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
    }
    Ok(words)
}

fn fnv1a32_packed_u32_bytes(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub(super) fn c11_statement_bounds_host(tokens: &[u32], n_tokens: u32) -> (Vec<u32>, u32) {
    let cap = n_tokens.clamp(1, MAX_TOK_SCAN);
    let n = cap as usize;
    let mut pairs: Vec<u32> = Vec::new();
    let mut start: u32 = 0;
    let mut stmt_count: u32 = 0;
    let mut paren_depth: u32 = 0;
    let mut bracket_depth: u32 = 0;
    for i in 0..n {
        let token = tokens.get(i).copied().unwrap_or_default();
        match token {
            TOK_LPAREN => paren_depth = paren_depth.saturating_add(1),
            TOK_RPAREN => paren_depth = paren_depth.saturating_sub(1),
            TOK_LBRACKET => bracket_depth = bracket_depth.saturating_add(1),
            TOK_RBRACKET => bracket_depth = bracket_depth.saturating_sub(1),
            _ => {}
        }
        let at_top_level_expr = paren_depth == 0 && bracket_depth == 0;
        let is_statement_boundary = token == TOK_SEMICOLON
            || (at_top_level_expr && matches!(token, TOK_LBRACE | TOK_RBRACE));
        if is_statement_boundary {
            let end = (i as u32).saturating_add(1).min(cap);
            if end <= start {
                continue;
            }
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

pub(super) fn build_ast_inputs(tok_types: &[u32], stmt_bytes: &[u8], num_stmt: u32) -> Vec<Vec<u8>> {
    build_ast_inputs_with_capacity(tok_types, stmt_bytes, num_stmt, MAX_TOK_SCAN)
}

pub(super) fn build_ast_inputs_with_capacity(
    tok_types: &[u32],
    stmt_bytes: &[u8],
    num_stmt: u32,
    token_capacity: u32,
) -> Vec<Vec<u8>> {
    let token_capacity = token_capacity.clamp(1, MAX_TOK_SCAN);
    let mut tok_b = vec![0u8; token_capacity as usize * 4];
    for (index, token) in tok_types.iter().take(token_capacity as usize).enumerate() {
        tok_b[index * 4..index * 4 + 4].copy_from_slice(&token.to_le_bytes());
    }
    let out_ast = vec![0u8; token_capacity as usize * 4 * 4];
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
