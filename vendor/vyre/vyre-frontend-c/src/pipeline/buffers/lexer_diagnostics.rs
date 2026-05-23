use super::*;
pub(crate) fn token_types_from_lex(types_buf: &[u8], n_tokens: u32) -> Result<Vec<u32>, String> {
    read_u32_stream(types_buf, n_tokens as usize, "token type buffer")
}

pub(crate) fn reject_c11_lexer_diagnostics(
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
        .ok_or_else(|| {
            format!(
                "C lexer diagnostic for {} points at token index {}, but only {} tokens were decoded. Fix: keep diagnostic token indices in bounds.",
                path.display(),
                diag.token_index,
                tok_types.len()
            )
        })?;
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
