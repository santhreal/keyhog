use std::path::Path;

use vyre_libs::parsing::c::lex::diagnostics::{first_c11_lexer_diagnostic, C11LexerDiagnosticKind};
use vyre_libs::parsing::c::lex::tokens::is_c_lexer_error_token;

use super::read_u32_stream;

pub(in crate::pipeline) fn reject_c11_lexer_diagnostics_bytes(
    path: &Path,
    tok_type_bytes: &[u8],
    starts_buf: &[u8],
    lens_buf: &[u8],
    n_tokens: u32,
) -> Result<(), String> {
    let byte_len = n_tokens as usize * 4;
    if byte_len > tok_type_bytes.len() {
        return Err(format!(
            "lexer diagnostic token types: need {byte_len} bytes for {n_tokens} tokens, have {}",
            tok_type_bytes.len()
        ));
    }
    if !tok_type_bytes[..byte_len].chunks_exact(4).any(|chunk| {
        is_c_lexer_error_token(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
    }) {
        return Ok(());
    }
    let tok_types = read_u32_stream(tok_type_bytes, n_tokens as usize, "lexer diagnostic types")?;
    reject_decoded_c11_lexer_diagnostics(path, &tok_types, starts_buf, lens_buf)
}

fn reject_decoded_c11_lexer_diagnostics(
    path: &Path,
    tok_types: &[u32],
    starts_buf: &[u8],
    lens_buf: &[u8],
) -> Result<(), String> {
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
                "C lexer diagnostic token index {} is outside {} decoded token kinds for {}. Fix: keep diagnostic token indices aligned with compact lexer outputs.",
                diag.token_index,
                tok_types.len(),
                path.display()
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
