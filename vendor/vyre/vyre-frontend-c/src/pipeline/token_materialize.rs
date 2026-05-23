use super::*;

pub(in crate::pipeline) struct DecodedC11Tokens {
    pub(in crate::pipeline) tok_types: Vec<u32>,
    pub(in crate::pipeline) start_words: Vec<u32>,
    pub(in crate::pipeline) len_words: Vec<u32>,
    pub(in crate::pipeline) starts_logical: Vec<u8>,
    pub(in crate::pipeline) lens_logical: Vec<u8>,
    pub(in crate::pipeline) types_logical: Vec<u8>,
    pub(in crate::pipeline) n_tokens: u32,
    pub(in crate::pipeline) nt: u32,
}

pub(in crate::pipeline) fn decode_c11_tokens(
    path: &Path,
    source: &str,
    types: &[u8],
    starts: &[u8],
    lens: &[u8],
    n_tokens: u32,
    mut log: impl FnMut(&str),
) -> Result<DecodedC11Tokens, String> {
    let tok_types = token_types_from_lex(types, n_tokens)?;
    let mut start_words = read_u32_stream(starts, n_tokens as usize, "token starts")?;
    let mut len_words = read_u32_stream(lens, n_tokens as usize, "token lengths")?;
    repair_token_spans_from_source(source, &tok_types, &mut start_words, &mut len_words)?;
    log("host token decode/repair/diagnostics");
    let starts_logical = vec_u32_le_bytes_min_words(&start_words, n_tokens.max(1))?;
    let lens_logical = vec_u32_le_bytes_min_words(&len_words, n_tokens.max(1))?;
    reject_c11_lexer_diagnostics(path, &tok_types, &starts_logical, &lens_logical)?;
    let types_logical = logical_type_bytes_from_lex_buffer(types, n_tokens)?;
    Ok(DecodedC11Tokens {
        tok_types,
        start_words,
        len_words,
        starts_logical,
        lens_logical,
        types_logical,
        n_tokens,
        nt: n_tokens.max(1),
    })
}

fn logical_type_bytes_from_lex_buffer(types: &[u8], n_tokens: u32) -> Result<Vec<u8>, String> {
    if n_tokens == 0 {
        return Ok(vec![0; 4]);
    }
    let logical_bytes = usize::try_from(n_tokens)
        .ok()
        .and_then(|tokens| tokens.checked_mul(4))
        .ok_or_else(|| {
            format!(
                "token type logical byte length overflows host indexing for n_tokens={n_tokens}. Fix: shard the token stream before materialization."
            )
        })?;
    if types.len() < logical_bytes {
        return Err(format!(
            "token type buffer has {} bytes, need {logical_bytes} for {n_tokens} logical token(s). Fix: keep lexer output buffers aligned before token materialization.",
            types.len()
        ));
    }
    Ok(types[..logical_bytes].to_vec())
}

#[cfg(test)]
mod tests {
    use super::logical_type_bytes_from_lex_buffer;

    #[test]
    fn logical_type_bytes_reuses_lex_prefix_without_repacking() {
        let bytes = vec![1, 0, 0, 0, 2, 0, 0, 0, 99, 99, 99, 99];
        assert_eq!(
            logical_type_bytes_from_lex_buffer(&bytes, 2).unwrap(),
            vec![1, 0, 0, 0, 2, 0, 0, 0]
        );
    }

    #[test]
    fn logical_type_bytes_zero_tokens_emit_single_zero_word() {
        assert_eq!(
            logical_type_bytes_from_lex_buffer(&[], 0).unwrap(),
            vec![0; 4]
        );
    }
}
