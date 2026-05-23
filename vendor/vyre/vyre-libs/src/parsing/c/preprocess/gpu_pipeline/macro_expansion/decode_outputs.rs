use super::*;

pub(crate) fn expanded_classified_from_materialized_outputs(
    expanded: &[Vec<u8>],
    token_count: usize,
    source: &[u8],
) -> Result<ClassifiedTokens, String> {
    if expanded.len() < 6 {
        return Err(format!(
            "named macro expansion materialization: expected at least 6 output buffers before token-column decode, got {}. Fix: preserve the macro expansion ABI outputs.",
            expanded.len()
        ));
    }
    Ok(ClassifiedTokens::from_parts(
        read_u32_words_exact(&expanded[0], token_count, "expanded token types")?,
        read_u32_words_exact(&expanded[1], token_count, "expanded token starts")?,
        read_u32_words_exact(&expanded[2], token_count, "expanded token lengths")?,
        vec![0; token_count],
        std::sync::Arc::from(source),
    ))
}

pub(crate) fn read_u32_words_exact(
    bytes: &[u8],
    count: usize,
    label: &str,
) -> Result<Vec<u32>, String> {
    let required = count.checked_mul(4).ok_or_else(|| {
        format!("named macro expansion {label} byte length overflow. Fix: shard macro expansion output before ABI decode.")
    })?;
    if bytes.len() < required {
        return Err(format!(
            "named macro expansion {label} buffer too short: need {required} bytes for {count} u32 words, got {}. Fix: backend must return the declared macro expansion token columns.",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(count);
    for idx in 0..count {
        out.push(read_u32_word(bytes, idx, label)?);
    }
    Ok(out)
}
