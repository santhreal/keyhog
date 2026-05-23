pub(super) fn checked_gpu_u32(label: &str, value: usize) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| {
        format!(
            "vyre-libs::gpu_pipeline: {label} {value} exceeds the current u32 GPU index space. Fix: shard the translation unit before preprocessing."
        )
    })
}

// =================================================================
// Phase 18b: gpu_tokenize_and_classify
// =================================================================

pub(super) fn unpack_u32_words_prefix(bytes: &[u8], count: usize) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .take(count)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

pub(super) fn unpack_u32_words_exact_into(
    bytes: &[u8],
    count: usize,
    label: &str,
    out: &mut Vec<u32>,
) -> Result<(), String> {
    let expected = count
        .checked_mul(4)
        .ok_or_else(|| format!("{label}: expected byte count overflows usize"))?;
    if bytes.len() != expected {
        return Err(format!(
            "{label}: malformed u32 table: expected exactly {expected} bytes for {count} rows, got {}. Fix: backend must emit the declared table shape and no trailing bytes.",
            bytes.len()
        ));
    }
    out.clear();
    out.reserve(count);
    for chunk in bytes.chunks_exact(4).take(count) {
        out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(())
}

pub(super) fn unpack_u32_words_prefix_exact(
    bytes: &[u8],
    prefix_count: usize,
    table_words: usize,
    label: &str,
) -> Result<Vec<u32>, String> {
    let expected = table_words
        .checked_mul(4)
        .ok_or_else(|| format!("{label}: expected byte count overflows usize"))?;
    if bytes.len() != expected {
        return Err(format!(
            "{label}: malformed u32 table: expected exactly {expected} bytes for {table_words} rows, got {}. Fix: backend must emit the declared table shape and no trailing bytes.",
            bytes.len()
        ));
    }
    Ok(unpack_u32_words_prefix(bytes, prefix_count))
}

pub(super) fn pack_u32_words(words: &[u32], pad_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(pad_len * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.resize(pad_len * 4, 0);
    out
}

pub(super) fn pack_u32_words_into(out: &mut Vec<u8>, words: &[u32], pad_len: usize) {
    let byte_len = pad_len.saturating_mul(4);
    out.clear();
    out.reserve(byte_len);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.resize(byte_len, 0);
}

pub(super) fn pad_to_u32_words(bytes: &[u8]) -> Vec<u8> {
    let target = bytes.len().div_ceil(4).max(1) * 4;
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(bytes);
    out.resize(target, 0);
    out
}

pub(super) fn pad_to_u32_words_into(out: &mut Vec<u8>, bytes: &[u8]) {
    let target = bytes.len().div_ceil(4).max(1) * 4;
    out.clear();
    out.reserve(target);
    out.extend_from_slice(bytes);
    out.resize(target, 0);
}

/// Cache the runtime-sized `gpu_ifdef_value(1, 0)` Program so the
/// live-conditional re-eval path does not reconstruct the IR per `#if` row.
pub fn bucket_pow2(value: usize, min: usize) -> usize {
    value.max(min).next_power_of_two()
}

pub(super) fn read_u32_word(buf: &[u8], word_index: usize, label: &str) -> Result<u32, String> {
    let offset = word_index
        .checked_mul(4)
        .ok_or_else(|| format!("vyre-libs::gpu_pipeline: {label} byte offset overflowed usize"))?;
    let bytes = buf.get(offset..offset + 4).ok_or_else(|| {
        format!(
            "vyre-libs::gpu_pipeline: {label} missing u32 word {word_index}; buffer has {} bytes",
            buf.len()
        )
    })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn read_u32_scalar_exact(buf: &[u8], label: &str) -> Result<u32, String> {
    if buf.len() != 4 {
        return Err(format!(
            "vyre-libs::gpu_pipeline: {label} has malformed byte length: expected exactly 4 bytes, got {}. Fix: backend must emit one u32 scalar and no trailing bytes.",
            buf.len()
        ));
    }
    read_u32_word(buf, 0, label)
}
