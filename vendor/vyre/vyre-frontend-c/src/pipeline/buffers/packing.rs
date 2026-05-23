pub(crate) fn fast_pack_u32_le(words: &[u32]) -> Vec<u8> {
    let byte_capacity = words.len().checked_mul(4).unwrap_or_else(|| {
        panic!(
            "fast_pack_u32_le word count {} overflows byte capacity. Fix: shard the GPU parser buffer before packing.",
            words.len()
        )
    });
    #[cfg(target_endian = "little")]
    {
        let bytes = bytemuck::cast_slice(words);
        debug_assert_eq!(bytes.len(), byte_capacity);
        return bytes.to_vec();
    }
    #[cfg(target_endian = "big")]
    {
        let mut out = Vec::with_capacity(byte_capacity);
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }
}

pub(crate) fn read_u32_at(buf: &[u8], off: usize) -> Result<u32, String> {
    let end = off.checked_add(4).ok_or_else(|| {
        format!("buffer u32 read offset {off} overflows byte index. Fix: repair parser buffer offsets before readback.")
    })?;
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

pub(crate) fn pack_haystack(source: &str) -> Result<(Vec<u8>, u32), String> {
    let haystack_u32_count = u32::try_from(source.len())
        .map_err(|_| {
            format!(
                "C frontend source length {} exceeds the u32 GPU index space. Fix: shard the translation unit before packing the haystack.",
                source.len()
            )
        })?
        .max(1);
    let mut bytes = vec![0u8; haystack_u32_count as usize * 4];
    for (i, byte) in source.bytes().enumerate() {
        bytes[i * 4] = byte;
    }
    Ok((bytes, haystack_u32_count))
}

pub(crate) fn cuda_lexer_haystack_view(source: &[u8]) -> Result<(Vec<u8>, u32), String> {
    let logical_len = u32::try_from(source.len()).map_err(|_| {
        format!(
            "CUDA lexer source length {} exceeds the current u32 GPU index space. Fix: shard the translation unit before CUDA sparse lexing.",
            source.len()
        )
    })?;
    let packed_words = logical_len.max(1).div_ceil(4).max(1) as usize;
    let packed_bytes = packed_words.checked_mul(4).ok_or_else(|| {
        format!(
            "CUDA lexer packed word count {packed_words} overflows byte length. Fix: shard the translation unit before CUDA sparse lexing."
        )
    })?;
    let mut packed = vec![0u8; packed_bytes];
    packed[..source.len()].copy_from_slice(source);
    Ok((packed, logical_len))
}
pub(crate) fn read_u32_stream(buf: &[u8], words: usize, label: &str) -> Result<Vec<u32>, String> {
    let byte_len = words.checked_mul(4).ok_or_else(|| {
        format!("{label}: word count {words} overflows byte length. Fix: shard parser readback before decoding.")
    })?;
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

pub(crate) fn vec_u32_le_bytes(words: &[u32]) -> Vec<u8> {
    // Same single-memcpy fast path as `fast_pack_u32_le`. The
    // upstream `pack_u32` in vyre-primitives::bracket_match still
    // uses the iter/flat_map pattern; we shortcut it here on the
    // hot pipeline path. Replace the upstream when it lands.
    fast_pack_u32_le(words)
}

pub(crate) fn vec_u32_le_bytes_min_words(words: &[u32], min_words: u32) -> Result<Vec<u8>, String> {
    let min_words = usize::try_from(min_words).map_err(|_| {
        format!(
            "u32 byte pack minimum word count {min_words} exceeds host usize. Fix: shard the token stream before GPU dispatch."
        )
    })?;
    if words.len() >= min_words {
        return Ok(vec_u32_le_bytes(words));
    }
    let byte_len = min_words.checked_mul(4).ok_or_else(|| {
        format!(
            "u32 byte pack minimum word count {min_words} overflows host byte indexing. Fix: shard the token stream before GPU dispatch."
        )
    })?;
    let packed_len = words.len().checked_mul(4).ok_or_else(|| {
        format!(
            "u32 byte pack word count {} overflows host byte indexing. Fix: shard the token stream before GPU dispatch.",
            words.len()
        )
    })?;
    debug_assert!(packed_len <= byte_len);
    let mut out = vec![0u8; byte_len];
    #[cfg(target_endian = "little")]
    {
        out[..packed_len].copy_from_slice(bytemuck::cast_slice(words));
    }
    #[cfg(target_endian = "big")]
    for (index, word) in words.iter().enumerate() {
        let start = index * 4;
        out[start..start + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{fast_pack_u32_le, vec_u32_le_bytes_min_words};

    #[test]
    fn fast_pack_u32_le_preserves_little_endian_wire_order() {
        assert_eq!(
            fast_pack_u32_le(&[0x0102_0304, 0xa0b0_c0d0]),
            vec![0x04, 0x03, 0x02, 0x01, 0xd0, 0xc0, 0xb0, 0xa0]
        );
    }

    #[test]
    fn vec_u32_le_bytes_min_words_pads_without_reordering_words() {
        assert_eq!(
            vec_u32_le_bytes_min_words(&[0x1122_3344], 3).unwrap(),
            vec![0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
