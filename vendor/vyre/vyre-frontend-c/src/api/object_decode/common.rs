pub(super) fn checked_count_u64(count: usize, label: &str) -> Result<u64, String> {
    u64::try_from(count).map_err(|_| {
        format!(
            "vyre-frontend-c {label} exceeds u64. Fix: shard the object before decoding summary metadata."
        )
    })
}

pub(super) fn decode_u32_words(bytes: &[u8]) -> Result<Vec<u32>, String> {
    if bytes.len() % 4 != 0 {
        return Err(format!(
            "vyre-frontend-c object section payload has {} bytes, not u32-aligned. Fix: regenerate the object.",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}
