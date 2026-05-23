pub(super) fn read_u32_at(bytes: &[u8], index: usize, label: &str) -> Result<u32, String> {
    let start = index
        .checked_mul(4)
        .ok_or_else(|| format!("{label}: u32 index {index} byte offset overflows usize"))?;
    let end = start
        .checked_add(4)
        .ok_or_else(|| format!("{label}: u32 index {index} byte end overflows usize"))?;
    let chunk = bytes.get(start..end).ok_or_else(|| {
        format!(
            "{label}: missing u32 at index {index}; buffer has {} bytes",
            bytes.len()
        )
    })?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}
