pub(super) fn read_output_u32(bytes: &[u8], label: &str) -> Result<u32, String> {
    if bytes.len() != 4 {
        return Err(format!(
            "{label}: malformed u32 output: expected exactly 4 bytes, got {}. Fix: backend must emit one u32 scalar and no trailing bytes.",
            bytes.len()
        ));
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
