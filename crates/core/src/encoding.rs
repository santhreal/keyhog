//! Standard Base64 (RFC 4648) decode for wire formats and structured data.
//!
//! Scan-time variant base64 (URL-safe, unpadded) lives in `keyhog-scanner`.

/// Maximum input length for [`decode_standard_base64`]. Matches the scanner
/// pipeline cap so credential serde and K8s secret parsing stay consistent.
pub const MAX_STANDARD_BASE64_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Decode standard-alphabet base64 (with optional `=` padding).
pub fn decode_standard_base64(input: &str) -> Result<Vec<u8>, String> {
    if input.len() > MAX_STANDARD_BASE64_INPUT_BYTES {
        return Err(format!(
            "base64 input exceeds {} bytes",
            MAX_STANDARD_BASE64_INPUT_BYTES
        ));
    }
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 char: {c:#x}")),
        }
    }
    let bytes = input.as_bytes();
    let stripped: Vec<u8> = bytes.iter().copied().take_while(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
    for chunk in stripped.chunks(4) {
        let v0 = val(chunk[0])?;
        let v1 = val(*chunk.get(1).ok_or_else(|| "truncated base64".to_string())?)?;
        out.push((v0 << 2) | (v1 >> 4));
        if let Some(&c2) = chunk.get(2) {
            let v2 = val(c2)?;
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            if let Some(&c3) = chunk.get(3) {
                let v3 = val(c3)?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }
    Ok(out)
}
