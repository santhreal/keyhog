//! Standard Base64 (RFC 4648) decode for wire formats and structured data.
//!
//! Scan-time variant base64 (URL-safe, unpadded) lives in `keyhog-scanner`.

/// Maximum input length for [`decode_standard_base64`]. Matches the scanner's
/// byte limit so credential serde and K8s secret parsing stay consistent.
pub(crate) const MAX_STANDARD_BASE64_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Encode bytes with the standard RFC 4648 alphabet and canonical `=` padding.
pub(crate) fn encode_standard_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = match chunk.get(1) {
            Some(byte) => *byte,
            None => 0,
        };
        let b2 = match chunk.get(2) {
            Some(byte) => *byte,
            None => 0,
        };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

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
    // `=` is only legal as TRAILING padding in standard base64. The previous
    // `take_while(|c| c != b'=')` silently TRUNCATED at the first `=`, so
    // `"AB=CD"` decoded as `"AB"` and dropped `"CD"` with no error — a
    // silent-accept that corrupts a credential round-trip. Split at the first
    // `=`: everything before it is data, and everything FROM it onward must be
    // padding-only (`=`). A non-`=` byte after an `=` is malformed; reject it
    // loudly instead of swallowing the tail.
    let first_pad = bytes.iter().position(|&c| c == b'=');
    let stripped: &[u8] = match first_pad {
        Some(idx) => {
            if bytes[idx..].iter().any(|&c| c != b'=') {
                return Err(
                    "invalid base64: data after padding '=' (padding may only appear at the end)"
                        .to_string(),
                );
            }
            // At most 2 padding chars are well-formed; more than 2, or padding
            // that does not align the data to a 4-char-quad boundary, is
            // malformed. `idx % 4` is the data length within the final quad:
            // 0 => no quad in progress (only valid with zero padding),
            // 1 => impossible to encode (1 base64 char carries <6 bits of a byte),
            // 2 => one data byte, needs `==`,
            // 3 => two data bytes, needs `=`.
            let pad_len = bytes.len() - idx;
            let rem = idx % 4;
            let pad_ok = match rem {
                2 => pad_len == 2 || pad_len == 1, // tolerate `QQ=`/`QQ==`
                3 => pad_len == 1,
                0 => pad_len <= 2, // trailing `=`/`==` after a whole quad ("QUJD==")
                _ => false,        // rem == 1: no valid encoding produces a lone char
            };
            if !pad_ok {
                return Err(format!(
                    "invalid base64: {pad_len} padding char(s) do not align the {idx} data char(s) to a quad"
                ));
            }
            &bytes[..idx]
        }
        None => bytes,
    };
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
