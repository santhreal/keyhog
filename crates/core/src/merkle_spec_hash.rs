//! Detector-spec hash digest for merkle cache invalidation.

use crate::spec::DetectorSpec;

/// Compute a stable BLAKE3 digest over the canonical detector set so a
/// later scan can detect that detectors changed.
pub fn compute_spec_hash(detectors: &[DetectorSpec]) -> [u8; 32] {
    let mut keys: Vec<String> = detectors
        .iter()
        .flat_map(|d| {
            let mut entries =
                Vec::with_capacity(2 + d.patterns.len() + d.companions.len() + d.keywords.len());
            entries.push(format!("id:{}", d.id));
            entries.push(format!("sev:{:?}", d.severity));
            for p in &d.patterns {
                entries.push(format!(
                    "p:{}|g:{}",
                    p.regex,
                    p.group.map(|g| g.to_string()).unwrap_or_default()
                ));
            }
            for c in &d.companions {
                entries.push(format!(
                    "c:{}|{}|w:{}|r:{}",
                    c.name, c.regex, c.within_lines, c.required
                ));
            }
            let mut kws: Vec<&String> = d.keywords.iter().collect();
            kws.sort();
            for k in kws {
                entries.push(format!("kw:{}:{}", d.id, k));
            }
            entries
        })
        .collect();
    keys.sort();
    let mut hasher = blake3::Hasher::new();
    for k in keys {
        hasher.update(k.as_bytes());
        hasher.update(b"\n");
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn hex_encode(bytes: &[u8; 32]) -> String {
    // Lowercase-hex each byte directly into the preallocated buffer. The
    // previous `push_str(&format!("{:02x}", b))` allocated a throwaway
    // `String` per byte (32 allocations per call) on the merkle-save hot
    // path - one call per cached entry, ~1M on a large repo.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    // Byte-slice, not `&str[..]`: a 64-byte input with a multibyte UTF-8 char
    // at an odd offset (corrupted / hand-edited cache, deserialized
    // `spec_hash`) would panic on a non-char boundary with `&hex[i*2..i*2+2]`.
    // Decode each nibble directly; any non-hex byte fails the parse cleanly.
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decode a single lowercase/uppercase hex digit byte to its 0-15 value.
/// Shared by the allowlist SHA-256 parser so both sites decode hex identically
/// (byte-wise, never `&str[..]` slicing - that panics on non-char boundaries).
#[inline]
pub(crate) fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
