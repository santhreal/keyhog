//! Printable string extraction from binary data.
//! Shared by the filesystem source (auto-detection) and binary source (explicit).

use keyhog_core::SensitiveString;
/// Extract printable ASCII strings of at least `min_len` from binary data.
pub(crate) fn extract_printable_strings(bytes: &[u8], min_len: usize) -> Vec<SensitiveString> {
    let mut strings = Vec::new();
    let mut current_string = String::with_capacity(64);
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            current_string.push(b as char);
        } else {
            if current_string.len() >= min_len {
                strings.push(SensitiveString::from(current_string.as_str()));
            }
            current_string.clear();
        }
    }
    if current_string.len() >= min_len {
        strings.push(SensitiveString::from(current_string.as_str()));
    }
    strings
}
