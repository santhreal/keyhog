//! Printable string extraction from binary data.
//! Shared by the filesystem source (auto-detection) and binary source (explicit).

/// Extract printable ASCII strings of at least `min_len` from binary data.
pub(crate) fn extract_printable_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = String::new();
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            current_string.push(b as char);
        } else if current_string.len() >= min_len {
            strings.push(std::mem::take(&mut current_string));
        } else {
            current_string.clear();
        }
    }
    if current_string.len() >= min_len {
        strings.push(current_string);
    }
    strings
}
