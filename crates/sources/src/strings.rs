//! Printable string extraction from binary data.
//! Shared by the filesystem source (auto-detection) and binary source (explicit).

use keyhog_core::SensitiveString;

/// ONE owner for the printable-run floor used by every `extract_printable_strings`
/// caller, binary sections/literals, web WASM extraction, and filesystem
/// archive/PDF strings. Tune the strings-scan recall floor here and nowhere else.
pub(crate) const MIN_PRINTABLE_STRING_LEN: usize = 8;

/// Extract printable ASCII strings of at least `min_len` from binary data.
///
/// Covers two encodings: contiguous printable ASCII runs, and UTF-16LE "wide"
/// strings (printable ASCII bytes interleaved with `0x00`), the dominant
/// string encoding in Windows PE / .NET assemblies and many embedded
/// resources, equivalent to `strings -e l`. The ASCII pass alone sees each
/// wide char interrupted by its `0x00` and never accumulates a run, so without
/// the UTF-16LE pass every wide-encoded secret in a binary is silently missed.
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
    extract_utf16le_into(bytes, min_len, &mut strings);
    strings
}

pub(crate) fn join_sensitive_strings(parts: &[SensitiveString], sep: &str) -> SensitiveString {
    let mut joined = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            joined.push_str(sep);
        }
        joined.push_str(part.as_ref());
    }
    SensitiveString::from(joined)
}

/// Append UTF-16LE printable runs (`X 00 Y 00 …`) of at least `min_len` decoded
/// chars to `out`. On a non-matching code unit the scan re-aligns by one byte,
/// so wide runs starting at an odd offset are still recovered. Pure-ASCII
/// regions never match (the high byte is non-zero), so this adds no spurious
/// strings on text-shaped input.
fn extract_utf16le_into(bytes: &[u8], min_len: usize, out: &mut Vec<SensitiveString>) {
    let mut current = String::with_capacity(64);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let (lo, hi) = (bytes[i], bytes[i + 1]);
        if hi == 0 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\t') {
            current.push(lo as char);
            i += 2;
        } else {
            if current.len() >= min_len {
                out.push(SensitiveString::from(current.as_str()));
            }
            current.clear();
            i += 1;
        }
    }
    if current.len() >= min_len {
        out.push(SensitiveString::from(current.as_str()));
    }
}
