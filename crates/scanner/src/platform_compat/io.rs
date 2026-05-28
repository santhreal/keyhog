//! Line-ending conventions for cross-platform scan inputs.

/// Detect whether `text` uses CRLF line endings.
pub fn uses_crlf_line_endings(text: &str) -> bool {
    #[cfg(windows)]
    {
        text.contains("\r\n")
    }
    #[cfg(unix)]
    {
        let _ = text;
        false
    }
    #[cfg(not(any(unix, windows)))]
    {
        text.contains("\r\n")
    }
}

/// Count logical lines regardless of `\n` vs `\r\n` separators.
pub fn count_logical_lines(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    // `lines()` strips trailing `\r` from `\r\n` on all platforms.
    text.lines().count()
}

/// Expected byte offset of line `line_idx` (0-based) for mixed endings.
///
/// Used by platform-compat tests to assert CRLF vs LF offset parity.
pub fn line_start_offsets_for_style(text: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            b'\n' => {
                offsets.push(idx + 1);
            }
            b'\r' if idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' => {
                offsets.push(idx + 2);
                idx += 1;
            }
            b'\r' => {
                offsets.push(idx + 1);
            }
            _ => {}
        }
        idx += 1;
    }
    offsets
}

#[cfg(unix)]
pub fn newline_bytes() -> &'static [u8] {
    b"\n"
}

#[cfg(windows)]
pub fn newline_bytes() -> &'static [u8] {
    b"\r\n"
}

#[cfg(not(any(unix, windows)))]
pub fn newline_bytes() -> &'static [u8] {
    b"\n"
}
