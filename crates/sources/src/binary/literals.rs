/// Extract C string literals from a line of decompiled code.
pub(crate) fn extract_string_literals(line: &str, out: &mut Vec<String>) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1; // skip escaped char
                }
                i += 1;
            }
            if i > start + crate::binary::MIN_STRING_LEN {
                // The inner loop only stops at a `"` byte or EOF, both valid
                // UTF-8 char boundaries, and `start` is the byte right after
                // an opening `"`; `.min(line.len())` clamps the escape-skip
                // overshoot. So this str slice is always boundary-safe even on
                // lines containing multi-byte UTF-8 (verified by fuzz).
                let raw = &line[start..i.min(line.len())];
                let unescaped = unescape_c_string(raw);
                if unescaped.len() >= crate::binary::MIN_STRING_LEN {
                    out.push(unescaped);
                }
            }
            i += 1; // skip closing quote
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A decompiled line whose quoted run contains a multi-byte UTF-8 char
    /// right after an escape backslash must still extract the literal
    /// without crashing. The inner scan only halts on a `"` byte or EOF
    /// (both char boundaries) and `.min(line.len())` clamps the escape-skip
    /// overshoot, so the str slice stays boundary-safe; this pins that
    /// invariant so a future change that slices on the raw cursor can't
    /// regress it into a "byte index is not a char boundary" panic.
    #[test]
    fn handles_utf8_after_escape_without_panic() {
        // `\` (1 byte) immediately before `é` (0xC3 0xA9): the escape-skip
        // (`i += 1; i += 1`) lands the cursor on the 0xA9 continuation byte.
        let line = r#"x = "abcdefghij\é klmnop";"#;
        let mut out = Vec::new();
        extract_string_literals(line, &mut out);
        // The run is > MIN_STRING_LEN, so exactly one literal is produced and
        // it contains the leading ASCII payload. No panic, real output.
        assert_eq!(out.len(), 1, "expected one literal, got {out:?}");
        assert!(
            out[0].contains("abcdefghij"),
            "literal missing ascii payload: {:?}",
            out[0]
        );
    }

    /// A normal C literal longer than MIN_STRING_LEN is extracted verbatim
    /// (escapes unescaped), proving the byte-slice path preserves behaviour
    /// for the common ASCII case.
    #[test]
    fn extracts_plain_ascii_literal_with_escapes() {
        let line = r#"puts("hello\tworld\n");"#;
        let mut out = Vec::new();
        extract_string_literals(line, &mut out);
        assert_eq!(out, vec!["hello\tworld\n".to_string()]);
    }

    /// Short literals (<= MIN_STRING_LEN bytes) are dropped, and an empty
    /// or quote-only line yields nothing rather than panicking.
    #[test]
    fn ignores_short_and_degenerate_lines() {
        let mut out = Vec::new();
        extract_string_literals("\"abc\"", &mut out);
        extract_string_literals("", &mut out);
        extract_string_literals("\"", &mut out);
        extract_string_literals("\"\"", &mut out);
        assert!(out.is_empty(), "unexpected literals: {out:?}");
    }
}

pub(crate) fn unescape_c_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('0') => result.push('\0'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}
