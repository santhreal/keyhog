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
                // Unescape basic C escapes
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
