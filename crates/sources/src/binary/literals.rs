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
            if i >= start + crate::strings::MIN_PRINTABLE_STRING_LEN {
                // The inner loop only stops at a `"` byte or EOF, both valid
                // UTF-8 char boundaries, and `start` is the byte right after
                // an opening `"`; `.min(line.len())` clamps the escape-skip
                // overshoot. So this str slice is always boundary-safe even on
                // lines containing multi-byte UTF-8 (verified by fuzz).
                let raw = &line[start..i.min(line.len())];
                let unescaped = unescape_c_string(raw);
                if unescaped.len() >= crate::strings::MIN_PRINTABLE_STRING_LEN {
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
    // Fast path: a literal with no backslash has no escapes to expand, so the
    // char-by-char scan below would just copy it verbatim — a single memcpy is
    // faster and is the common case for the bulk of extracted binary literals.
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('x') => match take_hex_byte_escape(&mut chars) {
                    Some(value) => result.push(char::from(value)),
                    None => {
                        result.push('\\');
                        result.push('x');
                    }
                },
                Some(first @ '0'..='7') => {
                    let value = take_octal_byte_escape(first, &mut chars);
                    result.push(char::from(value));
                }
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

fn take_hex_byte_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u8> {
    // Peek-and-convert in one step: `to_digit(16)` IS the hex-digit test, so a
    // non-hex char yields `None` and is left unconsumed — no separate
    // `is_ascii_hexdigit` predicate that could disagree with the conversion and
    // force an infallible `.expect()`.
    let first = chars.peek().and_then(|ch| ch.to_digit(16))?;
    chars.next();
    let mut value = first as u8;
    if let Some(second) = chars.peek().and_then(|ch| ch.to_digit(16)) {
        chars.next();
        value = (value << 4) | second as u8;
    }
    Some(value)
}

fn take_octal_byte_escape(first: char, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> u8 {
    // `first` and every `next` are matched against `'0'..='7'`, so each maps to
    // its value by ASCII offset — total arithmetic, no fallible `to_digit`.
    let mut value = (first as u8) - b'0';
    for _ in 0..2 {
        let Some(next) = chars.next_if(|ch| matches!(ch, '0'..='7')) else {
            break;
        };
        value = (value << 3) | ((next as u8) - b'0');
    }
    value
}
