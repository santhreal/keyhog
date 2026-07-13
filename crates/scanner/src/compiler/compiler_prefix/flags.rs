/// Strip leading inline flags like `(?i)`, `(?m)`, `(?ims)` from a regex.
/// These set modes for the rest of the pattern but don't produce a group.
pub(crate) fn strip_leading_inline_flags(pattern: &str) -> &str {
    if !pattern.starts_with("(?") {
        return pattern;
    }
    // (?i), (?m), (?s), (?x), (?im), (?ims), (?imsx) etc. - flags only, no ':'.
    // Also the negative form (?-i), (?im-sx): the `-` toggles following flags
    // off (keyhog uses (?-i) to make a pattern case-sensitive). A trailing `:`
    // means a scoped group `(?-i:...)`, not a leading directive - left intact.
    let bytes = pattern.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'(' || bytes[1] != b'?' {
        return pattern;
    }
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U' | b'-') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        // (?flags) - strip the entire inline flag group
        &pattern[i + 1..]
    } else {
        pattern
    }
}

/// Strip a leading run of zero-width assertions: `^`, `\A`, `\b`, `\B`: that
/// anchor the match position but consume no input. The literal that follows
/// (`\bser\.` -> `ser\.`, `^AKIA...` -> `AKIA...`) is the detector's real prefix, so
/// without this the leading assertion broke prefix extraction at the first byte
/// and the detector carried no AC trigger / literal-prefix anchor. Idempotent
/// and order-free across the four forms; anything else is left untouched.
pub(crate) fn strip_leading_zero_width_assertions(pattern: &str) -> &str {
    let mut p = pattern;
    loop {
        let next = p
            .strip_prefix('^')
            .or_else(|| p.strip_prefix(r"\A"))
            .or_else(|| p.strip_prefix(r"\b"))
            .or_else(|| p.strip_prefix(r"\B"));
        match next {
            Some(rest) => p = rest,
            None => return p,
        }
    }
}
