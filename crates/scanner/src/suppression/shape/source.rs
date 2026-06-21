use super::looks_like_public_version_identifier;

/// Source-code expressions are not credentials. This catches extracted
/// function/method/type syntax such as `TokenizationScratch::default()`,
/// `vec![...]`, `.unwrap_or(u32::MAX)`, and `foo(bar)` after the entropy or
/// generic bridge has already mistaken nearby `token`/`key` identifiers for a
/// credential anchor.
pub(crate) fn looks_like_source_code_expression(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 6 || bytes.len() > 240 {
        return false;
    }
    if looks_like_source_numeric_literal(value)
        || looks_like_source_const_label(value)
        || looks_like_source_string_terminator_fragment(value)
        || looks_like_source_escaped_string_fragment(value)
        || looks_like_source_format_template_fragment(value)
    {
        return true;
    }

    let mut alpha = 0usize;
    for &byte in bytes {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => alpha += 1,
            b'0'..=b'9'
            | b'_'
            | b':'
            | b'.'
            | b'!'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'<'
            | b'>'
            | b','
            | b';'
            | b'&'
            | b'|'
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'='
            | b'?'
            | b'"'
            | b'\''
            | b'`'
            | b'#'
            | b' '
            | b'\t' => {}
            _ => return false,
        }
    }
    if alpha < 3 {
        return false;
    }

    value.contains("::")
        || value.starts_with('.')
        || value.starts_with(':')
        || value.contains("->")
        || value.contains("=>")
        || has_call_or_index_syntax(value)
}

fn looks_like_source_numeric_literal(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("0x") else {
        return false;
    };
    if rest.len() < 6 || rest.len() > 40 || !rest.contains('_') {
        return false;
    }
    let rust_suffix = rest.rsplit_once('_').and_then(|(digits, suffix)| {
        matches!(
            suffix,
            "u8" | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
        )
        .then_some(digits)
    });
    let (digit_body, suffix_ok) = rust_suffix.map_or((rest, false), |digits| (digits, true));
    let mut hex_digits = 0usize;
    let mut groups = 0usize;
    for part in digit_body.split('_') {
        if part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        hex_digits += part.len();
        groups += 1;
    }
    hex_digits >= 6 && (suffix_ok || groups >= 2)
}

fn looks_like_source_const_label(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("const:") else {
        return false;
    };
    rest.len() >= 3
        && rest.len() <= 80
        && rest.bytes().any(|b| b == b'_')
        && rest
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn looks_like_source_string_terminator_fragment(value: &str) -> bool {
    let Some(prefix) = value.strip_suffix("\")") else {
        return false;
    };
    if prefix.len() < 2 || prefix.len() > 80 {
        return false;
    }
    looks_like_public_version_identifier(prefix)
        || looks_like_short_version_literal(prefix)
        || looks_like_source_symbol_identifier(prefix)
}

fn looks_like_short_version_literal(value: &str) -> bool {
    let Some((version, suffix)) = value.split_once(':') else {
        return false;
    };
    let Some(digits) = version.strip_prefix('v') else {
        return false;
    };
    !digits.is_empty()
        && digits.len() <= 3
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !suffix.is_empty()
        && suffix.len() <= 24
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn looks_like_source_escaped_string_fragment(value: &str) -> bool {
    let Some(after_quote) = value.strip_prefix("\\\"") else {
        return false;
    };
    let inner = after_quote.trim_end_matches('\\');
    if inner.len() < 6 || inner.len() > 40 {
        return false;
    }
    !crate::suppression::token_randomness::is_random_token(inner)
        && inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn looks_like_source_format_template_fragment(value: &str) -> bool {
    let Some((name, template)) = value.split_once('=') else {
        return false;
    };
    if name.len() < 3
        || name.len() > 48
        || !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || !name.bytes().any(|b| b.is_ascii_alphabetic())
    {
        return false;
    }
    template.contains('%')
        && (template.contains("\\n")
            || template.contains("%X")
            || template.contains("%x")
            || template.contains("%d")
            || template.contains("%s"))
}

pub(crate) fn looks_like_source_symbol_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || bytes.len() > 96 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() && bytes[0] != b'_' {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return false;
    }
    if value.contains('_') {
        return value
            .split('_')
            .all(|part| !part.is_empty() && part.len() <= 24);
    }
    let upper = bytes.iter().filter(|b| b.is_ascii_uppercase()).count();
    let lower = bytes.iter().filter(|b| b.is_ascii_lowercase()).count();
    if upper < 2 || lower < 3 {
        return false;
    }
    const SOURCE_TYPE_TERMS: &[&str] = &[
        "HashMap",
        "HashSet",
        "BTreeMap",
        "BTreeSet",
        "VecDeque",
        "SmallVec",
        "InputKey",
        "CacheKey",
        "SourceKey",
    ];
    SOURCE_TYPE_TERMS.iter().any(|term| value.contains(term))
        || !crate::suppression::token_randomness::is_random_token(value)
}

/// Heuristic: is this string a likely source-code identifier rather than a
/// credential? Identifiers in mainstream languages are all `[A-Za-z_]` with
/// camelCase / PascalCase / snake_case shape.
pub(crate) fn looks_like_program_identifier(value: &str) -> bool {
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return false;
    }
    if value.contains('_') && value.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_') {
        return true;
    }
    let bytes = value.as_bytes();
    let mut transitions = 0usize;
    for pair in bytes.windows(2) {
        if pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase() {
            transitions += 1;
        }
    }
    transitions >= 1
}

pub(crate) fn looks_like_dotted_source_identifier(value: &str) -> bool {
    let segments: Vec<&str> = value.split('.').collect();
    if !(2..=5).contains(&segments.len()) || segments.iter().any(|segment| segment.is_empty()) {
        return false;
    }
    if !segments.iter().all(|segment| {
        segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }) {
        return false;
    }

    let source_receiver = matches!(
        segments[0].to_ascii_lowercase().as_str(),
        "this" | "self" | "window" | "process" | "global" | "config" | "client" | "service"
    );
    if source_receiver {
        return true;
    }

    let has_camel_segment = segments.iter().any(|segment| {
        segment
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
    });
    let has_credential_word = segments.iter().any(|segment| {
        let lower = segment.to_ascii_lowercase();
        ["token", "secret", "key", "auth", "password", "credential"]
            .iter()
            .any(|needle| lower.contains(needle))
    });
    has_camel_segment && has_credential_word
}

fn has_call_or_index_syntax(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (idx, &byte) in bytes.iter().enumerate() {
        if !matches!(byte, b'(' | b'[' | b'{') {
            continue;
        }
        if idx == 0 {
            return true;
        }
        let Some(prev) = bytes[..idx]
            .iter()
            .rev()
            .copied()
            .find(|b| !matches!(b, b' ' | b'\t'))
        else {
            return true;
        };
        if prev.is_ascii_alphanumeric()
            || matches!(
                prev,
                b'_' | b'!' | b')' | b']' | b'>' | b'+' | b'-' | b'*' | b'/' | b'%'
            )
        {
            return true;
        }
    }
    false
}

#[cfg(feature = "entropy")]
pub(crate) fn looks_like_source_type_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || bytes.len() > 120 || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    if !bytes.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let upper = bytes.iter().filter(|b| b.is_ascii_uppercase()).count();
    let lower = bytes.iter().filter(|b| b.is_ascii_lowercase()).count();
    let digits = bytes.iter().filter(|b| b.is_ascii_digit()).count();
    upper >= 2
        && lower >= 3
        && digits >= 1
        && !crate::suppression::token_randomness::is_random_token(value)
}
