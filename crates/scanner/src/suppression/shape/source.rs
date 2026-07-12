use super::looks_like_public_version_identifier_with_randomness;
use crate::suppression::token_randomness::TokenRandomness;

/// Source-code expressions are not credentials. This catches extracted
/// function/method/type syntax such as `TokenizationScratch::default()`,
/// `vec![...]`, `.unwrap_or(u32::MAX)`, and `foo(bar)` after the entropy or
/// generic bridge has already mistaken nearby `token`/`key` identifiers for a
/// credential anchor.
pub(crate) fn looks_like_source_code_expression_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 6 || bytes.len() > 240 {
        return false;
    }
    if looks_like_source_numeric_literal(value)
        || looks_like_source_const_label(value)
        || looks_like_source_string_terminator_fragment(value, randomness)
        || looks_like_source_escaped_string_fragment(value, randomness)
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

fn looks_like_source_string_terminator_fragment(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    let Some(prefix) = value.strip_suffix("\")") else {
        return false;
    };
    if prefix.len() < 2 || prefix.len() > 80 {
        return false;
    }
    looks_like_public_version_identifier_with_randomness(prefix, randomness)
        || looks_like_short_version_literal(prefix)
        || looks_like_source_symbol_identifier_with_randomness(prefix, randomness)
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

fn looks_like_source_escaped_string_fragment(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
    let Some(after_quote) = value.strip_prefix("\\\"") else {
        return false;
    };
    let inner = after_quote.trim_end_matches('\\');
    if inner.len() < 6 || inner.len() > 40 {
        return false;
    }
    !randomness.is_random_token(inner)
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

#[derive(serde::Deserialize)]
struct SourceTypeTerms {
    terms: Vec<String>,
}

fn parse_source_type_terms(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<SourceTypeTerms>(raw)
        .map(|parsed| parsed.terms)
        .map_err(|error| error.to_string())
}

static SOURCE_TYPE_TERMS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_source_type_terms(include_str!("../../../../../rules/source-type-terms.toml")) {
        Ok(terms) => terms,
        Err(error) => panic!(
            "rules/source-type-terms.toml is invalid: {error}. \
             Fix the bundled Tier-B source-type terms list."
        ),
    }
});

#[derive(serde::Deserialize)]
struct SourceReceivers {
    receivers: Vec<String>,
}

fn parse_source_receivers(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<SourceReceivers>(raw)
        .map(|parsed| parsed.receivers)
        .map_err(|error| error.to_string())
}

static SOURCE_RECEIVERS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_source_receivers(include_str!("../../../../../rules/source-receivers.toml")) {
        Ok(receivers) => receivers,
        Err(error) => panic!(
            "rules/source-receivers.toml is invalid: {error}. \
             Fix the bundled source receivers list."
        ),
    }
});

pub(crate) fn looks_like_source_symbol_identifier_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
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
    SOURCE_TYPE_TERMS
        .iter()
        .any(|term| value.contains(term.as_str()))
        || !randomness.is_random_token(value)
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

pub(crate) fn looks_like_kebab_config_identifier(value: &str) -> bool {
    if value.len() > 24 {
        return false;
    }
    let bytes = value.as_bytes();
    let dash_count = bytes.iter().filter(|&&b| b == b'-').count();
    if dash_count == 0 {
        return false;
    }
    let lower_count = bytes
        .iter()
        .filter(|&&b| (b as char).is_ascii_lowercase())
        .count();
    if lower_count * 2 < bytes.len() {
        return false;
    }
    !bytes.iter().any(|&b| matches!(b as char, '+' | '/' | '='))
}

pub(crate) fn looks_like_dotted_source_identifier(value: &str) -> bool {
    // Single validating pass over `.`-separated segments (Law 7: per-candidate
    // suppression predicate, no `Vec`). Tracks count, first segment (for the
    // receiver match), camel-case presence, and credential-word presence.
    let mut count = 0usize;
    let mut first = "";
    let mut has_camel_segment = false;
    let mut has_credential_word = false;
    for segment in value.split('.') {
        count += 1;
        if count == 1 {
            first = segment;
        }
        let seg = segment.as_bytes();
        if seg.is_empty()
            || !seg
                .iter()
                .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return false;
        }
        if seg
            .windows(2)
            .any(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
        {
            has_camel_segment = true;
        }
        // `ci_find` needles are pre-lowered against the ONE canonical
        // credential-keyword needle set (`super::CREDENTIAL_KEYWORD_NEEDLES`).
        if super::CREDENTIAL_KEYWORD_NEEDLES
            .iter()
            .any(|needle| crate::ascii_ci::ci_find(seg, needle))
        {
            has_credential_word = true;
        }
    }
    if !(2..=5).contains(&count) {
        return false;
    }

    // Receiver match without allocating a lowercased copy of the first segment.
    if SOURCE_RECEIVERS
        .iter()
        .any(|recv| first.eq_ignore_ascii_case(recv.as_str()))
    {
        return true;
    }

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
pub(crate) fn looks_like_source_type_identifier_with_randomness(
    value: &str,
    randomness: &TokenRandomness<'_>,
) -> bool {
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
    upper >= 2 && lower >= 3 && digits >= 1 && !randomness.is_random_token(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Intent pin for the `CREDENTIAL_KEYWORD_NEEDLES` unification: `passwd`
    /// is a canonical credential keyword (same set the entropy keyword list and
    /// the TS non-null identifier gate use), so a camel-cased dotted candidate
    /// carrying a `passwd` segment IS a source identifier and must suppress.
    /// If someone narrows the canonical set and drops `passwd`, this fails.
    #[test]
    fn dotted_source_identifier_suppresses_camel_passwd_segment() {
        assert!(
            looks_like_dotted_source_identifier("userDb.passwd.value"),
            "camel-cased dotted candidate with a passwd segment must be a source identifier",
        );
    }

    /// Guardrail on the widening: `passwd` alone (no camel segment, no known
    /// receiver) must NOT suppress, so the passwd inclusion does not silently
    /// swallow flat dotted credential paths.
    #[test]
    fn dotted_passwd_without_camel_or_receiver_does_not_suppress() {
        assert!(
            !looks_like_dotted_source_identifier("db.passwd.field"),
            "a flat passwd dotted path with no camel segment must not be suppressed",
        );
    }

    /// Single-pass rewrite must preserve the 2..=5 segment-count window and the
    /// empty-segment / non-alnum rejections.
    #[test]
    fn dotted_source_identifier_segment_count_and_body_bounds() {
        // 6 dotted segments is over the 5-segment ceiling → not an identifier.
        assert!(!looks_like_dotted_source_identifier("aB.cD.eF.gH.iJ.kL"));
        // Single segment (no dot) is under the floor.
        assert!(!looks_like_dotted_source_identifier("userDbPasswd"));
        // Empty segment rejects regardless of count.
        assert!(!looks_like_dotted_source_identifier("userDb..passwd"));
        // Non-alnum body byte rejects.
        assert!(!looks_like_dotted_source_identifier("userDb.pass-wd.value"));
    }

    /// First-segment receiver match short-circuits to true without needing a
    /// camel/credential segment (the `first` capture in the single pass).
    #[test]
    fn dotted_source_identifier_receiver_first_segment() {
        assert!(looks_like_dotted_source_identifier(&format!(
            "{}.field",
            SOURCE_RECEIVERS[0].as_str()
        )));
    }
}
