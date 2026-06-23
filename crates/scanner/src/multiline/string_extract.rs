//! Per-line / per-language string-literal extraction primitives.
//!
//! The multiline preprocessor's job is orchestration: walk the line chain,
//! track offsets, and assemble the joined buffer. The actual work of pulling a
//! string value out of one source line - across quote styles, `\`-continuation,
//! `+`-concatenation, Python implicit adjacency, `paste0(...)`/`concat!(...)`
//! function joins, and JS template literals - is a cohesive family of pure
//! string functions that lives here. They take a `&str` line (and the
//! [`MultilineConfig`] toggles) and return the extracted literal content plus
//! whether the value continues onto the next line; they never touch offsets or
//! buffers.

#[cfg(feature = "multiline")]
use super::config::MultilineConfig;

#[cfg(feature = "multiline")]
#[derive(Debug, PartialEq)]
pub(super) enum ContinuationType {
    None,
    Backslash,
    PlusOperator,
    Implicit,
    TemplateLiteral,
}

pub(crate) fn extract_prefix(var_name: &str) -> String {
    var_name
        .to_lowercase()
        .replace("part", "")
        .replace(['_', '-'], "")
        .trim_end_matches(|ch: char| ch.is_ascii_digit())
        .to_string()
}

pub(crate) fn fragment_assignment_name_is_credential_like(var_name: &str) -> bool {
    let Some(normalized) =
        crate::engine::phase2_generic::keywords::normalize_assignment_keyword(var_name)
    else {
        return false;
    };
    if normalized_assignment_name_is_public_metadata_owner(&normalized) {
        return false;
    }
    normalized_or_fragment_base_is_credential_like(&normalized)
}

fn normalized_assignment_name_is_public_metadata_owner(normalized: &str) -> bool {
    matches!(
        normalized,
        "digest" | "hash" | "checksum" | "version" | "lines"
    ) || normalized.ends_with("_digest")
        || normalized.ends_with("_hash")
        || normalized.ends_with("_checksum")
        || normalized.ends_with("_version")
        || normalized.ends_with("_lines")
        || normalized.ends_with("_dedup_key")
}

fn normalized_or_fragment_base_is_credential_like(normalized: &str) -> bool {
    if normalized_assignment_name_is_credential_like(normalized, false) {
        return true;
    }
    if let Some(base) = strip_separated_fragment_suffix(normalized) {
        return normalized_assignment_name_is_credential_like(base, true);
    }
    let compact: String = normalized
        .bytes()
        .filter(|&b| b != b'_')
        .map(char::from)
        .collect();
    strip_compact_fragment_suffix(&compact)
        .is_some_and(|base| normalized_assignment_name_is_credential_like(base, true))
}

fn normalized_assignment_name_is_credential_like(
    normalized: &str,
    from_fragment_suffix: bool,
) -> bool {
    if !from_fragment_suffix && is_bare_ambiguous_fragment_owner(normalized) {
        return false;
    }
    crate::entropy::keywords::normalized_assignment_keyword_is_credential(normalized)
        || crate::engine::phase2_generic::keywords::normalized_assignment_keyword_has_secret_suffix(
            normalized,
        )
}

fn is_bare_ambiguous_fragment_owner(normalized: &str) -> bool {
    matches!(
        normalized,
        "key"
            | "token"
            | "secret"
            | "password"
            | "passwd"
            | "pwd"
            | "pass"
            | "credential"
            | "auth"
            | "authorization"
    )
}

fn strip_separated_fragment_suffix(normalized: &str) -> Option<&str> {
    let (base, suffix) = normalized.rsplit_once('_')?;
    if base.is_empty() {
        return None;
    }
    let suffix_is_fragment = matches!(
        suffix,
        "prefix"
            | "suffix"
            | "head"
            | "tail"
            | "left"
            | "right"
            | "chunk"
            | "piece"
            | "frag"
            | "fragment"
            | "part"
            | "chunks"
            | "pieces"
            | "frags"
            | "fragments"
            | "parts"
    ) || suffix
        .strip_prefix("part")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
    suffix_is_fragment.then_some(base)
}

fn strip_compact_fragment_suffix(compact: &str) -> Option<&str> {
    for suffix in [
        "prefix",
        "suffix",
        "head",
        "tail",
        "left",
        "right",
        "chunk",
        "piece",
        "frag",
        "fragment",
        "part",
        "chunks",
        "pieces",
        "frags",
        "fragments",
        "parts",
    ] {
        if let Some(base) = compact.strip_suffix(suffix) {
            if !base.is_empty() {
                return Some(base);
            }
        }
    }
    let without_digits = compact.trim_end_matches(|ch: char| ch.is_ascii_digit());
    let base = without_digits.strip_suffix("part")?;
    (!base.is_empty()).then_some(base)
}

#[cfg(feature = "multiline")]
pub(super) fn extract_string_part(
    line: &str,
    config: &MultilineConfig,
    is_continuation: bool,
) -> (String, bool, ContinuationType) {
    let trimmed = line.trim();

    if config.backslash_continuation && trimmed.ends_with('\\') && !trimmed.ends_with("\\\\") {
        let without_backslash = line
            .trim_end()
            .strip_suffix('\\')
            .unwrap_or(line) // LAW10: guarded by trimmed.ends_with('\\') so strip_suffix cannot fail on the trimmed form; unwrap_or keeps the full line conservatively (no extraction loss), recall-safe, no slower path.
            .trim_end();
        if config.plus_concatenation && without_backslash.trim().contains('+') {
            if let Some((part, _)) = extract_plus_concatenation(without_backslash) {
                return (part, true, ContinuationType::Backslash);
            }
        }
        let part = extract_string_content(without_backslash);
        return (part, true, ContinuationType::Backslash);
    }

    if let Some((part, continues)) = extract_function_concatenation(line) {
        return (part, continues, ContinuationType::Implicit);
    }

    if config.plus_concatenation {
        if let Some((part, continues)) = extract_plus_concatenation(line) {
            return (part, continues, ContinuationType::PlusOperator);
        }
    }

    if config.python_implicit {
        if let Some((part, continues)) = extract_python_implicit_concatenation(line) {
            return (part, continues, ContinuationType::Implicit);
        }
    }

    if config.template_literals {
        if let Some((part, continues)) = extract_template_literal_continuation(line) {
            return (part, continues, ContinuationType::TemplateLiteral);
        }
    }

    if is_continuation {
        (extract_string_content(line), false, ContinuationType::None)
    } else {
        (line.to_string(), false, ContinuationType::None)
    }
}

#[cfg(feature = "multiline")]
fn extract_string_content(line: &str) -> String {
    let trimmed = line.trim().trim_end_matches([';', ',', ' ']);
    for (open, close) in [('"', '"'), ('\'', '\''), ('`', '`')] {
        if let Some(content) = extract_quoted_content(trimmed, open, close) {
            return content;
        }
    }
    filter_line_content(trimmed)
}

#[cfg(feature = "multiline")]
pub(crate) fn extract_quoted_content(s: &str, open: char, close: char) -> Option<String> {
    let mut chars = s.chars().peekable();
    // Only a Python f-string prefix (`f"`/`F"`) where the `f`/`F` directly
    // abuts the opening quote enables `{...}` interpolation handling. Earlier
    // code OR'd over every preceding character, so any identifier containing an
    // `f` (`prefix`, `config`, `final`, `ref`, ...) wrongly flagged the value
    // as an f-string and silently dropped brace spans from the extracted
    // secret. Track only the char immediately before the quote and gate on
    // adjacency. f-string handling is Python-only, so backtick literals never
    // qualify.
    let mut prev: Option<char> = None;
    while let Some(&ch) = chars.peek() {
        if ch == open {
            break;
        }
        prev = Some(ch);
        chars.next();
    }
    let is_fstring = open != '`' && matches!(prev, Some('f') | Some('F'));

    if chars.next() != Some(open) {
        return None;
    }

    let mut content = String::new();
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if escaped {
            content.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
            content.push(ch);
        } else if ch == close {
            return Some(content);
        } else if is_fstring && ch == '{' && chars.peek() == Some(&'{') {
            // Python f-string escaped open brace `{{` -> literal `{`. Consume the
            // second '{' so it can't be mistaken for the start of an
            // interpolation (the bug: only the first '{' was protected, then the
            // second '{' fired the consumer below and ate the literal body).
            chars.next();
            content.push('{');
        } else if is_fstring && ch == '}' && chars.peek() == Some(&'}') {
            // Python f-string escaped close brace `}}` -> literal `}`.
            chars.next();
            content.push('}');
        } else if is_fstring && ch == '{' {
            // A real `{expr}` interpolation (escaped `{{`/`}}` are handled above):
            // a runtime-computed value, not literal secret bytes. Skip it with
            // nesting so the surrounding literal still reassembles.
            let mut brace_depth = 1;
            for c in chars.by_ref() {
                if c == '{' {
                    brace_depth += 1;
                } else if c == '}' {
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        break;
                    }
                }
            }
        } else {
            content.push(ch);
        }
    }

    None
}

#[cfg(feature = "multiline")]
fn filter_line_content(line: &str) -> String {
    let line = line
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("val ")
        .trim_start_matches("final ")
        .trim_start_matches("static ")
        .trim_start_matches("string ")
        .trim_start_matches("String ")
        .trim_start_matches("auto ")
        .trim_start_matches("dim ")
        .trim_start_matches("my ");

    if let Some(pos) = line.find(" = ") {
        return line[pos + 3..].trim().to_string();
    }
    if let Some(pos) = line.find("= ") {
        return line[pos + 2..].trim().to_string();
    }
    if let Some(pos) = line.find('=') {
        return line[pos + 1..].trim().to_string();
    }

    line.to_string()
}

#[cfg(feature = "multiline")]
fn extract_plus_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    let ends_with_plus = trimmed.ends_with('+');
    if !trimmed.contains('+') {
        return None;
    }

    let content_to_split = if let Some(pos) = trimmed.find('=') {
        &trimmed[pos + 1..]
    } else {
        trimmed
    };

    // This extractor owns quoted/string-literal concatenation only. Unquoted
    // `+` appears naturally inside standard base64 and arithmetic/config
    // expressions; treating it as a join mutates ordinary assignment values and
    // appends a synthetic scan body past EOF. Variable-reference joins such as
    // `token = head + tail` are handled by the structural resolver instead.
    if !content_to_split.contains('"')
        && !content_to_split.contains('\'')
        && !content_to_split.contains('`')
    {
        return None;
    }

    if !ends_with_plus && !content_to_split.contains('+') {
        return None;
    }

    let mut result = String::new();
    let mut part_count = 0usize;
    for part in content_to_split.split('+') {
        part_count += 1;
        let content = extract_string_content(part.trim());
        if !content.is_empty() {
            result.push_str(&content);
        }
    }

    if result.is_empty() || (part_count < 2 && !ends_with_plus) {
        None
    } else {
        Some((result, ends_with_plus))
    }
}

#[cfg(feature = "multiline")]
fn extract_python_implicit_concatenation(line: &str) -> Option<(String, bool)> {
    let chars: Vec<char> = line.chars().collect();
    let mut parts = Vec::new();
    let mut index = 0;
    let mut last_end = None;

    while index < chars.len() {
        if chars[index] == '"' || chars[index] == '\'' {
            let quote = chars[index];
            let start = index;
            let mut j = index + 1;
            let mut content = String::new();
            let mut escaped = false;
            let mut closed = false;

            while j < chars.len() {
                if escaped {
                    content.push(chars[j]);
                    escaped = false;
                } else if chars[j] == '\\' {
                    escaped = true;
                    content.push(chars[j]);
                } else if chars[j] == quote {
                    closed = true;
                    break;
                } else {
                    content.push(chars[j]);
                }
                j += 1;
            }

            if closed {
                if let Some(prev_end) = last_end {
                    let gap = &chars[prev_end + 1..start];
                    if gap.iter().any(|&c| !c.is_whitespace()) {
                        return None;
                    }
                }
                parts.push(content);
                last_end = Some(j);
                index = j;
            }
        }
        index += 1;
    }

    if parts.len() < 2 {
        return None;
    }
    Some((parts.join(""), false))
}

#[cfg(feature = "multiline")]
fn extract_function_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains("paste0(") && !trimmed.contains("paste(") && !trimmed.contains("concat!(")
    {
        return None;
    }
    let parts = extract_quoted_strings(trimmed);
    if parts.len() < 2 {
        return None;
    }
    Some((parts.join(""), false))
}

#[cfg(feature = "multiline")]
fn extract_quoted_strings(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut index = 0;
    let chars: Vec<char> = line.chars().collect();

    while index < chars.len() {
        if chars[index] == '"' || chars[index] == '\'' {
            let quote = chars[index];
            let mut j = index + 1;
            let mut content = String::new();
            let mut escaped = false;

            while j < chars.len() {
                if escaped {
                    content.push(chars[j]);
                    escaped = false;
                } else if chars[j] == '\\' {
                    escaped = true;
                    content.push(chars[j]);
                } else if chars[j] == quote {
                    parts.push(content);
                    index = j;
                    break;
                } else {
                    content.push(chars[j]);
                }
                j += 1;
            }
        }
        index += 1;
    }

    parts
}

#[cfg(feature = "multiline")]
fn extract_template_literal_continuation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains('`') {
        return None;
    }

    let continues = trimmed.chars().filter(|&ch| ch == '`').count() % 2 == 1;
    let mut result = String::new();
    let mut in_template = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '`' {
            in_template = !in_template;
            continue;
        }
        if in_template && ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            // Inside a `${...}` interpolation, string-literal contents ARE
            // concatenation fragments: `ghp_${"BODY"}` reassembles to
            // `ghp_BODY`. Pull the bytes inside any "..."/'...'/`...` and
            // append them; everything else (bare identifiers like
            // `${token}`, operators, whitespace) is a runtime expression,
            // not literal text, so it's skipped - which keeps variable
            // references from polluting the reassembled candidate.
            let mut brace_depth = 1;
            let mut in_str: Option<char> = None;
            for c in chars.by_ref() {
                if let Some(q) = in_str {
                    if c == q {
                        in_str = None;
                    } else {
                        result.push(c);
                    }
                    continue;
                }
                match c {
                    '"' | '\'' | '`' => in_str = Some(c),
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        if brace_depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        if in_template {
            result.push(ch);
        }
    }

    Some((result, continues))
}
