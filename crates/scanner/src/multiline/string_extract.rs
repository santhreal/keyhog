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
    DotOperator,
    Implicit,
    TemplateLiteral,
}

pub(crate) fn extract_prefix(var_name: &str) -> String {
    let bytes = var_name.as_bytes();
    let mut prefix = String::with_capacity(var_name.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'_' || bytes[i] == b'-' {
            i += 1;
            continue;
        }
        if bytes[i..]
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"part"))
        {
            i += 4;
            continue;
        }
        let Some(ch) = var_name[i..].chars().next() else {
            break;
        };
        prefix.push(ch.to_ascii_lowercase());
        i += ch.len_utf8();
    }
    prefix.truncate(
        prefix
            .trim_end_matches(|ch: char| ch.is_ascii_digit())
            .len(),
    );
    prefix
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

/// Fragment-name suffixes shared by the separated (`base_part`) and compact
/// (`basepart`) credential-fragment strippers below. A single owner so the two
/// suffix lists can never drift apart. The `part<digits>` numeric form is
/// handled separately by each stripper (it is a pattern, not a fixed literal).
const FRAGMENT_SUFFIXES: [&str; 16] = [
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
];

fn strip_separated_fragment_suffix(normalized: &str) -> Option<&str> {
    let (base, suffix) = normalized.rsplit_once('_')?;
    if base.is_empty() {
        return None;
    }
    let suffix_is_fragment = FRAGMENT_SUFFIXES.contains(&suffix)
        || suffix
            .strip_prefix("part")
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
    suffix_is_fragment.then_some(base)
}

fn strip_compact_fragment_suffix(compact: &str) -> Option<&str> {
    for suffix in FRAGMENT_SUFFIXES {
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

    if config.dot_concatenation {
        if let Some((part, continues)) = extract_dot_concatenation(line) {
            return (part, continues, ContinuationType::DotOperator);
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
            // a runtime-computed value, not literal secret bytes. Skip it,
            // tracking nested braces AND string literals inside the expression
            // so a `{`/`}` that appears INSIDE a quoted span (e.g.
            // `f"{d['}']}tail"`) does not miscount the depth and end the skip
            // early — which would leak the expression's tail (`']}tail`) into the
            // reassembled secret. Mirrors the string-aware `${...}` skip in
            // `extract_template_literal_continuation`.
            let mut brace_depth = 1;
            let mut in_str: Option<char> = None;
            for c in chars.by_ref() {
                if let Some(quote) = in_str {
                    if c == quote {
                        in_str = None;
                    }
                } else if c == '\'' || c == '"' {
                    in_str = Some(c);
                } else if c == '{' {
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

/// Iterate the literal segments of a string-concatenation expression, splitting
/// ONLY on the `op` join byte that sit OUTSIDE any quoted span. An `op` inside a
/// quoted literal is part of the value, not a join operator: base64 uses `+` in
/// its alphabet (`"aGVsbG8+d29ybGQ="`) and a `.` is ubiquitous inside string
/// values (`"api.example.com"`); a fragment can even end in one
/// (`"aGVsbG8+" + "d29ybGQ="`). A blind `split(op)` shredded those values,
/// truncating the secret and breaking reassembly. Quote state honors backslash
/// escapes so an escaped quote inside a literal does not end the span early.
///
/// Parameterized on the single join byte so the `+` (Java/JS/Python/C#) and `.`
/// (PHP/Perl) extractors share ONE quote-aware streaming splitter instead of
/// each hand-rolling its own scan loop. `op` must be single-byte ASCII (`b'+'`
/// or `b'.'`); like `"`, `'` and `` ` `` it then always lands on a char
/// boundary, so every yielded slice is valid UTF-8.
///
/// Yields borrowed slices LAZILY via `from_fn` — no `Vec` allocation, so the hot
/// path stays allocation-light.
#[cfg(feature = "multiline")]
fn split_concatenation_operators(expr: &str, op: u8) -> impl Iterator<Item = &str> {
    let bytes = expr.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let mut finished = false;
    std::iter::from_fn(move || {
        if finished {
            return None;
        }
        while i < bytes.len() {
            let b = bytes[i];
            i += 1;
            if let Some(q) = quote {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == q {
                    quote = None;
                }
            } else if matches!(b, b'"' | b'\'' | b'`') {
                quote = Some(b);
            } else if b == op {
                let segment = &expr[start..i - 1];
                start = i;
                return Some(segment);
            }
        }
        finished = true;
        Some(&expr[start..])
    })
}

/// Byte index of the first `=` that sits OUTSIDE any quoted span — the
/// assignment operator that separates a `name = value` line's LHS from its
/// value. A quote-UNAWARE `str::find('=')` mistakes a base64 padding `=` inside
/// the value's FIRST quoted literal for the assignment: on a bare continuation
/// fragment like `"aGVsbG8=" + "d29ybGQ="` it splits at the padding `=` inside
/// `"aGVsbG8="`, discarding the leading fragment and corrupting the `+`/`.`
/// operator split so the whole concatenation is dropped — a silent recall loss
/// on any secret whose reassembly crosses a padded base64 fragment. Tracking
/// quote state (with backslash escapes, matching [`split_concatenation_operators`])
/// keeps the value intact. Returns `None` when the line has no unquoted `=` (the
/// common continuation-fragment case), so the caller splits the whole line.
#[cfg(feature = "multiline")]
fn find_unquoted_assignment_eq(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
        } else if matches!(b, b'"' | b'\'' | b'`') {
            quote = Some(b);
        } else if b == b'=' {
            return Some(i);
        }
    }
    None
}

/// Strip a `name = value` assignment prefix using the quote-aware
/// [`find_unquoted_assignment_eq`], returning the value slice (or the whole line
/// when there is no unquoted `=`). Shared by the `+` and `.` concat extractors so
/// the assignment-boundary rule is defined ONCE and can never drift (both once
/// hand-rolled the same quote-unaware `find('=')`).
#[cfg(feature = "multiline")]
fn strip_assignment_prefix(trimmed: &str) -> &str {
    match find_unquoted_assignment_eq(trimmed) {
        Some(pos) => &trimmed[pos + 1..],
        None => trimmed,
    }
}

#[cfg(feature = "multiline")]
pub(crate) fn extract_plus_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    let ends_with_plus = trimmed.ends_with('+');
    if !trimmed.contains('+') {
        return None;
    }

    let content_to_split = strip_assignment_prefix(trimmed);

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

    // Split only on join `+` (outside quotes); stream the segments so a single
    // literal that merely contains a `+` (e.g. a base64 value) yields one
    // segment and — absent a trailing join `+` — is correctly rejected below as
    // "not a concatenation".
    let mut result = String::new();
    let mut part_count = 0usize;
    for part in split_concatenation_operators(content_to_split, b'+') {
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

/// PHP / Perl join string literals with the `.` operator:
///   `$token = "ghp_" . "abcdef" . "012345";`
///
/// Unlike `+`, `.` is heavily overloaded — member access (`obj.field`), float
/// literals (`3.14`), namespace and path separators, file extensions — so this
/// extractor is deliberately STRICT to stay precise on three axes:
///
/// 1. It splits ONLY on the `.` that sit OUTSIDE every quoted span (shared
///    [`split_concatenation_operators`]); a `.` inside `"a.b"` is value bytes.
/// 2. It reassembles ONLY segments that ARE a quoted literal. A bare segment
///    (`$var`, `PHP_EOL`, `trim("x")`) is a runtime value — never literal secret
///    bytes — so it is dropped, the same philosophy as the `${...}`
///    template-literal handler. Requiring the segment to *start* with a quote
///    (not merely contain one) keeps a function call's string argument from
///    being mistaken for a concatenated fragment.
/// 3. It requires at least two segments to contribute quoted bytes (the
///    `"x" . "y"` idiom). That guard is what stops `arr["k"].length`,
///    `cfg["db.host"]`, `explode(".", $s)` and `3.14` from reassembling into a
///    synthetic candidate — each yields at most one quoted literal.
///
/// A trailing join `.` (`$x = "a" .` continued on the next line) sets the
/// continuation flag so the chain walker pulls the next line, exactly like the
/// `+` and backslash continuations.
#[cfg(feature = "multiline")]
pub(crate) fn extract_dot_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains('.') {
        return None;
    }

    let content_to_split = strip_assignment_prefix(trimmed);

    // A `.`-join is meaningful only between quoted literals; an unquoted `.` is
    // member access / a float / a path separator, never a string join. Cheap
    // reject so ordinary `obj.method()` / `a.b.c` lines never enter the split.
    if !content_to_split.contains('"')
        && !content_to_split.contains('\'')
        && !content_to_split.contains('`')
    {
        return None;
    }

    let ends_with_dot = content_to_split.trim_end().ends_with('.');

    let mut result = String::new();
    let mut contributing = 0usize;
    for part in split_concatenation_operators(content_to_split, b'.') {
        let part = part.trim();
        // STRICT: only a segment that IS a quoted literal contributes. A bare
        // segment (identifier / variable ref / function call) is runtime, not
        // literal secret bytes — drop it rather than append the token verbatim.
        if !part.starts_with(['"', '\'', '`']) {
            continue;
        }
        if let Some(content) = first_quoted_literal(part) {
            if !content.is_empty() {
                result.push_str(&content);
                contributing += 1;
            }
        }
    }

    if result.is_empty() || (contributing < 2 && !ends_with_dot) {
        None
    } else {
        Some((result, ends_with_dot))
    }
}

/// Extract the content of the FIRST quoted literal in `s` (any of `"`, `'`,
/// `` ` ``), honoring backslash escapes via [`extract_quoted_content`].
/// Returns `None` when `s` has no quoted literal. Unlike
/// [`extract_string_content`], it has NO raw-line fallback — that absence is the
/// point: the dot-concat extractor uses it to DROP bare runtime segments rather
/// than append their source text.
#[cfg(feature = "multiline")]
fn first_quoted_literal(s: &str) -> Option<String> {
    for (open, close) in [('"', '"'), ('\'', '\''), ('`', '`')] {
        if let Some(content) = extract_quoted_content(s, open, close) {
            return Some(content);
        }
    }
    None
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
