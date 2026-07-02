#[cfg(feature = "multiline")]
use regex::Regex;
#[cfg(feature = "multiline")]
use std::sync::LazyLock;

#[cfg(feature = "multiline")]
const MAX_MULTILINE_PREPROCESS_BYTES: usize = 2 * 1024 * 1024;
#[cfg(feature = "multiline")]
const MAX_MULTILINE_LINE_BYTES: usize = 64 * 1024;
/// File-size threshold above which multiline concatenation preprocessing only
/// runs when a secret-related keyword is present — below it the cheap structural
/// scan runs unconditionally, above it the keyword gate avoids preprocessing
/// large non-secret blobs.
#[cfg(feature = "multiline")]
const LARGE_FILE_KEYWORD_GATE_BYTES: usize = 4096;
pub(crate) const DEFAULT_MAX_JOIN_LINES: usize = 64;

#[cfg(feature = "multiline")]
static VAR_REF_CONCAT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    match Regex::new(
        r#"(?i)^\s*[a-z0-9_\-\.]{2,64}\s*[:=]\s*[a-z0-9_\-]{2,32}(?:\s*\+\s*[a-z0-9_\-]{2,32}){1,8}\s*;?\s*$"#,
    ) {
        Ok(re) => Some(re),
        Err(error) => {
            crate::prefilter_degrade::warn_prefilter_disabled(
                "multiline variable-reference concatenation regex (VAR_REF_CONCAT_RE)",
                &error,
            );
            None
        }
    }
});

#[cfg(feature = "multiline")]
pub(crate) fn warm_runtime_regexes() {
    let _ = VAR_REF_CONCAT_RE.as_ref(); // LAW10: forces lazy-static/regex eager init (warm-up); not a fallback
}

/// A mapping from an offset in the joined text back to the original line number.
#[cfg(feature = "multiline")]
#[derive(Debug, Clone)]
pub(crate) struct LineMapping {
    /// Start offset in the joined text (inclusive).
    pub(crate) start_offset: usize,
    /// End offset in the joined text (exclusive).
    pub(crate) end_offset: usize,
    /// Original line number (1-indexed).
    pub(crate) line_number: usize,
    /// Start byte offset of the mapped source line in the original text.
    pub(crate) original_start_offset: usize,
}

pub(super) fn source_line_offset_or_record_gap(
    source_line_offsets: &[usize],
    zero_based_line_index: usize,
) -> usize {
    if let Some(offset) = source_line_offsets.get(zero_based_line_index).copied() {
        return offset;
    }
    crate::telemetry::record_line_offset_mapping_mismatch();
    match source_line_offsets.last().copied() {
        Some(offset) => offset,
        None => 0, // LAW10: mismatch was counted above; empty table has no better attribution anchor, finding still emits
    }
}

/// Result of preprocessing text for multi-line concatenation.
///
/// `text` is a [`Cow`] so the overwhelmingly common passthrough/identity case
/// (a chunk with no structured-config shape and no multiline concatenation)
/// can BORROW the caller's chunk bytes with zero allocation instead of paying a
/// full-body `to_string()` heap copy + memcpy on every chunk. Only the paths
/// that genuinely synthesize NEW bytes — multiline-joined concatenation,
/// structured-config key/value reassembly, homoglyph normalization — own a
/// `String` via `Cow::Owned`. Downstream consumers read `text` as `&str` via
/// `Deref`, so the borrow is internal to preprocessing.
#[cfg(feature = "multiline")]
#[derive(Debug, Clone)]
pub(crate) struct PreprocessedText<'a> {
    /// Original text (borrowed for passthrough) plus, for the synthesizing
    /// paths, appended multiline-joined / structured segments (owned).
    pub(crate) text: std::borrow::Cow<'a, str>,
    /// Byte offset where appended joined segments start.
    pub(crate) original_end: usize,
    /// Mapping from offsets in `text` to original line numbers.
    pub(crate) mappings: Vec<LineMapping>,
}

#[cfg(feature = "multiline")]
impl<'a> PreprocessedText<'a> {
    /// Map a byte offset in preprocessed text back to an original line number.
    ///
    /// Mappings are stored in `start_offset`-sorted, contiguous order
    /// (the preprocessor appends them as it walks the input), so a
    /// `partition_point` binary search resolves the lookup in
    /// `O(log L)` instead of the prior `O(L)` linear scan. On a
    /// 10 000-line file with ~100 matches that's 10 000 × 100 = 1 M
    /// pointer compares cut to ~1 400.
    pub(crate) fn line_for_offset(&self, offset: usize) -> Option<usize> {
        let idx = self.mappings.partition_point(|m| m.start_offset <= offset);
        if idx == 0 {
            return None;
        }
        let m = &self.mappings[idx - 1];
        if offset < m.end_offset {
            Some(m.line_number)
        } else {
            None
        }
    }

    pub(crate) fn source_offset_for_match(
        &self,
        source: &str,
        offset: usize,
        credential: &str,
    ) -> usize {
        let idx = self.mappings.partition_point(|m| m.start_offset <= offset);
        if idx == 0 {
            return offset.min(source.len().saturating_sub(1));
        }
        let m = &self.mappings[idx - 1];
        if offset >= m.end_offset {
            return offset.min(source.len().saturating_sub(1));
        }
        source_offset_from_mapping(source, m, offset, credential)
    }

    /// Build a preprocessed representation with a one-line identity mapping.
    ///
    /// Takes the text as a [`Cow`] so a byte-identical passthrough chunk can be
    /// carried as `Cow::Borrowed` (zero allocation — no heap alloc or memcpy of
    /// the chunk body) while a normalization-rewritten chunk passes its already-
    /// owned `String` through as `Cow::Owned`. Only the per-line `mappings`
    /// bookkeeping (size-independent of the body bytes) is allocated either way.
    pub(crate) fn passthrough(text: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        let text: std::borrow::Cow<'a, str> = text.into();
        let mut mappings = Vec::new();
        let mut offset = 0;
        for (line_idx, line) in text.split('\n').enumerate() {
            let end = offset + line.len();
            mappings.push(LineMapping {
                line_number: line_idx + 1,
                start_offset: offset,
                end_offset: end + 1,
                original_start_offset: offset,
            });
            offset = end + 1;
        }
        if let Some(last) = mappings.last_mut() {
            last.end_offset = text.len();
        }
        let original_end = text.len();
        Self {
            text,
            original_end,
            mappings,
        }
    }
}

#[cfg(feature = "multiline")]
fn source_offset_from_mapping(
    source: &str,
    mapping: &LineMapping,
    offset: usize,
    credential: &str,
) -> usize {
    if mapping.start_offset == mapping.original_start_offset && offset < source.len() {
        return offset;
    }
    if let Some(line) = source_line_at(source, mapping.original_start_offset) {
        if let Some(column) = line.find(credential) {
            return mapping.original_start_offset + column;
        }
    }
    let candidate = mapping
        .original_start_offset
        .saturating_add(offset.saturating_sub(mapping.start_offset));
    if candidate < source.len() {
        candidate
    } else if mapping.original_start_offset < source.len() {
        mapping.original_start_offset
    } else {
        source.len().saturating_sub(1)
    }
}

#[cfg(feature = "multiline")]
fn source_line_at(source: &str, start: usize) -> Option<&str> {
    if start >= source.len() {
        return None;
    }
    // `start` is a byte offset carried through the line-mapping bookkeeping; on
    // binary / lossy-UTF-8 input (e.g. a compiled artifact decoded with U+FFFD
    // replacement chars) it can land INSIDE a multi-byte scalar, where a raw
    // `&source[start..]` panics with "byte index N is not a char boundary" and
    // aborts the whole worker. Snap DOWN to the enclosing char boundary - the
    // line that contains that byte is unchanged - so the slice is always valid.
    // LAW10: snapping down to a char boundary is recall-preserving -- the same
    // line text is scanned and findings are unchanged; it only prevents a panic
    // on a mid-scalar byte index. Mirrors the pervasive `floor_char_boundary`
    // guarding the engine's other offset slices.
    let start = crate::engine::floor_char_boundary(source, start);
    let rest = &source[start..];
    let end = rest.find('\n').unwrap_or(rest.len()); // LAW10: no newline means the line runs to source end; reporting-only coordinate slice
    let line = &rest[..end];
    Some(line.strip_suffix('\r').unwrap_or(line)) // LAW10: no CR suffix means the source line is already normalized; reporting-only coordinate slice
}

/// Configuration for multiline concatenation recovery.
#[derive(Debug, Clone)]
pub struct MultilineConfig {
    /// Maximum number of lines to join in a single concatenation chain.
    pub max_join_lines: usize,
    /// Whether to enable Python-style implicit concatenation.
    pub python_implicit: bool,
    /// Whether to enable backslash line continuation.
    pub backslash_continuation: bool,
    /// Whether to enable explicit concatenation with `+`.
    pub plus_concatenation: bool,
    /// Whether to enable explicit concatenation with the `.` operator
    /// (PHP / Perl string concatenation: `$x = "a" . "b";`).
    pub dot_concatenation: bool,
    /// Whether to enable JavaScript template literal concatenation.
    pub template_literals: bool,
}

impl Default for MultilineConfig {
    fn default() -> Self {
        Self {
            max_join_lines: DEFAULT_MAX_JOIN_LINES,
            python_implicit: true,
            backslash_continuation: true,
            plus_concatenation: true,
            dot_concatenation: true,
            template_literals: true,
        }
    }
}

/// String markers for function-style string concatenation: R's `paste()` /
/// `paste0()` and Rust's `concat!()` macro. All three splice multiple string
/// literals into one value, so any of them signals a concat. Single owner shared
/// by the whole-text indicator scan, the per-line indicator scan (both here), and
/// the per-line extractor in `string_extract`, so the marker set can never drift
/// across the three call sites.
#[cfg(feature = "multiline")]
pub(super) fn has_function_concat_marker(s: &str) -> bool {
    s.contains("paste0(") || s.contains("paste(") || s.contains("concat!(")
}

/// Check if text contains any concatenation indicators.
#[cfg(feature = "multiline")]
pub(crate) fn has_concatenation_indicators(text: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{')
        || trimmed.starts_with('[')
        || trimmed.starts_with("<?xml")
        || trimmed.starts_with('<')
    {
        return false;
    }

    let bytes = text.as_bytes();

    // For large files, only preprocess if secret-related keywords are present.
    // The match is ASCII-case-insensitive: env-style credentials use all-caps
    // keys (`SECRET=`, `API_TOKEN=`, `DB_PASSWORD=`) at least as often as the
    // title/lowercase forms, and skipping their multiline-concat reassembly was
    // a silent recall hole. `ci_find` jumps to first-byte candidates with
    // memchr2 and only full-compares there, so this stays a fast prefilter.
    if bytes.len() > LARGE_FILE_KEYWORD_GATE_BYTES {
        use crate::ascii_ci::ci_find;
        let has_secret_keyword = ci_find(bytes, b"secret")
            || ci_find(bytes, b"token")
            || ci_find(bytes, b"password")
            || ci_find(bytes, b"api_key")
            || ci_find(bytes, b"credential");
        if !has_secret_keyword {
            return false;
        }
    }

    let has_explicit_concat = text.contains("\" +") || text.contains("' +");
    let has_dot_concat = has_dot_concat_shape(text);
    let has_backslash_cont = text.contains("\" \\") || text.contains("' \\");
    let has_template = memchr::memchr(b'`', bytes).is_some();
    // Function-style string concatenation (R paste()/paste0(), Rust concat!()).
    let has_paste = has_function_concat_marker(text);
    let has_implicit = has_implicit_concat_marker(bytes);
    let has_var_ref_concat =
        memchr::memchr(b'+', bytes).is_some() && has_var_ref_concatenation(text);
    if !has_explicit_concat
        && !has_dot_concat
        && !has_backslash_cont
        && !has_template
        && !has_paste
        && !has_implicit
        && !has_var_ref_concat
    {
        return false;
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with('+')
            || trimmed.starts_with('+')
            || trimmed.starts_with("+ ")
            || has_function_concat_marker(trimmed)
            || starts_parenthesized_implicit_block(trimmed)
            || trimmed.contains("\" +")
            || trimmed.contains("' +")
            || trimmed.contains("+ \"")
            || trimmed.contains("+ '")
            // PHP / Perl `.` join between two adjacent quoted literals
            // (`"x" . "y"`) or a trailing-dot continuation (`"x" .`).
            || has_dot_concat_shape(trimmed)
            || (trimmed.ends_with('\\') && !trimmed.ends_with("\\\\"))
            || trimmed.contains("\" \"")
            || trimmed.contains("' '")
            || has_var_ref_concat_line(trimmed)
            || (trimmed.ends_with('`') && trimmed.matches('`').count() == 1)
            // String literal interpolated INTO a template literal:
            // `ghp_${"BODY"}` / `${'a'}${'b'}`. The `${"`/`${'` shape is the
            // concat-evasion signal - a string literal spliced into an
            // interpolation. Deliberately narrow: bare `${ident}` (normal
            // runtime interpolation, ubiquitous in JS/TS) is NOT flagged, so
            // this adds no preprocessing cost to ordinary template code.
            || trimmed.contains("${\"")
            || trimmed.contains("${'")
            // Adjacent template interpolations `${a}${b}` - the close-brace
            // immediately followed by `${` is the concat-via-interpolation
            // signal. Ordinary single interpolation (`Hi ${name}!`) has
            // literal text between/around the braces and never produces
            // `}${`, so this stays clear of the ubiquitous JS/TS template
            // case and adds no cost to it.
            || trimmed.contains("}${")
        {
            return true;
        }
    }

    false
}

/// Detect a PHP / Perl `.`-operator string-concatenation join: a `.` that sits
/// OUTSIDE any quoted span and directly joins two adjacent quoted literals
/// (`"x" . "y"`, any amount of intervening whitespace) OR ends a line as a
/// trailing-dot continuation (`"x" .` continued on the next line).
///
/// This is the gate for [`extract_dot_concatenation`]. It is deliberately
/// precise so it does NOT trip preprocessing on the overloaded `.`:
///   * a `.` inside a string (`"a.b.c"`, `explode(".", $s)`) is skipped by
///     quote tracking — it never reaches the join check;
///   * a float (`3.14`) or member access (`obj.method`, `"str".length`) has a
///     non-quote on at least one side, so it is rejected — the literal-method
///     case `"str".length` in particular is NOT a join (identifier on the
///     right), which keeps ordinary JS/Python string-method calls cheap.
///
/// Single O(n) byte pass, no allocation. Only `"` and `'` are string delimiters
/// here (PHP/Perl); backtick is intentionally not a `.`-concat delimiter.
#[cfg(feature = "multiline")]
fn has_dot_concat_shape(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    // True when the most recent non-whitespace byte was a closing string quote,
    // i.e. a quoted literal just ended (modulo trailing spaces/tabs).
    let mut prev_nonspace_closed_quote = false;
    let mut i = 0usize;
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
                prev_nonspace_closed_quote = true;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => {
                quote = Some(b);
                prev_nonspace_closed_quote = false;
            }
            b' ' | b'\t' => { /* whitespace preserves the prev-token state */ }
            b'.' if prev_nonspace_closed_quote => {
                // Left side is a closed quote; a join requires the right side to
                // be another quoted literal (adjacent concatenation) or the end
                // of the line (trailing-dot continuation).
                let mut j = i;
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                    j += 1;
                }
                let right_is_quote = j < bytes.len() && matches!(bytes[j], b'"' | b'\'');
                let right_is_eol = j >= bytes.len() || matches!(bytes[j], b'\n' | b'\r');
                if right_is_quote || right_is_eol {
                    return true;
                }
                prev_nonspace_closed_quote = false;
            }
            _ => prev_nonspace_closed_quote = false,
        }
    }
    false
}

#[cfg(feature = "multiline")]
pub(super) fn starts_parenthesized_implicit_block(line: &str) -> bool {
    let Some(assign_idx) = line.find(['=', ':']) else {
        return false;
    };
    line[assign_idx + 1..].trim() == "("
}

#[cfg(feature = "multiline")]
fn has_implicit_concat_marker(bytes: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[
        b"\" \"", b"' '", b"\"\n\"", b"\"\n ", b"\"\n\t", b"'\n'", b"'\n ", b"'\n\t",
    ];
    MARKERS
        .iter()
        .any(|marker| memchr::memmem::find(bytes, marker).is_some())
}

/// Variable-reference concatenation: `token = head + tail` (no quoted
/// literals on the RHS). The structural reassembly pass resolves these
/// via `resolve_concat_reference`; without this indicator the multiline
/// preprocessor passthroughs and the split credential never surfaces.
#[cfg(feature = "multiline")]
fn has_var_ref_concatenation(text: &str) -> bool {
    text.lines().any(has_var_ref_concat_line)
}

#[cfg(feature = "multiline")]
fn has_var_ref_concat_line(line: &str) -> bool {
    // Cheap precheck: var-ref concatenation REQUIRES at least one `+`
    // separator between two identifiers. Lines without one cannot
    // possibly match - skip the regex entirely. Without this, the
    // `(?:\s*\+\s*[a-z0-9_\-]{2,32}){1,8}` repeated-group bound forces
    // the regex crate's NFA to evaluate every starting position on
    // identifier-dense source lines, which on Apple Silicon
    // (regex 1.12, lazy-DFA construction stalled by the `{1,8}`-bounded
    // alternation) burns minutes of CPU per line. Surfaced during
    // v0.5.25 cross-platform dogfood: a 171-byte Go file with shape
    // `var token = receiver.Flag("x", "y").Required().String()` hung
    // for 6+ minutes on Mac arm64 portable while Linux x86_64
    // completed it in 0.6 s. The precheck is correctness-preserving:
    // when no `+` exists in the line, the regex *cannot* match.
    if !line.contains('+') {
        return false;
    }
    VAR_REF_CONCAT_RE
        .as_ref()
        .is_some_and(|re| re.is_match(line))
}

#[cfg(feature = "multiline")]
pub(crate) fn should_passthrough(text: &str) -> bool {
    text.len() > MAX_MULTILINE_PREPROCESS_BYTES
        || text
            .lines()
            .any(|line| line.len() > MAX_MULTILINE_LINE_BYTES)
        || !has_concatenation_indicators(text)
}

#[cfg(all(test, feature = "multiline"))]
mod tests {
    use super::{has_concatenation_indicators, has_function_concat_marker};

    #[test]
    fn function_concat_marker_matches_all_three_forms_only() {
        // Every form the single-owner marker set must recognize.
        assert!(has_function_concat_marker("x = paste0(\"a\", \"b\")"));
        assert!(has_function_concat_marker("x <- paste(\"a\", \"b\")"));
        assert!(has_function_concat_marker("let x = concat!(\"a\", \"b\");"));
        // Near-misses that must NOT trip it: a different macro, and an
        // identifier that merely embeds "paste" without the call paren.
        assert!(!has_function_concat_marker("let x = format!(\"a\")"));
        assert!(!has_function_concat_marker("let pastexyz = 3"));
        assert!(!has_function_concat_marker("let x = 3.14"));
    }

    #[test]
    fn has_indicators_uses_function_concat_marker_at_both_scans() {
        // paste0 line: whole-text scan and per-line scan both route through the
        // shared marker and flag it as a concatenation indicator.
        assert!(has_concatenation_indicators(
            "token = paste0(\"gh\", \"p_deadbeefdeadbeef\")"
        ));
        // JSON-shaped body is rejected up front regardless of markers.
        assert!(!has_concatenation_indicators("{\"a\": \"b\"}"));
        // Plain assignment with no concat shape is not an indicator.
        assert!(!has_concatenation_indicators("token = \"static_value\""));
    }
}
