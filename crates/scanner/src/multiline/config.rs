#[cfg(feature = "multiline")]
use regex::Regex;
#[cfg(feature = "multiline")]
use std::sync::LazyLock;

#[cfg(feature = "multiline")]
const MAX_MULTILINE_PREPROCESS_BYTES: usize = 2 * 1024 * 1024;
#[cfg(feature = "multiline")]
const MAX_MULTILINE_LINE_BYTES: usize = 64 * 1024;
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
            template_literals: true,
        }
    }
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
    if bytes.len() > 4096 {
        let has_secret_keyword = memchr::memmem::find(bytes, b"ecret").is_some()
            || memchr::memmem::find(bytes, b"oken").is_some()
            || memchr::memmem::find(bytes, b"assword").is_some()
            || memchr::memmem::find(bytes, b"api_key").is_some()
            || memchr::memmem::find(bytes, b"API_KEY").is_some()
            || memchr::memmem::find(bytes, b"redential").is_some();
        if !has_secret_keyword {
            return false;
        }
    }

    let has_explicit_concat = text.contains("\" +") || text.contains("' +");
    let has_backslash_cont = text.contains("\" \\") || text.contains("' \\");
    let has_template = memchr::memchr(b'`', bytes).is_some();
    // Function-style string concatenation: R's paste()/paste0() and Rust's
    // concat!() macro. All three splice multiple string literals into one
    // value, so any of them is a concat indicator.
    let has_paste =
        text.contains("paste0(") || text.contains("paste(") || text.contains("concat!(");
    let has_implicit = has_implicit_concat_marker(bytes);
    let has_var_ref_concat =
        memchr::memchr(b'+', bytes).is_some() && has_var_ref_concatenation(text);
    if !has_explicit_concat
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
            || trimmed.contains("paste0(")
            || trimmed.contains("paste(")
            || trimmed.contains("concat!(")
            || starts_parenthesized_implicit_block(trimmed)
            || trimmed.contains("\" +")
            || trimmed.contains("' +")
            || trimmed.contains("+ \"")
            || trimmed.contains("+ '")
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
