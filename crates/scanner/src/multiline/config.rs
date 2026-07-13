#[cfg(feature = "multiline")]
const MAX_MULTILINE_PREPROCESS_BYTES: usize = 2 * 1024 * 1024;
#[cfg(feature = "multiline")]
const MAX_MULTILINE_LINE_BYTES: usize = 64 * 1024;
/// File-size threshold above which multiline concatenation preprocessing only
/// runs when a secret-related keyword is present, below it the cheap structural
/// scan runs unconditionally, above it the keyword gate avoids preprocessing
/// large non-secret blobs.
#[cfg(feature = "multiline")]
const LARGE_FILE_KEYWORD_GATE_BYTES: usize = 4096;
pub(crate) const DEFAULT_MAX_JOIN_LINES: usize = 64;

// `LineMapping` + `source_offset_from_mapping` are the ONE always-compiled owners
// in `crate::types` (this module's `#[cfg(feature="multiline")]` copies were
// field/body-identical duplicates). `source_line_at` is internal to
// `source_offset_from_mapping`, so it is not imported here.
// `pub(crate)` re-export so sibling modules (`preprocessor`, `structural`) that
// `use super::config::LineMapping` keep resolving after the definition moved to
// the single `crate::types` owner. `source_offset_from_mapping` is only called
// within this module, so it stays a private import.
#[cfg(feature = "multiline")]
use crate::types::source_offset_from_mapping;
#[cfg(feature = "multiline")]
pub(crate) use crate::types::LineMapping;

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
/// that genuinely synthesize NEW bytes, multiline-joined concatenation,
/// structured-config key/value reassembly, homoglyph normalization, own a
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

    pub(crate) fn transport_decoded_for_offset(&self, offset: usize) -> bool {
        crate::types::transport_decoded_for_offset(&self.mappings, offset)
    }

    /// Build a preprocessed representation with a one-line identity mapping.
    ///
    /// Takes the text as a [`Cow`] so a byte-identical passthrough chunk can be
    /// carried as `Cow::Borrowed` (zero allocation, no heap alloc or memcpy of
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
                transport_decoded: false,
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
pub(crate) fn has_function_concat_marker(s: &str) -> bool {
    s.contains("paste0(") || s.contains("paste(") || s.contains("concat!(")
}

/// Check if text contains any concatenation indicators.
#[cfg(feature = "multiline")]
pub(crate) fn has_concatenation_indicators(text: &str) -> bool {
    let trimmed = text.trim_start();
    // XML / HTML markup never carries a string-CONCATENATION continuation shape
    // (there is no `"a" + "b"` splice in element text), and is owned by its own
    // structured path, so a leading `<` / `<?xml` is a cheap, sound reject.
    if trimmed.starts_with("<?xml") || trimmed.starts_with('<') {
        return false;
    }
    // A buffer that OPENS with `{` / `[` is ambiguous: it may be JSON DATA (owned
    // by the structured JSON parser, and with no `"a" + "b"` concat surface to
    // recover) OR a JS / TS / Groovy / Jsonnet SOURCE file that legitimately
    // starts with an object / array literal carrying a multiline-concatenated
    // secret (e.g. a module that opens `{ apiKey: "gh" +\n  "p_deadbeef…" }`).
    // The old blanket leading-brace reject dropped the SECOND case's entire
    // multiline surface (Law 10: a whole scan surface silently skipped on a
    // shape heuristic). We defer the STRUCTURAL disambiguation (a strict-JSON
    // parse) to AFTER the cheap concat-indicator gate below so it runs only for
    // the narrow set of `{`/`[`-leading buffers that actually tripped a concat
    // shape, a benign large JSON blob with no concat bytes still bails via the
    // cheap byte scans without ever paying a full parse.
    let starts_structured = trimmed.starts_with('{') || trimmed.starts_with('[');

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
    let has_empty_array_join = text.contains('[') && has_empty_string_join_marker(text);
    let has_implicit = has_implicit_concat_marker(bytes);
    let has_var_ref_concat =
        memchr::memchr(b'+', bytes).is_some() && has_var_ref_concatenation(text);
    if !has_explicit_concat
        && !has_dot_concat
        && !has_backslash_cont
        && !has_template
        && !has_paste
        && !has_empty_array_join
        && !has_implicit
        && !has_var_ref_concat
    {
        return false;
    }

    // At least one concat shape is present. If the buffer nonetheless opened with
    // `{`/`[` AND parses as strict JSON, it is genuine JSON data (the concat byte
    // lived inside a quoted JSON value, e.g. a backtick or `+` in a string) with
    // no recoverable concatenation surface, skip it. A JS/TS object literal
    // fails this parse fast and proceeds to the per-line scan below.
    if starts_structured && parses_as_strict_json(trimmed) {
        return false;
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with('+')
            || trimmed.starts_with('+')
            || trimmed.starts_with("+ ")
            || has_function_concat_marker(trimmed)
            || has_empty_string_join_marker(trimmed)
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

/// Detect JavaScript's static empty-separator array join: `.join('')`,
/// `.join("")`, or the whitespace-equivalent forms. A non-empty separator is
/// not a secret-fragment concatenation and is deliberately excluded.
#[cfg(feature = "multiline")]
pub(super) fn has_empty_string_join_marker(text: &str) -> bool {
    let mut remaining = text;
    while let Some(index) = remaining.find(".join") {
        remaining = &remaining[index + ".join".len()..];
        let Some(arguments) = remaining.trim_start().strip_prefix('(') else {
            continue;
        };
        let arguments = arguments.trim_start();
        let after_empty = arguments
            .strip_prefix("''")
            .or_else(|| arguments.strip_prefix("\"\""))
            .or_else(|| arguments.strip_prefix("``"));
        if after_empty.is_some_and(|rest| rest.trim_start().starts_with(')')) {
            return true;
        }
    }
    false
}

/// Robust structural discriminator for a `{` / `[`-leading buffer: `true` iff
/// the WHOLE buffer parses as strict JSON.
///
/// This replaces the old "starts with `{`/`[` ⇒ skip" first-byte heuristic that
/// silently dropped the multiline surface of every JS/TS source file opening
/// with an object/array literal (Law 10). JSON has no string-concatenation
/// syntax, so a genuine JSON data file has nothing for the multiline join pass
/// to recover and is correctly skipped here; a JS/TS/Groovy literal is NOT valid
/// JSON (unquoted keys, `+` concatenation, backtick templates, trailing commas,
/// comments) and serde's streaming parser rejects it at the first offending
/// token, cheaply, without walking the whole buffer, so it falls through to
/// the concatenation-indicator scan and keeps its multiline surface.
#[cfg(feature = "multiline")]
fn parses_as_strict_json(text: &str) -> bool {
    // `IgnoredAny` validates the JSON grammar without materializing a `Value`
    // tree (zero heap allocation on the common already-JSON path).
    serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok()
}

/// Detect a PHP / Perl `.`-operator string-concatenation join: a `.` that sits
/// OUTSIDE any quoted span and directly joins two adjacent quoted literals
/// (`"x" . "y"`, any amount of intervening whitespace) OR ends a line as a
/// trailing-dot continuation (`"x" .` continued on the next line).
///
/// This is the gate for [`extract_dot_concatenation`]. It is deliberately
/// precise so it does NOT trip preprocessing on the overloaded `.`:
///   * a `.` inside a string (`"a.b.c"`, `explode(".", $s)`) is skipped by
///     quote tracking, it never reaches the join check;
///   * a float (`3.14`) or member access (`obj.method`, `"str".length`) has a
///     non-quote on at least one side, so it is rejected, the literal-method
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
    super::structural::CONCAT_RE.is_match(line)
}

#[cfg(feature = "multiline")]
pub(crate) fn should_passthrough(text: &str) -> bool {
    text.len() > MAX_MULTILINE_PREPROCESS_BYTES
        || text
            .lines()
            .any(|line| line.len() > MAX_MULTILINE_LINE_BYTES)
        || !has_concatenation_indicators(text)
}
