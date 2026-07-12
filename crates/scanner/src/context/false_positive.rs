use super::inference::{surrounding_line_window, COMMENT_MARKERS};
use crate::ascii_ci::ci_find;
use keyhog_core::git_lfs;
use std::collections::BTreeSet;

/// Returns `true` if the match is in a context that indicates a false positive.
pub(crate) fn is_false_positive_match_context(
    text: &str,
    match_start: usize,
    file_path: Option<&str>,
) -> bool {
    is_false_positive_match_context_with_path(text, match_start, file_path, None)
}

/// Same as `is_false_positive_match_context` but accepts a pre-lowered path
/// to avoid re-allocating the lowercase path string on every match.
pub(crate) fn is_false_positive_match_context_with_path(
    text: &str,
    match_start: usize,
    _file_path: Option<&str>,
    path_lower: Option<&str>,
) -> bool {
    // Raw bytes against pre-lowered needles via `ci_find`. The earlier shape
    // copied the window into a stack buffer, made it ascii-lowercase, then
    // `.to_string()`-allocated for the heap form before running 8 substring
    // searches on it. Every match was paying that 1-2 µs of memcpy + heap
    // copy even when the very first `ci_find` would have returned false
    // immediately. The `ci_find` path skims via memchr2 SIMD and only walks
    // bytes when a candidate first-byte is actually present.
    let window = surrounding_line_window(text, match_start, 1);
    let bytes = window.as_bytes();
    // The current line + its match-relative offset come from a single
    // `line_at_offset` scan; the earlier extra `surrounding_line_window(.., 0)`
    // recomputed the very same current line a second time per match.
    let (current_match_line, current_match_offset) = line_at_offset(text, match_start);
    let current_line_bytes = current_match_line.as_bytes();

    is_go_sum_checksum_bytes(current_line_bytes, path_lower)
        || is_integrity_hash_bytes(current_line_bytes)
        || (git_lfs::is_git_lfs_oid_line(current_line_bytes) && git_lfs::is_git_lfs_pointer(bytes))
        || is_renovate_digest_match_context(current_match_line.as_bytes(), current_match_offset)
        || is_cors_header_bytes(current_line_bytes)
        || is_http_cache_header_bytes(current_line_bytes)
        || has_disclaimer_comment_bytes(current_line_bytes)
}

/// Detect trailing/leading comment disclaimers like `// not a real key`,
/// `# fake credential`, `-- for demo only`. The credential value itself
/// may look 100% legitimate (correct prefix, high entropy) - the human
/// has just declared it isn't real. Suppress the finding.
///
/// Anchored to a comment marker first so we don't accidentally suppress
/// real findings on lines that happen to mention "fake" in prose.
/// Disclaimer-phrase list loaded once from the embedded Tier-B TOML
/// at `crates/scanner/data/disclaimer-phrases.toml`. Lifting this
/// list out of source code lets the community PR new phrases
/// without touching Rust - the moat under CLAUDE.md's Tier-B rule.
static DISCLAIMER_PHRASES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_disclaimer_phrases(include_str!("../../data/disclaimer-phrases.toml")) {
        Ok(phrases) => phrases,
        Err(error) => {
            panic!(
                "crates/scanner/data/disclaimer-phrases.toml is invalid: {error}. \
                 Fix the bundled Tier-B disclaimer phrases; refusing to run without \
                 disclaimer suppression truth."
            )
        }
    }
});

#[derive(serde::Deserialize)]
struct DisclaimerFile {
    schema_version: u32,
    phrases: Vec<String>,
}

pub(crate) fn parse_disclaimer_phrases(raw: &str) -> Result<Vec<String>, String> {
    let parsed: DisclaimerFile =
        toml::from_str(raw).map_err(|error| format!("invalid disclaimer-phrases.toml: {error}"))?;
    if parsed.schema_version != 1 {
        return Err(format!(
            "unsupported disclaimer phrase schema_version {}",
            parsed.schema_version
        ));
    }
    let mut seen = BTreeSet::new();
    let mut phrases = Vec::with_capacity(parsed.phrases.len());
    for raw_phrase in parsed.phrases {
        let phrase = raw_phrase.trim();
        if phrase.is_empty() {
            return Err("disclaimer phrase entries must not be empty".to_string());
        }
        if !phrase.is_ascii() || phrase != phrase.to_ascii_lowercase() {
            return Err(format!(
                "disclaimer phrase {phrase:?} must be lowercase ASCII"
            ));
        }
        if !seen.insert(phrase.to_string()) {
            return Err(format!("duplicate disclaimer phrase {phrase:?}"));
        }
        phrases.push(phrase.to_string());
    }
    if phrases.is_empty() {
        return Err("disclaimer phrases must contain at least one entry".to_string());
    }
    Ok(phrases)
}

/// Case-insensitive variant that avoids lowering the haystack. The needles
/// (comment markers + disclaimer phrases) are all ASCII lowercase already,
/// so we match the haystack against them case-insensitively via `ci_find`.
pub(crate) fn has_disclaimer_comment_bytes(bytes: &[u8]) -> bool {
    let phrases: &[String] = &DISCLAIMER_PHRASES;
    for marker in COMMENT_MARKERS.iter().map(|m| m.as_bytes()) {
        let m_len = marker.len();
        let first_lower = marker[0];
        let first_upper = first_lower.to_ascii_uppercase();
        // Incremental quote-state cursor, advanced MONOTONICALLY to each marker
        // hit. The old `is_inside_ascii_quotes(bytes, start)` rescanned `[0,
        // start)` from scratch on every hit — on a line of boundary-passing
        // markers (e.g. a run of spaced `// // …`) that is O(n²). `memchr2`
        // yields ascending starts, so advancing one cursor makes the
        // "inside quotes?" test O(1) amortized (O(n) per marker, O(n) overall).
        // Quote/escape state at `start` is a pure function of `bytes[0..start]`,
        // so this is byte-identical to the old per-hit rescan.
        let mut q_pos = 0usize;
        let mut quote: Option<u8> = None;
        let mut escaped = false;
        for start in memchr::memchr2_iter(first_lower, first_upper, bytes) {
            if start + m_len > bytes.len() {
                break;
            }
            if !bytes[start..start + m_len].eq_ignore_ascii_case(marker) {
                continue;
            }
            // The COMMENT_MARKERS contract: `--` opens a comment ONLY when it is
            // not the `---` document separator. `strip_comment_prefix` applies
            // this exception; the disclaimer scan must too, or a `--- fake …`
            // YAML separator would be misread as a disclaimer comment.
            if marker == b"--" && bytes.get(start + m_len).copied() == Some(b'-') {
                continue;
            }
            if !comment_marker_has_boundary(bytes, start) {
                continue;
            }
            // Advance the quote/escape cursor up to `start` (never backwards).
            while q_pos < start {
                let byte = bytes[q_pos];
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else {
                    match quote {
                        Some(open) if byte == open => quote = None,
                        None if byte == b'"' || byte == b'\'' => quote = Some(byte),
                        _ => {}
                    }
                }
                q_pos += 1;
            }
            if quote.is_some() {
                continue;
            }
            // A comment runs to end-of-input, so this marker's tail is a SUPERSET
            // of every later same-type marker's tail. Scanning it once and then
            // breaking is sufficient — a phrase after any later `//` is already in
            // this tail — and it is what keeps the scan O(n): the previous
            // "scan the tail per marker hit" made a dense-marker line (`// // …`,
            // every hit boundary-passing and unquoted) O(n²).
            //
            // Bound the tail to the current LINE: a line comment (`//`, `#`, `--`,
            // …) runs only to end-of-line, so a phrase on a LATER line is NOT
            // inside this comment. The sole production caller passes one line
            // (`current_line_bytes`), but the public test helper does not enforce
            // it — bounding here keeps the ci_find linear in the line and blocks a
            // cross-line false disclaimer match if a multi-line buffer is ever
            // passed. No-op on single-line input (no `\n` → tail runs to len()).
            let tail_start = start + m_len;
            let line_end = memchr::memchr(b'\n', &bytes[tail_start..])
                .map_or(bytes.len(), |nl| tail_start + nl);
            let comment_tail = &bytes[tail_start..line_end];
            for phrase in phrases {
                if ci_find(comment_tail, phrase.as_bytes()) {
                    return true;
                }
            }
            break;
        }
    }
    false
}

fn comment_marker_has_boundary(bytes: &[u8], start: usize) -> bool {
    start == 0 || bytes[start - 1].is_ascii_whitespace()
}

/// Check whether a line-level match sits in known false-positive context.
///
/// The path parameter is consumed case-insensitively via
/// `ends_with_ignore_ascii_case`, so callers do not need to pre-lower it.
pub(crate) fn is_false_positive_context(
    lines: &[&str],
    line_idx: usize,
    file_path: Option<&str>,
) -> bool {
    if line_idx >= lines.len() {
        return false;
    }

    // Operate on raw bytes against pre-lowered needles via `ci_find`. The
    // previous shape allocated a `String` per current line + per surrounding
    // line (radius up to 8) on every match; on a 100 KiB dense-hit chunk that
    // was ~24k transient `String`s landing in the per-match hot path.
    let line_bytes = lines[line_idx].as_bytes();

    is_go_sum_checksum_bytes(line_bytes, file_path)
        || is_integrity_hash_bytes(line_bytes)
        || is_configmap_binary_data_context(lines, line_idx, line_bytes)
        || is_git_lfs_pointer_context_with_lines(lines, line_idx, line_bytes)
        || is_cors_header_bytes(line_bytes)
        || is_http_cache_header_bytes(line_bytes)
}

fn is_go_sum_checksum_bytes(bytes: &[u8], path: Option<&str>) -> bool {
    let path_is_go_sum =
        path.is_some_and(|p| crate::ascii_ci::ends_with_ignore_ascii_case(p.as_bytes(), b"go.sum"));
    let mut start = 0;
    while let Some(h1_pos) = find_h1_marker(bytes, start) {
        if has_h1_token_boundary(bytes, h1_pos)
            && (path_is_go_sum || has_strict_go_sum_checksum_shape(bytes, h1_pos))
        {
            return true;
        }
        start = h1_pos + b"h1:".len();
    }
    false
}

fn find_h1_marker(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    while let Some(colon_rel) = memchr::memchr(b':', bytes.get(cursor..)?) {
        let colon = cursor + colon_rel;
        if colon >= 2 && bytes[colon - 1] == b'1' && bytes[colon - 2].eq_ignore_ascii_case(&b'h') {
            return Some(colon - 2);
        }
        cursor = colon + 1;
    }
    None
}

fn has_h1_token_boundary(bytes: &[u8], h1_pos: usize) -> bool {
    h1_pos == 0 || bytes[h1_pos - 1].is_ascii_whitespace()
}

/// Length of a go.sum `h1:` checksum: a SHA-256 digest (32 bytes) rendered as
/// standard base64 with padding is exactly 44 characters.
const GO_SUM_H1_BASE64_DIGEST_LEN: usize = 44;

fn has_strict_go_sum_checksum_shape(bytes: &[u8], h1_pos: usize) -> bool {
    if count_ascii_fields(&bytes[..h1_pos]) < 2 {
        return false;
    }
    let digest_start = h1_pos + b"h1:".len();
    let Some(digest) = bytes.get(digest_start..digest_start + GO_SUM_H1_BASE64_DIGEST_LEN) else {
        return false;
    };
    digest
        .iter()
        .all(|&byte| crate::decode::is_standard_base64_byte(byte))
        && bytes
            .get(digest_start + GO_SUM_H1_BASE64_DIGEST_LEN)
            .is_none_or(u8::is_ascii_whitespace)
}

fn count_ascii_fields(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut in_field = false;
    for byte in bytes {
        if byte.is_ascii_whitespace() {
            in_field = false;
        } else if !in_field {
            count += 1;
            in_field = true;
        }
    }
    count
}

pub(crate) fn is_integrity_hash_bytes(bytes: &[u8]) -> bool {
    // Integrity-body gate points at the single canonical label owner
    // (`sha512-`/`sha384-`/`sha256-`) so this in-module gate cannot diverge
    // from the decoded-labelled-hash gate in `decision.rs`. Hand-rolling the
    // subset here previously omitted `sha384-`, leaking `integrity="sha384-..."`
    // SRI bodies as false-positive secrets.
    ci_find(bytes, b"integrity")
        && crate::suppression::shape::HASH_ALGO_INTEGRITY_LABELS
            .iter()
            .any(|label| contains_sri_hash_value(bytes, label.as_bytes()))
}

fn contains_sri_hash_value(bytes: &[u8], prefix: &[u8]) -> bool {
    // Rare-byte-anchored scan (shared owner): an SRI prefix like `sha256-`
    // anchors on its `-`/digit, so a byte-repetitive buffer cannot force the
    // O(n·m) first-byte blowup the hand-rolled `memchr2(first, …)` loop had.
    for start in crate::ascii_ci::ci_find_iter(bytes, prefix) {
        let value_start = start + prefix.len();
        let mut value_end = value_start;
        while let Some(byte) = bytes.get(value_end) {
            if crate::decode::is_standard_base64_byte(*byte) {
                value_end += 1;
            } else {
                break;
            }
        }
        if is_base64_scalar(&bytes[value_start..value_end]) {
            return true;
        }
    }
    false
}

fn is_configmap_binary_data_context(lines: &[&str], line_idx: usize, line_bytes: &[u8]) -> bool {
    is_configmap_binary_data_value_line(line_bytes)
        && is_inside_configmap_binary_data_block(lines, line_idx)
}

/// How far back the block-header search may walk. The walk skips same-or-deeper
/// indent siblings and returns at the first LESS-indented line (the structural
/// parent), so for a well-formed block it naturally stops at the `binaryData:`
/// header. This cap only bounds the pathological case of a long same-indent run
/// with no dedent, keeping this per-match check from walking to the file start.
/// It is deliberately generous: the previous 8-line cap stopped finding the
/// header past the 8th entry, so every 9th-and-later `binaryData:` blob leaked
/// as a false positive. 4096 clears any realistic ConfigMap binaryData block,
/// and the walk only ever runs on YAML-key-shaped base64 value lines, so the
/// worst-case work stays small.
const BLOCK_HEADER_LOOKBACK: usize = 4096;

fn is_inside_configmap_binary_data_block(lines: &[&str], line_idx: usize) -> bool {
    let Some(current_line) = lines.get(line_idx) else {
        return false;
    };
    let current_indent = leading_ascii_space_count(current_line.as_bytes());
    if current_indent == 0 {
        return false;
    }
    let start = line_idx.saturating_sub(BLOCK_HEADER_LOOKBACK);
    for candidate in lines[start..line_idx].iter().rev() {
        let bytes = candidate.as_bytes();
        let trimmed = trim_ascii_bytes(bytes);
        if trimmed.is_empty() {
            continue;
        }
        let indent = leading_ascii_space_count(bytes);
        if indent >= current_indent {
            continue;
        }
        // `trimmed` is already whitespace-stripped by the caller.
        return trimmed.eq_ignore_ascii_case(b"binarydata:");
    }
    false
}

fn leading_ascii_space_count(bytes: &[u8]) -> usize {
    bytes.iter().take_while(|byte| **byte == b' ').count()
}

fn is_configmap_binary_data_value_line(bytes: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(bytes);
    let Some(colon) = memchr::memchr(b':', trimmed) else {
        return false;
    };
    let key = trim_ascii_bytes(&trimmed[..colon]);
    let value = trim_ascii_bytes(&trimmed[colon + 1..]);
    !key.is_empty()
        && is_yaml_scalar_key(key)
        && is_base64_scalar(strip_balanced_ascii_quotes(value))
}

fn is_yaml_scalar_key(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn strip_balanced_ascii_quotes(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &bytes[1..bytes.len() - 1]
    } else {
        bytes
    }
}

fn is_base64_scalar(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes.len() % 4 == 0
        && bytes
            .iter()
            .all(|&byte| crate::decode::is_standard_base64_byte(byte))
}

/// How many lines above/below the `oid sha256:` line a git-LFS pointer's
/// `version` and `size` lines may sit. A real LFS pointer file is three lines
/// (`version`, `oid`, `size`), so a window of 3 covers reordered/padded pointers
/// without reaching into unrelated content.
const GIT_LFS_POINTER_LOOKAROUND_LINES: usize = 3;

fn is_git_lfs_pointer_context_with_lines(
    lines: &[&str],
    line_idx: usize,
    line_bytes: &[u8],
) -> bool {
    git_lfs::is_git_lfs_oid_line(line_bytes)
        && nearby_lines_contain(
            lines,
            line_idx,
            GIT_LFS_POINTER_LOOKAROUND_LINES,
            |candidate| git_lfs::is_git_lfs_version_line(candidate.as_bytes()),
        )
        && following_lines_contain(
            lines,
            line_idx,
            GIT_LFS_POINTER_LOOKAROUND_LINES,
            |candidate| git_lfs::is_git_lfs_size_line(candidate.as_bytes()),
        )
}

fn trim_ascii_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len()); // LAW10: no recall impact — all-whitespace trim starts at end; no context is suppressed from this default
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |idx| idx + 1);
    &bytes[start..end]
}

fn is_renovate_digest_match_context(bytes: &[u8], match_offset: usize) -> bool {
    let match_offset = match_offset.min(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(relative_start) = crate::ascii_ci::ci_find_at(&bytes[cursor..], b"renovate/")
        else {
            return false;
        };
        let start = cursor + relative_start;
        let branch_start = start + b"renovate/".len();
        let mut branch_end = branch_start;
        while let Some(byte) = bytes.get(branch_end) {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
                branch_end += 1;
            } else {
                break;
            }
        }
        if branch_end > branch_start
            && match_offset >= branch_start
            && match_offset < branch_end
            && hex_run_contains_offset(bytes, branch_start, branch_end, match_offset)
        {
            return true;
        }
        cursor = branch_end.max(start + 1);
    }
    false
}

fn hex_run_contains_offset(bytes: &[u8], start: usize, end: usize, offset: usize) -> bool {
    let mut run_start = start;
    let mut run_len = 0usize;
    for idx in start..end {
        if bytes[idx].is_ascii_hexdigit() {
            if run_len == 0 {
                run_start = idx;
            }
            run_len += 1;
            continue;
        }
        if run_len >= 8 && offset >= run_start && offset < idx {
            return true;
        }
        run_len = 0;
    }
    run_len >= 8 && offset >= run_start && offset < end
}

fn line_at_offset(text: &str, offset: usize) -> (&str, usize) {
    let bytes = text.as_bytes();
    let safe_offset = offset.min(bytes.len());
    let line_start = bytes[..safe_offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |idx| idx + 1);
    let line_end = bytes[safe_offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |idx| safe_offset + idx);
    let line_start = crate::engine::ceil_char_boundary(text, line_start);
    let mut line_end = crate::engine::floor_char_boundary(text, line_end);
    if line_end < line_start {
        line_end = line_start;
    }
    let relative = safe_offset
        .saturating_sub(line_start)
        .min(line_end - line_start);
    (&text[line_start..line_end], relative)
}

#[derive(serde::Deserialize)]
struct FalsePositiveMarkers {
    cors_headers: Vec<String>,
}

/// Parse the bundled Tier-B false-positive marker list. Returns an error rather
/// than panicking so the `CORS_HEADERS` owner below is the single fail-closed
/// site (the `no_unwrap_expect` gate bans `expect` in production source).
fn parse_false_positive_markers(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<FalsePositiveMarkers>(raw)
        .map(|parsed| parsed.cors_headers)
        .map_err(|error| error.to_string())
}

static CORS_HEADERS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_false_positive_markers(include_str!(
        "../../../../rules/false-positive-markers.toml"
    )) {
        Ok(cors_headers) => cors_headers,
        Err(error) => panic!(
            "rules/false-positive-markers.toml is invalid: {error}. \
             Fix the bundled Tier-B false-positive markers list."
        ),
    }
});

fn is_cors_header_bytes(bytes: &[u8]) -> bool {
    let allowed: &[String] = &CORS_HEADERS;
    header_name_matches(bytes, allowed)
}

fn is_http_cache_header_bytes(bytes: &[u8]) -> bool {
    let allowed: &[&[u8]] = &[b"etag"];
    header_name_matches(bytes, allowed)
}

fn header_name_matches<T: AsRef<[u8]>>(bytes: &[u8], allowed: &[T]) -> bool {
    let trimmed = trim_ascii_bytes(bytes);
    let Some(colon) = memchr::memchr(b':', trimmed) else {
        return false;
    };
    let name = trim_ascii_bytes(&trimmed[..colon]);
    if name.is_empty() {
        return false;
    }
    if !name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return false;
    }
    allowed
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate.as_ref()))
}

fn nearby_lines_contain(
    lines: &[&str],
    line_idx: usize,
    lookback_lines: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    // Slice the exact lookback window `[start, line_idx]` instead of
    // `.take(line_idx+1).skip(start)`, which (because `Take` defeats
    // `slice::Iter`'s O(1) `nth`) walks from line 0 and discards `start` lines —
    // O(line_idx) for a line deep in a file. The slice is O(window). Bounds are
    // clamped so a `line_idx` past the end can never panic (matches the old
    // iterator's saturating behavior).
    let end = (line_idx + 1).min(lines.len());
    let start = line_idx.saturating_sub(lookback_lines).min(end);
    lines[start..end].iter().copied().any(predicate)
}

fn following_lines_contain(
    lines: &[&str],
    line_idx: usize,
    lookahead_lines: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let start = line_idx.saturating_add(1);
    let end = line_idx
        .saturating_add(lookahead_lines)
        .saturating_add(1)
        .min(lines.len());
    start < end && lines[start..end].iter().copied().any(predicate)
}
