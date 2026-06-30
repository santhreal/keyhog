use super::inference::surrounding_line_window;
use crate::ascii_ci::ci_find;
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
    let current_line = surrounding_line_window(text, match_start, 0);
    let current_line_bytes = current_line.as_bytes();
    let (current_match_line, current_match_offset) = line_at_offset(text, match_start);

    is_go_sum_checksum_bytes(current_line_bytes, path_lower)
        || is_integrity_hash_bytes(current_line_bytes)
        || (is_git_lfs_oid_line(current_line_bytes) && is_git_lfs_pointer_context_bytes(bytes))
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
fn has_disclaimer_comment_bytes(bytes: &[u8]) -> bool {
    const COMMENT_MARKERS: &[&[u8]] = &[b"//", b"#", b"--", b"/*", b"<!--", b"rem "];
    let phrases: &[String] = &DISCLAIMER_PHRASES;
    for marker in COMMENT_MARKERS {
        let m_len = marker.len();
        let first_lower = marker[0];
        let first_upper = first_lower.to_ascii_uppercase();
        for start in memchr::memchr2_iter(first_lower, first_upper, bytes) {
            if start + m_len > bytes.len() {
                break;
            }
            if !bytes[start..start + m_len].eq_ignore_ascii_case(marker) {
                continue;
            }
            if !comment_marker_has_boundary(bytes, start) || is_inside_ascii_quotes(bytes, start) {
                continue;
            }
            let comment_tail = &bytes[start + m_len..];
            for phrase in phrases {
                if ci_find(comment_tail, phrase.as_bytes()) {
                    return true;
                }
            }
        }
    }
    false
}

fn comment_marker_has_boundary(bytes: &[u8], start: usize) -> bool {
    start == 0 || bytes[start - 1].is_ascii_whitespace()
}

fn is_inside_ascii_quotes(bytes: &[u8], offset: usize) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for &byte in bytes.iter().take(offset) {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        match quote {
            Some(open) if byte == open => quote = None,
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            _ => {}
        }
    }
    quote.is_some()
}

/// Check whether a line-level match sits in known false-positive context.
///
/// The path parameter is consumed case-insensitively via
/// `ends_with_ignore_ascii_case`, so callers no longer need to pre-lower
/// it. The `_with_path` form kept as a stable alias for downstream
/// consumers that already passed a lowered path through.
pub(crate) fn is_false_positive_context(
    lines: &[&str],
    line_idx: usize,
    file_path: Option<&str>,
) -> bool {
    is_false_positive_context_with_path(lines, line_idx, file_path)
}

/// Same as [`is_false_positive_context`]. Retained for source compatibility
/// with callers that historically pre-lowered the path; the body no longer
/// requires a lowered string thanks to byte-wise case-insensitive checks.
fn is_false_positive_context_with_path(
    lines: &[&str],
    line_idx: usize,
    path_lower: Option<&str>,
) -> bool {
    if line_idx >= lines.len() {
        return false;
    }

    // Operate on raw bytes against pre-lowered needles via `ci_find`. The
    // previous shape allocated a `String` per current line + per surrounding
    // line (radius up to 8) on every match; on a 100 KiB dense-hit chunk that
    // was ~24k transient `String`s landing in the per-match hot path.
    let line_bytes = lines[line_idx].as_bytes();

    is_go_sum_checksum_bytes(line_bytes, path_lower)
        || is_integrity_hash_context(lines, line_idx, line_bytes)
        || is_configmap_binary_data_context(lines, line_idx, line_bytes)
        || is_git_lfs_pointer_context_with_lines(lines, line_idx, line_bytes)
        || is_renovate_digest_context_with_lines(lines, line_idx, line_bytes)
        || is_cors_header_bytes(line_bytes)
        || is_http_cache_header_context(lines, line_idx, line_bytes)
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

fn has_strict_go_sum_checksum_shape(bytes: &[u8], h1_pos: usize) -> bool {
    if count_ascii_fields(&bytes[..h1_pos]) < 2 {
        return false;
    }
    let digest_start = h1_pos + b"h1:".len();
    let Some(digest) = bytes.get(digest_start..digest_start + 44) else {
        return false;
    };
    digest
        .iter()
        .all(|&byte| crate::decode::is_standard_base64_byte(byte))
        && bytes
            .get(digest_start + 44)
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

fn is_integrity_hash_context(_lines: &[&str], _line_idx: usize, line_bytes: &[u8]) -> bool {
    is_integrity_hash_bytes(line_bytes)
}

fn is_integrity_hash_bytes(bytes: &[u8]) -> bool {
    ci_find(bytes, b"integrity")
        && (contains_sri_hash_value(bytes, b"sha256-")
            || contains_sri_hash_value(bytes, b"sha512-"))
}

fn contains_sri_hash_value(bytes: &[u8], prefix: &[u8]) -> bool {
    let Some((&first, _)) = prefix.split_first() else {
        return false;
    };
    let first_upper = first.to_ascii_uppercase();
    for start in memchr::memchr2_iter(first, first_upper, bytes) {
        let Some(candidate_prefix) = bytes.get(start..start + prefix.len()) else {
            break;
        };
        if !candidate_prefix.eq_ignore_ascii_case(prefix) {
            continue;
        }
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

fn is_inside_configmap_binary_data_block(lines: &[&str], line_idx: usize) -> bool {
    let Some(current_line) = lines.get(line_idx) else {
        return false;
    };
    let current_indent = leading_ascii_space_count(current_line.as_bytes());
    if current_indent == 0 {
        return false;
    }
    let start = line_idx.saturating_sub(8);
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
        return is_configmap_binary_data_header(trimmed);
    }
    false
}

fn leading_ascii_space_count(bytes: &[u8]) -> usize {
    bytes.iter().take_while(|byte| **byte == b' ').count()
}

fn is_configmap_binary_data_header(bytes: &[u8]) -> bool {
    trim_ascii_bytes(bytes).eq_ignore_ascii_case(b"binarydata:")
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

fn is_git_lfs_pointer_context_with_lines(
    lines: &[&str],
    line_idx: usize,
    line_bytes: &[u8],
) -> bool {
    is_git_lfs_oid_line(line_bytes)
        && nearby_lines_contain(lines, line_idx, 3, |candidate| {
            is_git_lfs_version_line(candidate.as_bytes())
        })
        && following_lines_contain(lines, line_idx, 3, |candidate| {
            is_git_lfs_size_line(candidate.as_bytes())
        })
}

fn is_git_lfs_pointer_context_bytes(bytes: &[u8]) -> bool {
    let mut has_version = false;
    let mut has_oid = false;
    for line in bytes.split(|byte| matches!(byte, b'\n' | b'\r')) {
        if !has_version {
            has_version = is_git_lfs_version_line(line);
            continue;
        }
        if !has_oid {
            has_oid = is_git_lfs_oid_line(line);
            continue;
        }
        if is_git_lfs_size_line(line) {
            return true;
        }
    }
    false
}

fn is_git_lfs_version_line(bytes: &[u8]) -> bool {
    trim_ascii_bytes(bytes).eq_ignore_ascii_case(b"version https://git-lfs.github.com/spec/v1")
}

fn is_git_lfs_oid_line(bytes: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(bytes);
    let Some(rest) = trimmed.strip_prefix(b"oid sha256:") else {
        return false;
    };
    rest.len() == 64 && rest.iter().all(u8::is_ascii_hexdigit)
}

fn is_git_lfs_size_line(bytes: &[u8]) -> bool {
    let trimmed = trim_ascii_bytes(bytes);
    let Some(rest) = trimmed.strip_prefix(b"size ") else {
        return false;
    };
    !rest.is_empty() && rest.iter().all(u8::is_ascii_digit)
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

fn is_renovate_digest_context_with_lines(
    _lines: &[&str],
    _line_idx: usize,
    _line_bytes: &[u8],
) -> bool {
    false
}

fn is_renovate_digest_match_context(bytes: &[u8], match_offset: usize) -> bool {
    let match_offset = match_offset.min(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(relative_start) = ci_find_index(&bytes[cursor..], b"renovate/") else {
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

fn ci_find_index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, _) = needle.split_first()?;
    let first_upper = first.to_ascii_uppercase();
    for start in memchr::memchr2_iter(first, first_upper, haystack) {
        let Some(candidate) = haystack.get(start..start + needle.len()) else {
            break;
        };
        if candidate.eq_ignore_ascii_case(needle) {
            return Some(start);
        }
    }
    None
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

fn is_cors_header_bytes(bytes: &[u8]) -> bool {
    const CORS_HEADERS: &[&[u8]] = &[
        b"access-control-allow-origin",
        b"access-control-allow-methods",
        b"access-control-allow-headers",
        b"access-control-allow-credentials",
        b"access-control-expose-headers",
        b"access-control-max-age",
        b"access-control-request-method",
        b"access-control-request-headers",
    ];
    header_name_matches(bytes, CORS_HEADERS)
}

fn is_http_cache_header_context(_lines: &[&str], _line_idx: usize, line_bytes: &[u8]) -> bool {
    is_http_cache_header_bytes(line_bytes)
}

fn is_http_cache_header_bytes(bytes: &[u8]) -> bool {
    header_name_matches(bytes, &[b"etag"])
}

fn header_name_matches(bytes: &[u8], allowed: &[&[u8]]) -> bool {
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
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn nearby_lines_contain(
    lines: &[&str],
    line_idx: usize,
    lookback_lines: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let start = line_idx.saturating_sub(lookback_lines);
    lines
        .iter()
        .take(line_idx + 1)
        .skip(start)
        .copied()
        .any(predicate)
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
