use super::inference::surrounding_line_window;
use crate::ascii_ci::ci_find;

/// Returns `true` if the match is in a context that indicates a false positive.
pub fn is_false_positive_match_context(
    text: &str,
    match_start: usize,
    file_path: Option<&str>,
) -> bool {
    is_false_positive_match_context_with_path(text, match_start, file_path, None)
}

/// Same as `is_false_positive_match_context` but accepts a pre-lowered path
/// to avoid re-allocating the lowercase path string on every match.
pub fn is_false_positive_match_context_with_path(
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

    is_go_sum_checksum_bytes(bytes, path_lower)
        || is_integrity_hash_bytes(bytes)
        || is_configmap_binary_data_bytes(bytes)
        || is_git_lfs_pointer_context_bytes(bytes)
        || is_renovate_digest_context_bytes(bytes)
        || is_cors_header_bytes(bytes)
        || is_http_cache_header_bytes(bytes)
        || has_disclaimer_comment_bytes(bytes)
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
    #[derive(serde::Deserialize)]
    struct DisclaimerFile {
        phrases: Vec<String>,
    }
    let raw = include_str!("../../data/disclaimer-phrases.toml");
    // Soft-fail to an empty phrase list rather than panicking the
    // scanner worker. A corrupted-binary / broken-build state should
    // degrade detection precision, not crash. The `tracing::warn!`
    // surfaces the regression in logs so CI catches it.
    match toml::from_str::<DisclaimerFile>(raw) {
        Ok(parsed) => parsed
            .phrases
            .into_iter()
            .map(|p| p.to_ascii_lowercase())
            .collect(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "disclaimer-phrases.toml failed to parse; falling back to empty phrase list \
                 (test-file disclaimers will not be suppressed this run)",
            );
            Vec::new()
        }
    }
});

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

/// Check whether a line-level match sits in known false-positive context.
pub fn is_false_positive_context(lines: &[&str], line_idx: usize, file_path: Option<&str>) -> bool {
    let path_lower = file_path.map(str::to_ascii_lowercase);
    is_false_positive_context_with_path(lines, line_idx, path_lower.as_deref())
}

/// Same as [`is_false_positive_context`] but accepts a pre-lowered path.
pub fn is_false_positive_context_with_path(
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

fn is_go_sum_checksum_bytes(bytes: &[u8], path_lower: Option<&str>) -> bool {
    ci_find(bytes, b"h1:") || path_lower.is_some_and(|path| path.ends_with("go.sum"))
}

fn is_integrity_hash_context(lines: &[&str], line_idx: usize, line_bytes: &[u8]) -> bool {
    is_integrity_hash_bytes(line_bytes)
        || surrounding_lines_contain(lines, line_idx, 2, |candidate| {
            is_integrity_hash_bytes(candidate.as_bytes())
        })
}

fn is_integrity_hash_bytes(bytes: &[u8]) -> bool {
    ci_find(bytes, b"integrity") && (ci_find(bytes, b"sha256-") || ci_find(bytes, b"sha512-"))
}

fn is_configmap_binary_data_context(lines: &[&str], line_idx: usize, line_bytes: &[u8]) -> bool {
    is_configmap_binary_data_bytes(line_bytes)
        || nearby_lines_contain(lines, line_idx, 8, |candidate| {
            is_configmap_binary_data_bytes(candidate.trim().as_bytes())
        })
}

fn is_configmap_binary_data_bytes(bytes: &[u8]) -> bool {
    ci_find(bytes, b"binarydata:")
}

fn is_git_lfs_pointer_context_with_lines(lines: &[&str], line_idx: usize, line_bytes: &[u8]) -> bool {
    is_git_lfs_pointer_context_bytes(line_bytes)
        || nearby_lines_contain(lines, line_idx, 3, |candidate| {
            is_git_lfs_pointer_context_bytes(candidate.as_bytes())
        })
}

fn is_git_lfs_pointer_context_bytes(bytes: &[u8]) -> bool {
    ci_find(bytes, b"oid sha256:") || ci_find(bytes, b"git-lfs")
}

fn is_renovate_digest_context_with_lines(lines: &[&str], line_idx: usize, line_bytes: &[u8]) -> bool {
    is_renovate_digest_context_bytes(line_bytes)
        || surrounding_lines_contain(lines, line_idx, 2, |candidate| {
            is_renovate_digest_context_bytes(candidate.as_bytes())
        })
}

fn is_renovate_digest_context_bytes(bytes: &[u8]) -> bool {
    ci_find(bytes, b"renovate/") && contains_hex_sequence_bytes(bytes)
}

fn is_cors_header_bytes(bytes: &[u8]) -> bool {
    ci_find(bytes, b"access-control-")
}

fn is_http_cache_header_context(lines: &[&str], line_idx: usize, line_bytes: &[u8]) -> bool {
    is_http_cache_header_bytes(line_bytes)
        || surrounding_lines_contain(lines, line_idx, 1, |candidate| {
            is_http_cache_header_bytes(candidate.as_bytes())
        })
}

fn is_http_cache_header_bytes(bytes: &[u8]) -> bool {
    let trimmed_start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
    let trimmed = &bytes[trimmed_start..];
    trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"etag"))
        || has_token_bytes(bytes, b"etag")
}

fn has_token_bytes(text: &[u8], token: &[u8]) -> bool {
    let n = token.len();
    if n == 0 {
        return true;
    }
    let mut start = 0usize;
    for (i, &b) in text.iter().enumerate() {
        if !b.is_ascii_alphanumeric() {
            if i - start == n && text[start..i].eq_ignore_ascii_case(token) {
                return true;
            }
            start = i + 1;
        }
    }
    text.len() - start == n && text[start..].eq_ignore_ascii_case(token)
}

fn contains_hex_sequence_bytes(bytes: &[u8]) -> bool {
    let mut run = 0usize;
    for &b in bytes {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
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

fn surrounding_lines_contain(
    lines: &[&str],
    line_idx: usize,
    radius: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let start = line_idx.saturating_sub(radius);
    let end = (line_idx + radius + 1).min(lines.len());
    lines[start..end].iter().copied().any(predicate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_slash_comment_disclaimer_suppresses() {
        let line = "const KEY = \"AKIAIOSFODNN7EXAMPLE\"; // not a real aws key";
        assert!(has_disclaimer_comment_bytes(line.as_bytes()));
    }

    #[test]
    fn trailing_hash_comment_disclaimer_suppresses() {
        let line =
            "API_TOKEN=ghp_1234567890abcdef1234567890abcdef123456 # fake credential, demo only";
        assert!(has_disclaimer_comment_bytes(line.as_bytes()));
    }

    #[test]
    fn html_comment_disclaimer_suppresses() {
        let line = "secret=xyz <!-- replace with your value -->";
        assert!(has_disclaimer_comment_bytes(line.as_bytes()));
    }

    #[test]
    fn disclaimer_outside_comment_does_not_suppress() {
        // The word "fake" appears as part of a real value, not in a comment.
        let line = r#"password = "FakePassword!2024" + suffix"#;
        assert!(!has_disclaimer_comment_bytes(line.as_bytes()));
    }

    #[test]
    fn ordinary_comment_without_disclaimer_does_not_suppress() {
        let line =
            r#"const KEY = concat!("AK", "IA1234567890ABCD12"); // production key, see vault"#;
        assert!(!has_disclaimer_comment_bytes(line.as_bytes()));
    }
}
