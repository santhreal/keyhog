use super::inference::surrounding_line_window;

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
    let window = surrounding_line_window(text, match_start, 1);
    // Use a stack-allocated lowercase buffer for short windows (covers 99% of cases).
    // Only heap-allocate for windows > 512 bytes.
    let lower = if window.len() <= 512 {
        let mut buf = [0u8; 512];
        let bytes = window.as_bytes();
        let len = bytes.len().min(512);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf[..len].make_ascii_lowercase();
        // SAFETY: input was valid ASCII/UTF-8, make_ascii_lowercase preserves validity
        unsafe { std::str::from_utf8_unchecked(&buf[..len]) }.to_string()
    } else {
        window.to_ascii_lowercase()
    };

    is_go_sum_checksum(&lower, path_lower)
        || is_integrity_hash(&lower)
        || is_configmap_binary_data(&lower)
        || is_git_lfs_pointer_context(&lower)
        || is_renovate_digest_context(&lower)
        || is_cors_header(&lower)
        || is_http_cache_header(&lower)
        || has_disclaimer_comment(&lower)
}

/// Detect trailing/leading comment disclaimers like `// not a real key`,
/// `# fake credential`, `-- for demo only`. The credential value itself
/// may look 100% legitimate (correct prefix, high entropy) — the human
/// has just declared it isn't real. Suppress the finding.
///
/// Anchored to a comment marker first so we don't accidentally suppress
/// real findings on lines that happen to mention "fake" in prose.
fn has_disclaimer_comment(lower: &str) -> bool {
    const COMMENT_MARKERS: &[&str] = &["//", "#", "--", "/*", "<!--", "rem "];
    const DISCLAIMER_PHRASES: &[&str] = &[
        "not a real",
        "not real",
        "not a secret",
        "not a key",
        "not a password",
        "not a token",
        "not an api",
        "not valid",
        "fake credential",
        "fake key",
        "fake token",
        "fake secret",
        "fake password",
        "dummy credential",
        "dummy key",
        "dummy token",
        "dummy secret",
        "for demo",
        "demo only",
        "for testing",
        "test only",
        "for example",
        "example only",
        "do not use",
        "replace this",
        "replace with",
        "fill in your",
        "put your",
    ];
    let bytes = lower.as_bytes();
    for marker in COMMENT_MARKERS {
        let mut search_from = 0usize;
        while let Some(rel) = memchr::memmem::find(&bytes[search_from..], marker.as_bytes()) {
            let comment_start = search_from + rel + marker.len();
            let comment_tail = &lower[comment_start..];
            for phrase in DISCLAIMER_PHRASES {
                if memchr::memmem::find(comment_tail.as_bytes(), phrase.as_bytes()).is_some() {
                    return true;
                }
            }
            search_from = comment_start;
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

    let line = lines[line_idx];
    let lower = line.to_ascii_lowercase();

    is_go_sum_checksum(&lower, path_lower)
        || is_integrity_hash_context(lines, line_idx, &lower)
        || is_configmap_binary_data_context(lines, line_idx, &lower)
        || is_git_lfs_pointer_context_with_lines(lines, line_idx, &lower)
        || is_renovate_digest_context_with_lines(lines, line_idx, &lower)
        || is_cors_header(&lower)
        || is_http_cache_header_context(lines, line_idx, &lower)
}

fn is_go_sum_checksum(lower: &str, path_lower: Option<&str>) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"h1:").is_some()
        || path_lower.is_some_and(|path| path.ends_with("go.sum"))
}

fn is_integrity_hash_context(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_integrity_hash(lower)
        || surrounding_lines_contain(lines, line_idx, 2, |candidate| {
            is_integrity_hash(&candidate.to_ascii_lowercase())
        })
}

fn is_integrity_hash(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"integrity").is_some()
        && (memchr::memmem::find(lower.as_bytes(), b"sha256-").is_some()
            || memchr::memmem::find(lower.as_bytes(), b"sha512-").is_some())
}

fn is_configmap_binary_data_context(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_configmap_binary_data(lower)
        || nearby_lines_contain(lines, line_idx, 8, |candidate| {
            let candidate = candidate.trim().to_ascii_lowercase();
            is_configmap_binary_data(&candidate)
        })
}

fn is_configmap_binary_data(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"binarydata:").is_some()
}

fn is_git_lfs_pointer_context_with_lines(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_git_lfs_pointer_context(lower)
        || nearby_lines_contain(lines, line_idx, 3, |candidate| {
            is_git_lfs_pointer_context(&candidate.to_ascii_lowercase())
        })
}

fn is_git_lfs_pointer_context(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"oid sha256:").is_some()
        || memchr::memmem::find(lower.as_bytes(), b"git-lfs").is_some()
}

fn is_renovate_digest_context_with_lines(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_renovate_digest_context(lower)
        || surrounding_lines_contain(lines, line_idx, 2, |candidate| {
            is_renovate_digest_context(&candidate.to_ascii_lowercase())
        })
}

fn is_renovate_digest_context(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"renovate/").is_some() && contains_hex_sequence(lower)
}

fn is_cors_header(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"access-control-").is_some()
}

fn is_http_cache_header_context(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_http_cache_header(lower)
        || surrounding_lines_contain(lines, line_idx, 1, |candidate| {
            is_http_cache_header(&candidate.to_ascii_lowercase())
        })
}

fn is_http_cache_header(lower: &str) -> bool {
    lower.trim_start().starts_with("etag") || has_token(lower, "etag")
}

fn has_token(text: &str, token: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|part| part.eq_ignore_ascii_case(token))
}

fn contains_hex_sequence(lower: &str) -> bool {
    let mut run = 0usize;
    for ch in lower.chars() {
        if ch.is_ascii_hexdigit() {
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
        assert!(has_disclaimer_comment(&line.to_ascii_lowercase()));
    }

    #[test]
    fn trailing_hash_comment_disclaimer_suppresses() {
        let line =
            "API_TOKEN=ghp_1234567890abcdef1234567890abcdef123456 # fake credential, demo only";
        assert!(has_disclaimer_comment(&line.to_ascii_lowercase()));
    }

    #[test]
    fn html_comment_disclaimer_suppresses() {
        let line = "secret=xyz <!-- replace with your value -->";
        assert!(has_disclaimer_comment(&line.to_ascii_lowercase()));
    }

    #[test]
    fn disclaimer_outside_comment_does_not_suppress() {
        // The word "fake" appears as part of a real value, not in a comment.
        let line = r#"password = "FakePassword!2024" + suffix"#;
        assert!(!has_disclaimer_comment(&line.to_ascii_lowercase()));
    }

    #[test]
    fn ordinary_comment_without_disclaimer_does_not_suppress() {
        let line = r#"const KEY = "AKIA1234567890ABCD12"; // production key, see vault"#;
        assert!(!has_disclaimer_comment(&line.to_ascii_lowercase()));
    }
}
