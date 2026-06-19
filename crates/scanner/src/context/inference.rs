use super::{documentation::documentation_line_flags, CodeContext};

const TEST_PREFIX_LEN: usize = 5;
const ENCRYPTED_BLOCK_LOOKBACK_LINES: usize = 10;
// 100 lines covers large Go/Java test functions with extensive setup.
// The previous 30-line limit caused test fixtures to be reported as findings.
const TEST_FUNCTION_LOOKBACK_LINES: usize = 100;

/// Infer the structural context of a match at a given line.
pub fn infer_context(lines: &[&str], line_idx: usize, file_path: Option<&str>) -> CodeContext {
    let documentation_lines = documentation_line_flags(lines);
    infer_context_with_documentation(lines, line_idx, file_path, &documentation_lines)
}

fn is_encrypted_marker_line(trimmed: &str) -> bool {
    trimmed.starts_with("$ANSIBLE_VAULT")
        || trimmed.starts_with("ENC[")
        || memchr::memmem::find(trimmed.as_bytes(), b"sops:").is_some()
        || memchr::memmem::find(trimmed.as_bytes(), b"sealed-secrets").is_some()
        || trimmed.starts_with("-----BEGIN PGP MESSAGE-----")
        || trimmed.starts_with("-----BEGIN AGE ENCRYPTED")
}

/// Infer context when documentation-line flags have already been computed.
pub(crate) fn infer_context_with_documentation(
    lines: &[&str],
    line_idx: usize,
    file_path: Option<&str>,
    documentation_lines: &[bool],
) -> CodeContext {
    if line_idx >= lines.len() {
        return CodeContext::Unknown;
    }

    let line = lines[line_idx];
    let trimmed = line.trim();

    if file_path.is_some_and(is_test_file) {
        return CodeContext::TestCode;
    }
    if is_in_encrypted_block(lines, line_idx) {
        return CodeContext::Encrypted;
    }
    if is_commented_assignment_line(trimmed) {
        return CodeContext::Assignment;
    }
    if is_comment_line(trimmed) {
        return CodeContext::Comment;
    }
    if documentation_lines
        .get(line_idx)
        .copied()
        .is_some_and(|v| v)
    {
        // Law 10: bounds-checked lookup; out-of-range => documented default (total fn), recall-safe
        return CodeContext::Documentation;
    }
    if is_in_test_function(lines, line_idx) {
        return CodeContext::TestCode;
    }
    if is_assignment_line(trimmed) {
        return CodeContext::Assignment;
    }
    infer_default_context(trimmed)
}

fn is_test_file(path: &str) -> bool {
    const TEST_PATH_COMPONENTS: &[&str] =
        &["test", "tests", "__tests__", "fixtures", "testdata", "spec"];
    let filename = crate::platform_compat::path_basename(path);
    let stem = filename.split('.').next().unwrap_or(filename); // LAW10: split yields >=1 element; unwrap_or is the never-taken total default, recall-safe

    stem.len() > TEST_PREFIX_LEN
        && stem
            .as_bytes()
            .get(..TEST_PREFIX_LEN)
            .is_some_and(|bytes| bytes.eq_ignore_ascii_case(b"test_"))
        || filename.ends_with("_test.go")
        || filename.ends_with("_test.rs")
        || filename.ends_with("_test.py")
        || filename.ends_with("_test.rb")
        || filename.ends_with("_test.java")
        || filename.ends_with("Test.java")
        || filename.ends_with("Tests.java")
        || filename.ends_with(".test.js")
        || filename.ends_with(".test.ts")
        || filename.ends_with(".spec.js")
        || filename.ends_with(".spec.ts")
        || crate::platform_compat::path_has_any_component(path, TEST_PATH_COMPONENTS)
}

fn infer_default_context(trimmed: &str) -> CodeContext {
    if memchr::memchr(b'"', trimmed.as_bytes()).is_some()
        || memchr::memchr(b'\'', trimmed.as_bytes()).is_some()
    {
        CodeContext::StringLiteral
    } else {
        CodeContext::Unknown
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || (trimmed.starts_with("--") && !trimmed.starts_with("---"))
        || trimmed.starts_with("/*")
        || trimmed.starts_with("<!--")
        || trimmed.starts_with("<#")
        || trimmed.starts_with("* ")
        || trimmed.starts_with("*/")
        || trimmed.starts_with("rem ")
        || trimmed.starts_with("REM ")
}

fn is_commented_assignment_line(trimmed: &str) -> bool {
    let Some(comment_body) = strip_comment_prefix(trimmed) else {
        return false;
    };
    let body = comment_body
        .trim_start()
        .trim_end_matches("*/")
        .trim_end_matches("-->")
        .trim();
    has_assignment_operator(body) || has_yaml_mapping(body)
}

fn strip_comment_prefix(trimmed: &str) -> Option<&str> {
    if let Some(rest) = trimmed.strip_prefix("//") {
        Some(rest)
    } else if let Some(rest) = trimmed.strip_prefix('#') {
        Some(rest)
    } else if trimmed.starts_with("--") && !trimmed.starts_with("---") {
        trimmed.strip_prefix("--")
    } else if let Some(rest) = trimmed.strip_prefix("/*") {
        Some(rest)
    } else if let Some(rest) = trimmed.strip_prefix("<!--") {
        Some(rest)
    } else if let Some(rest) = trimmed.strip_prefix("<#") {
        Some(rest)
    } else if let Some(rest) = trimmed.strip_prefix("* ") {
        Some(rest)
    } else if let Some(rest) = trimmed.strip_prefix("rem ") {
        Some(rest)
    } else {
        trimmed.strip_prefix("REM ")
    }
}

fn is_assignment_line(trimmed: &str) -> bool {
    has_assignment_operator(trimmed) || has_yaml_mapping(trimmed)
}

pub(crate) fn has_assignment_operator(trimmed: &str) -> bool {
    for operator in [":=", "->", "="] {
        if let Some(pos) = trimmed.find(operator) {
            if !is_comparison_operator(trimmed, pos, operator) {
                return true;
            }
        }
    }
    false
}

fn has_yaml_mapping(trimmed: &str) -> bool {
    memchr::memmem::find(trimmed.as_bytes(), b": ").is_some() && !trimmed.starts_with("- ")
}

fn is_comparison_operator(trimmed: &str, pos: usize, operator: &str) -> bool {
    if operator != "=" {
        return false;
    }

    let before = trimmed[..pos].chars().last();
    let after = trimmed[pos + operator.len()..].chars().next();
    matches!(before, Some('=' | '!' | '>' | '<')) || matches!(after, Some('='))
}

fn is_in_encrypted_block(lines: &[&str], line_idx: usize) -> bool {
    let start = line_idx.saturating_sub(ENCRYPTED_BLOCK_LOOKBACK_LINES);
    lines
        .iter()
        .take(line_idx + 1)
        .skip(start)
        .any(|line| is_encrypted_marker_line(line.trim()))
}

fn is_in_test_function(lines: &[&str], line_idx: usize) -> bool {
    let start = line_idx.saturating_sub(TEST_FUNCTION_LOOKBACK_LINES);
    for candidate_line_idx in (start..line_idx).rev() {
        let trimmed = lines[candidate_line_idx].trim();

        if trimmed.starts_with("def test_")
            || trimmed.starts_with("class Test")
            || trimmed.starts_with("it(")
            || trimmed.starts_with("describe(")
            || trimmed.starts_with("test(")
            || trimmed == "#[test]"
            || trimmed == concat!("#[cfg(", "test)]")
            || trimmed.starts_with("#[tokio::test")
            || trimmed.starts_with("func Test")
            || trimmed == "@Test"
        {
            return true;
        }

        // Stop looking back when we hit a non-test class or function boundary.
        if trimmed.starts_with("class ") {
            return false;
        }

        if (trimmed.starts_with("def ") || trimmed.starts_with("async def "))
            && !trimmed.contains("def test_")
        {
            return false;
        }

        if trimmed.starts_with("func ") && !trimmed.contains("func Test") {
            return false;
        }

        if (trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("pub async fn "))
            && !trimmed.contains("fn test_")
        {
            let pre_start = candidate_line_idx.saturating_sub(3);
            let mut is_test_attr = false;
            for pre_line in &lines[pre_start..candidate_line_idx] {
                let pre_trimmed = pre_line.trim();
                if pre_trimmed == "#[test]"
                    || pre_trimmed == concat!("#[cfg(", "test)]")
                    || pre_trimmed.starts_with("#[tokio::test")
                    || pre_trimmed.starts_with("#[test")
                    || pre_trimmed == "@Test"
                {
                    is_test_attr = true;
                    break;
                }
            }
            if is_test_attr {
                return true;
            }
            return false;
        }

        if trimmed.starts_with("function ") && !trimmed.contains("function test") {
            return false;
        }
    }
    false
}

pub(crate) fn surrounding_line_window(text: &str, offset: usize, radius: usize) -> &str {
    if text.is_empty() {
        return "";
    }
    let bytes = text.as_bytes();
    let safe_offset = offset.min(bytes.len());

    // Hard byte cap on each direction. The scan normally stops at a line
    // terminator, so for ordinary source (lines well under this cap) the
    // window is byte-identical to an uncapped walk. It only bites on a
    // pathological line with no `\n` for kilobytes (e.g. a minified bundle,
    // or a file that is one giant space-separated run of credential-shaped
    // tokens): there, an uncapped per-match `O(line_len)` walk turned the
    // whole-file scan quadratic — a 164 KiB single-line file with 8 K matches
    // took ~18 s, a 656 KiB one timed out. Capping the window keeps each
    // match's context cost O(1); the FP heuristics only need nearby keywords,
    // for which the immediate line is enough — these FP heuristics detect
    // HTTP cache / CORS / integrity-hash / renovate-digest *line* context, so
    // 2 KiB each side covers any real header line while keeping the per-match
    // substring scans cheap (this also speeds ordinary minified-bundle scans,
    // whose lines are routinely tens of KiB).
    const MAX_WINDOW_BYTES: usize = 2 * 1024;

    let mut start = safe_offset;
    let mut found_lines = 0;
    while start > 0 && found_lines <= radius && safe_offset - start < MAX_WINDOW_BYTES {
        start -= 1;
        if bytes[start] == b'\n' {
            found_lines += 1;
        }
    }
    if start > 0 || (start == 0 && bytes[0] == b'\n') {
        start += 1;
    }

    let mut end = safe_offset;
    let mut found_lines = 0;
    while end < bytes.len() && found_lines <= radius && end - safe_offset < MAX_WINDOW_BYTES {
        if bytes[end] == b'\n' {
            found_lines += 1;
        }
        end += 1;
    }

    let start = crate::engine::ceil_char_boundary(text, start);
    let mut end = crate::engine::floor_char_boundary(text, end);
    if end < start {
        end = start;
    }
    &text[start..end]
}
