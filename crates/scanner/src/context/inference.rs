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

/// Detect example/placeholder credentials using ONLY algorithmic heuristics.
/// No hardcoded credential lists — every suppression is based on a structural
/// property that generalizes to all credentials of that shape.
pub fn is_known_example_credential(credential: &str) -> bool {
    let upper = credential.to_uppercase();

    // EXAMPLE/EXAMPLEKEY is a universal documentation convention.
    if upper.ends_with("EXAMPLE") || upper.ends_with("EXAMPLEKEY") {
        return true;
    }

    // x/X-dominated values are masking filler.
    let body = credential.as_bytes();
    let x_count = body.iter().filter(|&&b| b == b'x' || b == b'X').count();
    if body.len() >= 16 && x_count > body.len() * 3 / 4 {
        return true;
    }

    // Ascending hex pairs are documentation placeholders.
    if is_hex_sequential_placeholder(credential) {
        return true;
    }

    // These appear in integrity checks, not as secrets.
    if is_empty_input_hash(credential) {
        return true;
    }

    // Monotonic or repetitive bodies remain placeholders after stripping prefixes.
    is_sequential_placeholder(credential)
}

/// Returns true if the credential is the hash of an empty input (common in
/// integrity/checksum fields, never a real secret).
fn is_empty_input_hash(credential: &str) -> bool {
    let lower = credential.to_ascii_lowercase();
    // Only match exact lengths to avoid false positives on substrings.
    match lower.len() {
        32 => lower == "d41d8cd98f00b204e9800998ecf8427e", // MD5("")
        40 => lower == "da39a3ee5e6b4b0d3255bfef95601890afd80709", // SHA1("")
        64 => lower == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256("")
        _ => false,
    }
}

fn is_sequential_placeholder(credential: &str) -> bool {
    // Strip ALL known service prefixes before checking for sequential/placeholder patterns.
    // This list MUST stay in sync with KNOWN_PREFIXES in confidence/prefixes.rs.
    // Missing a prefix here = false positive (placeholder not suppressed).
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghs_",
        "ghu_",
        "ghr_",
        "github_pat_",
        "sk-proj-",
        "sk-ant-",
        "sk-",
        "sk_test_",
        "sk_live_",
        "pk_test_",
        "pk_live_",
        "rk_test_",
        "rk_live_",
        "AKIA",
        "ASIA",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
        "SG.",
        "hf_",
        "npm_",
        "pypi-",
        "glpat-",
        "glcbt-",
        "glrt-",
        "dop_v1_",
        "eyJ",
        "vercel_",
        "sbp_",
        "0x",
    ];
    let body = PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
        .unwrap_or(credential);
    if body.len() < 16 {
        return false;
    }

    let bytes = body.as_bytes();
    if bytes.iter().all(|&byte| byte == bytes[0]) {
        return true;
    }
    if bytes.len() >= 8 {
        let pair = &bytes[..2];
        if bytes
            .chunks(2)
            .all(|chunk| chunk == pair || chunk.len() < 2)
        {
            return true;
        }
    }
    false
}

fn is_hex_sequential_placeholder(credential: &str) -> bool {
    let body = PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
        .unwrap_or(credential);

    // Reuse the same prefix list from is_sequential_placeholder
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghs_",
        "ghu_",
        "ghr_",
        "github_pat_",
        "sk-proj-",
        "sk-ant-",
        "sk-",
        "sk_test_",
        "sk_live_",
        "pk_test_",
        "pk_live_",
        "rk_test_",
        "rk_live_",
        "AKIA",
        "ASIA",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "SG.",
        "hf_",
        "npm_",
        "pypi-",
        "glpat-",
        "glcbt-",
        "glrt-",
        "dop_v1_",
        "eyJ",
        "vercel_",
        "sbp_",
        "0x",
    ];

    if body.len() < 16 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    let bytes: Vec<u8> = body.bytes().collect();

    // Single-byte monotonic sequences such as 0123456789abcdef or fedcba9876543210.
    if bytes.len() >= 16 {
        let ascending = bytes
            .windows(2)
            .filter(|w| {
                w[1] == w[0] + 1 || (w[0] == b'9' && w[1] == b'a') || (w[0] == b'f' && w[1] == b'0')
            })
            .count();
        let descending = bytes
            .windows(2)
            .filter(|w| {
                w[1] + 1 == w[0] || (w[0] == b'a' && w[1] == b'9') || (w[0] == b'0' && w[1] == b'f')
            })
            .count();
        let threshold = (bytes.len() - 1) * 9 / 10;
        if ascending > threshold || descending > threshold {
            return true;
        }
    }

    let pairs: Vec<&[u8]> = bytes.chunks(2).filter(|chunk| chunk.len() == 2).collect();
    if pairs.len() < 8 {
        return false;
    }

    let first_chars: Vec<u8> = pairs
        .iter()
        .map(|pair| pair[0].to_ascii_lowercase())
        .collect();
    let ascending = first_chars
        .windows(2)
        .filter(|window| {
            window[1] == window[0] + 1
                || (window[0] == b'f' && window[1] == b'a')
                || (window[0] == b'9' && window[1] == b'a')
                || (window[0] == b'9' && window[1] == b'0')
        })
        .count();

    let second_chars: Vec<u8> = pairs
        .iter()
        .map(|pair| pair[1].to_ascii_lowercase())
        .collect();
    let ascending2 = second_chars
        .windows(2)
        .filter(|window| {
            window[1] == window[0] + 1
                || (window[0] == b'f' && window[1] == b'0')
                || (window[0] == b'9' && window[1] == b'0')
                || (window[0] == b'9' && window[1] == b'a')
        })
        .count();

    let threshold = pairs.len() * 9 / 10;
    ascending > threshold && ascending2 > threshold
}

/// Infer context when documentation-line flags have already been computed.
pub fn infer_context_with_documentation(
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
    if is_comment_line(trimmed) {
        return CodeContext::Comment;
    }
    if documentation_lines.get(line_idx).copied().unwrap_or(false) {
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
    // Split on both / and \ for cross-platform compatibility.
    let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let stem = filename.split('.').next().unwrap_or(filename);

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
        || path.split(['/', '\\']).any(|component| {
            component.eq_ignore_ascii_case("test")
                || component.eq_ignore_ascii_case("tests")
                || component.eq_ignore_ascii_case("__tests__")
                || component.eq_ignore_ascii_case("fixtures")
                || component.eq_ignore_ascii_case("testdata")
                || component.eq_ignore_ascii_case("spec")
        })
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
    for line in lines.iter().take(line_idx + 1).skip(start) {
        let trimmed = line.trim();
        if trimmed.starts_with("$ANSIBLE_VAULT")
            || trimmed.starts_with("ENC[")
            || memchr::memmem::find(trimmed.as_bytes(), b"sops:").is_some()
            || memchr::memmem::find(trimmed.as_bytes(), b"sealed-secrets").is_some()
            || trimmed.starts_with("-----BEGIN PGP MESSAGE-----")
            || trimmed.starts_with("-----BEGIN AGE ENCRYPTED")
        {
            return true;
        }
    }
    false
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
            || trimmed == "#[cfg(test)]"
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

    let mut start = safe_offset;
    let mut found_lines = 0;
    while start > 0 && found_lines <= radius {
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
    while end < bytes.len() && found_lines <= radius {
        if bytes[end] == b'\n' {
            found_lines += 1;
        }
        end += 1;
    }

    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    while end > start && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[start..end]
}
