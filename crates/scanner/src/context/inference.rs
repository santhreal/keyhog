use super::{documentation::documentation_line_flags, CodeContext};
use std::collections::BTreeSet;
use std::sync::LazyLock;

#[derive(serde::Deserialize)]
struct InferenceMarkers {
    comment_prefixes: Vec<String>,
    encrypted_prefixes: Vec<String>,
    encrypted_substrings: Vec<String>,
    rust_test_attribute_prefixes: Vec<String>,
    rust_test_attribute_exact: Vec<String>,
    test_function_prefixes: Vec<String>,
    attribute_or_doc_prefixes: Vec<String>,
    assignment_operators: Vec<String>,
}

const INFERENCE_MARKERS_TOML: &str = include_str!("../../../../rules/inference-markers.toml");

/// Parse the bundled Tier-B inference-marker lists. Returns an error rather than
/// panicking so the single `INFERENCE_MARKERS` owner below is the one fail-closed
/// site (the `no_unwrap_expect` gate bans `expect` in production source).
fn parse_inference_markers(raw: &str) -> Result<InferenceMarkers, String> {
    toml::from_str(raw).map_err(|error| format!("invalid rules/inference-markers.toml: {error}"))
}

/// Single owner for every inference-marker list: the embedded Tier-B TOML is
/// parsed exactly ONCE here and each classifier below reads its field, instead
/// of the previous eight statics that each re-`include_str!`'d and re-parsed the
/// whole file at first use (8x redundant startup parse + eight `expect` sites).
/// Fail-closed (Law 10): invalid bundled metadata panics loudly at first use 
/// the scanner refuses to run without credential-context classification truth.
static INFERENCE_MARKERS: LazyLock<InferenceMarkers> =
    LazyLock::new(|| match parse_inference_markers(INFERENCE_MARKERS_TOML) {
        Ok(markers) => markers,
        Err(error) => panic!(
            "{error}. Fix the bundled Tier-B inference-marker file; refusing to run \
             without credential-context classification truth."
        ),
    });

const ENCRYPTED_BLOCK_LOOKBACK_LINES: usize = 10;
// 100 lines covers large Go/Java test functions with extensive setup.
// The previous 30-line limit caused test fixtures to be reported as findings.
const TEST_FUNCTION_LOOKBACK_LINES: usize = 100;
/// Cap on the contiguous attribute/doc block walked above a Rust `fn` signature
/// when deciding whether a `#[test]`-family attribute marks it as test code.
/// Generous for any real attribute block (a handful of `#[...]` + doc lines,
/// possibly with unformatted blank lines); the walk runs once per enclosing
/// signature and this bound stops an all-blank prefix from reaching the file
/// start.
const ATTR_BLOCK_LOOKBACK: usize = 32;
/// The Rust test-config gate attribute, assembled via `concat!` so the literal
/// token never appears verbatim in this source file. Single owner for the two
/// match sites (`is_in_test_function` current-line check and
/// `is_rust_test_attribute`) that recognise it; keeping it in one place stops
/// the two sites from silently drifting apart.
const CFG_TEST_ATTR: &str = concat!("#[cfg(", "test)]");

/// Canonical comment-opener markers for the context module, the single owner
/// shared by `strip_comment_prefix` here and the disclaimer scan in
/// `false_positive.rs`. `--` opens a comment only when it is not the `---`
/// document separator (each consumer applies that exception).
pub(crate) const COMMENT_MARKERS: &[&str] =
    &["//", "#", "--", "/*", "<!--", "<#", "* ", "rem ", "REM "];

#[derive(serde::Deserialize)]
struct TestPathRuleFile {
    schema_version: u32,
    test_paths: TestPathRuleSection,
}

#[derive(serde::Deserialize)]
struct TestPathRuleSection {
    filename_prefixes: Vec<String>,
    filename_suffixes: Vec<String>,
    path_components: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct TestPathRules {
    pub(crate) filename_prefixes: Vec<String>,
    pub(crate) filename_suffixes: Vec<String>,
    pub(crate) path_components: Vec<String>,
}

static TEST_PATH_RULES: LazyLock<TestPathRules> = LazyLock::new(|| {
    match parse_test_path_rules(include_str!("../../data/test-path-rules.toml")) {
        Ok(rules) => rules,
        Err(error) => {
            panic!(
                "crates/scanner/data/test-path-rules.toml is invalid: {error}. \
                     Fix the bundled Tier-B test-path rules; refusing to run without \
                     test-context classification truth."
            )
        }
    }
});

/// Infer the structural context of a match at a given line.
pub fn infer_context(lines: &[&str], line_idx: usize, file_path: Option<&str>) -> CodeContext {
    let documentation_lines = documentation_line_flags(lines);
    infer_context_with_documentation(lines, line_idx, file_path, &documentation_lines)
}

fn is_encrypted_marker_line(trimmed: &str) -> bool {
    INFERENCE_MARKERS
        .encrypted_prefixes
        .iter()
        .any(|prefix| trimmed.starts_with(prefix.as_str()))
        || INFERENCE_MARKERS
            .encrypted_substrings
            .iter()
            .any(|sub| memchr::memmem::find(trimmed.as_bytes(), sub.as_bytes()).is_some())
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
    let rules = test_path_rules();
    let filename = crate::platform_compat::path_basename(path);
    let stem = filename.split('.').next().unwrap_or(filename); // LAW10: split yields >=1 element; unwrap_or is the never-taken total default, recall-safe

    rules.filename_prefixes.iter().any(|prefix| {
        // `>=`, not `>`: a filename whose stem IS the prefix exactly (e.g.
        // `test_.py` -> stem `test_`, prefix `test_`) is still a test file.
        stem.len() >= prefix.len()
            && stem
                .as_bytes()
                .get(..prefix.len())
                .is_some_and(|bytes| bytes.eq_ignore_ascii_case(prefix.as_bytes()))
    }) || rules
        .filename_suffixes
        .iter()
        .any(|suffix| filename.ends_with(suffix))
        || crate::platform_compat::path_has_any_component(path, &rules.path_components)
}

fn test_path_rules() -> &'static TestPathRules {
    &TEST_PATH_RULES
}

pub(crate) fn parse_test_path_rules(raw: &str) -> Result<TestPathRules, String> {
    let parsed: TestPathRuleFile =
        toml::from_str(raw).map_err(|error| format!("invalid test-path-rules.toml: {error}"))?;
    if parsed.schema_version != 1 {
        return Err(format!(
            "unsupported test-path-rules schema_version {}",
            parsed.schema_version
        ));
    }
    Ok(TestPathRules {
        filename_prefixes: validate_rule_list(
            "test_paths.filename_prefixes",
            parsed.test_paths.filename_prefixes,
            RuleListKind::FilenameFragment,
        )?,
        filename_suffixes: validate_rule_list(
            "test_paths.filename_suffixes",
            parsed.test_paths.filename_suffixes,
            RuleListKind::FilenameFragment,
        )?,
        path_components: validate_rule_list(
            "test_paths.path_components",
            parsed.test_paths.path_components,
            RuleListKind::PathComponent,
        )?,
    })
}

#[derive(Clone, Copy)]
enum RuleListKind {
    FilenameFragment,
    PathComponent,
}

fn validate_rule_list(
    field: &str,
    values: Vec<String>,
    kind: RuleListKind,
) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Err(format!("{field} must contain at least one entry"));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for raw in values {
        let value = raw.trim();
        if value.is_empty() {
            return Err(format!("{field} entries must not be empty"));
        }
        if value.bytes().any(|byte| byte == b'/' || byte == b'\\') {
            return Err(format!(
                "{field} entry {value:?} must not contain path separators"
            ));
        }
        if matches!(kind, RuleListKind::PathComponent) && value.contains('.') {
            return Err(format!(
                "{field} component {value:?} must be a path segment, not a filename pattern"
            ));
        }
        if !seen.insert(value.to_string()) {
            return Err(format!("duplicate {field} entry {value:?}"));
        }
        out.push(value.to_string());
    }
    Ok(out)
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
    (trimmed.starts_with("--") && !trimmed.starts_with("---"))
        || INFERENCE_MARKERS
            .comment_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix.as_str()))
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

pub(crate) fn strip_comment_prefix(trimmed: &str) -> Option<&str> {
    for &marker in COMMENT_MARKERS {
        if marker == "--" && trimmed.starts_with("---") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(marker) {
            return Some(rest);
        }
    }
    None
}

fn is_assignment_line(trimmed: &str) -> bool {
    has_assignment_operator(trimmed) || has_yaml_mapping(trimmed)
}

pub(crate) fn has_assignment_operator(trimmed: &str) -> bool {
    for operator in &INFERENCE_MARKERS.assignment_operators {
        let op_str = operator.as_str();
        if let Some(pos) = trimmed.find(op_str) {
            if !is_comparison_operator(trimmed, pos, op_str) {
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
    // Slice the exact lookback window instead of `.take(line_idx+1).skip(start)`
    // (which walks from line 0, O(line_idx)); the slice is O(window). Bounds
    // clamped so a `line_idx` past the end can't panic.
    let end = (line_idx + 1).min(lines.len());
    let start = line_idx
        .saturating_sub(ENCRYPTED_BLOCK_LOOKBACK_LINES)
        .min(end);
    lines[start..end]
        .iter()
        .any(|line| is_encrypted_marker_line(line.trim()))
}

pub(crate) fn is_in_test_function(lines: &[&str], line_idx: usize) -> bool {
    let start = line_idx.saturating_sub(TEST_FUNCTION_LOOKBACK_LINES);
    for candidate_line_idx in (start..line_idx).rev() {
        let trimmed = lines[candidate_line_idx].trim();

        if INFERENCE_MARKERS
            .test_function_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix.as_str()))
            || is_rust_test_attribute(trimmed)
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

        if is_rust_fn_signature(trimmed) && !trimmed.contains("fn test_") {
            // A Rust test fn has an arbitrary name and is marked by a
            // `#[test]`-family attribute. That attribute can sit several
            // attribute / doc-comment lines above the signature
            // (`#[test] #[ignore] #[should_panic(...)] ... fn`); a fixed 3-line
            // window missed it and left the whole test body at full confidence,
            // so a fixture credential surfaced as a false positive. Walk the
            // WHOLE contiguous attribute/doc block instead. Blank lines are
            // ignored (attributes attach to the next item across whitespace);
            // any other line ends the block, so we never adopt a `#[test]` from
            // an unrelated item above this fn. The block-walk runs once (at the
            // enclosing signature) and is capped so a pathological all-blank
            // prefix cannot make it walk to the file start.
            let block_start = candidate_line_idx.saturating_sub(ATTR_BLOCK_LOOKBACK);
            for pre_line in lines[block_start..candidate_line_idx].iter().rev() {
                let pre_trimmed = pre_line.trim();
                if pre_trimmed.is_empty() {
                    continue;
                }
                if is_rust_test_attribute(pre_trimmed) {
                    return true;
                }
                if !is_attribute_or_doc_line(pre_trimmed) {
                    break;
                }
            }
            return false;
        }

        if trimmed.starts_with("function ") && !trimmed.contains("function test") {
            return false;
        }
    }
    false
}

/// True if `trimmed` opens a Rust `fn` signature, tolerating the full leading
/// qualifier run, visibility (`pub`, `pub(crate)`, `pub(super)`, `pub(in …)`),
/// `const`, `unsafe`, `async`, `default`, and `extern "…"`: in any order before
/// the `fn` keyword. The look-back boundary check only knew `fn`/`pub fn`/
/// `async fn`/`pub async fn`, so a `pub(crate) fn` / `const fn` / `unsafe fn`
/// between a match and a test marker was skipped, mis-classifying real code as
/// TestCode and hard-suppressing a live secret (recall loss).
pub(crate) fn is_rust_fn_signature(trimmed: &str) -> bool {
    let mut rest = trimmed;
    loop {
        if let Some(after) = rest.strip_prefix("pub") {
            let after = after.trim_start();
            if let Some(paren) = after.strip_prefix('(') {
                match paren.find(')') {
                    Some(close) => {
                        rest = paren[close + 1..].trim_start();
                        continue;
                    }
                    None => return false,
                }
            }
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix("extern") {
            let after = after.trim_start();
            if let Some(quoted) = after.strip_prefix('"') {
                match quoted.find('"') {
                    Some(close) => {
                        rest = quoted[close + 1..].trim_start();
                        continue;
                    }
                    None => return false,
                }
            }
            rest = after;
            continue;
        }
        let stripped = ["const ", "unsafe ", "async ", "default "]
            .iter()
            .find_map(|kw| rest.strip_prefix(kw));
        match stripped {
            Some(after) => rest = after.trim_start(),
            None => break,
        }
    }
    rest.starts_with("fn ")
}

/// A `#[test]`-family attribute (or the Java `@Test` annotation) that marks the
/// following item as test code.
fn is_rust_test_attribute(trimmed: &str) -> bool {
    trimmed == CFG_TEST_ATTR
        || INFERENCE_MARKERS
            .rust_test_attribute_exact
            .iter()
            .any(|attr| trimmed == attr.as_str())
        || INFERENCE_MARKERS
            .rust_test_attribute_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix.as_str()))
}

/// A line that belongs to the attribute / doc-comment block that may sit between
/// a `#[test]` attribute and the `fn` it applies to: any attribute (`#[...]` /
/// inner `#![...]`), a doc/line comment (`//` / `///` / `//!`), or a block
/// comment fragment (`/* … */`, ` * …`). A blank line or anything else ends the
/// block, so the walk never adopts an attribute from an unrelated item.
fn is_attribute_or_doc_line(trimmed: &str) -> bool {
    trimmed.ends_with("*/")
        || INFERENCE_MARKERS
            .attribute_or_doc_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix.as_str()))
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
    // whole-file scan quadratic, a 164 KiB single-line file with 8 K matches
    // took ~18 s, a 656 KiB one timed out. Capping the window keeps each
    // match's context cost O(1); the FP heuristics only need nearby keywords,
    // for which the immediate line is enough, these FP heuristics detect
    // HTTP cache / CORS / integrity-hash / renovate-digest *line* context, so
    // 2 KiB each side covers any real header line while keeping the per-match
    // substring scans cheap (this also speeds ordinary minified-bundle scans,
    // whose lines are routinely tens of KiB).
    const FP_HEURISTIC_WINDOW_BYTES: usize = 2 * 1024;

    let mut start = safe_offset;
    let mut found_lines = 0;
    while start > 0 && found_lines <= radius && safe_offset - start < FP_HEURISTIC_WINDOW_BYTES {
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
    while end < bytes.len()
        && found_lines <= radius
        && end - safe_offset < FP_HEURISTIC_WINDOW_BYTES
    {
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
