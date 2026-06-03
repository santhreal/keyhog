//! Structured format preprocessor.
//!
//! Detects known configuration formats (.env, Kubernetes Secrets, Docker Compose,
//! Terraform state, Jupyter notebooks), extracts (context, value) pairs, and
//! appends them as scannable lines to the original text.  This lets the regex
//! pipeline see values with their keys as context while keeping original line
//! mappings intact.

use crate::types::ScannerPreprocessedText;

pub mod parsers;

const MAX_STRUCTURED_PARSE_BYTES: usize = 2 * 1024 * 1024;

pub struct ExtractedPair {
    pub context: String,
    pub value: String,
    pub line: usize,
}

/// Detect format by path and/or content, parse it, and build a preprocessed text.
/// Returns `None` when the file is not a recognised structured format, when it
/// exceeds the size limit, or when no pairs could be extracted.
/// Pre-process structured configuration files to extract key-value pairs.
pub fn preprocess<'a>(text: &str, path: Option<&str>) -> Option<ScannerPreprocessedText<'a>> {
    if text.len() > MAX_STRUCTURED_PARSE_BYTES {
        return None;
    }
    let pairs = detect_and_parse(text, path)?;
    if pairs.is_empty() {
        return None;
    }
    Some(build_preprocessed_text(text, pairs))
}

fn detect_and_parse(text: &str, path: Option<&str>) -> Option<Vec<ExtractedPair>> {
    // ASCII case-insensitive byte compares - every chunk runs through this
    // detector to decide whether a structured parser applies. The previous
    // flow built a fully-lowercased copy of the path on every call.
    let path_bytes = path.map(str::as_bytes).unwrap_or(&[]);
    let ends_ci = |suffix: &[u8]| -> bool {
        path_bytes.len() >= suffix.len()
            && path_bytes[path_bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };
    let last_sep = path_bytes
        .iter()
        .rposition(|&b| b == b'/' || b == b'\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    let file_bytes = &path_bytes[last_sep..];
    let file_starts_ci = |prefix: &[u8]| -> bool {
        file_bytes.len() >= prefix.len() && file_bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
    };
    let file_ends_ci = |suffix: &[u8]| -> bool {
        file_bytes.len() >= suffix.len()
            && file_bytes[file_bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };
    let file_contains_ci = |needle: &[u8]| -> bool {
        if needle.is_empty() || needle.len() > file_bytes.len() {
            return false;
        }
        file_bytes
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    };

    if file_starts_ci(b".env") || file_ends_ci(b".env") {
        return Some(parsers::parse_env(text));
    }

    if (ends_ci(b".yaml") || ends_ci(b".yml")) && text.contains("kind: Secret") {
        return Some(parsers::parse_k8s_secret(text));
    }

    if (file_contains_ci(b"docker-compose") || file_contains_ci(b"compose"))
        && (ends_ci(b".yaml") || ends_ci(b".yml"))
    {
        return Some(parsers::parse_docker_compose(text));
    }

    if ends_ci(b".tfstate") {
        return Some(parsers::parse_tfstate(text));
    }

    // HCL / Terraform configuration. The block shape
    //   variable "x" { default = "<value>" }
    // hides the credential keyword (`x`) on the header line and the
    // value two lines below. Per-line keyword scanning misses both.
    // Extract `(x, <value>)` pairs so the keyword sits adjacent to the
    // value as a synthetic line and named detectors fire.
    if ends_ci(b".tf") || ends_ci(b".tfvars") || ends_ci(b".hcl") {
        return Some(parsers::parse_hcl(text));
    }

    if ends_ci(b".ipynb") {
        return Some(parsers::parse_jupyter(text));
    }

    None
}

#[cfg(feature = "multiline")]
fn build_preprocessed_text<'a>(
    text: &str,
    pairs: Vec<ExtractedPair>,
) -> ScannerPreprocessedText<'a> {
    use crate::multiline::LineMapping;
    let original_end = text.len();

    // Pre-size the output: original bytes + one '\n' separator + each synthetic
    // line ("{context}: {value}\n"). Avoids repeated reallocation while pushing
    // and the throwaway String that a `format!` per pair would allocate.
    let appended_len: usize = pairs
        .iter()
        .map(|p| p.context.len() + 2 + p.value.len() + 1)
        .sum();
    let mut final_text = String::with_capacity(original_end + 1 + appended_len);
    final_text.push_str(text);

    // One mapping per source line plus one per synthetic line.
    let line_count = text.split('\n').count();
    let mut mappings: Vec<LineMapping> = Vec::with_capacity(line_count + pairs.len());
    let mut offset = 0usize;

    for (line_idx, line) in text.split('\n').enumerate() {
        let end = offset + line.len();
        mappings.push(LineMapping {
            line_number: line_idx + 1,
            start_offset: offset,
            end_offset: (end + 1).min(original_end),
        });
        offset = end + 1;
    }

    final_text.push('\n');
    let mut current_offset = original_end + 1;
    for pair in pairs {
        // line == "{context}: {value}"; push the parts directly instead of
        // allocating an intermediate String via format!.
        let line_len = pair.context.len() + 2 + pair.value.len();
        mappings.push(LineMapping {
            line_number: pair.line,
            start_offset: current_offset,
            end_offset: current_offset + line_len,
        });
        final_text.push_str(&pair.context);
        final_text.push_str(": ");
        final_text.push_str(&pair.value);
        final_text.push('\n');
        current_offset += line_len + 1;
    }

    crate::multiline::PreprocessedText {
        // Synthesized text (original + appended key/value lines): owned.
        text: std::borrow::Cow::Owned(final_text),
        original_end,
        mappings,
    }
}

#[cfg(not(feature = "multiline"))]
fn build_preprocessed_text<'a>(
    text: &str,
    pairs: Vec<ExtractedPair>,
) -> ScannerPreprocessedText<'a> {
    use crate::types::LineMapping;

    // Pre-size the output: original bytes + one '\n' separator + each synthetic
    // line ("{context}: {value}\n"). Avoids repeated reallocation while pushing
    // and the throwaway String that a `format!` per pair would allocate.
    let appended_len: usize = pairs
        .iter()
        .map(|p| p.context.len() + 2 + p.value.len() + 1)
        .sum();
    let mut final_text = String::with_capacity(text.len() + 1 + appended_len);
    final_text.push_str(text);

    // One mapping per source line plus one per synthetic line.
    let line_count = text.split('\n').count();
    let mut mappings: Vec<LineMapping> = Vec::with_capacity(line_count + pairs.len());
    let mut offset = 0usize;

    for (line_idx, line) in text.split('\n').enumerate() {
        let end = offset + line.len();
        mappings.push(LineMapping {
            line_number: line_idx + 1,
            start_offset: offset,
            end_offset: end + 1,
        });
        offset = end + 1;
    }
    if let Some(last) = mappings.last_mut() {
        last.end_offset = text.len();
    }

    final_text.push('\n');
    let mut current_offset = text.len() + 1;
    for pair in pairs {
        // line == "{context}: {value}"; push the parts directly instead of
        // allocating an intermediate String via format!.
        let line_len = pair.context.len() + 2 + pair.value.len();
        mappings.push(LineMapping {
            line_number: pair.line,
            start_offset: current_offset,
            end_offset: current_offset + line_len,
        });
        final_text.push_str(&pair.context);
        final_text.push_str(": ");
        final_text.push_str(&pair.value);
        final_text.push('\n');
        current_offset += line_len + 1;
    }

    crate::types::PreprocessedText {
        // Synthesized text (original + appended key/value lines): owned.
        text: std::borrow::Cow::Owned(final_text),
        mappings,
    }
}
