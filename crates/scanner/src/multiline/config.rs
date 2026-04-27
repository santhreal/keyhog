const MAX_MULTILINE_PREPROCESS_BYTES: usize = 2 * 1024 * 1024;
const MAX_MULTILINE_LINE_BYTES: usize = 64 * 1024;

/// A mapping from an offset in the joined text back to the original line number.
#[derive(Debug, Clone)]
pub struct LineMapping {
    /// Start offset in the joined text (inclusive).
    pub start_offset: usize,
    /// End offset in the joined text (exclusive).
    pub end_offset: usize,
    /// Original line number (1-indexed).
    pub line_number: usize,
}

/// Result of preprocessing text for multi-line concatenation.
#[derive(Debug, Clone)]
pub struct PreprocessedText {
    /// Original text plus appended multiline-joined segments.
    pub text: String,
    /// Byte offset where appended joined segments start.
    pub original_end: usize,
    /// Mapping from offsets in `text` to original line numbers.
    pub mappings: Vec<LineMapping>,
}

impl PreprocessedText {
    /// Map a byte offset in preprocessed text back to an original line number.
    pub fn line_for_offset(&self, offset: usize) -> Option<usize> {
        self.mappings
            .iter()
            .find(|mapping| offset >= mapping.start_offset && offset < mapping.end_offset)
            .map(|mapping| mapping.line_number)
    }

    /// Build a preprocessed representation with a one-line identity mapping.
    pub fn passthrough(text: &str) -> Self {
        let mut mappings = Vec::new();
        let mut offset = 0;
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
        let original_end = text.len();
        Self {
            text: text.to_string(),
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
    /// Whether to enable JavaScript template literal concatenation.
    pub template_literals: bool,
}

impl Default for MultilineConfig {
    fn default() -> Self {
        Self {
            max_join_lines: 10,
            python_implicit: true,
            backslash_continuation: true,
            plus_concatenation: true,
            template_literals: true,
        }
    }
}

/// Check if text contains any concatenation indicators.
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
    let has_paste = text.contains("paste0(");
    let has_implicit = bytes.windows(3).any(|window| {
        (window[0] == b'"' && window[1] == b' ' && window[2] == b'"')
            || (window[0] == b'\'' && window[1] == b' ' && window[2] == b'\'')
            || (window[0] == b'"'
                && window[1] == b'\n'
                && (window[2] == b'"' || window[2] == b' ' || window[2] == b'\t'))
            || (window[0] == b'\''
                && window[1] == b'\n'
                && (window[2] == b'\'' || window[2] == b' ' || window[2] == b'\t'))
    });
    if !has_explicit_concat && !has_backslash_cont && !has_template && !has_paste && !has_implicit {
        return false;
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with('+')
            || trimmed.starts_with('+')
            || trimmed.starts_with("+ ")
            || trimmed.contains("paste0(")
            || trimmed.contains("paste(")
            || trimmed.contains("\" +")
            || trimmed.contains("' +")
            || trimmed.contains("+ \"")
            || trimmed.contains("+ '")
            || (trimmed.ends_with('\\') && !trimmed.ends_with("\\\\"))
            || trimmed.contains("\" \"")
            || trimmed.contains("' '")
            || (trimmed.ends_with('`') && trimmed.matches('`').count() == 1)
        {
            return true;
        }
    }

    false
}

pub(crate) fn should_passthrough(text: &str) -> bool {
    text.len() > MAX_MULTILINE_PREPROCESS_BYTES
        || text
            .lines()
            .any(|line| line.len() > MAX_MULTILINE_LINE_BYTES)
        || !has_concatenation_indicators(text)
}
