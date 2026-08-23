//! Candidate-bounded roles for documentation, roff, and shell sources.

use keyhog_core::SemanticSourceRole;

use crate::source_semantics::{SourceSemanticEvidence, SourceSpan};

pub(crate) const MAX_DOCUMENT_SOURCE_BYTES: usize = 64 * 1024;
pub(crate) const STRUCTURED_MARKDOWN_FENCES: &[(&str, &str)] = &[
    ("env", ".env"),
    ("dotenv", ".env"),
    ("json", "snippet.json"),
    ("jsonl", "snippet.jsonl"),
    ("ndjson", "snippet.ndjson"),
    ("toml", "snippet.toml"),
    ("yaml", "snippet.yaml"),
    ("yml", "snippet.yml"),
    ("ini", "snippet.ini"),
    ("cfg", "snippet.cfg"),
    ("conf", "snippet.conf"),
    ("properties", "snippet.properties"),
];

#[derive(Debug, Clone, Copy)]
struct DocumentValue {
    span: SourceSpan,
    role: SemanticSourceRole,
}

#[derive(Debug)]
pub(crate) struct DocumentSourceIndex {
    values: Vec<DocumentValue>,
}

impl DocumentSourceIndex {
    fn new(text_len: usize, default_role: SemanticSourceRole) -> Self {
        let mut values = Vec::new();
        if text_len != 0 {
            values.push(DocumentValue {
                span: SourceSpan::new(0, text_len),
                role: default_role,
            });
        }
        Self { values }
    }

    fn push(&mut self, span: SourceSpan, role: SemanticSourceRole) {
        if span.start < span.end {
            self.values.push(DocumentValue { span, role });
        }
    }

    pub(crate) fn classify(&self, target: SourceSpan) -> Option<SourceSemanticEvidence> {
        let value = self
            .values
            .iter()
            .filter(|value| value.span.contains(target))
            .min_by_key(|value| value.span.end.saturating_sub(value.span.start))?;
        Some(SourceSemanticEvidence::parsed(
            value.role, target, value.span,
        ))
    }
}

pub(crate) fn build_document_source_index(text: &str, path: &str) -> Option<DocumentSourceIndex> {
    if text.len() > MAX_DOCUMENT_SOURCE_BYTES {
        return None;
    }
    match document_kind(path)? {
        DocumentKind::Markdown => index_markdown(text),
        DocumentKind::Roff => index_roff(text),
        DocumentKind::Shell => index_shell(text, 0),
    }
}

#[derive(Clone, Copy)]
enum DocumentKind {
    Markdown,
    Roff,
    Shell,
}

fn document_kind(path: &str) -> Option<DocumentKind> {
    let name = path
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(path)
        .split('?')
        .next()
        .unwrap_or(path);
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    if extension.is_some_and(|extension| {
        ["md", "markdown", "mdown"]
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    }) {
        Some(DocumentKind::Markdown)
    } else if extension.is_some_and(|extension| {
        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "man", "roff"]
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    }) {
        Some(DocumentKind::Roff)
    } else if extension.is_some_and(|extension| {
        ["sh", "bash", "zsh", "ksh"]
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    }) || ["Dockerfile", "Containerfile"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        Some(DocumentKind::Shell)
    } else {
        None
    }
}

#[derive(Clone, Copy)]
enum MarkdownFenceLanguage {
    Documentation,
    Shell,
    Structured(&'static str),
}

#[derive(Clone, Copy)]
struct MarkdownFence {
    marker: u8,
    width: usize,
    language: MarkdownFenceLanguage,
    content_start: usize,
}

fn index_markdown(text: &str) -> Option<DocumentSourceIndex> {
    let mut index = DocumentSourceIndex::new(text.len(), SemanticSourceRole::ProseDocumentation);
    let mut line = 0usize;
    let mut fence: Option<MarkdownFence> = None;
    while line < text.len() {
        let inside_fence = fence.is_some();
        let end = line_end(text, line);
        let trimmed_start = skip_spaces(text.as_bytes(), line, end);
        let marker = fence_marker(text.as_bytes(), trimmed_start, end);
        if let Some(active) = fence {
            if marker.is_some_and(|(candidate, candidate_width, _)| {
                candidate == active.marker && candidate_width >= active.width
            }) {
                if let MarkdownFenceLanguage::Structured(path) = active.language {
                    append_structured_fence(&mut index, text, active.content_start, line, path)?;
                }
                fence = None;
            } else if matches!(active.language, MarkdownFenceLanguage::Shell) {
                append_shell_line(&mut index, text, line, end)?;
            }
        } else if let Some((marker, width, language)) = marker {
            fence = Some(MarkdownFence {
                marker,
                width,
                language,
                content_start: next_line(text, line).unwrap_or(end),
            });
        }
        if !inside_fence && marker.is_none() {
            append_inline_code(&mut index, text, line, end)?;
        }
        let Some(next) = next_line(text, line) else {
            break;
        };
        line = next;
    }
    fence.is_none().then_some(index)
}

fn fence_marker(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Option<(u8, usize, MarkdownFenceLanguage)> {
    let byte @ (b'`' | b'~') = *bytes.get(start)? else {
        return None;
    };
    let width = bytes[start..end]
        .iter()
        .take_while(|candidate| **candidate == byte)
        .count();
    if width < 3 {
        return None;
    }
    let info = std::str::from_utf8(&bytes[start + width..end]).ok()?.trim();
    let language = if ["sh", "shell", "bash", "zsh", "console"]
        .iter()
        .any(|candidate| info.eq_ignore_ascii_case(candidate))
    {
        MarkdownFenceLanguage::Shell
    } else if let Some((_, path)) = STRUCTURED_MARKDOWN_FENCES
        .iter()
        .find(|(candidate, _)| info.eq_ignore_ascii_case(candidate))
    {
        MarkdownFenceLanguage::Structured(path)
    } else {
        MarkdownFenceLanguage::Documentation
    };
    Some((byte, width, language))
}

fn append_structured_fence(
    index: &mut DocumentSourceIndex,
    text: &str,
    start: usize,
    end: usize,
    path: &str,
) -> Option<()> {
    let body = text.get(start..end)?;
    let structured = crate::source_semantics::build_structured_source_index(body, Some(path))?;
    let mut valid = true;
    structured.for_each_value(|role, span| {
        let Some(value_start) = start.checked_add(span.start) else {
            valid = false;
            return;
        };
        let Some(value_end) = start.checked_add(span.end) else {
            valid = false;
            return;
        };
        index.push(SourceSpan::new(value_start, value_end), role);
    });
    valid.then_some(())
}

fn append_inline_code(
    index: &mut DocumentSourceIndex,
    text: &str,
    start: usize,
    end: usize,
) -> Option<()> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while cursor < end {
        if bytes[cursor] != b'`' {
            cursor += 1;
            continue;
        }
        let width = bytes[cursor..end]
            .iter()
            .take_while(|byte| **byte == b'`')
            .count();
        let content_start = cursor + width;
        let close = find_run(bytes, content_start, end, b'`', width)?;
        index.push(
            SourceSpan::new(content_start, close),
            SemanticSourceRole::ProseDocumentation,
        );
        cursor = close + width;
    }
    Some(())
}

fn index_roff(text: &str) -> Option<DocumentSourceIndex> {
    let mut index = DocumentSourceIndex::new(text.len(), SemanticSourceRole::ProseDocumentation);
    let mut line = 0usize;
    while line < text.len() {
        let end = line_end(text, line);
        let trimmed = skip_spaces(text.as_bytes(), line, end);
        if text.as_bytes().get(trimmed) == Some(&b'.') {
            let tokens = shell_tokens(text, trimmed, end)?;
            if tokens.iter().any(|token| {
                text[token.start..token.end]
                    .trim_matches(['\'', '"'])
                    .starts_with("--")
            }) {
                index.push(
                    SourceSpan::new(trimmed, end),
                    SemanticSourceRole::CommandOptionDeclaration,
                );
            }
        }
        let Some(next) = next_line(text, line) else {
            break;
        };
        line = next;
    }
    Some(index)
}

fn index_shell(text: &str, base: usize) -> Option<DocumentSourceIndex> {
    let mut index = DocumentSourceIndex { values: Vec::new() };
    let mut line = 0usize;
    while line < text.len() {
        let end = line_end(text, line);
        append_shell_line_with_base(&mut index, text, line, end, base)?;
        let Some(next) = next_line(text, line) else {
            break;
        };
        line = next;
    }
    Some(index)
}

fn append_shell_line(
    index: &mut DocumentSourceIndex,
    text: &str,
    start: usize,
    end: usize,
) -> Option<()> {
    append_shell_line_with_base(index, text, start, end, 0)
}

fn append_shell_line_with_base(
    index: &mut DocumentSourceIndex,
    text: &str,
    start: usize,
    end: usize,
    base: usize,
) -> Option<()> {
    let tokens = shell_tokens(text, start, end)?;
    let mut expects_option_value = false;
    let mut command_started = false;
    for token in tokens {
        let raw = &text[token.start..token.end];
        let unquoted = raw.trim_matches(['\'', '"']);
        let unquoted_offset = raw.find(unquoted).unwrap_or(0);
        let span = SourceSpan::new(
            base + token.start + unquoted_offset,
            base + token.start + unquoted_offset + unquoted.len(),
        );
        if expects_option_value {
            index.push(span, SemanticSourceRole::CommandArgumentValue);
            expects_option_value = false;
            continue;
        }
        if unquoted.starts_with('-') {
            command_started = true;
            if let Some(equals) = unquoted.find('=') {
                let value_start = span.start + equals + 1;
                index.push(
                    SourceSpan::new(value_start, span.end),
                    SemanticSourceRole::CommandArgumentValue,
                );
            } else {
                expects_option_value = true;
            }
        } else if !command_started
            && unquoted
                .split_once('=')
                .is_some_and(|(name, _)| is_shell_name(name))
        {
            let equals = unquoted.find('=').expect("split_once proved assignment");
            index.push(
                SourceSpan::new(span.start + equals + 1, span.end),
                SemanticSourceRole::EnvironmentAssignmentValue,
            );
        } else if command_started {
            index.push(span, SemanticSourceRole::CommandArgumentValue);
        } else {
            command_started = true;
        }
    }
    Some(())
}

fn is_shell_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn shell_tokens(text: &str, start: usize, end: usize) -> Option<Vec<SourceSpan>> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = start;
    while cursor < end {
        cursor = skip_spaces(bytes, cursor, end);
        if cursor == end || bytes[cursor] == b'#' {
            break;
        }
        let token_start = cursor;
        let mut quote = None;
        while cursor < end {
            if let Some(active) = quote {
                if bytes[cursor] == b'\\' && active == b'"' {
                    cursor = cursor.saturating_add(2);
                } else if bytes[cursor] == active {
                    quote = None;
                    cursor += 1;
                } else {
                    cursor += 1;
                }
            } else if matches!(bytes[cursor], b'\'' | b'"') {
                quote = Some(bytes[cursor]);
                cursor += 1;
            } else if bytes[cursor].is_ascii_whitespace() {
                break;
            } else if bytes[cursor] == b'#' && cursor == token_start {
                break;
            } else if bytes[cursor] == b'\\' {
                cursor = cursor.saturating_add(2);
            } else {
                cursor += 1;
            }
        }
        if quote.is_some() || cursor > end {
            return None;
        }
        tokens.push(SourceSpan::new(token_start, cursor));
    }
    Some(tokens)
}

fn find_run(bytes: &[u8], mut cursor: usize, end: usize, byte: u8, width: usize) -> Option<usize> {
    while cursor + width <= end {
        if bytes[cursor..cursor + width]
            .iter()
            .all(|candidate| *candidate == byte)
        {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn skip_spaces(bytes: &[u8], mut cursor: usize, end: usize) -> usize {
    while cursor < end && matches!(bytes[cursor], b' ' | b'\t') {
        cursor += 1;
    }
    cursor
}

fn line_end(text: &str, start: usize) -> usize {
    text.as_bytes()[start..]
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .map_or(text.len(), |offset| start + offset)
}

fn next_line(text: &str, start: usize) -> Option<usize> {
    let end = line_end(text, start);
    (end < text.len()).then_some(if text.as_bytes().get(end..end + 2) == Some(b"\r\n") {
        end + 2
    } else {
        end + 1
    })
}
