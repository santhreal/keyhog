use keyhog_core::SourceError;

#[derive(Debug)]
pub(crate) enum UnifiedDiffEvent<'a> {
    FileHeader {
        new_path: Option<String>,
        invalid_path: bool,
    },
    DeletedFile,
    Metadata,
    HunkStart {
        base_line: usize,
    },
    AddedLine(&'a [u8]),
    BinaryFile,
    Other,
}

pub(crate) struct UnifiedDiffParser {
    in_hunk: bool,
}

impl UnifiedDiffParser {
    pub(crate) fn new() -> Self {
        Self { in_hunk: false }
    }

    pub(crate) fn parse_line<'a>(
        &mut self,
        line: &'a [u8],
        source_type: &str,
    ) -> Result<UnifiedDiffEvent<'a>, SourceError> {
        if line.starts_with(b"diff --git ") {
            self.in_hunk = false;
            return Ok(UnifiedDiffEvent::FileHeader {
                new_path: None,
                invalid_path: false,
            });
        }

        if line.starts_with(b"deleted file mode") {
            self.in_hunk = false;
            return Ok(UnifiedDiffEvent::DeletedFile);
        }

        if line.starts_with(b"new file mode") || line.starts_with(b"index ") {
            return Ok(UnifiedDiffEvent::Metadata);
        }

        if line.starts_with(b"Binary files ") || line.starts_with(b"Binary file ") {
            self.in_hunk = false;
            return Ok(UnifiedDiffEvent::BinaryFile);
        }

        if line.starts_with(b"--- ") {
            self.in_hunk = false;
            return Ok(UnifiedDiffEvent::Metadata);
        }

        if line.starts_with(b"@@") {
            if memchr::memmem::find(&line[2..], b"@@").is_none() {
                return Err(malformed_diff_line_error(source_type, line, "hunk header"));
            }
            let new_start = super::parse_hunk_new_start_bytes_or_error(line, source_type)?;
            self.in_hunk = true;
            return Ok(UnifiedDiffEvent::HunkStart {
                base_line: new_start.saturating_sub(1),
            });
        }

        if self.in_hunk && line.starts_with(b"+") {
            return Ok(UnifiedDiffEvent::AddedLine(&line[1..]));
        }

        if let Some((new_path, invalid_path)) = extract_new_path_from_plus_header(line) {
            self.in_hunk = false;
            return Ok(UnifiedDiffEvent::FileHeader {
                new_path,
                invalid_path,
            });
        }

        if line.starts_with(b"+++") {
            self.in_hunk = false;
            return Err(malformed_diff_line_error(
                source_type,
                line,
                "new-file header",
            ));
        }

        Ok(UnifiedDiffEvent::Other)
    }
}

fn malformed_diff_line_error(source_type: &str, line: &[u8], label: &str) -> SourceError {
    let line = diff_line_excerpt(line);
    SourceError::Other(format!(
        "{source_type} output contains malformed unified-diff {label} {line:?}; \
         refusing to treat it as ordinary diff content because that would hide changed lines"
    ))
}

fn diff_line_excerpt(line: &[u8]) -> String {
    const MAX: usize = 96;
    let mut output = String::with_capacity(line.len().min(MAX).saturating_mul(4));
    for &byte in line.iter().take(MAX) {
        match byte {
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            b'\\' => output.push_str("\\\\"),
            b'"' => output.push_str("\\\""),
            0x20..=0x7e => output.push(byte as char),
            other => {
                output.push_str("\\x");
                output.push(hex_digit(other >> 4));
                output.push(hex_digit(other & 0x0f));
            }
        }
    }
    if line.len() > MAX {
        output.push_str("...");
    }
    output
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '?',
    }
}

pub(crate) fn trim_diff_line_bytes(mut line: &[u8]) -> &[u8] {
    if line.ends_with(b"\n") {
        line = &line[..line.len() - 1];
    }
    if line.ends_with(b"\r") {
        line = &line[..line.len() - 1];
    }
    line
}

fn extract_new_path_from_plus_header(line: &[u8]) -> Option<(Option<String>, bool)> {
    if let Some(path_part) = line.strip_prefix(b"+++ b/") {
        return Some(sanitize_path_bytes_with_status(path_part));
    }
    if line == b"+++ /dev/null" {
        return Some((None, false));
    }
    if let Some(path_part) = line.strip_prefix(b"+++ \"b/") {
        return Some(sanitize_quoted_git_path_with_status(path_part));
    }
    if line == b"+++ \"/dev/null\"" {
        return Some((None, false));
    }
    None
}

fn sanitize_path_bytes_with_status(path: &[u8]) -> (Option<String>, bool) {
    match sanitize_path_bytes(path) {
        Some(path) => (Some(path), false),
        None => (None, true),
    }
}

fn sanitize_path_bytes(path: &[u8]) -> Option<String> {
    sanitize_path_bytes_inner(path, true, true, false)
}

fn sanitize_quoted_git_path_with_status(path_after_open_quote: &[u8]) -> (Option<String>, bool) {
    match quoted_git_path_body(path_after_open_quote)
        .and_then(unescape_quoted_git_path_body)
        .and_then(|path| sanitize_path_bytes_inner(&path, false, true, true))
    {
        Some(path) => (Some(path), false),
        None => (None, true),
    }
}

fn quoted_git_path_body(path_after_open_quote: &[u8]) -> Option<&[u8]> {
    let mut escaped = false;
    for (index, byte) in path_after_open_quote.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b'"' {
            return Some(&path_after_open_quote[..index]);
        }
    }
    None
}

fn unescape_quoted_git_path_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        let byte = body[index];
        if byte != b'\\' {
            output.push(byte);
            index += 1;
            continue;
        }

        index += 1;
        let escaped = *body.get(index)?;
        if escaped.is_ascii_digit() && escaped < b'8' {
            let mut value = u16::from(escaped - b'0');
            index += 1;
            for _ in 0..2 {
                let Some(&next) = body.get(index) else {
                    break;
                };
                if !next.is_ascii_digit() || next >= b'8' {
                    break;
                }
                value = (value * 8) + u16::from(next - b'0');
                index += 1;
            }
            if value > u16::from(u8::MAX) {
                return None;
            }
            output.push(value as u8);
            continue;
        }

        output.push(match escaped {
            b'\\' => b'\\',
            b'"' => b'"',
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'b' => 0x08,
            b'a' => 0x07,
            b'f' => 0x0c,
            b'v' => 0x0b,
            other => other,
        });
        index += 1;
    }
    Some(output)
}

fn sanitize_path_bytes_inner(
    path: &[u8],
    trim_whitespace: bool,
    backslash_is_separator: bool,
    allow_control_bytes: bool,
) -> Option<String> {
    let path = if trim_whitespace {
        trim_ascii_whitespace(path)
    } else {
        path
    };
    if path.is_empty() || path == b"/dev/null" {
        return None;
    }
    if !allow_control_bytes && path.iter().any(|byte| byte.is_ascii_control()) {
        return None;
    }

    let path = String::from_utf8_lossy(path);
    let path = if backslash_is_separator {
        path.replace('\\', "/")
    } else {
        path.into_owned()
    };
    normalize_git_relative_path(&path)
}

fn normalize_git_relative_path(path: &str) -> Option<String> {
    if path.starts_with('/') {
        return None;
    }

    let mut normalized = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                normalized.pop()?;
            }
            part => normalized.push(part.to_string()),
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized.join("/"))
    }
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while matches!(bytes.first(), Some(byte) if byte.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    while matches!(bytes.last(), Some(byte) if byte.is_ascii_whitespace()) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{sanitize_path_bytes, trim_diff_line_bytes, UnifiedDiffEvent, UnifiedDiffParser};

    #[test]
    fn parser_emits_added_lines_only_inside_hunks() {
        let mut parser = UnifiedDiffParser::new();
        assert!(matches!(
            parser.parse_line(b"+outside", "git diff").unwrap(),
            UnifiedDiffEvent::Other
        ));
        assert!(matches!(
            parser.parse_line(b"@@ -0,0 +9,1 @@", "git diff").unwrap(),
            UnifiedDiffEvent::HunkStart { base_line: 8 }
        ));
        match parser.parse_line(b"+secret", "git diff").unwrap() {
            UnifiedDiffEvent::AddedLine(line) => assert_eq!(line, b"secret"),
            _ => panic!("expected added line"),
        }
        assert!(matches!(
            parser
                .parse_line(b"diff --git a/file.txt b/file.txt", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: None,
                invalid_path: false
            }
        ));
        assert!(matches!(
            parser.parse_line(b"+++ b/file.txt", "git diff").unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: Some(path),
                invalid_path: false
            } if path == "file.txt"
        ));
        assert!(matches!(
            parser
                .parse_line(b"+++ \"b/tab\\tfile.txt\"", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: Some(path),
                invalid_path: false
            } if path == "tab\tfile.txt"
        ));
        assert!(matches!(
            parser
                .parse_line(b"+++ \"b/dir\\040name/quote\\\"x.txt\"", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: Some(path),
                invalid_path: false
            } if path == "dir name/quote\"x.txt"
        ));
        assert!(matches!(
            parser
                .parse_line(b"+++ \"b/unic\\303\\266de.txt\"", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: Some(path),
                invalid_path: false
            } if path == "unic\u{f6}de.txt"
        ));
        assert!(matches!(
            parser
                .parse_line(b"+++ b/../secret.txt", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: None,
                invalid_path: true
            }
        ));
        assert!(matches!(
            parser
                .parse_line(b"+++ \"b/..\\\\..\\\\etc\\\\passwd\"", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: None,
                invalid_path: true
            }
        ));
        assert!(matches!(
            parser
                .parse_line(b"+after file header", "git diff")
                .unwrap(),
            UnifiedDiffEvent::Other
        ));
        assert!(matches!(
            parser
                .parse_line(
                    b"Binary files a/image.png and b/image.png differ",
                    "git diff"
                )
                .unwrap(),
            UnifiedDiffEvent::BinaryFile
        ));
    }

    #[test]
    fn parser_rejects_bad_hunk_headers() {
        let mut parser = UnifiedDiffParser::new();
        let error = parser
            .parse_line(b"@@ garbage @@", "git diff")
            .expect_err("bad hunk header must fail");
        assert!(
            error.to_string().contains("refusing to guess line 1"),
            "{error}"
        );

        let error = parser
            .parse_line(b"@@ -1,0 +1,1", "git diff")
            .expect_err("unterminated hunk header must fail");
        assert!(
            error
                .to_string()
                .contains("malformed unified-diff hunk header"),
            "{error}"
        );
    }

    #[test]
    fn parser_keeps_header_shaped_added_lines_inside_hunks() {
        let mut parser = UnifiedDiffParser::new();
        assert!(matches!(
            parser.parse_line(b"+++ b/file.txt", "git diff").unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: Some(path),
                invalid_path: false
            } if path == "file.txt"
        ));
        assert!(matches!(
            parser.parse_line(b"@@ -0,0 +1,1 @@", "git diff").unwrap(),
            UnifiedDiffEvent::HunkStart { base_line: 0 }
        ));
        match parser
            .parse_line(b"+++ b/not-a-header", "git diff")
            .unwrap()
        {
            UnifiedDiffEvent::AddedLine(line) => assert_eq!(line, b"++ b/not-a-header"),
            other => panic!("expected header-shaped added content, got {other:?}"),
        }
    }

    #[test]
    fn path_sanitizer_normalizes_without_allowing_escape() {
        assert_eq!(
            sanitize_path_bytes(b" ./a/../b.txt \r"),
            Some("b.txt".into())
        );
        assert_eq!(sanitize_path_bytes(b"../secret.txt"), None);
        assert_eq!(sanitize_path_bytes(b"/abs.txt"), None);
        assert_eq!(sanitize_path_bytes(b"a/\x01/b.txt"), None);
        assert_eq!(sanitize_path_bytes(b"/dev/null"), None);
    }

    #[test]
    fn diff_git_header_is_only_a_boundary() {
        let mut parser = UnifiedDiffParser::new();
        assert!(matches!(
            parser
                .parse_line(b"diff --git a/my b/file.txt b/my b/file.txt", "git diff")
                .unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: None,
                invalid_path: false
            }
        ));
    }

    #[test]
    fn line_trim_removes_one_lf_then_one_cr() {
        assert_eq!(trim_diff_line_bytes(b"+a\r\n"), b"+a");
        assert_eq!(trim_diff_line_bytes(b"+a\n"), b"+a");
        assert_eq!(trim_diff_line_bytes(b"+a\r"), b"+a");
    }
}
