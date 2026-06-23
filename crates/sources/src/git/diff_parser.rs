use keyhog_core::SourceError;

#[derive(Debug)]
pub(crate) enum UnifiedDiffEvent<'a> {
    FileHeader {
        new_path: Option<String>,
        invalid_path: bool,
    },
    DeletedFile,
    Metadata,
    HunkStart { base_line: usize },
    AddedLine(&'a [u8]),
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
            let (new_path, invalid_path) = extract_new_path_from_header(line);
            return Ok(UnifiedDiffEvent::FileHeader {
                new_path,
                invalid_path,
            });
        }

        if line.starts_with(b"deleted file mode") {
            self.in_hunk = false;
            return Ok(UnifiedDiffEvent::DeletedFile);
        }

        if line.starts_with(b"new file mode")
            || line.starts_with(b"index ")
            || line.starts_with(b"--- ")
        {
            return Ok(UnifiedDiffEvent::Metadata);
        }

        if let Some(path_part) = line.strip_prefix(b"+++ b/") {
            self.in_hunk = false;
            let (new_path, invalid_path) = sanitize_path_bytes_with_status(path_part);
            return Ok(UnifiedDiffEvent::FileHeader {
                new_path,
                invalid_path,
            });
        }

        if line.starts_with(b"@@") && memchr::memmem::find(&line[2..], b"@@").is_some() {
            let hunk_line = String::from_utf8_lossy(line);
            let new_start = super::parse_hunk_new_start_or_error(&hunk_line, source_type)?;
            self.in_hunk = true;
            return Ok(UnifiedDiffEvent::HunkStart {
                base_line: new_start.saturating_sub(1),
            });
        }

        if self.in_hunk && line.starts_with(b"+") && !line.starts_with(b"+++") {
            return Ok(UnifiedDiffEvent::AddedLine(&line[1..]));
        }

        Ok(UnifiedDiffEvent::Other)
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

fn extract_new_path_from_header(line: &[u8]) -> (Option<String>, bool) {
    match memchr::memmem::find(line, b" b/") {
        Some(index) => sanitize_path_bytes_with_status(&line[index + 3..]),
        None => (None, true),
    }
}

fn sanitize_path_bytes_with_status(path: &[u8]) -> (Option<String>, bool) {
    match sanitize_path_bytes(path) {
        Some(path) => (Some(path), false),
        None => (None, true),
    }
}

fn sanitize_path_bytes(path: &[u8]) -> Option<String> {
    let path = trim_ascii_whitespace(path);
    if path.is_empty() || path == b"/dev/null" {
        return None;
    }
    if path.iter().any(|byte| byte.is_ascii_control()) {
        return None;
    }

    let path = String::from_utf8_lossy(path).replace('\\', "/");
    let candidate = std::path::Path::new(&path);
    if candidate.is_absolute() {
        return None;
    }

    let mut normalized = Vec::new();
    for component in candidate.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => {
                normalized.push(part.to_string_lossy().into_owned());
            }
            std::path::Component::ParentDir => {
                normalized.pop()?;
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return None,
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
            parser.parse_line(b"+++ b/file.txt", "git diff").unwrap(),
            UnifiedDiffEvent::FileHeader {
                new_path: Some(path),
                invalid_path: false
            } if path == "file.txt"
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
                .parse_line(b"+after file header", "git diff")
                .unwrap(),
            UnifiedDiffEvent::Other
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
    fn line_trim_removes_one_lf_then_one_cr() {
        assert_eq!(trim_diff_line_bytes(b"+a\r\n"), b"+a");
        assert_eq!(trim_diff_line_bytes(b"+a\n"), b"+a");
        assert_eq!(trim_diff_line_bytes(b"+a\r"), b"+a");
    }
}
