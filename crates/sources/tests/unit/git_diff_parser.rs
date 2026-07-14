use super::{
    sanitize_path_bytes, trim_diff_line_bytes, unescape_quoted_git_path_body, UnifiedDiffEvent,
    UnifiedDiffParser,
};
use proptest::prelude::*;

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// `git diff` output is UNTRUSTED, a malicious repository controls it. The
    /// stateful line parser must NEVER panic on any byte sequence across any
    /// parser state (the `@@` hunk-header math, the `+++`/quoted-path branch,
    /// the octal unescape) (it may only return `Ok(event)` or `Err`).
    #[test]
    fn parse_line_is_total_on_arbitrary_diff_bytes(
        lines in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..48usize), 0..8usize),
    ) {
        let mut parser = UnifiedDiffParser::new();
        for line in &lines {
            // Panicking here (index-OOB, subtract-overflow, non-char-boundary
            // slice) is the failure; both Ok and Err are acceptable outcomes.
            drop(parser.parse_line(line, "git diff"));
        }
    }

    /// SECURITY INVARIANT: the path sanitizer feeds a write/scan path derived
    /// from an attacker-controlled `+++ b/…` header. Any `Some(path)` it emits
    /// MUST stay inside the repo, never absolute, never carrying a surviving
    /// `..` traversal component, never empty. (A crafted `+++ b/../../etc/passwd`
    /// or `+++ b//abs` must sanitize to `None`, not to an escaping path.)
    #[test]
    fn sanitize_path_bytes_never_yields_an_escaping_path(
        raw in prop::collection::vec(any::<u8>(), 0..64usize),
    ) {
        if let Some(path) = sanitize_path_bytes(&raw) {
            prop_assert!(!path.is_empty(), "sanitized path is empty for {raw:?}");
            prop_assert!(
                !path.starts_with('/'),
                "sanitized path is absolute: {path:?} from {raw:?}"
            );
            prop_assert!(
                !path.split('/').any(|component| component == ".."),
                "sanitized path retains a `..` traversal component: {path:?} from {raw:?}"
            );
        }
    }

    /// The quoted-git-path octal/backslash unescaper does index arithmetic
    /// (`body.get(index)?`, 3-digit octal accumulation) over attacker bytes, it
    /// must be total (no panic) on any input.
    #[test]
    fn unescape_quoted_git_path_body_is_total(
        body in prop::collection::vec(any::<u8>(), 0..48usize),
    ) {
        drop(unescape_quoted_git_path_body(&body));
    }
}
