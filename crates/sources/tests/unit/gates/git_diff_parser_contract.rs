#[test]
fn git_diff_sources_share_byte_oriented_parser() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let parser = std::fs::read_to_string(root.join("src/git/diff_parser.rs"))
        .expect("git diff parser readable");
    let diff = std::fs::read_to_string(root.join("src/git/diff.rs")).expect("git diff readable");
    let history =
        std::fs::read_to_string(root.join("src/git/history.rs")).expect("git history readable");

    for required in [
        "struct UnifiedDiffParser",
        "enum UnifiedDiffEvent",
        "fn parse_line<'a>(",
        "fn trim_diff_line_bytes(",
        "fn sanitize_path_bytes(",
        "fn extract_new_path_from_plus_header(",
        "fn sanitize_quoted_git_path_with_status(",
        "fn unescape_quoted_git_path_body(",
        "fn normalize_git_relative_path(",
        "quoted_git_path_body",
        "invalid_path: bool",
        "UnifiedDiffEvent::BinaryFile",
        "line.starts_with(b\"Binary files \")",
        "parse_hunk_new_start_bytes_or_error",
        "UnifiedDiffEvent::AddedLine(&line[1..])",
    ] {
        assert!(
            parser.contains(required),
            "shared git diff parser must own `{required}`"
        );
    }

    assert!(
        parser.contains("new_path: None")
            && parser.contains("invalid_path: false")
            && !parser.contains("memmem::find(line, b\" b/\")"),
        "`diff --git` headers are path-ambiguous; parser must use them only as file boundaries and take scan paths from +++ headers"
    );

    for (rel, source) in [("diff.rs", diff.as_str()), ("history.rs", history.as_str())] {
        assert!(
            source.contains("UnifiedDiffParser::new()")
                && source.contains("diff_parser.parse_line(")
                && source.contains("UnifiedDiffEvent::"),
            "{rel} must consume shared unified-diff parser events"
        );
        assert!(
            source.contains("\"--src-prefix=a/\"") && source.contains("\"--dst-prefix=b/\""),
            "{rel} must force git patch prefixes so global diff config cannot change parser assumptions"
        );
        for forbidden in [
            "line.starts_with(b\"diff --git \")",
            "line.starts_with(\"diff --git \")",
            "line.starts_with(b\"deleted file mode\")",
            "line.starts_with(\"deleted file mode\")",
            "line.strip_prefix(b\"+++ b/\")",
            "line.strip_prefix(\"+++ b/\")",
            "line.starts_with(b\"@@\")",
            "line.starts_with(\"@@\")",
            "parse_hunk_new_start_or_error(&line",
            "sanitize_path(",
            "extract_new_path(",
        ] {
            assert!(
                !source.contains(forbidden),
                "{rel} must not inline unified-diff parsing detail `{forbidden}`"
            );
        }
    }

    for (rel, source, message) in [
        (
            "diff.rs",
            diff.as_str(),
            "git diff file header path failed sanitization",
        ),
        (
            "history.rs",
            history.as_str(),
            "git history file header path failed sanitization",
        ),
    ] {
        assert!(
            source.contains("invalid_path")
                && source.contains(message)
                && source.contains("if current_path.is_none()")
                && source.contains("continue;")
                && source.contains("SourceSkipEvent::Unreadable")
                && source.contains("UnifiedDiffEvent::BinaryFile")
                && source.contains("SourceSkipEvent::Binary")
                && source.contains("pending_errors")
                && source.contains("pending_errors.push_back(SourceError::Other")
                && source.contains("pending_errors.pop_front()"),
            "{rel} must emit SourceError rows for invalid unified-diff file headers and count binary patch skips instead of silently dropping added lines"
        );
    }

    let git_mod =
        std::fs::read_to_string(root.join("src/git/mod.rs")).expect("git module readable");
    assert!(
        git_mod.contains("fn parse_hunk_new_start_bytes(header: &[u8])")
            && git_mod.contains("memchr::memchr(b'+', header)")
            && git_mod.contains("let digits_end = after_plus"),
        "git hunk header parsing must locate borrowed digit slices in git/mod.rs without UTF-8 conversion"
    );
    assert!(
        !git_mod.contains("let digits: String")
            && !git_mod.contains(".take_while(|c| c.is_ascii_digit()).collect()"),
        "git hunk header parsing must parse borrowed digit slices without allocating"
    );
    assert!(
        !parser.contains("String::from_utf8_lossy(line)")
            && !parser.contains("parse_hunk_new_start_or_error(&hunk_line"),
        "shared git diff parser must not allocate or UTF-8-convert hunk headers on the hot path"
    );
}
