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
        "parse_hunk_new_start_or_error",
        "UnifiedDiffEvent::AddedLine(&line[1..])",
    ] {
        assert!(
            parser.contains(required),
            "shared git diff parser must own `{required}`"
        );
    }

    for (rel, source) in [("diff.rs", diff.as_str()), ("history.rs", history.as_str())] {
        assert!(
            source.contains("UnifiedDiffParser::new()")
                && source.contains("diff_parser.parse_line(")
                && source.contains("UnifiedDiffEvent::"),
            "{rel} must consume shared unified-diff parser events"
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
}
