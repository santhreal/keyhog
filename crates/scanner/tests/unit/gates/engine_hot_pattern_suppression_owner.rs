//! Gate: hot-pattern suppression policy has one suppression owner.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

fn uncommented_code(src: &str) -> String {
    src.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                None
            } else {
                Some(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn hot_pattern_suppression_routes_through_suppression_owner() {
    let src = scanner_src();
    let suppression = uncommented_code(&read(&src.join("suppression/api.rs")));
    assert!(
        suppression.contains("struct HotPatternSuppressionCtx")
            && suppression.contains("fn suppress_hot_pattern_candidate(")
            && suppression.contains("suppress_known_example_credential")
            && suppression.contains("looks_like_regex_literal_tail")
            && suppression.contains("looks_like_vendored_minified_path")
            && suppression.contains("looks_like_secret_scanner_source")
            && suppression.contains("looks_like_hot_pattern_base64_path"),
        "suppression::api must own the hot-pattern suppression gates"
    );

    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("crate::suppression::suppress_hot_pattern_candidate("),
        "hot-pattern fast path must call the suppression owner"
    );
    for forbidden in [
        "suppress_known_example_credential",
        "looks_like_regex_literal_tail",
        "looks_like_vendored_minified_path",
        "looks_like_secret_scanner_source",
        "binary-strings",
        "archive-binary",
        "base64_string",
    ] {
        assert!(
            !hot_patterns.contains(forbidden),
            "hot-pattern fast path must not own suppression policy token {forbidden:?}"
        );
    }
}
