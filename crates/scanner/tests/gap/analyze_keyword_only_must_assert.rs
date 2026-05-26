//! Bar gate: `analyze_keyword_only.rs` must not be a decorative
//! println-only test — real assertions or delete the file.

use std::path::PathBuf;

fn count_assertion_macros(src: &str) -> usize {
    const MACROS: &[&str] = &[
        "assert!(",
        "assert_eq!(",
        "assert_ne!(",
        "assert_matches!(",
        "debug_assert!(",
        "debug_assert_eq!(",
        "debug_assert_ne!(",
    ];
    MACROS.iter().map(|m| src.matches(m).count()).sum()
}

#[test]
fn analyze_keyword_only_must_assert() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("analyze_keyword_only.rs");
    if !path.exists() {
        return;
    }

    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let assertion_count = count_assertion_macros(&src);

    assert!(
        assertion_count > 0,
        "analyze_keyword_only.rs exists with zero assertion macros — \
         add real gates or delete the decorative test"
    );
}
