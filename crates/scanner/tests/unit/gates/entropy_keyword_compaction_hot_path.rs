use super::support::{read, scanner_src, source_without_whitespace};

#[test]
fn entropy_keyword_compaction_does_not_materialize_strings() {
    // Raw source (NOT comment-stripped): the assertions below match a multiline
    // `\n`-bearing needle, so the shared `read` primitive is used but not
    // `uncommented_code`.
    let src = scanner_src();
    let entropy_keywords = read(&src.join("entropy/keywords.rs"));
    let generic_keywords = read(&src.join("engine/phase2_generic/keywords.rs"));

    assert!(
        !entropy_keywords.contains("let compact: String = normalized")
            && !entropy_keywords
                .contains(".map(|b| b.to_ascii_lowercase() as char)\n        .collect()"),
        "entropy assignment-key classification must not allocate a compact String per key"
    );
    assert!(
        entropy_keywords.contains("let mut compact = [0u8; 128];")
            && entropy_keywords.contains("compact_assignment_keyword_bytes_are_credential"),
        "entropy assignment-key classification should use stack byte compaction with no-allocation fallback"
    );
    assert!(
        !generic_keywords.contains("let canon: String = keyword")
            && !generic_keywords.contains("let compact: String = normalized"),
        "generic strong-anchor classification must not allocate compact String keys"
    );
    // Whitespace-insensitive: `cargo fmt` may wrap either call across lines
    // (`compact_keyword_eq(\n    &normalized,\n    anchor.as_bytes(),\n)`), so
    // collapse all whitespace before matching. This still fails loudly if the
    // call or its argument order changes — it only tolerates reformatting.
    let generic_ws = source_without_whitespace(&generic_keywords);
    assert!(
        generic_ws.contains("compact_keyword_eq(keyword,exact")
            && generic_ws.contains("compact_keyword_eq(&normalized,anchor"),
        "generic strong-anchor classification should match compacted byte views directly"
    );
}
