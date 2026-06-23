#[test]
fn entropy_keyword_compaction_does_not_materialize_strings() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let entropy_keywords = std::fs::read_to_string(root.join("src/entropy/keywords.rs"))
        .expect("entropy keywords source readable");
    let generic_keywords =
        std::fs::read_to_string(root.join("src/engine/phase2_generic/keywords.rs"))
            .expect("generic keyword source readable");

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
    assert!(
        generic_keywords.contains("compact_keyword_eq(keyword, exact")
            && generic_keywords.contains("compact_keyword_eq(&normalized, anchor"),
        "generic strong-anchor classification should match compacted byte views directly"
    );
}
