#[test]
fn allowlist_glob_segment_backtracker_has_one_owner() {
    let glob = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/allowlist/glob.rs"
    ))
    .expect("allowlist glob source readable");

    assert!(
        glob.contains("fn segment_match_units<T>(")
            && glob.contains("segment_match_units(pattern.as_bytes(), text.as_bytes(), b'*')")
            && glob.contains("segment_match_units(&pattern_chars, &text_chars, '*')"),
        "allowlist glob matching must share one unit backtracker for ASCII and Unicode paths"
    );
    for forbidden in [
        "fn segment_match_ascii(",
        "fn segment_match_chars(",
        "while ti < text_chars.len()",
    ] {
        assert!(
            !glob.contains(forbidden),
            "allowlist glob matching must not restore duplicate backtracker `{forbidden}`"
        );
    }
}
