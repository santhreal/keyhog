#[test]
fn entropy_placeholder_and_ascii_uniqueness_stay_allocation_light() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let placeholder = std::fs::read_to_string(root.join("src/placeholder_words.rs"))
        .expect("placeholder_words source readable");
    let plausibility = std::fs::read_to_string(root.join("src/entropy/plausibility.rs"))
        .expect("entropy plausibility source readable");

    assert!(
        !placeholder.contains("String::from_utf8_lossy(bytes).to_uppercase()"),
        "entropy placeholder marker checks must not allocate an uppercase copy per candidate"
    );
    // The specific `your_` marker moved to a Tier-B loop
    // (`ci_find(bytes, word.lower_bytes())`), so assert the allocation-light
    // byte-search PRIMITIVE is used rather than pinning one needle that data-driven
    // vocabulary migrations legitimately relocate. The AKIA/EXAMPLE literals remain
    // in code and stay pinned.
    assert!(
        placeholder.contains("crate::ascii_ci::ci_find(bytes,")
            && placeholder.contains("starts_with_ignore_ascii_case(bytes, b\"AKIA\")")
            && placeholder.contains("ends_with_ignore_ascii_case(bytes, b\"EXAMPLE\")"),
        "entropy placeholder marker checks should use shared ASCII byte-search primitives"
    );
    // The ASCII fast path was deduplicated: it now delegates to the single-owner
    // distinct-byte primitive `entropy::unique_byte_count` (mod.rs) instead of
    // re-inlining the 256-slot presence table a fourth time. Assert the
    // allocation-light PRIMITIVE is used (not a per-candidate HashSet) and that
    // the primitive itself still owns the fixed-size stack bitmap — pinning the
    // owner, not a copy the dedup legitimately relocated (same principle as the
    // placeholder marker assertion above).
    let entropy_mod = std::fs::read_to_string(root.join("src/entropy/mod.rs"))
        .expect("entropy mod source readable");
    assert!(
        plausibility.contains("if value.is_ascii()")
            && plausibility.contains("super::unique_byte_count(value.as_bytes())"),
        "ASCII plausibility uniqueness must delegate to the allocation-light unique_byte_count primitive before the Unicode fallback"
    );
    assert!(
        entropy_mod.contains("fn unique_byte_count(")
            && entropy_mod.contains("let mut seen = [false; 256];"),
        "the canonical unique_byte_count primitive must own the fixed-size stack bitmap (no per-candidate allocation)"
    );
}
