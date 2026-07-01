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
    assert!(
        plausibility.contains("if value.is_ascii()")
            && plausibility.contains("let mut seen = [false; 256];")
            && plausibility.contains("return count;"),
        "ASCII plausibility uniqueness must use the fixed-size stack bitmap before the Unicode fallback"
    );
}
