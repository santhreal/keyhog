//! Gate unicode hardening hot paths against double-pass normalization and full-input drop masks.

#[test]
fn unicode_hardening_normalizes_evasion_with_lazy_single_pass() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/unicode_hardening.rs");
    let src = std::fs::read_to_string(path).expect("unicode_hardening source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("fn normalize_evasive_chars"),
        "normalize_homoglyphs needs a lazy rebuild owner"
    );
    assert!(
        !prod.contains("if !contains_evasion(text)"),
        "normalize_homoglyphs must not pre-scan non-ASCII text before rebuilding"
    );
    assert!(
        !prod.contains(
            "let mut normalized = String::with_capacity(text.len());\n    for ch in text.chars()"
        ),
        "normalization must allocate only after the first replacing/dropped char"
    );
}

#[test]
fn unicode_hardening_strips_controls_with_drop_indices_not_full_mask() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/unicode_hardening.rs");
    let src = std::fs::read_to_string(path).expect("unicode_hardening source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("drop_indices"),
        "interior-control stripping should store only dropped byte positions"
    );
    assert!(
        !prod.contains("vec![false; bytes.len()]") && !prod.contains("drop_mask"),
        "interior-control stripping must not allocate a full input-sized bool mask"
    );
    assert!(
        prod.contains("out.extend_from_slice(&bytes[keep_start..drop_index])"),
        "interior-control stripping should rebuild from kept byte ranges"
    );
}
