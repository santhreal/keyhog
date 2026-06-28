//! Regression: `expand_homoglyphs` reserves its output `String` capacity up
//! front (Law 7 — no realloc growth while expanding every detector prefix) and
//! the reserve changes no output (Law 6). Also pins the documented example to
//! the real map output (the doc was stale: it showed fewer glyphs than the map
//! actually emits).
//!
//! The expansion turns each mapped ASCII char into a `[<ascii><glyphs>]` regex
//! class and escapes regex-special chars. Capacity is unobservable through the
//! returned String, so asserting the exact expanded bytes proves the reserve is
//! byte-identical.

#[test]
fn expand_homoglyphs_produces_exact_class_expansion() {
    use keyhog_scanner::testing::expand_homoglyphs_str as expand;

    // ghp_: g/h/p are mapped; `_` is a literal non-special char passed through.
    // This is the real map output (the stale doc example showed only one glyph
    // per class).
    assert_eq!(
        expand("ghp_"),
        "[gɡｇ][hнһｈ][pрρｐ]_",
        "each mapped char becomes its full [ascii+glyphs] class, literals pass through"
    );

    // A mapped char followed by a regex-special char that must be escaped.
    assert_eq!(
        expand("a."),
        "[aаαａ]\\.",
        "mapped 'a' expands; '.' is escaped as a literal"
    );

    // An unmapped, non-special char passes through verbatim.
    assert_eq!(expand("z"), "z", "an unmapped char is emitted as-is");

    // A bare regex-special char with no mapping is escaped.
    assert_eq!(
        expand("."),
        "\\.",
        "a special char with no mapping is escaped"
    );

    // Empty input yields empty output.
    assert_eq!(expand(""), "", "empty pattern expands to empty");
}

#[test]
fn expand_homoglyphs_reserves_output_capacity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src =
        std::fs::read_to_string(root.join("src/homoglyph.rs")).expect("homoglyph source readable");
    assert!(
        src.contains("String::with_capacity(pattern.len() * 8)"),
        "expand_homoglyphs must pre-reserve its output capacity (no realloc growth)"
    );
    assert!(
        !src.contains("let mut expanded = String::new();"),
        "expand_homoglyphs must not start from a zero-capacity String"
    );
}
