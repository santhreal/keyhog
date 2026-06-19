use keyhog_scanner::testing::unicode_hardening::*;

/// Proving test: Cyrillic + zero-width characters together normalize correctly.
/// Contract: "ghp_\u{0430}bc\u{200B}def" normalizes to "ghp_abcdef".
#[test]
fn normalize_mixed_cyrillic_and_zero_width() {
    // Cyrillic 'а' (U+0430) + Zero-Width Space (U+200B)
    let text = "ghp_\u{0430}bc\u{200B}def";
    let normalized = normalize_homoglyphs(text);

    // Both evasion techniques must be handled
    assert_eq!(
        normalized.as_ref(),
        "ghp_abcdef",
        "Cyrillic homoglyph + zero-width must both normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: Fullwidth + Cyrillic homoglyph mixed.
/// Contract: "ｇｈｐ_sk\u{0430}bc" normalizes to "ghp_skabc" (fullwidth ｇｈｐ →
/// "ghp", literal "_sk", Cyrillic а → "a", literal "bc").
#[test]
fn normalize_mixed_fullwidth_and_cyrillic() {
    // Fullwidth letters (U+FF01-U+FF5E range): ｇ ｈ ｐ
    // Plus Cyrillic 'а' (U+0430)
    let fullwidth_g = '\u{FF47}'; // Fullwidth 'g'
    let fullwidth_h = '\u{FF48}'; // Fullwidth 'h'
    let fullwidth_p = '\u{FF50}'; // Fullwidth 'p'
    let text = format!(
        "{}{}{}_{}\u{0430}bc",
        fullwidth_g, fullwidth_h, fullwidth_p, "sk"
    );

    let normalized = normalize_homoglyphs(&text);

    // Fullwidth must convert + Cyrillic must convert
    assert!(
        normalized.contains("ghp_skabc"),
        "Fullwidth + Cyrillic mixed must normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: Greek + RTL override + zero-width in single string.
/// Contract: "sk_\u{202E}\u{03B1}bc\u{200B}d" normalizes to "sk_abcd".
#[test]
fn normalize_mixed_greek_rtl_zero_width() {
    // RTL Override (U+202E) + Greek alpha (U+03B1) + Zero-Width Space (U+200B)
    let text = "sk_\u{202E}\u{03B1}bc\u{200B}d";
    let normalized = normalize_homoglyphs(text);

    // All three evasion types must be handled
    assert_eq!(
        normalized.as_ref(),
        "sk_abcd",
        "Greek + RTL + zero-width mixed must all normalize; got: {normalized:?}"
    );
}

/// Proving test: Combining marks + Cyrillic homoglyphs together.
/// Contract: "a\u{0301}\u{0430}b" normalizes to "aab".
#[test]
fn normalize_mixed_combining_marks_and_cyrillic() {
    // Combining acute accent (U+0301) + Cyrillic 'а' (U+0430)
    let text = "token=a\u{0301}\u{0430}b";
    let normalized = normalize_homoglyphs(text);

    // Both must be handled: mark removed, homoglyph converted
    assert_eq!(
        normalized.as_ref(),
        "token=aab",
        "Combining mark + Cyrillic must both normalize; got: {normalized:?}"
    );
}

/// Proving test: Multiple Cyrillic homoglyphs + multiple zero-width chars.
/// Contract: "ghp_\u{0430}bc\u{200B}\u{200C}def" normalizes correctly.
#[test]
fn normalize_multiple_cyrillic_multiple_zero_width() {
    // Multiple instances of each evasion type
    let text = "ghp_\u{0430}bc\u{200B}\u{200C}def\u{043E}ghi";
    let normalized = normalize_homoglyphs(text);

    // Must handle all instances: 'а' + 'о' converted, both zero-widths removed
    assert!(
        normalized.contains("ghp_abcdefoghi"),
        "Multiple evasions must all normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: Fullwidth Greek letters.
/// Contract: Fullwidth Greek α (if such exists) normalizes appropriately.
#[test]
fn normalize_fullwidth_in_presence_of_homoglyphs() {
    // Fullwidth ASCII + Cyrillic homoglyph together
    let fullwidth_s = '\u{FF33}'; // Fullwidth 'S'
    let text = format!("{}k_\u{0430}live", fullwidth_s); // Fullwidth S + Cyrillic a
    let normalized = normalize_homoglyphs(&text);

    // Both fullwidth and homoglyph must be handled
    assert!(
        normalized.contains("Sk_alive"),
        "Fullwidth + homoglyph must normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: RTL override + combining marks together.
/// Contract: "a\u{0301}\u{202E}b" normalizes to "ab".
#[test]
fn normalize_mixed_rtl_and_combining() {
    // Combining mark (U+0301) + RTL Override (U+202E)
    let text = "token=a\u{0301}\u{202E}b";
    let normalized = normalize_homoglyphs(text);

    // Both must be stripped
    assert_eq!(
        normalized.as_ref(),
        "token=ab",
        "RTL + combining mark must both normalize; got: {normalized:?}"
    );
}

/// Proving test: Adversarial sequence with many consecutive evasion chars.
/// Contract: Longest evasion subsequence still normalizes correctly.
#[test]
fn normalize_adversarial_dense_evasion_sequence() {
    // Dense evasion sequence at one point
    let text = "ghp_\u{200B}\u{200C}\u{200D}\u{202E}\u{0430}abc";
    let normalized = normalize_homoglyphs(text);

    // All evasion in dense sequence must be handled: the three zero-width
    // joiners and the RTL override are stripped, and Cyrillic а (U+0430)
    // folds to Latin 'a'. That folded 'a' is a SEPARATE character that
    // precedes the literal "abc", so the result is "ghp_aabc" (double 'a'),
    // not "ghp_abc".
    assert!(
        normalized.contains("ghp_aabc"),
        "Dense evasion sequence must normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}

/// Proving test: Evasion interspersed throughout credential.
/// Contract: Multiple evasion types spread through string all normalize.
#[test]
fn normalize_evasion_interspersed_throughout() {
    // Evasion types distributed: homoglyph here, zero-width there, etc.
    let text = "g\u{0430}p_\u{200B}a\u{0301}bc\u{202E}def";
    let normalized = normalize_homoglyphs(text);

    // All instances across the string must be handled
    assert!(
        normalized.contains("gap_abcdef"),
        "Interspersed evasion must normalize; got: {normalized:?}"
    );
    assert!(normalized.is_ascii());
}
