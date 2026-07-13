//! Regression: `contains_evasion` delegates its per-character evasion test to
//! `normalized_char` (the single owner of that classification) instead of
//! re-listing the eight homoglyph/zero-width/control predicates inline, and the
//! delegation changes no output (Law 6 + DEDUP / drift-hazard removal).
//!
//! `contains_evasion` used to inline `cyrillic_to_latin(ch).is_some() || … ||
//! is_ascii_evasion_control(ch)`, the same disjunction `normalized_char`
//! already computes (Replace for the homoglyphs, Drop for the rest, Keep
//! otherwise). Two copies of "which chars are evasive" can drift: add a new
//! category to `normalized_char` and the detector silently misses it. The
//! detector now flags a char exactly when `normalized_char(ch) != Keep`.
//!
//! This pins the real classification across every category (each still detected,
//! clean ASCII still rejected) AND that the inline duplicate is gone.

#[test]
fn contains_evasion_matches_normalized_char_classification() {
    use keyhog_scanner::testing::unicode_hardening::contains_evasion;

    // Clean ASCII source is never flagged; newline/tab/CR are structural.
    assert!(
        !contains_evasion("let api_key = \"value\";"),
        "clean ascii is not evasion"
    );
    assert!(!contains_evasion(""), "empty text is not evasion");
    assert!(
        !contains_evasion("line one\n\tindented\r\n"),
        "newline/tab/CR are structural, not evasion"
    );

    // Every category `normalized_char` recognizes is still detected.
    assert!(
        contains_evasion("g\u{0430}p_token"),
        "cyrillic homoglyph U+0430 is evasion (Replace arm)"
    );
    assert!(
        contains_evasion("\u{03B1}lpha"),
        "greek homoglyph U+03B1 is evasion (Replace arm)"
    );
    assert!(
        contains_evasion("\u{FF41}bc"),
        "fullwidth U+FF41 is evasion (Replace arm)"
    );
    assert!(
        contains_evasion("se\u{200B}cret"),
        "zero-width U+200B is evasion (Drop arm)"
    );
    assert!(
        contains_evasion("ab\u{202E}cd"),
        "RTL override U+202E is evasion (Drop arm)"
    );
    assert!(
        contains_evasion("a\u{00A0}b"),
        "no-break space U+00A0 is separator evasion (Drop arm)"
    );
    assert!(
        contains_evasion("e\u{0301}"),
        "combining mark U+0301 is decomposed evasion (Drop arm)"
    );

    // DEL (0x7F) is >= 0x20 so the byte fast-path misses it; it must be caught
    // through `normalized_char`'s Drop arm (is_ascii_evasion_control), the exact
    // path this dedup routes through.
    assert!(
        contains_evasion("ab\u{007F}cd"),
        "DEL control is evasion via the char/normalized_char path"
    );
    // A sub-0x20 control is caught by the byte fast-path before the char loop.
    assert!(
        contains_evasion("ab\u{0001}cd"),
        "SOH control is evasion via the byte fast-path"
    );
}

#[test]
fn contains_evasion_delegates_to_normalized_char_single_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src =
        std::fs::read_to_string(root.join("src/unicode_hardening.rs")).expect("source readable");
    let start = src
        .find("pub(crate) fn contains_evasion(")
        .expect("contains_evasion present");
    let after = &src[start..];
    let body_end = after
        .find("\nfn contains_ascii_evasion")
        .expect("next fn marks the end of contains_evasion's body");
    let body = &after[..body_end];

    assert!(
        body.contains("matches!(normalized_char(ch), NormalizedChar::Keep)"),
        "contains_evasion must delegate to normalized_char (single-owner classification)"
    );
    // The duplicated per-char predicate list must no longer be inlined here.
    assert!(
        !body.contains("is_unicode_separator_evasion(ch)"),
        "the duplicated 8-predicate disjunction must be gone from contains_evasion"
    );
    assert!(
        !body.contains("cyrillic_to_latin(ch).is_some()"),
        "the duplicated 8-predicate disjunction must be gone from contains_evasion"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector enumerates one instance per evasion category; these SWEEP the
// two directional guarantees the detector exists for. `contains_evasion` gates
// the unicode-hardening scan path, a false negative lets an evasion-obfuscated
// secret through (recall), a false positive flags clean source (precision). No
// proptest covered it before.

use keyhog_scanner::testing::unicode_hardening::contains_evasion;
use proptest::prelude::*;

/// One always-evasion char per non-`Keep` `normalized_char` arm the fixed test
/// enumerates: Cyrillic + fullwidth homoglyphs (Replace) and zero-width / RTL /
/// no-break-space / combining (Drop). Each must be flagged in ANY clean context.
const EVASION_CHARS: &[char] = &[
    '\u{200B}', // zero-width space (Drop)
    '\u{0430}', // Cyrillic a homoglyph (Replace)
    '\u{202E}', // RTL override (Drop)
    '\u{00A0}', // no-break space (Drop)
    '\u{FF41}', // fullwidth a (Replace)
    '\u{0301}', // combining acute (Drop)
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// PRECISION: clean printable ASCII (0x20..=0x7e, no control byte, no
    /// homoglyph) is NEVER flagged as evasion, so ordinary source lines are never
    /// falsely rejected by the hardening gate.
    #[test]
    fn clean_printable_ascii_is_never_evasion(s in "[\\x20-\\x7e]{0,60}") {
        prop_assert!(!contains_evasion(&s));
    }

    /// RECALL: a single evasion char is detected regardless of surrounding clean
    /// text, no clean prefix or suffix can mask it. One char per non-Keep
    /// category, wrapped in arbitrary clean-ASCII context.
    #[test]
    fn an_evasion_char_is_detected_in_any_clean_context(
        prefix in "[\\x20-\\x7e]{0,30}",
        suffix in "[\\x20-\\x7e]{0,30}",
        idx in 0usize..EVASION_CHARS.len(),
    ) {
        let evasive = EVASION_CHARS[idx];
        let text = format!("{prefix}{evasive}{suffix}");
        prop_assert!(
            contains_evasion(&text),
            "evasion char U+{:04X} masked by clean context",
            evasive as u32
        );
    }

    /// The detector must never panic on arbitrary Unicode input.
    #[test]
    fn contains_evasion_never_panics(s in "(?s).{0,60}") {
        let _ = contains_evasion(&s);
    }
}
