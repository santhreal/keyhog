//! Completeness contract: the evasion strip must drop every invisible Unicode
//! space separator (`Zs`/`Zl`/`Zp`, except the normal ASCII space) and every
//! `Bidi_Control` character, since each can split a credential body on the main
//! scan path.
//!
//! Two codepoints were previously uncovered and are pinned here:
//!   - U+1680 OGHAM SPACE MARK (`Zs`) (a space separator).
//!   - U+061C ARABIC LETTER MARK (`Bidi_Control`, `Cf`), an invisible
//!     directional mark like LRM/RLM.
//! The enumerated sets below are the authoritative `Zs`/`Zl`/`Zp` and
//! `Bidi_Control` members (confirmed against `unicodedata`); the contract tests
//! assert the whole set normalizes away so a future edit cannot reopen a hole.

use keyhog_scanner::testing::unicode_hardening::{
    contains_evasion, detect_unicode_attacks, normalize_homoglyphs, EvasionKind,
};
use std::borrow::Cow;

/// Every invisible space separator the strip must drop, the full `Zs` set
/// MINUS the normal ASCII space U+0020 (which is structural, not evasion), plus
/// the line/paragraph separators `Zl`/`Zp`.
const SEPARATORS: &[char] = &[
    '\u{0085}', // NEL
    '\u{00A0}', // NO-BREAK SPACE
    '\u{1680}', // OGHAM SPACE MARK  (newly covered)
    '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}',
    '\u{2008}', '\u{2009}', '\u{200A}', // en/em/thin/hair spaces
    '\u{2028}', // LINE SEPARATOR (Zl)
    '\u{2029}', // PARAGRAPH SEPARATOR (Zp)
    '\u{202F}', // NARROW NO-BREAK SPACE
    '\u{205F}', // MEDIUM MATHEMATICAL SPACE
    '\u{3000}', // IDEOGRAPHIC SPACE
];

/// Every `Bidi_Control` character the strip must drop.
const BIDI_CONTROLS: &[char] = &[
    '\u{061C}', // ARABIC LETTER MARK (newly covered)
    '\u{200E}', '\u{200F}', // LRM, RLM
    '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // embeddings + overrides
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // isolates
];

/// Splice `c` into a `ghp_` token; assert it is dropped so the token reassembles.
fn assert_dropped(c: char, label: &str) {
    let text = format!("ghp_ab{c}cd");
    let normalized = normalize_homoglyphs(&text);
    assert!(
        normalized.contains("ghp_abcd") && !normalized.contains(c),
        "{label} (U+{:04X}) must be dropped so the token reassembles; got {normalized:?}",
        c as u32
    );
}

// ── the two newly-covered codepoints ────────────────────────────────────────

#[test]
fn ogham_space_1680_dropped() {
    assert_dropped('\u{1680}', "Ogham space mark");
}

#[test]
fn ogham_space_splice_reassembles_aws_key() {
    let normalized = normalize_homoglyphs("AKIA\u{1680}QYLPMN5HFIQR7BBB");
    assert!(
        normalized.contains("AKIAQYLPMN5HFIQR7BBB"),
        "Ogham space after AKIA must be dropped; got {normalized:?}"
    );
}

#[test]
fn ogham_space_classified_suspicious() {
    let attacks = detect_unicode_attacks("ghp_a\u{1680}b");
    assert!(
        attacks
            .iter()
            .any(|a| a.kind == EvasionKind::Suspicious && a.char == '\u{1680}'),
        "Ogham space must be reported as a separator (Suspicious) evasion; got {attacks:?}"
    );
}

#[test]
fn ogham_space_triggers_contains_evasion() {
    assert!(contains_evasion("ghp_a\u{1680}b"));
}

#[test]
fn arabic_letter_mark_061c_dropped() {
    assert_dropped('\u{061C}', "Arabic letter mark");
}

#[test]
fn arabic_letter_mark_splice_reassembles_ghp() {
    let normalized = normalize_homoglyphs("g\u{061C}hp_deadbeefcafe");
    assert!(normalized.starts_with("ghp_"), "got {normalized:?}");
}

#[test]
fn arabic_letter_mark_classified_zero_width() {
    let attacks = detect_unicode_attacks("ghp_a\u{061C}b");
    assert!(
        attacks
            .iter()
            .any(|a| a.kind == EvasionKind::ZeroWidth && a.char == '\u{061C}'),
        "Arabic letter mark must be reported as ZeroWidth evasion; got {attacks:?}"
    );
}

#[test]
fn arabic_letter_mark_triggers_contains_evasion() {
    assert!(contains_evasion("ghp_a\u{061C}b"));
}

#[test]
fn both_new_codepoints_in_one_token_reassemble() {
    let normalized = normalize_homoglyphs("g\u{1680}h\u{061C}p_secret");
    assert_eq!(normalized.as_ref(), "ghp_secret", "got {normalized:?}");
}

// ── completeness contracts (lock the whole set) ─────────────────────────────

#[test]
fn every_space_separator_is_dropped() {
    for &c in SEPARATORS {
        assert_dropped(c, "space separator");
    }
}

#[test]
fn every_space_separator_triggers_contains_evasion() {
    for &c in SEPARATORS {
        let s = format!("ghp_a{c}b");
        assert!(
            contains_evasion(&s),
            "U+{:04X} must trigger contains_evasion",
            c as u32
        );
    }
}

#[test]
fn every_bidi_control_is_dropped() {
    for &c in BIDI_CONTROLS {
        assert_dropped(c, "bidi control");
    }
}

#[test]
fn every_bidi_control_triggers_contains_evasion() {
    for &c in BIDI_CONTROLS {
        let s = format!("ghp_a{c}b");
        assert!(
            contains_evasion(&s),
            "U+{:04X} must trigger contains_evasion",
            c as u32
        );
    }
}

#[test]
fn separators_and_bidi_controls_are_disjoint() {
    // The two sets must not overlap, or a codepoint's classification is ambiguous.
    for &c in SEPARATORS {
        assert!(
            !BIDI_CONTROLS.contains(&c),
            "U+{:04X} is in both sets",
            c as u32
        );
    }
}

// ── existing-coverage regressions ───────────────────────────────────────────

#[test]
fn nel_0085_still_dropped() {
    assert_dropped('\u{0085}', "NEL");
}

#[test]
fn nbsp_00a0_still_dropped() {
    assert_dropped('\u{00A0}', "NBSP");
}

#[test]
fn rlo_202e_still_dropped() {
    assert_dropped('\u{202E}', "RTL override");
}

#[test]
fn lrm_200e_still_dropped() {
    assert_dropped('\u{200E}', "LRM");
}

#[test]
fn ideographic_space_3000_still_dropped() {
    assert_dropped('\u{3000}', "ideographic space");
}

// ── safety: a NORMAL ASCII space must NOT be dropped (it is structural) ──────

#[test]
fn normal_ascii_space_is_preserved() {
    // U+0020 is `Zs` too but is a legitimate separator; dropping it would mangle
    // ordinary text. It must NOT be treated as evasion.
    let normalized = normalize_homoglyphs("key = value here");
    assert!(
        normalized.contains(' '),
        "normal ASCII space must be preserved; got {normalized:?}"
    );
    assert!(
        !contains_evasion("key = value here"),
        "a normal space is not evasion"
    );
}

#[test]
fn pure_ascii_stays_borrowed_and_identical() {
    let normalized = normalize_homoglyphs("ghp_abcdef0123456789");
    assert!(
        matches!(normalized, Cow::Borrowed(_)),
        "pure-ASCII must not allocate"
    );
    assert_eq!(normalized.as_ref(), "ghp_abcdef0123456789");
}
