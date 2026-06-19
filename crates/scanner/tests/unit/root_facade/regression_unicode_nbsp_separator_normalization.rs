//! Regression: no-break / NEL / narrow-no-break separators must be stripped on
//! the normalization path and reported by `detect_unicode_attacks`.
//!
//! Findings M8/M6: U+00A0 (NO-BREAK SPACE), U+202F (NARROW NO-BREAK SPACE), and
//! U+0085 (NEL) previously survived `normalize_homoglyphs`, letting an attacker
//! split a credential body so the precise regex validator rejected it (recall
//! hole), and `detect_unicode_attacks` returned an empty Vec for them.

use keyhog_scanner::testing::unicode_hardening::{
    detect_unicode_attacks, normalize_homoglyphs, EvasionKind,
};

/// A GitHub PAT body split by a NO-BREAK SPACE (U+00A0) must re-join after
/// normalization so the contiguous credential is recoverable for scanning.
#[test]
fn nbsp_split_credential_rejoins_after_normalization() {
    let text = "ghp_abcdefghijklmnopqrstuvwx\u{00A0}yzABCDEFGHIJ0123";
    let normalized = normalize_homoglyphs(text);

    assert_eq!(
        normalized.as_ref(),
        "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123",
        "NO-BREAK SPACE (U+00A0) must be stripped, rejoining the split PAT; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{00A0}'));
}

/// Narrow no-break space (U+202F) is likewise an invisible word splitter.
#[test]
fn narrow_nbsp_stripped_from_credential() {
    let text = "sk_live_abc\u{202F}def123456789";
    let normalized = normalize_homoglyphs(text);

    assert_eq!(
        normalized.as_ref(),
        "sk_live_abcdef123456789",
        "NARROW NO-BREAK SPACE (U+202F) must be stripped; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{202F}'));
}

/// NEL (U+0085) is a line separator that must not survive into a credential.
#[test]
fn nel_stripped_from_credential() {
    let text = "token=abc\u{0085}def0123456789";
    let normalized = normalize_homoglyphs(text);

    assert_eq!(
        normalized.as_ref(),
        "token=abcdef0123456789",
        "NEL (U+0085) must be stripped; got: {normalized:?}"
    );
    assert!(!normalized.contains('\u{0085}'));
}

/// `detect_unicode_attacks` must surface these separators (M6): the function
/// previously returned empty for them despite documenting separator detection.
#[test]
fn detect_reports_nbsp_separator_as_suspicious() {
    let text = "ghp_abc\u{00A0}def";
    let attacks = detect_unicode_attacks(text);

    assert!(
        attacks
            .iter()
            .any(|a| a.char == '\u{00A0}' && a.kind == EvasionKind::Suspicious),
        "U+00A0 must be reported as a Suspicious separator; attacks={attacks:?}"
    );
}
