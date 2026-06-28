//! `\uXXXX` surrogate PAIRS decode to their astral-plane scalar (mu-ue-02): a
//! credential hidden behind an emoji/astral JS-string escape was previously lost
//! because a lone high surrogate errored the whole decode. Lone/unpaired
//! surrogates still fail closed.
//!
//! The escape inputs are BUILT at runtime via `format!("\\u{:04X}", code)` so the
//! literal 6-char `\uXXXX` text reaches the decoder (writing the glyph directly
//! would hand it a pre-decoded char, defeating the test).

use keyhog_scanner::testing::unicode_escape_decode;

/// The literal text `\uHHHH\uLLLL` (two backslash-u escapes), not a decoded char.
fn surrogate_escape(high: u32, low: u32) -> String {
    format!("\\u{high:04X}\\u{low:04X}")
}

/// The literal text `\uHHHH` for a single (lone) code unit.
fn lone_escape(unit: u32) -> String {
    format!("\\u{unit:04X}")
}

#[test]
fn unicode_escape_decodes_surrogate_pairs_and_rejects_lone_surrogates() {
    // U+1F600 GRINNING FACE = surrogate pair D83D/DE00. Was Err before the fix.
    let grin = surrogate_escape(0xD83D, 0xDE00);
    let decoded = unicode_escape_decode(&format!("emoji{grin}here"))
        .expect("a valid surrogate pair must decode to its astral char");
    assert_eq!(decoded, "emoji\u{1F600}here");

    // U+10437 (astral, different high surrogate) = D801/DC37.
    let yee = surrogate_escape(0xD801, 0xDC37);
    let deseret =
        unicode_escape_decode(&format!("x{yee}y")).expect("surrogate pair for U+10437 must decode");
    assert_eq!(deseret, "x\u{10437}y");

    // A plain BMP escape (A = 'A') next to a surrogate pair resolves both.
    let mixed = unicode_escape_decode(&format!(r"A{grin}B"))
        .expect("BMP escape + surrogate pair must both decode");
    assert_eq!(mixed, "A\u{1F600}B");

    // Lone HIGH surrogate (no following \u low) -> Err (fail closed).
    assert!(
        unicode_escape_decode(&format!("bad{}tail", lone_escape(0xD83D))).is_err(),
        "a lone high surrogate must fail the decode"
    );
    // High surrogate followed by a \u that is NOT a low surrogate -> Err.
    assert!(
        unicode_escape_decode(&surrogate_escape(0xD83D, 0x0041)).is_err(),
        "a high surrogate followed by a non-low-surrogate escape must fail"
    );
    // Lone LOW surrogate first -> Err.
    assert!(
        unicode_escape_decode(&format!("bad{}tail", lone_escape(0xDE00))).is_err(),
        "a lone low surrogate must fail the decode"
    );
    // Truncated low surrogate (high ok, low has <4 hex) -> Err.
    assert!(
        unicode_escape_decode(r"\uD83D\uDE0").is_err(),
        "a truncated low surrogate must fail"
    );
}
