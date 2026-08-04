//! The homoglyph-variant skip is keyed on "no confusable glyph is present",
//! proved by a one-pass lead-byte test, not on "the chunk is pure ASCII".
//!
//! The old proxy forced the full residual pattern set over every chunk with any
//! non-ASCII byte. On this repository's own sources that was 858 of 945
//! non-ASCII files paying for homoglyph batches that provably could not match,
//! and those chunks were where `phase2:prefilter` spent its time.
//!
//! The prescreen is only allowed to be a SOUND over-approximation: `false` must
//! prove absence. These tests pin that direction, because a false negative
//! silently drops every homoglyph-evasion finding in the chunk.

use crate::homoglyph::{expand_homoglyphs, homoglyph_confusables, may_contain_confusable};

/// Every glyph the expansion map can emit must be detected. This is the
/// soundness property: the prescreen is derived from the same map, so adding a
/// glyph without updating the lead-byte table would surface here.
#[test]
fn every_mapped_confusable_is_detected() {
    let mut checked = 0usize;
    for (ascii, glyphs) in homoglyph_confusables() {
        for glyph in glyphs {
            let text = format!("prefix {glyph} suffix");
            assert!(
                may_contain_confusable(&text),
                "confusable {glyph:?} (for ASCII {ascii:?}) must be detected"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 80,
        "expected the confusable map to carry at least 80 glyphs, saw {checked}"
    );
}

/// Pure ASCII can never contain a confusable, so the prescreen must always
/// clear it. This is the case the old proxy handled and the new one must not
/// regress.
#[test]
fn pure_ascii_never_looks_confusable() {
    for text in [
        "",
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"",
        "let x = 1; // plain comment\n\tprintln!(\"{x}\");",
        &(0u8..128).map(|b| b as char).collect::<String>(),
    ] {
        assert!(
            !may_contain_confusable(text),
            "pure ASCII must never be treated as possibly confusable: {text:?}"
        );
    }
}

/// The characters real source files actually carry: accented Latin, CJK, box
/// drawing, arrows, punctuation, and emoji. None is in the confusable map, so
/// each must clear the prescreen. These are the chunks the change exists to
/// stop charging for homoglyph batches.
#[test]
fn ordinary_non_ascii_source_text_clears_the_prescreen() {
    for text in [
        "// author: José Müller",
        "// 日本語のコメント",
        "// ┌─────┐ box drawing",
        "// step ▲ then ▼",
        "// done ✅ shipped 🚀",
        "// em dash — and curly “quotes”",
        "// naïve café résumé",
    ] {
        assert!(
            !may_contain_confusable(text),
            "ordinary non-ASCII source text must clear the prescreen: {text:?}"
        );
    }
}

/// A confusable hidden inside otherwise-ordinary non-ASCII text must still be
/// detected. This is the adversarial case: an attacker who pads a homoglyph
/// credential with emoji and CJK must not buy a skip.
#[test]
fn a_confusable_buried_in_ordinary_non_ascii_text_is_detected() {
    let cyrillic_a = '\u{0410}';
    let text = format!("// 日本語 ✅ 🚀 résumé\nAWS_ACCESS_KEY_ID = \"{cyrillic_a}KIAQYLPMN5HFIQR7XYA\"");
    assert!(
        may_contain_confusable(&text),
        "a Cyrillic capital A among ordinary non-ASCII text must be detected"
    );
}

/// Every glyph an expanded pattern can match is detectable, checked through the
/// expansion itself rather than the map. `expand_homoglyphs` is what builds the
/// variant regexes, so this ties the prescreen to the thing it gates.
#[test]
fn every_glyph_an_expanded_prefix_accepts_is_detected() {
    let expanded = expand_homoglyphs("AKIAghp_sk");
    let mut inside_class = false;
    let mut glyphs = 0usize;
    for ch in expanded.chars() {
        match ch {
            '[' => inside_class = true,
            ']' => inside_class = false,
            _ if inside_class && !ch.is_ascii() => {
                assert!(
                    may_contain_confusable(&ch.to_string()),
                    "expanded prefix accepts {ch:?}, which the prescreen must detect"
                );
                glyphs += 1;
            }
            _ => {}
        }
    }
    assert!(
        glyphs >= 10,
        "the expansion of a realistic prefix must contribute at least 10 confusables, saw {glyphs}"
    );
}

/// The prescreen reads bytes, so it must behave identically wherever the glyph
/// sits: a confusable at the very start, the very end, or spanning a UTF-8
/// boundary in the middle is the same answer.
#[test]
fn glyph_position_does_not_change_the_answer() {
    let glyph = '\u{03BF}'; // Greek small omicron, an 'o' confusable
    let filler = "x".repeat(4096);
    for text in [
        format!("{glyph}{filler}"),
        format!("{filler}{glyph}"),
        format!("{}{glyph}{}", &filler[..2048], &filler[2048..]),
    ] {
        assert!(
            may_contain_confusable(&text),
            "a confusable must be detected wherever it sits in the chunk"
        );
    }
}
