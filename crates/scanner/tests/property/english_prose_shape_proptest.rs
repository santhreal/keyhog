//! English-prose FP-suppression contract
//! (`crates/scanner/src/suppression/shape/prose.rs`).
//!
//! A captured value that reads like English text (a log line, a sentence, a
//! comment) is not a credential. This heuristic suppresses it when the keyword
//! anchor is weak. It accepts two shapes: a single all-lowercase run of >= 16
//! bytes, OR >= 2 all-alphabetic whitespace-separated words with at least one
//! lowercase word. A value with ANY digit or symbol can be neither, so it is
//! never prose, the property this suite pins hardest, since a real secret almost
//! always carries a digit/symbol and must not be swallowed as "prose".

use keyhog_scanner::testing::looks_like_english_prose_for_test;
use proptest::prelude::*;

// ── example truth table ──────────────────────────────────────────────────────

#[test]
fn prose_shapes_are_recognized() {
    assert!(looks_like_english_prose_for_test("abcdefghijklmnop")); // all-lowercase >= 16
    assert!(looks_like_english_prose_for_test(
        "Session opened with handle"
    )); // words + lowercase word
}

#[test]
fn non_prose_is_rejected() {
    assert!(!looks_like_english_prose_for_test("abcdefghijklmno")); // 15 bytes (< 16)
    assert!(!looks_like_english_prose_for_test(
        "hello world 12345 foobar"
    )); // digit token
    assert!(!looks_like_english_prose_for_test(
        "HELLO WORLD FOO BAR BAZ"
    )); // no lowercase word
    assert!(!looks_like_english_prose_for_test("ghp_1a2b3c4d5e6f7g8h")); // token with digits/_
    assert!(!looks_like_english_prose_for_test(""));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// Any single all-lowercase run of >= 16 bytes is ALWAYS prose (first branch).
    #[test]
    fn all_lowercase_16_plus_is_always_prose(s in "[a-z]{16,64}") {
        prop_assert!(looks_like_english_prose_for_test(&s));
    }

    /// Any value shorter than 16 bytes is NEVER prose (the length floor).
    #[test]
    fn under_sixteen_is_never_prose(s in ".{0,15}") {
        prop_assert!(!looks_like_english_prose_for_test(&s));
    }

    /// Any value containing an ASCII DIGIT is never prose, the all-lowercase
    /// branch rejects the digit and the word branch's all-alpha check rejects the
    /// digit-bearing token. This is the recall-critical guard: a secret with a
    /// digit is never mistaken for prose.
    #[test]
    fn value_with_a_digit_is_never_prose(
        head in "[a-zA-Z ]{0,20}",
        tail in "[a-zA-Z ]{0,20}",
        d in "[0-9]",
    ) {
        let value = format!("{head}{d}{tail}");
        prop_assert!(!looks_like_english_prose_for_test(&value));
    }

    /// A prose match on a value WITH whitespace implies every token is all-alpha
    /// and length >= 2 (no lone letters, no symbol/digit tokens).
    #[test]
    fn whitespace_prose_match_implies_alpha_words(value in "[a-zA-Z ]{16,60}") {
        if looks_like_english_prose_for_test(&value) && value.contains(' ') {
            for tok in value.split_whitespace() {
                prop_assert!(tok.len() >= 2);
                prop_assert!(tok.bytes().all(|b| b.is_ascii_alphabetic()));
            }
        }
    }
}
