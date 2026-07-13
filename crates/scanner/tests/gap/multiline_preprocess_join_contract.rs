//! Gap test: the multiline preprocessor join-pass contract.
//!
//! `preprocess_multiline` joins adjacent string fragments/continuations before
//! scanning so a credential split across `"abc" +` / `"def"` lines surfaces as
//! one contiguous token. Two invariants are pinned here:
//!   * `original_end` ALWAYS equals the input byte length, on every return path
//!     (passthrough and concatenation alike), the original region length is
//!     never rewritten, so offsets into it stay valid.
//!   * a passthrough chunk (no concat indicator / structured-doc shape) is
//!     carried through BYTE-IDENTICALLY (`text == input`), while a real
//!     concatenation preserves the original as a prefix and APPENDS the
//!     reassembled `abcdef` token.
//!
//! The module is multiline-feature-gated (the preprocessor only exists there).
#![cfg(feature = "multiline")]

use keyhog_scanner::testing::multiline::preprocess_multiline_for_test as preprocess;

#[test]
fn passthrough_chunk_is_carried_through_byte_identically() {
    // A JSON object starts with `{`: a structured-doc shape that passes through
    // with no join, so the output text equals the input verbatim.
    let input = "{\"key\": \"value\", \"n\": 1}";
    let (text, original_end) = preprocess(input);
    assert_eq!(text, input);
    assert_eq!(original_end, input.len());
}

#[test]
fn concatenation_preserves_the_original_prefix_and_appends_the_reassembly() {
    // `secret = "abc" +` / `"def"` is an explicit string concatenation: the two
    // literals reassemble to `abcdef`, appended after the preserved original.
    let input = "secret = \"abc\" +\n    \"def\"\n";
    let (text, original_end) = preprocess(input);

    // The original region length is never rewritten.
    assert_eq!(original_end, input.len());
    // The original chunk is preserved verbatim as the prefix of the output.
    assert!(
        text.starts_with(input),
        "preprocessed text must keep the original chunk as its prefix; got {text:?}"
    );
    // The split literal is reassembled into one contiguous token.
    assert!(
        text.contains("abcdef"),
        "the `\"abc\" + \"def\"` split must reassemble to `abcdef`; got {text:?}"
    );
    // Bytes were genuinely appended (the join is not a passthrough).
    assert!(text.len() > input.len());
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one passthrough and one concat example; these SWEEP both
// invariants. `original_end == input.len()` is a UNIVERSAL that must hold on EVERY
// return path (a rewritten length would corrupt offsets into the original region),
// so it runs over a mixed alphabet exercising both the passthrough and the
// string-concat join branches. Plus constructive recall: a no-concat chunk is
// byte-identical, and an explicit `"a" + "b"` split reassembles to `ab` appended
// after the preserved prefix. Traced against `preprocess_multiline`. No proptest before.

use proptest::prelude::*;

/// Chars that exercise both the passthrough and the string-concat join paths.
const ALPHABET: &[char] = &['a', 'b', '"', '+', '\n', ' ', '{', '}', ':', '='];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// `original_end` equals the input byte length on EVERY return path, the
    /// original region length is never rewritten, so offsets into it stay valid.
    #[test]
    fn original_end_always_equals_input_len(
        idxs in prop::collection::vec(0usize..ALPHABET.len(), 0..60),
    ) {
        let input: String = idxs.iter().map(|&i| ALPHABET[i]).collect();
        let (_text, original_end) = preprocess(&input);
        prop_assert_eq!(original_end, input.len());
    }

    /// A no-concat, no-continuation chunk (plain content, optionally wrapped in a
    /// `{...}` structured-doc shape) is carried through byte-identically.
    #[test]
    fn passthrough_chunk_is_byte_identical(
        body in "[a-zA-Z0-9 ]{0,40}",
        wrap in any::<bool>(),
    ) {
        let input = if wrap { format!("{{{body}}}") } else { body };
        let (text, original_end) = preprocess(&input);
        prop_assert_eq!(text.as_str(), input.as_str());
        prop_assert_eq!(original_end, input.len());
    }

    /// An explicit `"a" + "b"` string concatenation preserves the original as a
    /// prefix and appends the reassembled `ab` token (genuinely more bytes).
    #[test]
    fn concatenation_reassembles_split_literal(
        a in "[a-zA-Z0-9]{1,12}",
        b in "[a-zA-Z0-9]{1,12}",
    ) {
        let input = format!("secret = \"{a}\" +\n    \"{b}\"\n");
        let (text, original_end) = preprocess(&input);
        prop_assert_eq!(original_end, input.len());
        prop_assert!(text.starts_with(&input));
        let joined = format!("{a}{b}");
        let msg = format!("expected reassembled {joined:?} in {text:?}");
        prop_assert!(text.contains(&joined), "{}", msg);
        prop_assert!(text.len() > input.len());
    }
}
