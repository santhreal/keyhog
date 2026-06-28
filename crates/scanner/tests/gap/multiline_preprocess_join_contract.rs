//! Gap test: the multiline preprocessor join-pass contract.
//!
//! `preprocess_multiline` joins adjacent string fragments/continuations before
//! scanning so a credential split across `"abc" +` / `"def"` lines surfaces as
//! one contiguous token. Two invariants are pinned here:
//!   * `original_end` ALWAYS equals the input byte length, on every return path
//!     (passthrough and concatenation alike) — the original region length is
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
    // A JSON object starts with `{` — a structured-doc shape that passes through
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
