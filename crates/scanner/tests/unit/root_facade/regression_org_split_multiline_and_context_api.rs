//! Regression: the file-responsibility splits of `multiline/preprocessor.rs`
//! (string-extraction primitives -> `multiline/string_extract.rs`) and
//! `context/inference.rs` (example/placeholder credential heuristics ->
//! `context/placeholder.rs`) must NOT change scanner behavior.
//!
//! The multiline and context internals are tested through
//! `keyhog_scanner::testing::{multiline, context}`. These pin EXACT outputs of
//! the orchestrator + the heuristics so a helper that drifted during the move
//! is caught - never `is_empty`/`is_ok`.

use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::testing::context::{is_known_example_credential, is_sequential_placeholder};
use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

// ── multiline: orchestrator + moved string-extraction primitives ────────────

#[test]
fn multiline_plus_concatenation_reassembles_after_string_extract_split() {
    // `+`-concatenation extraction moved to `string_extract.rs`. The two
    // fragments must still reassemble into the joined secret, proving
    // `extract_string_part` -> `extract_plus_concatenation` -> the buffer
    // assembly all still wire together through `preprocess_multiline`.
    let cfg = MultilineConfig::default();
    let cache = FragmentCache::new(64);
    let src = "key = \"ghp_AAAA\" +\n      \"BBBBCCCC\"";
    let out = preprocess_multiline(src, &cfg, &cache);
    assert!(
        out.text.contains("ghp_AAAABBBBCCCC"),
        "plus-concatenation must reassemble across lines after the split; got: {}",
        out.text
    );
}

#[test]
fn multiline_passthrough_is_byte_identical_after_split() {
    // A chunk with no concatenation indicator must pass through unchanged
    // (Cow::Borrowed), byte-for-byte. The passthrough decision did not move,
    // but the moved extractors must not be invoked on it.
    let cfg = MultilineConfig::default();
    let cache = FragmentCache::new(64);
    let src = "let token = \"single_line_value_123\";\n";
    let out = preprocess_multiline(src, &cfg, &cache);
    assert_eq!(
        &*out.text, src,
        "a non-concatenation chunk must pass through byte-identical after the split"
    );
    assert_eq!(out.original_end, src.len());
}

#[test]
fn multiline_template_literal_interpolation_after_split() {
    // JS template-literal `${"..."}` fragment extraction moved to
    // `string_extract.rs`; the literal inside the interpolation must still be
    // pulled in and concatenated to the prefix.
    let cfg = MultilineConfig::default();
    let cache = FragmentCache::new(64);
    let src = "const t = `ghp_${\"BODYBODYBODY\"}`;\n";
    let out = preprocess_multiline(src, &cfg, &cache);
    assert!(
        out.text.contains("ghp_BODYBODYBODY"),
        "template-literal interpolation must reassemble after the split; got: {}",
        out.text
    );
}

// ── context: example/placeholder heuristics moved to `placeholder.rs` ────────

#[test]
fn placeholder_example_suffix_heuristic_after_split() {
    // EXAMPLE / EXAMPLEKEY documentation convention.
    assert!(is_known_example_credential("ANYPREFIX_EXAMPLE"));
    assert!(is_known_example_credential("TOKEN_EXAMPLEKEY"));
    assert!(is_known_example_credential("token_example"));
    // A real-looking token must NOT be suppressed.
    assert!(!is_known_example_credential("sk-proj-realtokenbody1234"));
}

#[test]
fn placeholder_x_filler_and_empty_hash_after_split() {
    // x/X masking filler (>= 16 chars, > 3/4 are x).
    assert!(is_known_example_credential("xxxxxxxxxxxxxxxxxxxx"));
    // The MD5/SHA1/SHA256 empty-input hashes are integrity placeholders.
    assert!(is_known_example_credential(
        "d41d8cd98f00b204e9800998ecf8427e"
    ));
    assert!(is_known_example_credential(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
    // A non-empty-input hash of the same length is NOT suppressed by that arm.
    assert!(!is_known_example_credential(
        "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffaa"
    ));
}

#[test]
fn placeholder_sequential_and_hex_monotonic_after_split() {
    // Sequential / repetitive body (prefix-stripped) is a placeholder.
    assert!(is_sequential_placeholder("aaaaaaaaaaaaaaaa"));
    assert!(is_known_example_credential(
        "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    // Monotonic ascending hex body.
    assert!(is_known_example_credential(
        "0123456789abcdef0123456789abcdef"
    ));
    // A short, non-sequential body is NOT a placeholder.
    assert!(!is_sequential_placeholder("ab12"));
}

#[test]
fn context_inference_still_reachable_after_placeholder_split() {
    // The inference half stayed in `inference.rs`; confirm it still resolves
    // line context correctly now that the placeholder helpers moved out.
    let lines = [
        "// just a comment with key = value",
        "API_KEY = \"realvalue\"",
    ];
    assert_eq!(
        infer_context(&lines, 0, Some("src/main.rs")),
        CodeContext::Assignment,
        "a commented assignment must classify as Assignment after the split"
    );
    assert_eq!(
        infer_context(&lines, 1, Some("src/main.rs")),
        CodeContext::Assignment,
        "a bare assignment must classify as Assignment after the split"
    );
    // A test file path short-circuits to TestCode regardless of line content.
    assert_eq!(
        infer_context(&["x = 1"], 0, Some("foo_test.go")),
        CodeContext::TestCode
    );
}
