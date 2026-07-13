//! Recall boundaries for the example/placeholder suppression heuristics in
//! `context/placeholder.rs`. Over-matching here suppresses a REAL secret, so
//! every positive (a genuine placeholder shape) is paired with a negative twin
//! (a real-looking value that must survive). Covers the empty-input hash gate
//! (MD5/SHA1/SHA256, case-insensitive, exact-length only), the EXAMPLE suffix
//! convention, the x-dominated mask, and the ascending/descending hex-sequential
//! placeholder, all reached through `is_known_example_credential`, plus the
//! `is_sequential_placeholder` repeated-body gate directly.

use keyhog_scanner::testing::context::{is_known_example_credential, is_sequential_placeholder};

// ── empty-input hash digests are integrity values, never secrets ────────────

#[test]
fn md5_empty_input_hash_is_placeholder() {
    assert!(is_known_example_credential(
        "d41d8cd98f00b204e9800998ecf8427e"
    ));
}

#[test]
fn sha1_empty_input_hash_is_placeholder() {
    assert!(is_known_example_credential(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ));
}

#[test]
fn sha256_empty_input_hash_is_placeholder() {
    assert!(is_known_example_credential(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
}

#[test]
fn empty_input_hash_match_is_case_insensitive() {
    assert!(is_known_example_credential(
        "D41D8CD98F00B204E9800998ECF8427E"
    ));
    assert!(is_known_example_credential(
        "Da39A3ee5e6b4b0d3255bfef95601890afd80709"
    ));
}

#[test]
fn non_empty_md5_length_value_is_not_placeholder() {
    // A real 32-hex digest that is not MD5("") must survive.
    assert!(!is_known_example_credential(
        "5f4dcc3b5aa765d61d8327deb882cf99"
    ));
}

#[test]
fn real_sha256_digest_is_not_placeholder() {
    // SHA256("test") (real content hash, not the empty-input hash, not monotonic).
    assert!(!is_known_example_credential(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    ));
}

#[test]
fn empty_hash_off_by_one_short_is_not_placeholder() {
    // 31 chars: not an exact digest length, must not match.
    assert!(!is_known_example_credential(
        "d41d8cd98f00b204e9800998ecf8427"
    ));
}

#[test]
fn empty_hash_off_by_one_long_is_not_placeholder() {
    // 33 chars: exact-length gate means a digest with a trailing char is not it.
    assert!(!is_known_example_credential(
        "d41d8cd98f00b204e9800998ecf8427e0"
    ));
}

// ── EXAMPLE / EXAMPLEKEY documentation convention ───────────────────────────

#[test]
fn aws_example_access_key_is_placeholder() {
    // The canonical AWS docs key ends in EXAMPLE.
    assert!(is_known_example_credential("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn examplekey_suffix_is_placeholder() {
    assert!(is_known_example_credential("AKIAIOSFODNN7EXAMPLEKEY"));
}

#[test]
fn example_suffix_is_case_insensitive() {
    assert!(is_known_example_credential("sometokenvalueexample"));
    assert!(is_known_example_credential("sometokenvalueExAmPlE"));
}

#[test]
fn value_without_example_suffix_is_not_placeholder() {
    assert!(!is_known_example_credential("AKIAIOSFODNN7REALKEYAB"));
}

// ── x-dominated masking filler ──────────────────────────────────────────────

#[test]
fn x_dominated_value_is_placeholder() {
    // 16 chars, 13 'x' (> 3/4) is masking filler.
    assert!(is_known_example_credential("xxxxxxxxxxxxxabc"));
}

#[test]
fn uppercase_x_dominated_value_is_placeholder() {
    assert!(is_known_example_credential("XXXXXXXXXXXXXabc"));
}

#[test]
fn x_below_three_quarter_threshold_is_not_placeholder() {
    // 16 chars, exactly 12 'x' (not strictly greater than 12) must survive.
    assert!(!is_known_example_credential("xxxxxxxxxxxxabcd"));
}

#[test]
fn mostly_x_under_sixteen_is_not_placeholder() {
    // 13 chars, 10 'x' (77%), would be x-dominated at >=16 chars, but below the
    // floor the mask rule does not apply. Not all-same-byte and not a repeated
    // pair, so the sequential gate does not catch it either: it must survive.
    assert!(!is_known_example_credential("xxxxxxxxxxabc"));
}

// ── ascending / descending hex sequential placeholders ──────────────────────

#[test]
fn ascending_hex_sequence_is_placeholder() {
    assert!(is_known_example_credential(
        "0123456789abcdef0123456789abcdef"
    ));
}

#[test]
fn descending_hex_sequence_is_placeholder() {
    assert!(is_known_example_credential(
        "fedcba9876543210fedcba9876543210"
    ));
}

#[test]
fn ascending_hex_with_known_prefix_is_placeholder() {
    // The prefix is stripped before the monotonic-hex check.
    assert!(is_known_example_credential(
        "ghp_0123456789abcdef0123456789ab"
    ));
}

#[test]
fn random_hex_token_is_not_placeholder() {
    // A high-entropy 64-hex value (no monotonic run) must survive the gate.
    assert!(!is_known_example_credential(
        "a3f80b17c4e92d65fb0a8c7e21d9430f5c6b1e8a72f04d9bc3e571a0689d2f4c"
    ));
}

// ── is_sequential_placeholder: uniform / repeated bodies ────────────────────

#[test]
fn all_same_byte_body_is_sequential_placeholder() {
    assert!(is_sequential_placeholder("aaaaaaaa"));
}

#[test]
fn repeated_two_byte_pair_is_sequential_placeholder() {
    assert!(is_sequential_placeholder("abababababab"));
}

#[test]
fn high_entropy_body_is_not_sequential_placeholder() {
    assert!(!is_sequential_placeholder("a1b2c3d4e5f6g7"));
}

#[test]
fn body_under_eight_chars_is_not_sequential_placeholder() {
    assert!(!is_sequential_placeholder("abcabc"));
}
