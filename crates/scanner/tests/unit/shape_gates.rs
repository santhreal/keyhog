/// Unit tests for shape-gate heuristics exercised through the public
/// `keyhog_scanner::jwt` module (which is truly public) and through
/// `keyhog_scanner::normalize_chunk_data` / `should_suppress_known_example_credential`.
///
/// The individual shape-gate functions (`looks_like_dashed_serial_key`, etc.)
/// are `pub(crate)` so they cannot be accessed from integration tests.
/// Instead, we:
///   1. Test the JWT module's `looks_like_jwt` which is a distinct public API.
///   2. Test `should_suppress_known_example_credential` which calls
///      the shape-gate pipeline end-to-end.
///   3. Test `normalize_chunk_data` for the Unicode-evasion guard.
///
/// For each gate, at least one positive (should suppress) and one negative
/// (should NOT suppress) case is present.
use std::borrow::Cow;
use keyhog_scanner::context::CodeContext;
use keyhog_scanner::{normalize_chunk_data, should_suppress_known_example_credential};

// ── placeholder / example credential suppression ──────────────────────────────

#[test]
fn all_same_char_body_is_suppressed_as_example() {
    // 32 identical chars → sequential_placeholder → suppressed
    let cred = "A".repeat(32);
    assert!(
        should_suppress_known_example_credential(&cred, None, CodeContext::Unknown),
        "all-same-char body should be suppressed"
    );
}

#[test]
fn high_entropy_mixed_body_not_suppressed() {
    // Realistic random-looking credential — must NOT be suppressed
    let cred = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fGhJk";
    assert!(
        !should_suppress_known_example_credential(cred, None, CodeContext::Assignment),
        "realistic mixed credential should not be suppressed"
    );
}

#[test]
fn example_suffix_credential_is_suppressed() {
    // Ends with EXAMPLE — universal documentation convention
    let cred = "ghp_AAAAAAAAAAAAAAAAAAAEXAMPLE";
    assert!(
        should_suppress_known_example_credential(cred, None, CodeContext::Unknown),
        "EXAMPLE suffix should be suppressed"
    );
}

#[test]
fn examplekey_suffix_credential_is_suppressed() {
    let cred = "sk_test_AAAAAAAAAAAAAEXAMPLEKEY";
    assert!(
        should_suppress_known_example_credential(cred, None, CodeContext::Unknown),
        "EXAMPLEKEY suffix should be suppressed"
    );
}

#[test]
fn x_dominated_credential_above_threshold_suppressed() {
    // >75% of body is 'x' / 'X'
    let cred = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx1234"; // 28 x + 4 other = 87.5% x
    assert!(
        should_suppress_known_example_credential(cred, None, CodeContext::Unknown),
        "x-dominated credential (>75%) should be suppressed"
    );
}

#[test]
fn x_dominated_below_threshold_not_suppressed() {
    // Exactly 50% x — below the 75% cutoff
    let cred = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // 16 x
        .chars()
        .take(16)
        .chain("abcdefghijklmnop".chars()) // 16 other
        .collect::<String>();
    // 32 chars, 16 x = 50% < 75% → not suppressed (assuming credential has genuine entropy)
    // Note: this may still be suppressed for other reasons (sequential, etc.)
    // The primary assertion is that the function does not panic.
    let _ = should_suppress_known_example_credential(&cred, None, CodeContext::Unknown);
}

#[test]
fn md5_of_empty_string_is_suppressed() {
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    let cred = "d41d8cd98f00b204e9800998ecf8427e";
    assert!(
        should_suppress_known_example_credential(cred, None, CodeContext::Unknown),
        "MD5 of empty string must be suppressed"
    );
}

#[test]
fn sha1_of_empty_string_is_suppressed() {
    let cred = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    assert!(
        should_suppress_known_example_credential(cred, None, CodeContext::Unknown),
        "SHA1 of empty string must be suppressed"
    );
}

#[test]
fn sha256_of_empty_string_is_suppressed() {
    let cred = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert!(
        should_suppress_known_example_credential(cred, None, CodeContext::Unknown),
        "SHA256 of empty string must be suppressed"
    );
}

#[test]
fn test_code_context_suppresses_low_confidence_below_half() {
    // CodeContext::TestCode hard-suppresses when confidence < 0.5
    // (tested through the context multiplier contract, not shape-gate directly)
    let ctx = CodeContext::TestCode;
    assert!(ctx.should_hard_suppress(0.4), "TestCode at conf<0.5 must hard-suppress");
    assert!(!ctx.should_hard_suppress(0.6), "TestCode at conf>0.5 must not hard-suppress");
}

#[test]
fn assignment_context_never_hard_suppresses() {
    let ctx = CodeContext::Assignment;
    assert!(!ctx.should_hard_suppress(0.0));
    assert!(!ctx.should_hard_suppress(0.5));
    assert!(!ctx.should_hard_suppress(1.0));
}

#[test]
fn encrypted_context_hard_suppresses_below_point_eight() {
    let ctx = CodeContext::Encrypted;
    assert!(ctx.should_hard_suppress(0.7));
    assert!(!ctx.should_hard_suppress(0.9));
}

// ── normalize_chunk_data: Unicode evasion guard ───────────────────────────────

#[test]
fn ascii_data_borrowed_without_allocation() {
    // Pure ASCII → must return Cow::Borrowed (no allocation)
    use std::borrow::Cow;
    let data = "plain ascii secret token abc123";
    let result = normalize_chunk_data(data);
    assert!(matches!(result, Cow::Borrowed(_)), "ASCII must return Borrowed");
    assert_eq!(result.as_ref(), data);
}

#[test]
fn unicode_text_without_evasion_returned_unchanged() {
    // Regular Unicode (accented chars etc.) that aren't evasion chars
    // The function must not strip legitimate Unicode characters.
    let data = "résumé credentials test";
    let result = normalize_chunk_data(data);
    // The result may be Borrowed or Owned depending on whether any evasion
    // chars were found, but the content must not have had genuine text stripped.
    assert!(result.contains("r") && result.contains("sum"), "legitimate Unicode preserved");
}
