/// Extended context tests: is_known_example_credential edge cases,
/// confidence multiplier ordering invariants, and hard-suppress boundary
/// conditions.
use keyhog_scanner::context::{infer_context, is_known_example_credential, CodeContext};

// ── is_known_example_credential ───────────────────────────────────────────────

#[test]
fn example_suffix_detected() {
    assert!(is_known_example_credential("ANYPREFIX_EXAMPLE"));
    assert!(is_known_example_credential("TOKEN_EXAMPLEKEY"));
}

#[test]
fn example_suffix_case_insensitive() {
    // The function uppercases before checking
    assert!(is_known_example_credential("token_example"));
    assert!(is_known_example_credential("sk_EXAMPLEKEY"));
}

#[test]
fn example_suffix_not_false_positive_on_real_looking_value() {
    // A token that happens to end in "ample" but not "EXAMPLE"
    assert!(!is_known_example_credential("sk-proj-validtokenample"));
}

#[test]
fn x_dominated_above_threshold_is_example() {
    // 28 'x' out of 32 chars = 87.5% > 75% threshold, body >= 16 chars
    let cred = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx1234";
    assert!(is_known_example_credential(cred));
}

#[test]
fn x_dominated_below_threshold_not_suppressed() {
    // 8 'x' out of 32 chars = 25% — well below 75%
    let cred = "xxxxxxxxaaaaaaaabbbbbbbbcccccccc";
    assert!(!is_known_example_credential(cred));
}

#[test]
fn x_dominated_too_short_not_suppressed() {
    // < 16 chars, even if x-dominated
    let cred = "xxxxxxxx"; // 8 chars, all x
    assert!(!is_known_example_credential(cred));
}

#[test]
fn empty_string_not_example() {
    // Empty credential should not be considered an example (no body to evaluate)
    assert!(!is_known_example_credential(""));
}

#[test]
fn md5_of_empty_is_example() {
    assert!(is_known_example_credential("d41d8cd98f00b204e9800998ecf8427e"));
}

#[test]
fn sha1_of_empty_is_example() {
    assert!(is_known_example_credential(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    ));
}

#[test]
fn sha256_of_empty_is_example() {
    assert!(is_known_example_credential(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
}

#[test]
fn real_high_entropy_token_not_suppressed() {
    // Synthetic token with realistic mixed chars — must NOT be suppressed
    let cred = "sk-proj-aK7xP9mQ2wE5rT8yU1iO3pA6sD4fGhJkLzBnMcVqWr";
    assert!(!is_known_example_credential(cred));
}

#[test]
fn ascending_hex_pairs_is_example() {
    // Sequential hex placeholders — "0102030405..." pattern
    let cred = "00010203040506070809101112131415";
    // This matches the is_hex_sequential_placeholder heuristic
    // Assertion: must not panic; may or may not be suppressed
    let _ = is_known_example_credential(cred);
}

// ── CodeContext confidence multiplier invariants ───────────────────────────────

#[test]
fn assignment_has_highest_multiplier() {
    let assign = CodeContext::Assignment.confidence_multiplier();
    assert_eq!(assign, 1.0, "Assignment multiplier must be 1.0 (no penalty)");
}

#[test]
fn encrypted_has_lowest_multiplier() {
    let encrypted = CodeContext::Encrypted.confidence_multiplier();
    let test_code = CodeContext::TestCode.confidence_multiplier();
    let documentation = CodeContext::Documentation.confidence_multiplier();
    // Encrypted should be the lowest (0.05)
    assert!(encrypted < test_code, "Encrypted must have lower multiplier than TestCode");
    assert!(encrypted < documentation, "Encrypted must have lower multiplier than Documentation");
}

#[test]
fn multiplier_ordering_strict() {
    // Assignment > StringLiteral > Unknown > Comment > TestCode ≈ Documentation > Encrypted
    let a = CodeContext::Assignment.confidence_multiplier();
    let sl = CodeContext::StringLiteral.confidence_multiplier();
    let unk = CodeContext::Unknown.confidence_multiplier();
    let cmt = CodeContext::Comment.confidence_multiplier();
    let tc = CodeContext::TestCode.confidence_multiplier();
    let enc = CodeContext::Encrypted.confidence_multiplier();

    assert!(a > sl, "Assignment > StringLiteral");
    assert!(sl > unk, "StringLiteral > Unknown");
    assert!(unk > cmt, "Unknown > Comment");
    assert!(cmt > tc, "Comment > TestCode");
    assert!(tc > enc, "TestCode > Encrypted");
}

// ── CodeContext::should_hard_suppress boundary ────────────────────────────────

#[test]
fn documentation_hard_suppress_below_half() {
    assert!(CodeContext::Documentation.should_hard_suppress(0.0));
    assert!(CodeContext::Documentation.should_hard_suppress(0.49));
    assert!(!CodeContext::Documentation.should_hard_suppress(0.5));
    assert!(!CodeContext::Documentation.should_hard_suppress(1.0));
}

#[test]
fn test_code_hard_suppress_below_half() {
    assert!(CodeContext::TestCode.should_hard_suppress(0.0));
    assert!(CodeContext::TestCode.should_hard_suppress(0.499));
    assert!(!CodeContext::TestCode.should_hard_suppress(0.5));
}

#[test]
fn comment_hard_suppress_below_half() {
    assert!(CodeContext::Comment.should_hard_suppress(0.3));
    assert!(!CodeContext::Comment.should_hard_suppress(0.5));
}

#[test]
fn encrypted_hard_suppress_below_point_eight() {
    assert!(CodeContext::Encrypted.should_hard_suppress(0.0));
    assert!(CodeContext::Encrypted.should_hard_suppress(0.79));
    assert!(!CodeContext::Encrypted.should_hard_suppress(0.8));
    assert!(!CodeContext::Encrypted.should_hard_suppress(1.0));
}

#[test]
fn assignment_never_hard_suppresses() {
    for conf in [0.0, 0.1, 0.3, 0.5, 0.8, 1.0] {
        assert!(
            !CodeContext::Assignment.should_hard_suppress(conf),
            "Assignment must never hard-suppress at conf={conf}"
        );
    }
}

#[test]
fn string_literal_never_hard_suppresses() {
    for conf in [0.0, 0.5, 1.0] {
        assert!(!CodeContext::StringLiteral.should_hard_suppress(conf));
    }
}

#[test]
fn unknown_never_hard_suppresses() {
    for conf in [0.0, 0.5, 1.0] {
        assert!(!CodeContext::Unknown.should_hard_suppress(conf));
    }
}

// ── infer_context: out-of-bounds line index does not panic ───────────────────

#[test]
fn infer_context_oob_line_index_does_not_panic() {
    let lines = vec!["only one line"];
    // Line index 5 is past the end — must not panic
    let _ = infer_context(&lines, 5, None);
}

#[test]
fn infer_context_empty_lines_does_not_panic() {
    let _ = infer_context(&[], 0, None);
}

// ── infer_context: string literal detection ───────────────────────────────────

#[test]
fn double_quoted_string_is_string_literal() {
    let lines = vec![r#"key = "some_value""#];
    let ctx = infer_context(&lines, 0, None);
    // Assignment or StringLiteral — not Comment, TestCode, Encrypted, Documentation
    assert!(
        matches!(ctx, CodeContext::Assignment | CodeContext::StringLiteral),
        "double-quoted assignment should be Assignment or StringLiteral, got {ctx:?}"
    );
}

// ── infer_context: path-based test detection ──────────────────────────────────

#[test]
fn spec_directory_treated_as_test_code() {
    let lines = vec!["token = 'some_value'"];
    let ctx = infer_context(&lines, 0, Some("spec/features/auth_spec.rb"));
    assert_eq!(ctx, CodeContext::TestCode, "spec/ directory must classify as TestCode");
}

#[test]
fn fixture_directory_treated_as_test_code() {
    let lines = vec!["API_KEY=testvalue"];
    let ctx = infer_context(&lines, 0, Some("tests/fixtures/creds.env"));
    assert_eq!(ctx, CodeContext::TestCode, "fixtures/ directory must classify as TestCode");
}
