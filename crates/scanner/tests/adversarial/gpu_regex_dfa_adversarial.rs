//! Adversarial tests for `gpu_regex_dfa` — edge cases, error paths,
//! and degenerate inputs that the RegexDfaPipeline must handle
//! gracefully without panicking or producing incorrect results.

use keyhog_scanner::engine::{build_regex_dfa, RegexDfaError};

#[test]
fn empty_regex_set_returns_error() {
    let result = build_regex_dfa(&[], 64);
    assert!(
        matches!(result, Err(RegexDfaError::EmptyPatternSet)),
        "empty pattern set should return EmptyPatternSet error, got: {result:?}"
    );
}

#[test]
fn single_char_regex() {
    // Single-char patterns are valid and should compile.
    let result = build_regex_dfa(&["a"], 64);
    assert!(
        result.is_ok(),
        "single-char regex should compile: {result:?}"
    );
    let pipeline = result.unwrap();
    let matches = pipeline.reference_scan(b"bab");
    assert!(
        matches.iter().any(|m| m.pattern_id == 0),
        "single-char regex should match"
    );
}

#[test]
fn alternation_explosion() {
    // a|b|c|...|z repeated — should be compilable because each branch
    // has a literal core. The NFA will have many states but the DFA
    // operates on extracted literals only.
    let letters: Vec<String> = (b'a'..=b'z').map(|c| String::from(c as char)).collect();
    let pattern_refs: Vec<&str> = letters.iter().map(|s| s.as_str()).collect();
    let result = build_regex_dfa(&pattern_refs, 256);
    assert!(
        result.is_ok(),
        "26 single-char alternations should compile: {result:?}"
    );
}

#[test]
fn very_long_regex_pattern_10k_chars() {
    // A 10K-char literal pattern should either compile or return a
    // structured error — never panic.
    let long_literal: String = "a".repeat(10_000);
    let result = build_regex_dfa(&[&long_literal], 64);
    // We accept either success or a structured error.
    match result {
        Ok(pipeline) => {
            assert!(pipeline.dfa.state_count > 0);
        }
        Err(err) => {
            // Must be a structured error, not a panic.
            let msg = format!("{err}");
            assert!(!msg.is_empty(), "error should have a descriptive message");
        }
    }
}

#[test]
fn regex_with_nested_quantifiers() {
    // `(a+)+` — pathological NFA pattern that can cause exponential
    // blowup in naive NFA engines. Should either compile (if within
    // state cap) or return TooManyStates.
    let result = build_regex_dfa(&["(a+)+"], 64);
    // Either compile success (NFA is within cap) or structured error.
    match &result {
        Ok(pipeline) => {
            // If it compiles, the literal core is empty since pattern
            // starts with `(` which is a metachar — so DFA build will
            // fail. Actually, `(` starts a group, so literal extraction
            // stops, yielding an empty literal.
            // The pipeline should have been constructed from at least
            // one non-empty literal to reach Ok.
            assert!(pipeline.pattern_count > 0);
        }
        Err(RegexDfaError::DfaBudgetExceeded { .. }) => {
            // Expected — no literal core extractable.
        }
        Err(RegexDfaError::RegexCompile(_)) => {
            // Also acceptable — NFA state cap hit.
        }
        Err(other) => {
            panic!("unexpected error variant: {other}");
        }
    }
}

#[test]
fn unicode_character_classes_are_rejected() {
    // Unicode classes should be rejected by the byte-NFA frontend.
    // The regex-syntax parser with unicode(false) should handle this
    // as an error or the vyre NFA compiler should reject it.
    let result = build_regex_dfa(&[r"\p{Greek}"], 64);
    assert!(
        result.is_err(),
        "unicode character classes should be rejected"
    );
    match result {
        Err(RegexDfaError::RegexCompile(_)) => {
            // Expected — vyre's byte-NFA rejects Unicode classes.
        }
        Err(RegexDfaError::DfaBudgetExceeded { .. }) => {
            // Also acceptable — pattern has no literal core.
        }
        Err(other) => {
            // Any structured error is acceptable.
            let _ = format!("{other}");
        }
        Ok(_) => unreachable!(),
    }
}

#[test]
fn pure_regex_no_literal_core_returns_error() {
    // Patterns that are pure regex with no literal prefix or infix
    // should produce a DfaBudgetExceeded error (no literals to compile).
    let result = build_regex_dfa(&["[a-z]+", "[0-9]{4}"], 64);
    assert!(
        matches!(result, Err(RegexDfaError::DfaBudgetExceeded { .. })),
        "patterns without literal cores should return DfaBudgetExceeded: {result:?}"
    );
}

#[test]
fn regex_dfa_error_display_is_nonempty() {
    // Verify Display impl for all error variants.
    let e1 = RegexDfaError::EmptyPatternSet;
    assert!(!format!("{e1}").is_empty());

    let e2 = RegexDfaError::DfaBudgetExceeded {
        message: "test".into(),
    };
    assert!(!format!("{e2}").is_empty());
}

#[test]
fn single_dot_metachar_pattern_no_core() {
    // `.` is a metacharacter — no literal core extractable.
    let result = build_regex_dfa(&["."], 64);
    assert!(result.is_err(), "dot-only pattern has no literal core");
}

#[test]
fn escaped_metachar_is_valid_literal() {
    // `\.` should extract `.` as a literal byte.
    let result = build_regex_dfa(&[r"example\.com"], 128);
    assert!(
        result.is_ok(),
        "escaped metachar should yield extractable literal: {result:?}"
    );
    let pipeline = result.unwrap();
    assert_eq!(&pipeline.pattern_literals[0], b"example.com");
}

#[test]
fn mixed_extractable_and_non_extractable_patterns() {
    // At least one pattern must have a literal core. The DFA is built
    // from the extractable subset.
    let result = build_regex_dfa(&["AKIA", "[a-z]+"], 256);
    assert!(
        result.is_ok(),
        "should compile when at least one pattern has a literal core: {result:?}"
    );
    let pipeline = result.unwrap();
    // reference_scan should find AKIA in haystack.
    let matches = pipeline.reference_scan(b"find AKIA here");
    assert!(
        matches.iter().any(|m| m.pattern_id == 0),
        "should find the extractable-literal pattern"
    );
}
