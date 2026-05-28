//! Unit tests for `gpu_regex_dfa` — the RegexDfaPipeline that compiles
//! regex sets through DFA subset construction into O(1)/byte AC scanning.
//!
//! Tests exercise the `build_regex_dfa` path directly (no scanner compile
//! round-trip) so failures pinpoint the DFA compilation layer.

use keyhog_scanner::engine::{build_regex_dfa, RegexDfaError};

#[test]
fn single_regex_through_dfa_pipeline() {
    let result = build_regex_dfa(&["AKIA[A-Z0-9]{16}"], 1024);
    assert!(
        result.is_ok(),
        "single regex with literal prefix should compile: {:?}",
        result.err()
    );
    let pipeline = result.unwrap();
    assert_eq!(pipeline.pattern_count, 1);
    assert!(pipeline.dfa.state_count > 0);
    // The literal core extracted should be "AKIA".
    assert_eq!(&pipeline.pattern_literals[0], b"AKIA");
}

#[test]
fn mixed_literal_and_regex_pattern_set() {
    let patterns = &["AKIA", "ghp_[a-zA-Z0-9]{36}", "sk_live_[a-zA-Z0-9]+"];
    let result = build_regex_dfa(patterns, 1024);
    assert!(
        result.is_ok(),
        "mixed literal+regex set should compile: {:?}",
        result.err()
    );
    let pipeline = result.unwrap();
    assert_eq!(pipeline.pattern_count, 3);
    // All patterns should have extractable literal cores.
    assert_eq!(&pipeline.pattern_literals[0], b"AKIA");
    assert_eq!(&pipeline.pattern_literals[1], b"ghp_");
    assert_eq!(&pipeline.pattern_literals[2], b"sk_live_");
}

#[test]
fn patterns_with_character_classes() {
    // [a-z] at start means no literal core — but the second pattern has one.
    let patterns = &["AKIA", "token_[a-z]{3,8}"];
    let result = build_regex_dfa(patterns, 512);
    assert!(result.is_ok());
    let pipeline = result.unwrap();
    assert_eq!(&pipeline.pattern_literals[0], b"AKIA");
    assert_eq!(&pipeline.pattern_literals[1], b"token_");
}

#[test]
fn patterns_with_quantifiers() {
    let patterns = &["secret_[0-9]{3,8}", "key_[a-f]{4}"];
    let result = build_regex_dfa(patterns, 256);
    assert!(result.is_ok());
    let pipeline = result.unwrap();
    assert_eq!(&pipeline.pattern_literals[0], b"secret_");
    assert_eq!(&pipeline.pattern_literals[1], b"key_");
}

#[test]
fn dfa_pipeline_produces_correct_match_positions() {
    let pipeline = build_regex_dfa(&["AKIA", "ghp_"], 256).unwrap();
    let haystack = b"before AKIA after ghp_ end";

    let matches = pipeline.reference_scan(haystack);
    assert!(
        !matches.is_empty(),
        "reference_scan should find matches in haystack"
    );

    // Find AKIA match.
    let akia_matches: Vec<_> = matches.iter().filter(|m| m.pattern_id == 0).collect();
    assert_eq!(akia_matches.len(), 1, "should find exactly one AKIA match");
    let m = akia_matches[0];
    assert_eq!(m.start, 7, "AKIA starts at byte 7");
    assert_eq!(m.end, 11, "AKIA ends at byte 11");

    // Find ghp_ match.
    let ghp_matches: Vec<_> = matches.iter().filter(|m| m.pattern_id == 1).collect();
    assert_eq!(ghp_matches.len(), 1, "should find exactly one ghp_ match");
    let m = ghp_matches[0];
    assert_eq!(m.start, 18, "ghp_ starts at byte 18");
    assert_eq!(m.end, 22, "ghp_ ends at byte 22");
}

#[test]
fn multiple_overlapping_matches() {
    let pipeline = build_regex_dfa(&["ab", "abc", "bc"], 128).unwrap();
    let haystack = b"zabc";
    let matches = pipeline.reference_scan(haystack);
    // Should find: ab @ (1,3), abc @ (1,4), bc @ (2,4)
    assert!(matches.len() >= 2, "should find multiple matches");
}

#[test]
fn pure_literal_pattern_round_trips() {
    let pipeline = build_regex_dfa(&["hello", "world"], 128).unwrap();
    let matches = pipeline.reference_scan(b"hello world");
    assert_eq!(
        matches.len(),
        2,
        "should find both 'hello' and 'world'"
    );
}
