use keyhog_core::{redact, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

#[test]
fn raw_match_sorting_priority() {
    let mut matches = [
        RawMatch {
            detector_id: "test-low".into(),
            detector_name: "Low".into(),
            service: "test".into(),
            severity: Severity::Low,
            credential: "key1".into(),
            credential_hash: "hash1".into(),
            companions: HashMap::new(),
            location: MatchLocation {
                source: "fs".into(),
                file_path: None,
                line: None,
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.5),
        },
        RawMatch {
            detector_id: "test-high".into(),
            detector_name: "High".into(),
            service: "test".into(),
            severity: Severity::High,
            credential: "key2".into(),
            credential_hash: "hash2".into(),
            companions: HashMap::new(),
            location: MatchLocation {
                source: "fs".into(),
                file_path: None,
                line: None,
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        },
        RawMatch {
            detector_id: "test-med".into(),
            detector_name: "Med".into(),
            service: "test".into(),
            severity: Severity::Medium,
            credential: "key3".into(),
            credential_hash: "hash3".into(),
            companions: HashMap::new(),
            location: MatchLocation {
                source: "fs".into(),
                file_path: None,
                line: None,
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        },
    ];

    matches.sort();

    // Sort order is Confidence (high first), then Severity (high first)
    assert_eq!(matches[0].detector_id.as_ref(), "test-high");
    assert_eq!(matches[1].detector_id.as_ref(), "test-med");
    assert_eq!(matches[2].detector_id.as_ref(), "test-low");
}

#[test]
fn redact_short_secret() {
    assert_eq!(redact("123"), "****");
    assert_eq!(redact("12345678"), "****");
}

#[test]
fn redact_long_secret() {
    let redacted = redact("abcdefghijklmnop");
    assert_eq!(redacted, "abcd...mnop");
}

#[test]
fn redact_utf8_secret_handles_multibyte_chars() {
    // 12 chars / 24 bytes (each emoji is 4 bytes in UTF-8). Should keep
    // the first 4 and last 4 *chars*, not bytes.
    let s = "😀😁😂😃😄😅😆😇😈😉😊😋";
    let redacted = redact(s);
    assert_eq!(redacted, "😀😁😂😃...😈😉😊😋");
}

#[test]
fn redact_utf8_short_returns_stars() {
    // 5 chars (20 bytes) — falls under the 8-char threshold even though
    // bytes-len would not. Exercises the UTF-8 char-count path.
    let s = "😀😁😂😃😄";
    assert_eq!(redact(s), "****");
}

#[test]
fn match_location_equality() {
    let loc1 = MatchLocation {
        source: "fs".into(),
        file_path: Some("a.txt".into()),
        line: Some(10),
        offset: 100,
        commit: None,
        author: None,
        date: None,
    };
    let loc2 = loc1.clone();
    assert_eq!(loc1, loc2);
}

#[test]
fn raw_match_sorting_handles_close_floats_without_epsilon_collapse() {
    let mut lower = RawMatch {
        detector_id: "alpha".into(),
        detector_name: "Alpha".into(),
        service: "test".into(),
        severity: Severity::High,
        credential: "key-a".into(),
        credential_hash: "hash-a".into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "fs".into(),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
    };
    let mut higher = lower.clone();
    higher.detector_id = "beta".into();
    higher.confidence = Some(0.9000000000000001);

    let mut matches = [lower.clone(), higher.clone()];
    matches.sort();
    assert_eq!(matches[0].detector_id.as_ref(), "beta");

    lower.confidence = Some(f64::NAN);
    let mut matches = [lower, higher];
    matches.sort();
    assert_eq!(matches.len(), 2);
}
