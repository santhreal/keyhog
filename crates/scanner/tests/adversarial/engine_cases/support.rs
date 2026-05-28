pub use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
pub use keyhog_scanner::CompiledScanner;
pub use std::collections::HashMap;

/// Build a chunk with the given data and default metadata.
pub fn make_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "test".into(),
            path: None,
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
        },
    }
}

pub fn assert_detected(data: &str) {
    let scanner = test_scanner();
    let chunk = make_chunk(data);
    let matches = scanner.scan(&chunk);
    assert!(
        matches
            .iter()
            .any(|matched| matched.credential.as_ref() == VALID_CREDENTIAL),
        "expected credential to be detected in: {data}"
    );
}

/// Build a simple token detector for testing.
pub fn token_detector() -> DetectorSpec {
    DetectorSpec {
        id: "test-token".into(),
        name: "Test Token".into(),
        service: "test".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "TESTKEY_[a-zA-Z0-9]{20}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["TESTKEY_".into()],
    }
}

/// Build a scanner with the test token detector.
pub fn test_scanner() -> CompiledScanner {
    CompiledScanner::compile(vec![token_detector()]).unwrap()
}

/// A valid test credential that the token detector should match.
pub const VALID_CREDENTIAL: &str = "TESTKEY_aK7xP9mQ2wE5rT8yU1iO";

/// Repetitive-mask twin that must stay suppressed.
pub const FAKE_CREDENTIAL: &str = "TESTKEY_11111111111111111111";

pub fn assert_not_detected(data: &str, credential: &str) {
    let scanner = test_scanner();
    let matches = scanner.scan(&make_chunk(data));
    assert!(
        !matches.iter().any(|m| m.credential.as_ref() == credential),
        "expected {credential} to be suppressed in:\n{data}\nmatches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn plain_testkey_assignment_is_detected() {
    assert_detected(&format!("export KEY=\"{VALID_CREDENTIAL}\"\n"));
}
