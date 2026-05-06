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
