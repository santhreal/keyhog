//! LR1-A8 replacement gate: `engine/scan.rs` empty chunk yields no matches.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::engine::CompiledScanner;

#[test]
fn scan_empty_chunk_produces_no_matches() {
    let det = DetectorSpec {
        tests: Vec::new(),
        id: "gate".into(),
        name: "Gate".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![det]).unwrap();
    let chunk = Chunk {
        data: String::new().into(),
        metadata: ChunkMetadata::default(),
    };
    assert!(scanner.scan(&chunk).is_empty());
}
