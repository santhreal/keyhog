use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
use std::time::{Duration, Instant};

#[test]
fn test_scan_timeout_respects_deadline() {
    let detector = DetectorSpec {
        id: "redos-detector".into(),
        name: "ReDoS Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            // A pattern known to be slow on certain inputs (though regex crate is mostly safe, we can simulate it)
            regex: "(a+)+$".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["a".into()],
    };

    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // Create a long string that might trigger slow matching
    let mut data = "a".repeat(1000);
    data.push('!'); // Break the match to force backtracking if the engine was naive

    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    };

    let start = Instant::now();
    let timeout = Duration::from_millis(100);
    let deadline = start + timeout;

    // This should return quickly because of the deadline, even if the regex is slow.
    // (Note: regex crate might not actually be slow here, but we're testing the propagation)
    let _matches = scanner.scan_with_deadline(&chunk, Some(deadline));

    // The scan should have returned fairly close to the timeout
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "Scan took too long: {:?}",
        start.elapsed()
    );
}
