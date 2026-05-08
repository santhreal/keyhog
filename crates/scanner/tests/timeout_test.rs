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

/// Regression test: prior to the inner-loop deadline plumbing, a
/// single pattern that produced many matches per chunk could run
/// unboundedly because the deadline was only checked between
/// patterns, not within `extract_grouped_matches` /
/// `extract_plain_matches`. A chunk shaped like the
/// `false_prefix_storm` adversarial case (thousands of matches for
/// one pattern) would blow through `--timeout` silently.
///
/// This test feeds a 1 MiB chunk that produces ~50k+ matches for a
/// trivial regex, sets a 5 ms deadline, and asserts the scan
/// returns within 100 ms — proving the inner loop is checking the
/// deadline at its `is_multiple_of(64)` cadence and breaking
/// early.
#[test]
fn test_inner_loop_deadline_aborts_many_match_pattern() {
    let detector = DetectorSpec {
        id: "many-match-detector".into(),
        name: "Many Match Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            // Matches almost every character — fires once per byte
            // on the test chunk below.
            regex: "[a-z]".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
    };

    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // 1 MiB of lowercase letters — produces > 1M find_iter matches
    // for the [a-z] regex, which absent an inner-loop deadline
    // would take seconds even with a 5ms deadline.
    let chunk = Chunk {
        data: "a".repeat(1024 * 1024).into(),
        metadata: ChunkMetadata::default(),
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(5);

    let _ = scanner.scan_with_deadline(&chunk, Some(deadline));

    let elapsed = start.elapsed();
    // 100ms is a generous ceiling: the scan setup (line offsets,
    // code_lines split, AC trigger walk) takes a few ms before the
    // inner regex loop even starts. The deadline check fires every
    // 64 matches; on this corpus that's well under 100ms.
    assert!(
        elapsed < Duration::from_millis(100),
        "Inner-loop deadline did not abort: scan ran for {:?} \
         despite a 5ms deadline. The `extract_grouped_matches` /
         `extract_plain_matches` deadline check is not firing.",
        elapsed
    );
}
