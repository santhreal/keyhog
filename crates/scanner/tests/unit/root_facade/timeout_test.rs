use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
use std::time::{Duration, Instant};

#[test]
fn test_scan_timeout_respects_deadline() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "redos-detector".into(),
        name: "ReDoS Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            // A pattern known to be slow on certain inputs (though regex crate is mostly safe, we can simulate it)
            regex: "(a+)+$".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["a".into()],
        min_confidence: None,
        ..Default::default()
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
    let _matches = keyhog_scanner::testing::scan_with_deadline(&scanner, &chunk, Some(deadline));

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
/// returns within 100 ms - proving the regex loop and the per-match
/// post-processing chain both honor the deadline.
#[test]
fn test_inner_loop_deadline_aborts_many_match_pattern() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "many-match-detector".into(),
        name: "Many Match Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            // Matches almost every character - fires once per byte
            // on the test chunk below.
            regex: "[a-z]".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        min_confidence: None,
        ..Default::default()
    };

    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // 1 MiB of lowercase letters - produces > 1M find_iter matches
    // for the [a-z] regex, which absent an inner-loop deadline
    // would take seconds even with a 5ms deadline.
    let chunk = Chunk {
        data: "a".repeat(1024 * 1024).into(),
        metadata: ChunkMetadata::default(),
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(5);

    let _ = keyhog_scanner::testing::scan_with_deadline(&scanner, &chunk, Some(deadline));

    let elapsed = start.elapsed();
    // 100ms is a generous ceiling: the scan setup (line offsets,
    // code_lines split, AC trigger walk) takes a few ms before the
    // inner regex loop even starts. The deadline check fires every
    // 64 matches; on this corpus that's well under 100ms.
    assert!(
        elapsed < Duration::from_millis(100),
        "Inner-loop deadline did not abort: scan ran for {:?} \
         despite a 5ms deadline. The extractor regex/post-processing \
         deadline checks are not firing.",
        elapsed
    );
}

#[test]
fn test_inner_loop_deadline_aborts_many_match_grouped_pattern() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "many-match-grouped-detector".into(),
        name: "Many Match Grouped Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            // Same one-byte storm as the plain-path test, but with an explicit
            // capture group so the grouped extraction loop owns the work.
            regex: "([a-z])".into(),
            description: None,
            group: Some(1),
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        min_confidence: None,
        ..Default::default()
    };

    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = Chunk {
        data: "a".repeat(1024 * 1024).into(),
        metadata: ChunkMetadata::default(),
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(5);

    let _ = keyhog_scanner::testing::scan_with_deadline(&scanner, &chunk, Some(deadline));

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "Grouped extraction loop ignored the scan deadline: elapsed={elapsed:?}"
    );
}

#[test]
fn test_inner_loop_deadline_aborts_many_match_anchored_pattern() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "many-match-anchored-detector".into(),
        name: "Many Match Anchored Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "sk_live_[A-Za-z0-9]{24}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["sk_live_".into()],
        min_confidence: None,
        ..Default::default()
    };

    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = Chunk {
        // Dense required-prefix candidates with no valid 24-byte body: this
        // drives anchored candidate verification without report emission.
        data: "sk_live_".repeat(500_000).into(),
        metadata: ChunkMetadata::default(),
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(5);

    let _ = keyhog_scanner::testing::scan_with_deadline(&scanner, &chunk, Some(deadline));

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "Anchored extraction loop ignored the scan deadline: elapsed={elapsed:?}"
    );
}

/// Regression test: deadline enforcement must not stop at subsystem borders.
/// The generic assignment bridge runs after triggered and phase-2 scanning; if
/// it only inherits a caller-side before/after check, a dense `api_key = value`
/// corpus can continue processing long after the scan deadline has expired.
#[test]
fn test_generic_assignment_deadline_aborts_inside_bridge() {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "prefix-pass-detector".into(),
        name: "Prefix Pass Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..Default::default()
    };

    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let mut data = String::from("abc\n");
    let value = "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081";
    for idx in 0..100_000 {
        data.push_str("api_key_");
        data.push_str(&idx.to_string());
        data.push_str(" = \"");
        data.push_str(value);
        data.push_str("\"\n");
    }

    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    };

    let start = Instant::now();
    let deadline = start + Duration::from_millis(5);

    let _ = keyhog_scanner::testing::scan_with_deadline(&scanner, &chunk, Some(deadline));

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "Generic assignment bridge ignored the scan deadline: elapsed={elapsed:?}"
    );
}
