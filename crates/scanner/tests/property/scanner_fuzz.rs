//! Property-test fuzz harness for the full scanner pipeline.
//!
//! Random byte input → `CompiledScanner::scan` → must not panic. The
//! existing per-component proptests cover decoders, entropy, and the
//! alphabet filter; this fills the gap of "feed garbage at the WHOLE
//! pipeline and confirm nothing in extract / process_match / dedup
//! / fragment-cache / ML-pending construction trips an unwrap."
//!
//! Test corpus is bounded at 64 KiB per case so the property runner
//! can churn through hundreds of cases per second in CI. Larger
//! pathological inputs are exercised by `tests/oom_test.rs` and
//! `tests/adversarial`.

use keyhog_core::{
    Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity,
};
use keyhog_scanner::CompiledScanner;
use proptest::prelude::*;

/// Build a synthetic detector that exercises both the AC-prefix path
/// (literal "key=") and a capture group, so the fuzz hits both
/// `extract_grouped_matches` and `extract_plain_matches`.
fn fuzz_detectors() -> Vec<DetectorSpec> {
    vec![
        DetectorSpec {
            id: "fuzz-grouped".into(),
            name: "Fuzz Grouped".into(),
            service: "fuzz".into(),
            severity: Severity::Medium,
            patterns: vec![PatternSpec {
                regex: r#"key\s*=\s*([A-Za-z0-9_-]{8,40})"#.into(),
                description: None,
                group: Some(1),
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["key".into()],
        },
        DetectorSpec {
            id: "fuzz-plain".into(),
            name: "Fuzz Plain".into(),
            service: "fuzz".into(),
            severity: Severity::Low,
            patterns: vec![PatternSpec {
                regex: r"AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["AKIA".into()],
        },
    ]
}

fn make_chunk(bytes: Vec<u8>) -> Chunk {
    // SensitiveString requires valid UTF-8 — lossy-decode any random
    // byte slice to a String. The actual scanner production path does
    // the same (lossy decode in the filesystem source) so the fuzz
    // exercises the same input shape.
    let s = String::from_utf8_lossy(&bytes).into_owned();
    Chunk {
        data: s.into(),
        metadata: ChunkMetadata {
            source_type: "fuzz".into(),
            ..Default::default()
        },
    }
}

proptest! {
    // Modest case count — the regex engine + AC + pattern matching
    // make every case relatively expensive, and we rely on bounded
    // input size + diverse byte distributions to find panics rather
    // than sheer iteration count.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Random bytes (any 0..16 KiB length, fully arbitrary u8 content).
    /// The scan must complete without panic for every input.
    #[test]
    fn scanner_does_not_panic_on_random_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..16_384)
    ) {
        let scanner = CompiledScanner::compile(fuzz_detectors())
            .expect("fuzz detectors compile");
        let chunk = make_chunk(bytes);
        let _ = scanner.scan(&chunk);
    }

    /// Random ASCII (printable-ish range) — exercises the regex path
    /// hard since most matches will be plausibly secret-shaped.
    #[test]
    fn scanner_does_not_panic_on_random_ascii(
        text in "[\\x20-\\x7e]{0,8192}"
    ) {
        let scanner = CompiledScanner::compile(fuzz_detectors())
            .expect("fuzz detectors compile");
        let chunk = Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "fuzz".into(),
                ..Default::default()
            },
        };
        let _ = scanner.scan(&chunk);
    }

    /// Bytes with embedded NULs + control chars + high-bit bytes.
    /// Hostile-input shape, similar to what a binary-string source
    /// produces when scanning compiled artifacts.
    #[test]
    fn scanner_does_not_panic_on_mixed_control_bytes(
        prefix in proptest::collection::vec(any::<u8>(), 0..512),
        nul_count in 0..32usize,
        high_bytes in proptest::collection::vec(0x80u8..=0xff, 0..256),
    ) {
        let mut bytes = prefix;
        bytes.extend(std::iter::repeat_n(0u8, nul_count));
        bytes.extend(high_bytes);
        let scanner = CompiledScanner::compile(fuzz_detectors())
            .expect("fuzz detectors compile");
        let chunk = make_chunk(bytes);
        let _ = scanner.scan(&chunk);
    }
}
