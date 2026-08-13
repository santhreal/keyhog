//! Corpus-wide detection coverage RATCHET (#177/#184). For every Regex detector,
//! deterministically generate strings matching its own primary regex and assert
//! the scanner recovers a finding from that detector. This validates the basic
//! regex→compile→scan wiring of the ENTIRE ~900-detector corpus in one place and
//! guards against a refactor silently breaking a swath of detectors. Uses floors
//! (not exact counts) to tolerate ungeneratable-regex + minimal-generation
//! churn. ML-independent; run without `ml` while the embedded weights are
//! mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

/// Up to this many generated examples are tried per detector; a single minimal
/// generation can fall below an entropy/length floor, so retrying a few random
/// samples clears that artifact and measures real regex→scan wiring.
const SAMPLES_PER_DETECTOR: usize = 8;

fn scan_for_detector_with_path(
    scanner: &CompiledScanner,
    id: &str,
    data: &str,
    path: &str,
) -> bool {
    let chunk = Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "corpus-ratchet".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("selected backend scan succeeds")
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .any(|m| m.detector_id.as_ref() == id)
}

fn scan_for_detector(
    scanner: &CompiledScanner,
    id: &str,
    data: &str,
) -> bool {
    scan_for_detector_with_path(scanner, id, data, "s.txt")
}

fn detector_fires_on_own_regex(
    scanner: &CompiledScanner,
    runner: &mut TestRunner,
    id: &str,
    regex: &str,
) -> bool {
    let Ok(strat) = proptest::string::string_regex(regex) else {
        return false; // regex outside proptest's generatable subset
    };
    for _ in 0..SAMPLES_PER_DETECTOR {
        let Ok(tree) = strat.new_tree(runner) else {
            continue;
        };
        let example = tree.current();
        if scan_for_detector(scanner, id, &example) {
            return true;
        }
    }
    false
}

/// When proptest cannot generate from a regex (87 of 922 detectors use
/// features like `\b`, `(?-i)`, `(?:^|[^A-Za-z])` that proptest's
/// `string_regex` does not support), fall back to the detector's own
/// `test_positive` example. The author wrote that example into the TOML
/// specifically to prove the detector fires on its canonical shape.
/// If no `test_positive` exists, the detector is counted as ungeneratable
/// and does not count against the floor.
fn detector_fires_on_test_positive(
    scanner: &CompiledScanner,
    id: &str,
    tests: &[keyhog_core::DetectorTestSpec],
) -> bool {
    for test in tests {
        if let Some(positive) = &test.test_positive {
            // Use the detector's own test_path when provided — path-restricted
            // detectors (e.g. netrc-password, which only fires on .netrc) would
            // be rejected by source_admission on the default s.txt path.
            let path = test.test_path.as_deref().unwrap_or("s.txt");
            if scan_for_detector_with_path(scanner, id, positive, path) {
                return true;
            }
        }
    }
    false
}

#[test]
fn most_regex_detectors_fire_on_a_generated_example() {
    let specs = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(specs.clone()).expect("scanner compile");
    let mut runner = TestRunner::deterministic();

    let mut total_regex = 0u32;
    let mut fired = 0u32;
    let mut fallback_used = 0u32;
    for spec in specs.iter() {
        if format!("{:?}", spec.kind) != "Regex" {
            continue;
        }
        let Some(pat) = spec.patterns.first() else {
            continue;
        };
        total_regex += 1;
        if detector_fires_on_own_regex(&scanner, &mut runner, &spec.id, &pat.regex) {
            fired += 1;
        } else if detector_fires_on_test_positive(&scanner, &spec.id, &spec.tests) {
            fired += 1;
            fallback_used += 1;
        }
    }

    // The live corpus contains a large regex-backed majority. Every regex
    // detector either (a) fires on a proptest-generated sample from its own
    // regex, or (b) fires on its own test_positive example from the TOML.
    // The floor sits at 920 to tolerate minor corpus churn (a few detectors
    // added or removed) while catching any regression that breaks the
    // regex→compile→scan wiring for a swath of detectors.
    assert!(
        total_regex >= 880,
        "expected a large regex-detector corpus, got {total_regex}"
    );
    assert!(
        fired >= 920,
        "detection coverage regressed: only {fired}/{total_regex} regex detectors \
         fired on a generated or test_positive example (floor 920)"
    );
    eprintln!(
        "corpus coverage: {fired}/{total_regex} regex detectors fired ({fallback_used} via test_positive fallback)"
    );
}
