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
        let chunk = Chunk {
            data: example.into(),
            metadata: ChunkMetadata {
                source_type: "corpus-ratchet".into(),
                path: Some("s.txt".into()),
                base_offset: 0,
                ..Default::default()
            },
        };
        let hit = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
            .iter()
            .flat_map(|per_chunk| per_chunk.iter())
            .any(|m| m.detector_id.as_ref() == id);
        if hit {
            return true;
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
        }
    }

    // The live corpus contains a large regex-backed majority and hundreds of
    // detectors that fire with multiple samples. Floors
    // sit below that with margin so this is a regression ratchet, not brittle.
    assert!(
        total_regex >= 880,
        "expected a large regex-detector corpus, got {total_regex}"
    );
    assert!(
        fired >= 830,
        "detection coverage regressed: only {fired}/{total_regex} regex detectors \
         fired on a generated example (floor 830)"
    );
    eprintln!("corpus coverage: {fired}/{total_regex} regex detectors fired");
}
