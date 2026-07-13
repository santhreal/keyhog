//! Corpus-wide finding WELL-FORMEDNESS invariants (#177/#185). Independent of
//! WHICH detector fires: EVERY finding the scanner emits, across the whole
//! ~900-detector corpus, must be structurally valid. A malformed finding
//! (empty service, bogus severity, offset that doesn't point at the credential)
//! is a reporter/SARIF corruption bug. This generates an example per Regex
//! detector and asserts the invariants on every resulting finding. ML-
//! independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

// The full Severity domain (keyhog_core::spec::Severity), Debug-formatted.
// ClientSafe covers publishable keys (e.g. algolia *search* keys).
const VALID_SEVERITIES: &[&str] = &["Critical", "High", "Medium", "Low", "ClientSafe", "Info"];

#[test]
fn every_corpus_finding_is_well_formed() {
    let specs = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(specs.clone()).expect("scanner compile");
    let mut runner = TestRunner::deterministic();

    let mut findings_checked = 0u32;
    let mut detectors_exercised = 0u32;
    for spec in specs.iter() {
        if format!("{:?}", spec.kind) != "Regex" {
            continue;
        }
        let Some(pat) = spec.patterns.first() else {
            continue;
        };
        let Ok(strat) = proptest::string::string_regex(&pat.regex) else {
            continue;
        };
        let Ok(tree) = strat.new_tree(&mut runner) else {
            continue;
        };
        let example = tree.current();
        let chunk = Chunk {
            data: example.clone().into(),
            metadata: ChunkMetadata {
                source_type: "corpus-invariants".into(),
                path: Some("s.txt".into()),
                base_offset: 0,
                ..Default::default()
            },
        };
        let per = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
        let mut fired = false;
        for m in per.iter().flat_map(|c| c.iter()) {
            fired = true;
            findings_checked += 1;
            let cred = m.credential.as_ref();
            let sev = format!("{:?}", m.severity);
            assert!(
                !m.service.is_empty(),
                "empty service for detector {} on {example:?}",
                m.detector_id
            );
            assert!(
                VALID_SEVERITIES.contains(&sev.as_str()),
                "invalid severity {sev:?} for detector {} on {example:?}",
                m.detector_id
            );
            assert!(
                !cred.is_empty(),
                "empty credential for detector {} on {example:?}",
                m.detector_id
            );
            assert!(
                !m.detector_id.is_empty(),
                "empty detector_id on {example:?}"
            );
            // The reported byte offset must point AT the recovered credential in
            // the input, a wrong offset misreports the leak site. Scoped to
            // ASCII examples: unicode-hardening normalizes whitespace/homoglyphs
            // before matching, which legitimately shifts offsets out of raw-input
            // space (tracked separately as the offset-under-normalization finding).
            // For ASCII input no normalization occurs, so the offset must be exact.
            let off = m.location.offset;
            if example.is_ascii() {
                if let Some(window) = example.as_bytes().get(off..off + cred.len()) {
                    assert_eq!(
                        window,
                        cred.as_bytes(),
                        "offset {off} does not point at credential {cred:?} in {example:?} \
                         (detector {})",
                        m.detector_id
                    );
                }
            }
        }
        if fired {
            detectors_exercised += 1;
        }
    }

    assert!(
        detectors_exercised >= 700,
        "expected findings from a large slice of the corpus, got {detectors_exercised}"
    );
    assert!(
        findings_checked >= 700,
        "expected many findings to validate, got {findings_checked}"
    );
    eprintln!(
        "finding invariants: {findings_checked} findings across {detectors_exercised} detectors OK"
    );
}
