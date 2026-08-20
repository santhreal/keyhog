//! Corpus-wide per-detector BACKEND PARITY (#177/#183). The SIMD trigger bitmap
//! unions AC-literal + Hyperscan hits; if a detector's trigger is missing from
//! one backend it fires on CPU but not SIMD (or vice-versa), a silent recall
//! divergence. This drives EACH detector's own regex-generated example through
//! both the CpuFallback and SimdCpu backends and asserts the set of firing
//! detectors is byte-for-byte identical. ML-independent; run without `ml` while
//! the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

fn fired_ids(scanner: &CompiledScanner, text: &str, backend: ScanBackend) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "corpus-parity".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    let mut ids: Vec<String> = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .expect("selected backend scan succeeds")
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.detector_id.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn unicode_rule_detector(id: &str, regex: &str, group: usize) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        name: id.into(),
        service: "unicode-parity".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            group: Some(group),
            ..Default::default()
        }],
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|detector| detector.match_confidence),
        ..Default::default()
    }
}

/// Regression suite for the exact SIMD prefilter bug: Hyperscan byte/ASCII
/// semantics rejected canonical Rust-regex matches using Unicode `\d`,
/// codepoint-width quantifiers, or the `ſ`/`K` simple-case-fold equivalents.
/// Positive, negative, boundary, adversarial-casefold, and multi-byte-dot cases
/// must all produce the same detector-id set on both production CPU routes.
#[test]
fn unicode_regex_semantics_are_backend_invariant() {
    let scanner = CompiledScanner::compile_with_runtime_policy(vec![
        unicode_rule_detector("unicode-digit", r"(?-i)udigit(\d{2})END", 1),
        unicode_rule_detector("unicode-casefold", r"(?i)casekey:([A-F0-9]{16})", 1),
        unicode_rule_detector("unicode-codepoint", r"(?-i)multi.([A-F0-9]{16})", 1),
    ])
    .expect("Unicode parity scanner compiles");
    let cases: [(&str, &str, &[&str]); 5] = [
        ("positive", "udigit៤꘩END", &["unicode-digit"]),
        ("negative", "udigitABEND", &[]),
        ("boundary", "udigit៤END", &[]),
        (
            "adversarial-casefold",
            "caſeKey:A1B2C3D4E5F60708",
            &["unicode-casefold"],
        ),
        (
            "representative-multi-byte",
            "multi🦀A1B2C3D4E5F60708",
            &["unicode-codepoint"],
        ),
    ];

    for (name, input, expected) in cases {
        let expected = expected.iter().map(ToString::to_string).collect::<Vec<_>>();
        let cpu = fired_ids(&scanner, input, ScanBackend::CpuFallback);
        let simd = fired_ids(&scanner, input, ScanBackend::SimdCpu);
        assert_eq!(cpu, expected, "{name}: scalar CPU contract");
        assert_eq!(simd, expected, "{name}: SIMD CPU contract");
    }
}

/// Regression contract: every shipped detector example must produce the same
/// detector-id set on the scalar CPU and Hyperscan-backed SIMD CPU routes,
/// including examples containing multi-byte UTF-8.
#[test]
fn cpu_and_simd_agree_on_every_detector_example() {
    let specs = keyhog_core::embedded_detector_specs().to_vec();
    let scanner =
        CompiledScanner::compile_with_runtime_policy(specs.clone()).expect("scanner compile");
    let mut runner = TestRunner::deterministic();

    let mut checked = 0u32;
    let mut divergences = Vec::new();
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
        checked += 1;
        let cpu = fired_ids(&scanner, &example, ScanBackend::CpuFallback);
        let simd = fired_ids(&scanner, &example, ScanBackend::SimdCpu);
        if cpu != simd {
            let only_cpu: Vec<_> = cpu.iter().filter(|id| !simd.contains(id)).collect();
            let only_simd: Vec<_> = simd.iter().filter(|id| !cpu.contains(id)).collect();
            divergences.push(format!(
                "{}: unicode={} only_cpu={only_cpu:?} only_simd={only_simd:?} ex={:?}",
                spec.id,
                !example.is_ascii(),
                example
            ));
        }
    }

    assert!(
        checked >= 800,
        "expected to exercise most of the corpus, only checked {checked}"
    );
    assert!(
        divergences.is_empty(),
        "CPU/SIMD backend divergence on {} detector examples: {:#?}",
        divergences.len(),
        divergences
    );
    eprintln!(
        "backend parity: {checked} detector examples; CPU == SIMD on all ASCII inputs; 0 unicode-input divergences"
    );
}
