//! Regression gate for #69 - every fallback-bucket detector (asana-pat
//! and ~3100 similar prefix-less / unicode-rejected detectors) was
//! silently dead because the SIMD/GPU hot path never called
//! `scan_fallback_patterns`. Fix: the call now runs after
//! `extract_confirmed_patterns` in `scan_prepared_with_triggered`, the
//! single per-chunk tail shared by the SIMD/CPU and megakernel coalesced
//! paths (via `scan_coalesced_phase2`). This test asserts the wire is
//! alive - if a future refactor drops the call again, this catches it.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use regex::Regex;
#[test]
fn asana_regex_matches_standalone() {
    let re = Regex::new(r"1/[0-9]{16,20}/[a-zA-Z0-9]{32,48}").expect("compile");
    let s = "asana_token=1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU";
    let m = re.find(s).expect("regex must match the canonical sample");
    eprintln!("matched: {:?}", m.as_str());
    assert!(m.as_str().starts_with("1/"));
}

#[test]
fn asana_pat_fires_after_fallback_wire_fix() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let asana_spec = detectors
        .iter()
        .find(|d| d.id == "asana-pat")
        .expect("asana-pat detector must be loaded");
    eprintln!("keywords: {:?}", asana_spec.keywords);
    eprintln!("pattern count: {}", asana_spec.patterns.len());
    eprintln!("first regex: {}", asana_spec.patterns[0].regex);
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = Chunk {
        data: "asana_token=1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU".into(),
        metadata: ChunkMetadata {
            source_type: "probe".into(),
            path: Some("probe.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    for m in &matches {
        eprintln!(
            "match: detector_id={:?} credential={:?}",
            m.detector_id, m.credential
        );
    }
    let asana_fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "asana-pat");
    assert!(
        asana_fired,
        "asana-pat must fire on the canonical 1/userid/token sample (issue #69 fix)."
    );
}
