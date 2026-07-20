//! Regression: the `weak_anchor` classification (which keeps the Tier-B shape
//! gates engaged for collision-prone captures) must be resolved PER MATCHED
//! PATTERN, not per detector.
//!
//! `servicenow-api-key` ships three patterns: a STRONG
//! `…instance=([a-z0-9-]+\.service-now\.com)` (anchored to the literal
//! `.service-now.com` host) and WEAK `…user=([a-zA-Z0-9_-]+)` /
//! `…password=(…)` patterns whose broad-identifier captures match any short
//! token. The detector-level classifier flagged the WHOLE detector weak because
//! ONE pattern is broad, so the strong instance match inherited the username
//! pattern's shape gates + lost the named-detector confidence floor and dropped
//! as `below_min_confidence`.
//!
//! The policy is explicit beside each detector pattern and compiled
//! into `CompiledPattern`; no regex-text inference or confidence-floor coupling
//! participates. The negative twin pins that the lift still rides on the
//! service-anchored match (the keyword), not the bare host shape.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "per-pattern-weak-anchor-regression".into(),
            path: Some("notes/per-pattern-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

#[test]
fn strong_pattern_in_a_multi_pattern_detector_keeps_its_anchor() {
    // The strong `instance=` pattern surfaces even though a sibling `user=`
    // pattern is broad-identifier (which had dragged the whole detector to
    // weak_anchor).
    let matches = matches_for("servicenow_instance=dev12345.service-now.com");
    assert!(
        matches
            .iter()
            .any(|(id, found)| id == "servicenow-api-key"
                && found.contains("dev12345.service-now.com")),
        "strong servicenow instance pattern must surface; matches={matches:?}"
    );
}

#[test]
fn bare_host_without_service_keyword_does_not_claim_the_detector() {
    // The strong pattern still REQUIRES the `servicenow…instance` keyword anchor:
    // a bare `*.service-now.com` host with no keyword does not match the regex,
    // so the detector must not fire on the host shape alone.
    let matches = matches_for("redirect_url = https://dev12345.service-now.com/login");
    assert!(
        !matches.iter().any(|(id, _)| id == "servicenow-api-key"),
        "bare service-now.com host without the keyword anchor must not fire; matches={matches:?}"
    );
}
