//! Regression: a service-anchored ("named") detector whose regex required a
//! context anchor (a service-specific keyword next to a value of the contracted
//! shape) must clear the `min_confidence` floor on the strength of that anchor
//! alone.
//!
//! `compute_confidence` is a normalized signal sum: it divides earned weight by
//! the full signal set (literal prefix, sensitive file, companion, ...). A
//! keyword-anchored service detector earns the context-anchor weight but
//! structurally cannot earn the others, so a real `Splunk=<uuid>` match landed
//! below the default `0.40` floor and was dropped as `below_min_confidence` —
//! the dominant cause of 538 contract-positive misses (recovered 467 here).
//!
//! The fix lifts such matches to [`NAMED_DETECTOR_ANCHOR_FLOOR`]; it is FP-safe
//! because generic / entropy / private-key-fallback / weak-anchor detectors are
//! excluded upstream (`is_named_detector == is_service_anchored_detector &&
//! !weak_anchor`) and keep the full gate stack. Negative twins below pin that
//! the lift requires the service-anchored match (not the bare value shape).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{apply_named_detector_anchor_floor, NAMED_DETECTOR_ANCHOR_FLOOR};
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
            source_type: "named-anchor-floor-regression".into(),
            path: Some("notes/anchor-floor-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

fn surfaced(matches: &[(String, String)], detector_id: &str, credential_substr: &str) -> bool {
    matches
        .iter()
        .any(|(id, found)| id == detector_id && found.contains(credential_substr))
}

fn detector_fired(matches: &[(String, String)], detector_id: &str) -> bool {
    matches.iter().any(|(id, _)| id == detector_id)
}

#[test]
fn named_detector_anchor_floor_lifts_only_named_context_anchored_matches() {
    // Named + context anchor: lifted to the floor (the keyword-required regex
    // match is positive evidence the normalized signal sum under-credits).
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, true, true),
        NAMED_DETECTOR_ANCHOR_FLOOR,
        "named + context-anchored match must lift to the floor"
    );
    // Not named (generic / entropy / weak-anchor): unchanged — the collision-
    // prone shapes keep the full gate stack.
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, false, true),
        0.30,
        "non-named detector must not be lifted"
    );
    // Named but no context anchor (bare-value literal pattern): unchanged.
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, true, false),
        0.30,
        "named detector without a context anchor must not be lifted"
    );
    // Floor, never a cap: a stronger match keeps its higher score.
    assert_eq!(
        apply_named_detector_anchor_floor(0.80, true, true),
        0.80,
        "lift is a floor (max), never a cap"
    );
    assert!(
        NAMED_DETECTOR_ANCHOR_FLOOR > 0.40,
        "floor must clear the default 0.40 min_confidence with headroom"
    );
}

#[test]
fn keyword_anchored_service_detector_positive_surfaces() {
    // `splunk-hec-token`: `Splunk` keyword + UUID. The UUID earns only the
    // context-anchor weight, so pre-fix it scored below the 0.40 floor and was
    // dropped as `below_min_confidence`. It must now surface.
    let matches = matches_for("Splunk=70977ea1-11e0-e768-18f3-48ab955cd5fc");
    assert!(
        surfaced(
            &matches,
            "splunk-hec-token",
            "70977ea1-11e0-e768-18f3-48ab955cd5fc"
        ),
        "Splunk-keyword-anchored HEC token must surface; matches={matches:?}"
    );
}

#[test]
fn bare_uuid_without_service_keyword_does_not_claim_the_named_detector() {
    // The lift rides on the service-anchored *match*, not the value shape: a
    // bare UUID with no `Splunk` keyword does not match the detector regex, so
    // the named detector must not fire (no anchor → no lift → no claim).
    let matches = matches_for("request_id = 70977ea1-11e0-e768-18f3-48ab955cd5fc");
    assert!(
        !detector_fired(&matches, "splunk-hec-token"),
        "bare UUID without the Splunk anchor must not fire splunk-hec-token; matches={matches:?}"
    );
}
