//! Regression: a service-anchored ("named") detector match carrying a strong
//! anchor, a required keyword **context anchor** (`Splunk=<uuid>`) OR a
//! distinctive **literal prefix** (`cs_…` cloudsmith, `pl_…` promptlayer), must
//! clear the `min_confidence` floor on the strength of that anchor alone.
//!
//! `compute_confidence` is a normalized signal sum: it divides earned weight by
//! the full signal set (literal prefix, context anchor, entropy, sensitive file,
//! companion, ...). A match that earns ONLY the anchor weight structurally
//! cannot earn the others, so a real `Splunk=<uuid>` or a bare `cs_<34 alnum>`
//! token landed below the default `0.40` floor and was dropped as
//! `below_min_confidence`: the dominant cause of the strict contract-positive
//! misses.
//!
//! The fix lifts such matches to [`NAMED_DETECTOR_ANCHOR_FLOOR`] when
//! `is_named_detector && (has_context_anchor || has_literal_prefix)`; it is
//! FP-safe because generic / entropy / private-key-fallback / weak-anchor
//! detectors are excluded upstream (`is_named_detector ==
//! is_service_anchored_detector && !weak_anchor`) and keep the full gate stack.
//! Negative twins below pin that the lift requires the service-anchored match
//! (the keyword or the literal prefix), not the bare value shape.

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
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
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
fn named_detector_anchor_floor_lifts_only_named_anchored_matches() {
    // Named + anchor (context keyword group OR distinctive literal prefix):
    // lifted to the floor. The caller passes `has_anchor = has_context_anchor
    // || has_literal_prefix`; the required-keyword match and the bare
    // literal-prefix token (`cs_…`, `pl_…`) are both positive evidence the
    // normalized signal sum under-credits.
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, true, true),
        NAMED_DETECTOR_ANCHOR_FLOOR,
        "named + anchored match must lift to the floor"
    );
    // Not named (generic / entropy / weak-anchor): unchanged, the collision-
    // prone shapes keep the full gate stack.
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, false, true),
        0.30,
        "non-named detector must not be lifted"
    );
    // Named but no anchor at all (bare-value match, no keyword, no literal
    // prefix): unchanged.
    assert_eq!(
        apply_named_detector_anchor_floor(0.30, true, false),
        0.30,
        "named detector without any anchor must not be lifted"
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
fn literal_prefix_bare_service_token_surfaces() {
    // cloudsmith-api-key: `(?-i)cs_[a-zA-Z0-9]{32,48}`. A bare token with NO
    // surrounding keyword has `has_context_anchor = false`; the distinctive
    // `cs_` literal prefix is the anchor that lifts it past the 0.40 floor
    // (pre-fix it dropped as `below_min_confidence`).
    let matches = matches_for("cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567");
    assert!(
        surfaced(
            &matches,
            "cloudsmith-api-key",
            "cs_AbCdEfGhIjKlMnOpQrStUvWxYz01234567"
        ),
        "bare cs_-prefixed cloudsmith token must surface on the literal prefix; matches={matches:?}"
    );

    // promptlayer-api-key: bare `pl_` token, same mechanism.
    let matches = matches_for("pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON");
    assert!(
        surfaced(
            &matches,
            "promptlayer-api-key",
            "pl_OhX5esA2JNCvMTNpyfUbF1xLPsfJUnON"
        ),
        "bare pl_-prefixed promptlayer token must surface on the literal prefix; matches={matches:?}"
    );

    // hanko-passkey-credentials: `(?:hanko_|corbado1_)[a-zA-Z0-9_-]{20,}`. The
    // branches share NO common head, so the single-prefix extractor returned
    // nothing and `has_literal_prefix` was false; the routing (plural) extractor
    // returns BOTH branch prefixes, so confidence now agrees that `hanko_` is a
    // distinctive anchor. Pins the multi-prefix-alternation recall.
    let matches = matches_for("hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF");
    assert!(
        surfaced(
            &matches,
            "hanko-passkey-credentials",
            "hanko_w5rqbu3NdOSohlPl0gstZPf_n6SdF"
        ),
        "bare hanko_-prefixed token (multi-prefix alternation) must surface; matches={matches:?}"
    );
}

#[test]
fn unprefixed_random_token_does_not_claim_a_literal_prefix_detector() {
    // The lift rides on the detector's literal prefix: a random token with no
    // `cs_` prefix does not match the cloudsmith regex, so the detector must
    // not fire (no prefix → no match → no claim).
    let matches = matches_for("AbCdEfGhIjKlMnOpQrStUvWxYz01234567");
    assert!(
        !matches.iter().any(|(id, _)| id == "cloudsmith-api-key"),
        "an unprefixed random token must not fire cloudsmith-api-key; matches={matches:?}"
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
