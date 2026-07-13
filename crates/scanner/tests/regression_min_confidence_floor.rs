//! Regression: the post-scan `min_confidence` floor, global default AND the
//! per-detector `spec.min_confidence` override, decides, exactly, which
//! findings survive.
//!
//! The floor is a pure `confidence < floor` gate applied after the confidence
//! is computed (`crates/scanner/src/adjudicate/mod.rs::final_emit_suppression_stage`,
//! `crates/scanner/src/engine/process.rs`). The *effective* floor for a match is
//! `detector.min_confidence.unwrap_or(config.min_confidence)`
//! (`adjudicate::detector_min_confidence_floor`): a detector's self-declared
//! floor WINS over the global `[scan] min_confidence` when present, else the
//! global default (0.40) applies. This file proves that resolution end-to-end on
//! the real scanner + the shipped detector corpus.
//!
//! ANCHOR DETECTOR: `sourcegraph-access-token`. It ships `min_confidence = 0.2`
//! (a per-detector floor BELOW the 0.40 global default). Its `sgp_<40 hex>` body
//! scores low on entropy alone, but under the anchored `SRC_ACCESS_TOKEN=` context
//! the observed confidence is a *stable value ~0.70* (context boosts it above the
//! global default). That still makes it the ideal probe: the confidence is
//! deterministic, so a per-detector floor set just above/below/equal to the
//! OBSERVED value (`sgp_confidence()`) flips the finding deterministically, which
//! is exactly what the per-detector-floor `>=` semantics must honour. (This
//! fixture clears the global default on its own; the 0.2 floor is load-bearing
//! only for lower-scoring sourcegraph bodies, which these tests note explicitly.)
//!
//! HOST-INDEPENDENCE: `sgp_` is a distinctive LITERAL prefix, so the detector
//! fires on the scalar `CpuFallback` path (it does not depend on Hyperscan/SIMD
//! the way a no-literal detector such as `datadog-api-key` does). Every scan
//! here forces `ScanBackend::CpuFallback`, so the confidence, and therefore the
//! floor decision (is identical on every host, GPU or not).

mod support;
use keyhog_core::{load_detectors, Chunk, DetectorSpec, RawMatch, ScanConfig};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use support::paths::detector_dir;

/// Detector whose shipped per-detector `min_confidence` (0.2) undercuts the
/// global 0.40 default.
const SGP_DETECTOR_ID: &str = "sourcegraph-access-token";

/// The detector's own `test_positive` credential (`sgp_<40 hex>`, group 0).
const SGP_TOKEN: &str = "sgp_210f1131b08e93adcfc3f05faa2d768ff883a61f";

/// The detector's own `test_positive` line. Anchored context (`SRC_ACCESS_TOKEN=`)
/// is the shape the contract harness fires on; under that context the observed
/// confidence is ~0.70 (above the 0.40 global default).
const CHUNK_TEXT: &str = "SRC_ACCESS_TOKEN=sgp_210f1131b08e93adcfc3f05faa2d768ff883a61f\n";

/// The full shipped detector corpus, loaded once.
fn load_base() -> Vec<DetectorSpec> {
    load_detectors(&detector_dir())
        .unwrap_or_else(|e| panic!("load detectors from {}: {e}", detector_dir().display()))
}

/// Clone the corpus, overriding ONLY the sourcegraph detector's per-detector
/// `min_confidence`: every other detector is untouched, so the floor decision
/// is isolated to this one detector.
fn with_sgp_floor(base: &[DetectorSpec], floor: Option<f64>) -> Vec<DetectorSpec> {
    base.iter()
        .cloned()
        .map(|mut d| {
            if d.id == SGP_DETECTOR_ID {
                d.min_confidence = floor;
            }
            d
        })
        .collect()
}

/// Scan the fixed sourcegraph chunk on the deterministic scalar backend and
/// return every raw match.
fn scan(detectors: Vec<DetectorSpec>, global_floor: f64) -> Vec<RawMatch> {
    let config = ScannerConfig::default().min_confidence(global_floor);
    let scanner = CompiledScanner::compile(detectors)
        .expect("scanner compiles from the shipped detector corpus")
        .with_config(config);
    let chunk = Chunk::from(CHUNK_TEXT.to_string());
    scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback)
}

/// The sourcegraph-attributed match for our planted token, if it survived. Keyed
/// on `detector_id` so any unrelated generic finding on the same value (a
/// distinct dedup key: `RawMatchDedupKey` includes `detector_id`) can never
/// mask the floor decision for THIS detector.
fn sgp_finding(matches: &[RawMatch]) -> Option<&RawMatch> {
    matches
        .iter()
        .find(|m| &*m.detector_id == SGP_DETECTOR_ID && (&*m.credential).contains(SGP_TOKEN))
}

/// True iff the sourcegraph finding survives the given detector/global floors.
fn sgp_present(detectors: Vec<DetectorSpec>, global_floor: f64) -> bool {
    let matches = scan(detectors, global_floor);
    sgp_finding(&matches).is_some()
}

/// The computed confidence of the sourcegraph finding, observed with NO
/// per-detector floor and a permissive 0.0 global floor so nothing can gate it.
/// The floor never feeds back into the confidence, so this value is stable
/// across every other scan in this file.
fn sgp_confidence(base: &[DetectorSpec]) -> f64 {
    let matches = scan(with_sgp_floor(base, None), 0.0);
    let m = sgp_finding(&matches).unwrap_or_else(|| {
        panic!(
            "sourcegraph token must surface at global floor 0.0 with no per-detector floor \
             (got {} matches, none attributed to {SGP_DETECTOR_ID})",
            matches.len()
        )
    });
    m.confidence
        .expect("a named sourcegraph match must carry a confidence score")
}

// ---------------------------------------------------------------------------
// The default floor value.
// ---------------------------------------------------------------------------

/// The compiled Tier-A default floor is exactly 0.40, on both the core config
/// and the scanner config that derefs to it.
#[test]
fn default_min_confidence_floor_is_0_40() {
    assert!(
        (ScanConfig::default().min_confidence - 0.40).abs() < 1e-12,
        "ScanConfig default floor must be 0.40, got {}",
        ScanConfig::default().min_confidence
    );
    assert!(
        (ScannerConfig::default().min_confidence - 0.40).abs() < 1e-12,
        "ScannerConfig default must inherit the canonical 0.40 floor, got {}",
        ScannerConfig::default().min_confidence
    );
}

/// The sourcegraph detector ships a self-declared per-detector floor of 0.2.
#[test]
fn sourcegraph_ships_per_detector_floor_of_0_2() {
    let base = load_base();
    let spec = base
        .iter()
        .find(|d| d.id == SGP_DETECTOR_ID)
        .expect("sourcegraph-access-token detector ships in the corpus");
    let floor = spec
        .min_confidence
        .expect("sourcegraph ships a self-declared per-detector floor");
    assert!(
        (floor - 0.2).abs() < 1e-12,
        "sourcegraph per-detector floor must be 0.2, got {floor}"
    );
}

// ---------------------------------------------------------------------------
// The observed confidence clears both the 0.2 floor and the 0.40 global default.
// ---------------------------------------------------------------------------

/// The finding's confidence is at/above its shipped 0.2 floor (so the detector
/// works out of the box) and, under the anchored context, above the 0.40 global
/// default. If the observed value ever drops below 0.40 the "clears the default"
/// tests below must be revisited (a real coherence signal).
#[test]
fn sourcegraph_confidence_clears_its_floor_and_the_global_default() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        c >= 0.2 - 1e-9,
        "sourcegraph body must score at/above its shipped 0.2 floor, got {c}"
    );
    // This token's body scores ABOVE the 0.40 global default, so it survives on
    // its own merits; the per-detector floor (0.2) only becomes load-bearing for
    // LOWER-scoring sourcegraph bodies. Pin the concrete observed relationship.
    assert!(
        c > 0.40,
        "this sourcegraph body scores above the 0.40 global default, got {c}"
    );
}

// ---------------------------------------------------------------------------
// Per-detector floor override: keeps what the global default would drop.
// ---------------------------------------------------------------------------

/// The shipped detector (per-detector floor 0.2) surfaces its own test_positive
/// under the 0.40 global default: with the observed confidence ~0.70 the finding
/// clears both floors and is kept.
#[test]
fn shipped_sourcegraph_detector_surfaces_at_the_global_default() {
    let base = load_base();
    assert!(
        sgp_present(base, 0.40),
        "the shipped sourcegraph detector must surface its test_positive under \
         the global 0.40 default"
    );
}

/// With the per-detector floor REMOVED, the global 0.40 default applies. This
/// token scores above 0.40, so it survives, the floor is load-bearing only for
/// sourcegraph bodies scoring in [0.2, 0.40), which this fixture is not.
#[test]
fn removing_per_detector_floor_keeps_finding_that_clears_global_default() {
    let base = load_base();
    assert!(
        sgp_present(with_sgp_floor(&base, None), 0.40),
        "a sourcegraph finding scoring above 0.40 survives the global default \
         even with the per-detector floor removed"
    );
}

/// The per-detector floor overrides even a punishing global floor: 0.2 beats
/// 0.99, and the finding survives.
#[test]
fn per_detector_floor_overrides_a_high_global_floor() {
    let base = load_base();
    assert!(
        sgp_present(base, 0.99),
        "a per-detector floor of 0.2 must override even a 0.99 global floor \
         and keep the finding"
    );
}

/// Mirror direction: a per-detector floor set ABOVE the finding's confidence
/// drops it even when the global floor is a permissive 0.0, the detector floor
/// is consulted regardless of how low the global is.
#[test]
fn per_detector_floor_above_confidence_drops_despite_permissive_global() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        !sgp_present(with_sgp_floor(&base, Some(c + 0.05)), 0.0),
        "a per-detector floor above the finding's confidence ({c}) must drop it \
         even though the global floor is a permissive 0.0"
    );
}

// ---------------------------------------------------------------------------
// Exact boundary of the per-detector floor (>= semantics).
// ---------------------------------------------------------------------------

/// `confidence == floor` is KEPT: the gate drops only `confidence < floor`.
#[test]
fn boundary_per_detector_floor_equal_to_confidence_keeps() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        sgp_present(with_sgp_floor(&base, Some(c)), 0.0),
        "confidence == floor must be kept (>= semantics), C={c}"
    );
}

/// A per-detector floor 1e-4 ABOVE the confidence drops the finding.
#[test]
fn boundary_per_detector_floor_just_above_confidence_drops() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        !sgp_present(with_sgp_floor(&base, Some(c + 1e-4)), 0.0),
        "a per-detector floor 1e-4 above the confidence must drop the finding, C={c}"
    );
}

/// A per-detector floor 1e-4 BELOW the confidence keeps the finding.
#[test]
fn boundary_per_detector_floor_just_below_confidence_keeps() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        sgp_present(with_sgp_floor(&base, Some(c - 1e-4)), 0.0),
        "a per-detector floor 1e-4 below the confidence must keep the finding, C={c}"
    );
}

// ---------------------------------------------------------------------------
// Exact boundary of the GLOBAL floor (per-detector floor removed).
// ---------------------------------------------------------------------------

/// With no per-detector floor, `global_floor == confidence` is KEPT (same
/// >= semantics resolved through the global default path).
#[test]
fn boundary_global_floor_equal_to_confidence_keeps_when_no_per_detector_floor() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        sgp_present(with_sgp_floor(&base, None), c),
        "with no per-detector floor, global floor == confidence must keep the finding, C={c}"
    );
}

/// With no per-detector floor, a global floor 1e-4 above the confidence drops it.
#[test]
fn boundary_global_floor_just_above_confidence_drops_when_no_per_detector_floor() {
    let base = load_base();
    let c = sgp_confidence(&base);
    assert!(
        !sgp_present(with_sgp_floor(&base, None), c + 1e-4),
        "with no per-detector floor, a global floor 1e-4 above the confidence \
         must drop the finding, C={c}"
    );
}

// ---------------------------------------------------------------------------
// Global floor extremes.
// ---------------------------------------------------------------------------

/// A global floor of 0.0 keeps every surfaced finding (nothing is < 0.0).
#[test]
fn global_floor_zero_keeps_finding_when_no_per_detector_floor() {
    let base = load_base();
    assert!(
        sgp_present(with_sgp_floor(&base, None), 0.0),
        "a global floor of 0.0 must keep the surfaced finding"
    );
}

/// A global floor of 1.0 drops the sub-maximum-confidence finding.
#[test]
fn global_floor_of_one_drops_sub_max_confidence_finding() {
    let base = load_base();
    assert!(
        !sgp_present(with_sgp_floor(&base, None), 1.0),
        "a global floor of 1.0 must drop the sourcegraph finding whose confidence \
         is below the maximum"
    );
}
