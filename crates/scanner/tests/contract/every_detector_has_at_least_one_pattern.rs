//! Contract: every RUNTIME-LOADED detector can fire, via a regex pattern, or
//! (for the generic/entropy family alone) via keyword + entropy with no pattern.
//!
//! This pins the GATED `load_detectors` population (what the scanner actually
//! runs). The embedded-corpus twin (`detector_registry_truth_matrix.rs`) pins
//! the same invariant over the ungated embed and additionally guards that the
//! pattern-less set is EXACTLY the generic family. Both apply the ONE owner of
//! "is this the pattern-less-by-design family?": `is_generic_or_entropy_detector`
//! (so the exemption can never diverge between the two load paths).

use crate::support::paths::detector_dir;

#[test]
fn every_detector_has_at_least_one_pattern() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    // A pattern-less detector can never fire via the AC/regex scan path. The ONE
    // legitimate exception is the generic/entropy family (generic-secret /
    // generic-api-key / generic-keyword-secret), which fires via the
    // phase2-generic + entropy path anchored by keyword + entropy_floor with NO
    // regex by design. Every OTHER pattern-less detector is dead corpus weight.
    let bare: Vec<_> = detectors
        .iter()
        .filter(|d| d.patterns.is_empty())
        .filter(|d| !keyhog_scanner::is_generic_or_entropy_detector(&d.id))
        .map(|d| d.id.as_str())
        .collect();

    assert!(
        bare.is_empty(),
        "non-generic detectors with zero patterns (unmatchable, dead weight): {:?}",
        bare
    );
}
