//! Detector-catalog test support: the bundled detector-id set used by the
//! detector-id corpus-guard tests (`detector_ids.rs`) to prove that every scanner
//! detector-id const/predicate names a real embedded detector.
//!
//! This is TEST-ONLY (`#[cfg(test)]`). It once also hosted
//! `validate_rule_detector_ids` — a Tier-B rule-file detector-id-list validator —
//! but the DET-0 migration moved every per-detector property onto the detector's
//! OWN spec (`weak_anchor` / `private_key_block` / `credential_shape`), so no rule
//! file carries a detector-id list anymore and the validator had no production
//! caller. It was removed rather than left as dead code (Law 11 — a symbol used by
//! nothing but its own tests is decoration).

#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::sync::OnceLock;

/// The set of every bundled detector id, loaded once, fail-closed. Test-only: the
/// only callers are the `#[cfg(test)]` corpus-guards in `detector_ids.rs` (and the
/// tests below), which assert the scanner's detector-id consts name real embedded
/// detectors.
#[cfg(test)]
pub(crate) fn bundled_detector_ids() -> Result<&'static HashSet<String>, String> {
    static DETECTOR_IDS: OnceLock<Result<HashSet<String>, String>> = OnceLock::new();
    DETECTOR_IDS
        .get_or_init(|| {
            keyhog_core::load_embedded_detectors_or_fail()
                .map(|detectors| {
                    detectors
                        .into_iter()
                        .map(|detector| detector.id)
                        .collect::<HashSet<_>>()
                })
                .map_err(|error| format!("failed to load bundled detector ids: {error}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_detector_ids_is_nonempty() {
        let ids = bundled_detector_ids().unwrap();
        assert!(!ids.is_empty());
    }

    #[test]
    fn bundled_detector_ids_is_memoized_to_the_same_instance() {
        let first = bundled_detector_ids().unwrap();
        let second = bundled_detector_ids().unwrap();
        assert!(std::ptr::eq(first, second));
    }
}
