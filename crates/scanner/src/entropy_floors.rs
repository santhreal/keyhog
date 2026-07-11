//! Per-detector generic entropy floors, sourced from the detector TOMLs.
//!
//! The floor a generic-detector candidate must clear to survive the low-entropy
//! suppression gate ([`crate::adjudicate::generic_entropy_floor`]) is owned in
//! each generic detector's OWN `detectors/<id>.toml` `entropy_floor` field — the
//! single home for that knob (there is no separate `rules/entropy-floors.toml`,
//! no hardcoded `match`, no override). This module builds the runtime lookup
//! ONCE from the embedded detector corpus and exposes the single [`family_floor`]
//! lookup. Floors are length-bucketed, so re-tuning a family is a data edit in
//! that detector's TOML, never a source change. The Tier-A `entropy_threshold`
//! override stays in `adjudicate`, so this module owns only the calibration DATA.

use keyhog_core::{DetectorSpec, EntropyFloorBucket};
use std::sync::LazyLock;

/// Floor for any generic detector that declares no `entropy_floor` bucket. The
/// ONE owner of the generic default (was `rules/entropy-floors.toml`
/// `default_floor`). A detector opts into a stricter/looser floor by declaring
/// `entropy_floor` in its TOML; everything else clears this default.
pub(crate) const DEFAULT_FLOOR: f64 = 3.5;

/// A validated, length-bucketed entropy-floor table keyed by detector id.
///
/// Keyed lookup, NOT a linear scan: `family_floor` runs per surviving generic
/// candidate on the scan path, and the per-detector-everything direction (A5)
/// means the family count grows from a handful toward the full corpus — an
/// O(families) string-compare walk per candidate would silently become a
/// Law-7 hot-path regression as detectors adopt `entropy_floor`.
#[derive(Debug)]
pub(crate) struct EntropyFloorTable {
    families: std::collections::HashMap<String, Vec<EntropyFloorBucket>>,
}

impl EntropyFloorTable {
    /// The calibrated Shannon-entropy floor for `detector_id` at `credential_len`.
    ///
    /// Returns the first bucket (in TOML order) whose `max_len >= credential_len`,
    /// or the family catch-all bucket, or [`DEFAULT_FLOOR`] for any detector that
    /// declares no `entropy_floor`. Never applies the Tier-A `entropy_threshold`
    /// override — that is the caller's job (`adjudicate::generic_entropy_floor`).
    pub(crate) fn family_floor(&self, detector_id: &str, credential_len: usize) -> f64 {
        let Some(buckets) = self.families.get(detector_id) else {
            return DEFAULT_FLOOR;
        };
        buckets
            .iter()
            .find(|bucket| bucket.max_len.is_none_or(|max| credential_len <= max))
            .map_or(DEFAULT_FLOOR, |bucket| bucket.floor)
    }

    /// Build the table from the detector corpus: every detector that declares an
    /// `entropy_floor` contributes one family. Each detector's buckets are
    /// validated for well-formedness; an invalid floor is a corpus bug and is
    /// returned as an error (the caller fails closed — see [`ENTROPY_FLOORS`]).
    fn from_specs(specs: &[DetectorSpec]) -> Result<Self, String> {
        let mut families = std::collections::HashMap::new();
        for spec in specs {
            if spec.entropy_floor.is_empty() {
                continue;
            }
            validate_buckets(&spec.id, &spec.entropy_floor)?;
            families.insert(spec.id.clone(), spec.entropy_floor.clone());
        }
        Ok(Self { families })
    }
}

static ENTROPY_FLOORS: LazyLock<EntropyFloorTable> = LazyLock::new(|| {
    let specs = keyhog_core::load_embedded_detectors_or_fail().unwrap_or_else(|error| {
        panic!(
            "embedded detector corpus failed to load for entropy floors: {error}. \
             The generic-detector entropy floors live in the detector TOMLs; refusing \
             to run without them."
        )
    });
    EntropyFloorTable::from_specs(&specs).unwrap_or_else(|error| {
        panic!(
            "a detector's entropy_floor is invalid: {error}. Fix the offending \
             detector TOML's `entropy_floor` buckets."
        )
    })
});

/// The calibrated base entropy floor for `detector_id` at `credential_len`.
pub(crate) fn family_floor(detector_id: &str, credential_len: usize) -> f64 {
    ENTROPY_FLOORS.family_floor(detector_id, credential_len)
}

fn finite_non_negative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

/// Validate one detector's `entropy_floor` buckets. Same well-formedness contract
/// the separate rules file used to enforce, now applied per detector: only the
/// LAST bucket may omit `max_len` (the catch-all); a non-final catch-all would
/// shadow later buckets, and a final bucket WITH `max_len` would leave longer
/// values with no floor (a silent recall hole); `max_len` must strictly increase;
/// every floor must be finite and non-negative.
fn validate_buckets(detector_id: &str, buckets: &[EntropyFloorBucket]) -> Result<(), String> {
    // Empty is handled by the caller (skipped = no floor), so buckets is non-empty here.
    let last = buckets.len() - 1;
    for (index, bucket) in buckets.iter().enumerate() {
        if !finite_non_negative(bucket.floor) {
            return Err(format!(
                "detector '{detector_id}' entropy_floor bucket {index} has a non-finite or \
                 negative floor ({})",
                bucket.floor
            ));
        }
        if index < last && bucket.max_len.is_none() {
            return Err(format!(
                "detector '{detector_id}' entropy_floor has a catch-all bucket before the last \
                 position (only the final bucket may omit max_len)"
            ));
        }
        if index == last && bucket.max_len.is_some() {
            return Err(format!(
                "detector '{detector_id}' entropy_floor final bucket must be the catch-all \
                 (omit max_len)"
            ));
        }
    }
    let mut previous = 0usize;
    for bucket in buckets {
        if let Some(max) = bucket.max_len {
            if max <= previous {
                return Err(format!(
                    "detector '{detector_id}' entropy_floor max_len values must strictly increase \
                     (got {max} after {previous})"
                ));
            }
            previous = max;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Detector ids are referenced through the `detector_ids` constants, never as
    // string literals — the `detector_id_owner` gate requires `detector_ids.rs` to
    // be the sole owner of scanner detector-identity literals.
    use super::*;
    use crate::detector_ids::{
        GENERIC_API_KEY, GENERIC_KEYWORD_SECRET, GENERIC_PASSWORD, GENERIC_SECRET,
    };

    /// The live table, built from the embedded detector corpus — the exact path
    /// production uses. Every value assertion below therefore proves the shipped
    /// detector TOMLs carry the intended floors.
    fn table() -> EntropyFloorTable {
        let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
        EntropyFloorTable::from_specs(&specs).expect("corpus entropy_floor buckets are valid")
    }

    /// The exact floor logic this refactor replaced (adjudicate `generic_entropy_floor`
    /// match arms, before the Tier-B move to the detector TOMLs). The parity test below
    /// proves the corpus-loaded table reproduces this for every family and length
    /// bucket — no floor changed, so recall is unaffected.
    fn legacy_base_floor(detector_id: &str, credential_len: usize) -> f64 {
        match detector_id {
            id if id == GENERIC_API_KEY && credential_len <= 24 => 3.0,
            id if id == GENERIC_API_KEY && credential_len <= 40 => 2.8,
            id if id == GENERIC_API_KEY => 3.5,
            id if id == GENERIC_PASSWORD => 2.5,
            id if id == GENERIC_SECRET && credential_len <= 24 => 2.8,
            id if id == GENERIC_SECRET && credential_len <= 40 => 3.2,
            id if id == GENERIC_SECRET => 3.5,
            id if id == GENERIC_KEYWORD_SECRET => 1.5,
            _ => 3.5,
        }
    }

    #[test]
    fn corpus_table_builds() {
        let _ = table();
    }

    #[test]
    fn api_key_short_bucket_is_3_0() {
        assert_eq!(table().family_floor(GENERIC_API_KEY, 10), 3.0);
        assert_eq!(table().family_floor(GENERIC_API_KEY, 24), 3.0);
    }

    #[test]
    fn api_key_mid_bucket_is_2_8() {
        assert_eq!(table().family_floor(GENERIC_API_KEY, 25), 2.8);
        assert_eq!(table().family_floor(GENERIC_API_KEY, 40), 2.8);
    }

    #[test]
    fn api_key_long_bucket_is_3_5() {
        assert_eq!(table().family_floor(GENERIC_API_KEY, 41), 3.5);
        assert_eq!(table().family_floor(GENERIC_API_KEY, 100), 3.5);
    }

    #[test]
    fn api_key_boundary_24_25_steps_down() {
        let t = table();
        assert_eq!(t.family_floor(GENERIC_API_KEY, 24), 3.0);
        assert_eq!(t.family_floor(GENERIC_API_KEY, 25), 2.8);
    }

    #[test]
    fn api_key_boundary_40_41_steps_up() {
        let t = table();
        assert_eq!(t.family_floor(GENERIC_API_KEY, 40), 2.8);
        assert_eq!(t.family_floor(GENERIC_API_KEY, 41), 3.5);
    }

    #[test]
    fn api_key_length_zero_uses_short_bucket() {
        assert_eq!(table().family_floor(GENERIC_API_KEY, 0), 3.0);
    }

    #[test]
    fn secret_short_bucket_is_2_8() {
        assert_eq!(table().family_floor(GENERIC_SECRET, 10), 2.8);
        assert_eq!(table().family_floor(GENERIC_SECRET, 24), 2.8);
    }

    #[test]
    fn secret_mid_bucket_is_3_2() {
        assert_eq!(table().family_floor(GENERIC_SECRET, 25), 3.2);
        assert_eq!(table().family_floor(GENERIC_SECRET, 40), 3.2);
    }

    #[test]
    fn secret_long_bucket_is_3_5() {
        assert_eq!(table().family_floor(GENERIC_SECRET, 41), 3.5);
        assert_eq!(table().family_floor(GENERIC_SECRET, 200), 3.5);
    }

    #[test]
    fn secret_boundary_24_25_steps_up() {
        let t = table();
        assert_eq!(t.family_floor(GENERIC_SECRET, 24), 2.8);
        assert_eq!(t.family_floor(GENERIC_SECRET, 25), 3.2);
    }

    #[test]
    fn secret_boundary_40_41_steps_up() {
        let t = table();
        assert_eq!(t.family_floor(GENERIC_SECRET, 40), 3.2);
        assert_eq!(t.family_floor(GENERIC_SECRET, 41), 3.5);
    }

    #[test]
    fn password_floor_is_2_5_at_every_length() {
        let t = table();
        assert_eq!(t.family_floor(GENERIC_PASSWORD, 5), 2.5);
        assert_eq!(t.family_floor(GENERIC_PASSWORD, 50), 2.5);
        assert_eq!(t.family_floor(GENERIC_PASSWORD, 500), 2.5);
    }

    #[test]
    fn keyword_secret_floor_is_1_5() {
        assert_eq!(table().family_floor(GENERIC_KEYWORD_SECRET, 12), 1.5);
    }

    #[test]
    fn unknown_detector_uses_default_floor() {
        // A named (non-generic) detector and the empty id both fall through to the
        // default. The literal here is intentionally NOT any real detector id.
        assert_eq!(table().family_floor("some-named-vendor-detector", 20), 3.5);
        assert_eq!(table().family_floor("", 20), 3.5);
    }

    #[test]
    fn loaded_table_matches_legacy_floor_for_every_family_and_length() {
        let t = table();
        let detectors = [
            GENERIC_API_KEY,
            GENERIC_SECRET,
            GENERIC_PASSWORD,
            GENERIC_KEYWORD_SECRET,
            "some-named-vendor-detector",
            "",
        ];
        // Sweep the boundaries and a spread of lengths on both sides of every rung.
        for detector in detectors {
            for len in [0usize, 1, 8, 16, 23, 24, 25, 32, 39, 40, 41, 64, 128, 512] {
                assert_eq!(
                    t.family_floor(detector, len),
                    legacy_base_floor(detector, len),
                    "floor drift for detector={detector:?} len={len}: refactor must not change any value"
                );
            }
        }
    }

    #[test]
    fn floor_declaring_detectors_are_exactly_the_generic_ids() {
        let t = table();
        let mut ids: Vec<&str> = t.families.keys().map(String::as_str).collect();
        ids.sort_unstable();
        let mut expected = vec![
            GENERIC_API_KEY,
            GENERIC_SECRET,
            GENERIC_PASSWORD,
            GENERIC_KEYWORD_SECRET,
        ];
        expected.sort_unstable();
        assert_eq!(
            ids, expected,
            "exactly the generic detectors declare an entropy_floor in their TOML"
        );
    }

    // Bucket-validation fixtures use a non-detector id (`fam-a`) so the tests
    // exercise structural validation without embedding real detector-id literals.
    fn bucket(max_len: Option<usize>, floor: f64) -> EntropyFloorBucket {
        EntropyFloorBucket { max_len, floor }
    }

    #[test]
    fn validate_rejects_catch_all_before_last() {
        let err =
            validate_buckets("fam-a", &[bucket(None, 3.0), bucket(Some(40), 2.8)]).unwrap_err();
        assert!(
            err.contains("catch-all bucket before the last"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_rejects_final_bucket_with_max_len() {
        let err =
            validate_buckets("fam-a", &[bucket(Some(24), 3.0), bucket(Some(40), 2.8)]).unwrap_err();
        assert!(
            err.contains("final bucket must be the catch-all"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_rejects_non_increasing_max_len() {
        let err = validate_buckets(
            "fam-a",
            &[
                bucket(Some(40), 3.0),
                bucket(Some(24), 2.8),
                bucket(None, 3.5),
            ],
        )
        .unwrap_err();
        assert!(err.contains("strictly increase"), "got: {err}");
    }

    #[test]
    fn validate_rejects_negative_bucket_floor() {
        let err = validate_buckets("fam-a", &[bucket(None, -0.5)]).unwrap_err();
        assert!(err.contains("non-finite or negative floor"), "got: {err}");
    }

    #[test]
    fn validate_accepts_well_formed_single_and_multi_bucket() {
        validate_buckets("fam-a", &[bucket(None, 2.5)]).expect("single catch-all is valid");
        validate_buckets(
            "fam-a",
            &[
                bucket(Some(24), 3.0),
                bucket(Some(40), 2.8),
                bucket(None, 3.5),
            ],
        )
        .expect("increasing buckets with final catch-all are valid");
    }

    #[test]
    fn override_raises_floor_when_threshold_exceeds_default() {
        // The Tier-A entropy_threshold override lives in adjudicate; prove the two
        // compose: a stricter-than-default threshold raises the family base floor.
        assert_eq!(
            crate::adjudicate::generic_entropy_floor(5.0, GENERIC_API_KEY, 10),
            5.0
        );
    }

    #[test]
    fn override_is_noop_at_or_below_default_threshold() {
        assert_eq!(
            crate::adjudicate::generic_entropy_floor(4.5, GENERIC_API_KEY, 10),
            3.0
        );
        assert_eq!(
            crate::adjudicate::generic_entropy_floor(0.0, GENERIC_SECRET, 30),
            3.2
        );
    }
}
