//! Per-family generic-detector entropy floors, loaded from Tier-B data.
//!
//! The floor table consumed by [`crate::adjudicate::generic_entropy_floor`] —
//! the minimum Shannon entropy a generic-detector candidate must clear to survive
//! the low-entropy suppression gate — lives in the Tier-B `rules/entropy-floors.toml`
//! file, NOT as a hardcoded `match` in code (CLAUDE.md: "Hardcoded lists are
//! banned"). Floors are calibrated per detector family and per length bucket, so
//! re-tuning a family (or adding one) is a data edit in the rules file, never a
//! source change. This module parses and caches that table once and exposes the
//! single [`family_floor`] lookup; the Tier-A `entropy_threshold` override stays
//! in `adjudicate` so this module owns only the calibration DATA.

use std::sync::LazyLock;

const ENTROPY_FLOORS_TOML: &str = include_str!("../../../rules/entropy-floors.toml");

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EntropyFloorFile {
    default_floor: f64,
    #[serde(default)]
    family: Vec<FamilyEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FamilyEntry {
    detector: String,
    bucket: Vec<FloorBucket>,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorBucket {
    #[serde(default)]
    max_len: Option<usize>,
    floor: f64,
}

/// A validated, length-bucketed entropy-floor table keyed by detector family.
#[derive(Debug)]
pub(crate) struct EntropyFloorTable {
    default_floor: f64,
    families: Vec<FamilyEntry>,
}

impl EntropyFloorTable {
    /// The calibrated Shannon-entropy floor for `detector_id` at `credential_len`.
    ///
    /// Returns the first bucket (in file order) whose `max_len >= credential_len`,
    /// or the family catch-all bucket, or `default_floor` for any detector with no
    /// family entry. Never applies the Tier-A `entropy_threshold` override — that
    /// is the caller's job (`adjudicate::generic_entropy_floor`).
    pub(crate) fn family_floor(&self, detector_id: &str, credential_len: usize) -> f64 {
        let Some(family) = self.families.iter().find(|f| f.detector == detector_id) else {
            return self.default_floor;
        };
        family
            .bucket
            .iter()
            .find(|bucket| bucket.max_len.is_none_or(|max| credential_len <= max))
            .map_or(self.default_floor, |bucket| bucket.floor)
    }
}

static ENTROPY_FLOORS: LazyLock<EntropyFloorTable> =
    LazyLock::new(|| match parse_entropy_floors(ENTROPY_FLOORS_TOML) {
        Ok(table) => table,
        Err(error) => panic!(
            "rules/entropy-floors.toml is invalid: {error}. Fix the bundled Tier-B \
             entropy-floor calibration; refusing to run without generic-detector \
             entropy-floor truth."
        ),
    });

/// The calibrated base entropy floor for `detector_id` at `credential_len`.
pub(crate) fn family_floor(detector_id: &str, credential_len: usize) -> f64 {
    ENTROPY_FLOORS.family_floor(detector_id, credential_len)
}

fn parse_entropy_floors(raw: &str) -> Result<EntropyFloorTable, String> {
    let file: EntropyFloorFile =
        toml::from_str(raw).map_err(|error| format!("invalid entropy-floor rules: {error}"))?;
    validate(&file)?;
    Ok(EntropyFloorTable {
        default_floor: file.default_floor,
        families: file.family,
    })
}

fn finite_non_negative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn validate(file: &EntropyFloorFile) -> Result<(), String> {
    if !finite_non_negative(file.default_floor) {
        return Err(format!(
            "default_floor must be finite and >= 0 (got {})",
            file.default_floor
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for family in &file.family {
        if family.detector.trim().is_empty() {
            return Err("entropy-floor family has an empty detector id".to_string());
        }
        if !seen.insert(family.detector.as_str()) {
            return Err(format!(
                "entropy-floor family '{}' is defined more than once",
                family.detector
            ));
        }
        if family.bucket.is_empty() {
            return Err(format!(
                "entropy-floor family '{}' has no buckets",
                family.detector
            ));
        }
        let last = family.bucket.len() - 1;
        for (index, bucket) in family.bucket.iter().enumerate() {
            if !finite_non_negative(bucket.floor) {
                return Err(format!(
                    "entropy-floor family '{}' bucket {index} has a non-finite or negative floor ({})",
                    family.detector, bucket.floor
                ));
            }
            // Only the LAST bucket may omit max_len (the catch-all). A non-final
            // bucket without max_len would shadow every later bucket; a final
            // bucket WITH max_len would leave longer values with no floor, which
            // silently drops them to the default — a precision/recall hole.
            if index < last && bucket.max_len.is_none() {
                return Err(format!(
                    "entropy-floor family '{}' has a catch-all bucket before the last position \
                     (only the final bucket may omit max_len)",
                    family.detector
                ));
            }
            if index == last && bucket.max_len.is_some() {
                return Err(format!(
                    "entropy-floor family '{}' final bucket must be the catch-all (omit max_len)",
                    family.detector
                ));
            }
        }
        let mut previous = 0usize;
        for bucket in &family.bucket {
            if let Some(max) = bucket.max_len {
                if max <= previous {
                    return Err(format!(
                        "entropy-floor family '{}' bucket max_len values must strictly increase \
                         (got {max} after {previous})",
                        family.detector
                    ));
                }
                previous = max;
            }
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
        GENERIC_API_KEY, GENERIC_DATABASE_URL, GENERIC_KEYWORD_SECRET, GENERIC_PASSWORD,
        GENERIC_SECRET,
    };

    fn table() -> EntropyFloorTable {
        parse_entropy_floors(ENTROPY_FLOORS_TOML).expect("bundled entropy-floors.toml parses")
    }

    /// The exact floor logic this refactor replaced (adjudicate `generic_entropy_floor`
    /// match arms, before the Tier-B move). The parity test below proves the loaded
    /// table reproduces this for every family and length bucket — no floor changed,
    /// so recall is unaffected.
    fn legacy_base_floor(detector_id: &str, credential_len: usize) -> f64 {
        match detector_id {
            id if id == GENERIC_API_KEY && credential_len <= 24 => 3.0,
            id if id == GENERIC_API_KEY && credential_len <= 40 => 2.8,
            id if id == GENERIC_API_KEY => 3.5,
            id if id == GENERIC_PASSWORD => 2.5,
            id if id == GENERIC_DATABASE_URL => 2.0,
            id if id == GENERIC_SECRET && credential_len <= 24 => 2.8,
            id if id == GENERIC_SECRET && credential_len <= 40 => 3.2,
            id if id == GENERIC_SECRET => 3.5,
            id if id == GENERIC_KEYWORD_SECRET => 1.5,
            _ => 3.5,
        }
    }

    #[test]
    fn bundled_table_parses() {
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
    fn database_url_floor_is_2_0() {
        assert_eq!(table().family_floor(GENERIC_DATABASE_URL, 30), 2.0);
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
            GENERIC_DATABASE_URL,
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
    fn family_detectors_are_exactly_the_generic_constants() {
        let file: EntropyFloorFile = toml::from_str(ENTROPY_FLOORS_TOML).unwrap();
        let mut ids: Vec<&str> = file.family.iter().map(|f| f.detector.as_str()).collect();
        ids.sort_unstable();
        let mut expected = vec![
            GENERIC_API_KEY,
            GENERIC_SECRET,
            GENERIC_PASSWORD,
            GENERIC_DATABASE_URL,
            GENERIC_KEYWORD_SECRET,
        ];
        expected.sort_unstable();
        assert_eq!(
            ids, expected,
            "entropy-floor families must be exactly the generic detector ids"
        );
    }

    // Parse-rejection fixtures use non-detector family ids (`fam-a`/`fam-b`) so the
    // tests exercise structural validation without embedding detector-id literals.
    #[test]
    fn parse_rejects_duplicate_family() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "fam-a"
bucket = [{ floor = 3.0 }]
[[family]]
detector = "fam-a"
bucket = [{ floor = 2.0 }]
"#,
        )
        .unwrap_err();
        assert!(err.contains("more than once"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_detector_id() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "  "
bucket = [{ floor = 3.0 }]
"#,
        )
        .unwrap_err();
        assert!(err.contains("empty detector id"), "got: {err}");
    }

    #[test]
    fn parse_rejects_catch_all_before_last() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "fam-a"
bucket = [{ floor = 3.0 }, { max_len = 40, floor = 2.8 }]
"#,
        )
        .unwrap_err();
        assert!(
            err.contains("catch-all bucket before the last"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_rejects_final_bucket_with_max_len() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "fam-a"
bucket = [{ max_len = 24, floor = 3.0 }, { max_len = 40, floor = 2.8 }]
"#,
        )
        .unwrap_err();
        assert!(
            err.contains("final bucket must be the catch-all"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_rejects_non_increasing_max_len() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "fam-a"
bucket = [{ max_len = 40, floor = 3.0 }, { max_len = 24, floor = 2.8 }, { floor = 3.5 }]
"#,
        )
        .unwrap_err();
        assert!(err.contains("strictly increase"), "got: {err}");
    }

    #[test]
    fn parse_rejects_negative_default_floor() {
        let err = parse_entropy_floors(
            r#"
default_floor = -1.0
[[family]]
detector = "fam-a"
bucket = [{ floor = 3.0 }]
"#,
        )
        .unwrap_err();
        assert!(err.contains("default_floor must be finite"), "got: {err}");
    }

    #[test]
    fn parse_rejects_negative_bucket_floor() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "fam-a"
bucket = [{ floor = -0.5 }]
"#,
        )
        .unwrap_err();
        assert!(err.contains("non-finite or negative floor"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_bucket_list() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
[[family]]
detector = "fam-a"
bucket = []
"#,
        )
        .unwrap_err();
        assert!(err.contains("has no buckets"), "got: {err}");
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let err = parse_entropy_floors(
            r#"
default_floor = 3.5
surprise = 1
"#,
        )
        .unwrap_err();
        assert!(err.contains("invalid entropy-floor rules"), "got: {err}");
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
