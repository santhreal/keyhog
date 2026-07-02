//! Regression: the shipped Tier-B entropy-floor calibration
//! (`rules/entropy-floors.toml`) and the drop/keep semantics the scanner layers
//! on top of it.
//!
//! The floor table itself is scanner-internal (`crate::entropy_floors`,
//! `pub(crate)`), so this integration crate cannot call `family_floor`. Instead
//! it parses the SAME embedded data file the scanner compiles in
//! (`include_str!` of `../../../rules/entropy-floors.toml`) and re-derives, byte
//! for byte, the two behaviors that file drives:
//!
//!   1. `EntropyFloorTable::family_floor` — first-matching-bucket lookup keyed by
//!      detector family and credential length.
//!   2. `adjudicate::generic_entropy_below_floor` / the `generic_keyword_low_entropy`
//!      toggle in `generic_bridge_entropy_below_floor` — the kept-vs-dropped
//!      decision (`entropy < floor`) and the Tier-A `entropy_threshold` override
//!      that can only RAISE a floor.
//!
//! Every assertion pins a CONCRETE f64 floor or a CONCRETE kept/dropped bool
//! against the shipped data, so a stray edit to a floor, a bucket boundary, or
//! the toggle wiring fails here loudly. The detector-id keys are the literal
//! Tier-B strings the TOML uses (`generic-api-key`, ...) — the scanner's
//! `detector_ids` constants are `pub(crate)` and deliberately equal these.

use serde::Deserialize;

/// The exact bytes the scanner compiles in via `entropy_floors::ENTROPY_FLOORS_TOML`.
const SHIPPED_TOML: &str = include_str!("../../../rules/entropy-floors.toml");

/// Compiled default for the Tier-A `entropy_threshold` knob
/// (`keyhog_core::ScanConfig::default().entropy_threshold`). The override only
/// bites STRICTLY above this value; at/below it, the calibrated family floor stands.
const DEFAULT_GENERIC_ENTROPY_THRESHOLD: f64 = 4.5;

// Tier-B detector-family ids exactly as they appear in the shipped TOML.
const GENERIC_API_KEY: &str = "generic-api-key";
const GENERIC_SECRET: &str = "generic-secret";
const GENERIC_PASSWORD: &str = "generic-password";
const GENERIC_DATABASE_URL: &str = "generic-database-url";
const GENERIC_KEYWORD_SECRET: &str = "generic-keyword-secret";

#[derive(Debug, Deserialize)]
struct FloorFile {
    default_floor: f64,
    #[serde(default)]
    family: Vec<Family>,
}

#[derive(Debug, Deserialize)]
struct Family {
    detector: String,
    bucket: Vec<Bucket>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct Bucket {
    #[serde(default)]
    max_len: Option<usize>,
    floor: f64,
}

fn load() -> FloorFile {
    toml::from_str(SHIPPED_TOML).expect("shipped rules/entropy-floors.toml parses")
}

fn family<'a>(file: &'a FloorFile, detector: &str) -> Option<&'a Family> {
    file.family.iter().find(|f| f.detector == detector)
}

/// Faithful re-implementation of `EntropyFloorTable::family_floor`: the FIRST
/// bucket (file order) whose `max_len >= len` (or the catch-all with no
/// `max_len`) sets the floor; an unknown detector uses `default_floor`.
fn family_floor(file: &FloorFile, detector: &str, len: usize) -> f64 {
    let Some(fam) = family(file, detector) else {
        return file.default_floor;
    };
    fam.bucket
        .iter()
        .find(|b| b.max_len.is_none_or(|max| len <= max))
        .map_or(file.default_floor, |b| b.floor)
}

/// Faithful re-implementation of `adjudicate::generic_entropy_floor`: the base
/// family floor, RAISED to `threshold` only when `threshold` is finite and
/// strictly above the Tier-A default. Never lowers the calibrated floor.
fn effective_floor(file: &FloorFile, threshold: f64, detector: &str, len: usize) -> f64 {
    let base = family_floor(file, detector, len);
    if threshold.is_finite() && threshold > DEFAULT_GENERIC_ENTROPY_THRESHOLD {
        base.max(threshold)
    } else {
        base
    }
}

/// `adjudicate::generic_entropy_below_floor`: true == DROPPED.
fn dropped(file: &FloorFile, entropy: f64, threshold: f64, detector: &str, len: usize) -> bool {
    entropy < effective_floor(file, threshold, detector, len)
}

/// `adjudicate::generic_bridge_entropy_below_floor`: the `generic_keyword_low_entropy`
/// toggle selects which family floor the keyword-bridge value is judged against.
fn bridge_dropped(
    file: &FloorFile,
    entropy: f64,
    threshold: f64,
    keyword_low_entropy: bool,
    len: usize,
) -> bool {
    let detector = if keyword_low_entropy {
        GENERIC_KEYWORD_SECRET
    } else {
        GENERIC_SECRET
    };
    dropped(file, entropy, threshold, detector, len)
}

// ---------------------------------------------------------------------------
// Exact floor constants in the shipped Tier-B data.
// ---------------------------------------------------------------------------

#[test]
fn default_floor_is_exactly_3_5() {
    assert_eq!(load().default_floor, 3.5);
}

#[test]
fn api_key_buckets_are_24_3_0__40_2_8__catch_3_5() {
    let file = load();
    let fam = family(&file, GENERIC_API_KEY).expect("generic-api-key family present");
    assert_eq!(fam.bucket.len(), 3, "api-key is length-graded into 3 rungs");
    assert_eq!(fam.bucket[0].max_len, Some(24));
    assert_eq!(fam.bucket[0].floor, 3.0);
    assert_eq!(fam.bucket[1].max_len, Some(40));
    assert_eq!(fam.bucket[1].floor, 2.8);
    assert_eq!(fam.bucket[2].max_len, None, "final rung is the catch-all");
    assert_eq!(fam.bucket[2].floor, 3.5);
}

#[test]
fn secret_buckets_are_24_2_8__40_3_2__catch_3_5() {
    let file = load();
    let fam = family(&file, GENERIC_SECRET).expect("generic-secret family present");
    assert_eq!(fam.bucket.len(), 3);
    assert_eq!(fam.bucket[0].max_len, Some(24));
    assert_eq!(fam.bucket[0].floor, 2.8);
    assert_eq!(fam.bucket[1].max_len, Some(40));
    assert_eq!(fam.bucket[1].floor, 3.2);
    assert_eq!(fam.bucket[2].max_len, None);
    assert_eq!(fam.bucket[2].floor, 3.5);
}

#[test]
fn password_is_single_flat_bucket_2_5() {
    let file = load();
    let fam = family(&file, GENERIC_PASSWORD).expect("generic-password family present");
    assert_eq!(fam.bucket.len(), 1);
    assert_eq!(fam.bucket[0].max_len, None);
    assert_eq!(fam.bucket[0].floor, 2.5);
}

#[test]
fn database_url_is_single_flat_bucket_2_0() {
    let file = load();
    let fam = family(&file, GENERIC_DATABASE_URL).expect("generic-database-url family present");
    assert_eq!(fam.bucket.len(), 1);
    assert_eq!(fam.bucket[0].max_len, None);
    assert_eq!(fam.bucket[0].floor, 2.0);
}

#[test]
fn keyword_secret_floor_is_exactly_1_5() {
    // KEYWORD_SECRET_FLOOR: the lowest bar of any family — the keyword anchor is
    // the evidence, not entropy.
    let file = load();
    let fam = family(&file, GENERIC_KEYWORD_SECRET).expect("generic-keyword-secret family present");
    assert_eq!(fam.bucket.len(), 1);
    assert_eq!(fam.bucket[0].max_len, None);
    assert_eq!(fam.bucket[0].floor, 1.5);
}

#[test]
fn exactly_the_five_generic_families_are_present() {
    let file = load();
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
    assert_eq!(ids, expected);
}

// ---------------------------------------------------------------------------
// family_floor lookup: bucket boundaries.
// ---------------------------------------------------------------------------

#[test]
fn api_key_length_bucket_boundaries() {
    let file = load();
    // Length 0 falls in the first rung (<=24).
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 0), 3.0);
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 24), 3.0);
    // Step DOWN across the 24/25 boundary.
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 25), 2.8);
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 40), 2.8);
    // Step UP across the 40/41 boundary into the catch-all.
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 41), 3.5);
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 4096), 3.5);
}

#[test]
fn secret_length_bucket_boundaries() {
    let file = load();
    assert_eq!(family_floor(&file, GENERIC_SECRET, 24), 2.8);
    // Both boundaries step UP for the secret family.
    assert_eq!(family_floor(&file, GENERIC_SECRET, 25), 3.2);
    assert_eq!(family_floor(&file, GENERIC_SECRET, 40), 3.2);
    assert_eq!(family_floor(&file, GENERIC_SECRET, 41), 3.5);
}

#[test]
fn flat_families_ignore_length() {
    let file = load();
    for len in [1usize, 16, 24, 25, 40, 41, 500] {
        assert_eq!(family_floor(&file, GENERIC_PASSWORD, len), 2.5);
        assert_eq!(family_floor(&file, GENERIC_DATABASE_URL, len), 2.0);
        assert_eq!(family_floor(&file, GENERIC_KEYWORD_SECRET, len), 1.5);
    }
}

#[test]
fn unknown_and_empty_detector_use_default_floor() {
    let file = load();
    // Neither a real named-vendor detector id nor the empty id has a family entry.
    assert_eq!(family_floor(&file, "some-named-vendor-detector", 20), 3.5);
    assert_eq!(family_floor(&file, "", 20), 3.5);
}

// ---------------------------------------------------------------------------
// Kept / dropped: entropy strictly below the floor is dropped; at/above kept.
// ---------------------------------------------------------------------------

#[test]
fn keyword_secret_drop_keep_at_1_5_boundary() {
    let file = load();
    let t = DEFAULT_GENERIC_ENTROPY_THRESHOLD;
    // Just below the 1.5 floor -> DROPPED.
    assert!(dropped(&file, 1.4999, t, GENERIC_KEYWORD_SECRET, 12));
    // Exactly at the floor -> KEPT (comparison is strict `<`).
    assert!(!dropped(&file, 1.5, t, GENERIC_KEYWORD_SECRET, 12));
    // Above the floor -> KEPT.
    assert!(!dropped(&file, 2.0, t, GENERIC_KEYWORD_SECRET, 12));
}

#[test]
fn api_key_drop_keep_tracks_the_length_bucket() {
    let file = load();
    let t = DEFAULT_GENERIC_ENTROPY_THRESHOLD;
    // len 20 -> floor 3.0: entropy 2.9 dropped, 3.0 kept.
    assert!(dropped(&file, 2.9, t, GENERIC_API_KEY, 20));
    assert!(!dropped(&file, 3.0, t, GENERIC_API_KEY, 20));
    // len 30 -> floor 2.8: entropy 2.9 now KEPT (looser mid bucket), 2.79 dropped.
    assert!(!dropped(&file, 2.9, t, GENERIC_API_KEY, 30));
    assert!(dropped(&file, 2.79, t, GENERIC_API_KEY, 30));
    // len 60 -> floor 3.5: entropy 2.9 dropped again (catch-all tightens back up).
    assert!(dropped(&file, 2.9, t, GENERIC_API_KEY, 60));
}

// ---------------------------------------------------------------------------
// Tier-A entropy_threshold override: RAISES a floor, never lowers it.
// ---------------------------------------------------------------------------

#[test]
fn override_raises_floor_only_strictly_above_default() {
    let file = load();
    // Base for a short api-key is 3.0.
    assert_eq!(family_floor(&file, GENERIC_API_KEY, 10), 3.0);
    // A stricter-than-default threshold raises the effective floor to it.
    assert_eq!(effective_floor(&file, 5.0, GENERIC_API_KEY, 10), 5.0);
    // At the default (4.5) and below, the calibrated base stands.
    assert_eq!(effective_floor(&file, 4.5, GENERIC_API_KEY, 10), 3.0);
    assert_eq!(effective_floor(&file, 0.0, GENERIC_API_KEY, 10), 3.0);
    // The override NEVER lowers a floor: a threshold under the base is ignored.
    assert_eq!(effective_floor(&file, 1.0, GENERIC_SECRET, 30), 3.2);
}

#[test]
fn override_ignores_non_finite_threshold() {
    let file = load();
    // Infinite / NaN thresholds are not finite, so the base floor stands rather
    // than raising the floor to an impossible bar (which would drop everything).
    assert_eq!(
        effective_floor(&file, f64::INFINITY, GENERIC_API_KEY, 10),
        3.0
    );
    assert_eq!(effective_floor(&file, f64::NAN, GENERIC_API_KEY, 10), 3.0);
}

// ---------------------------------------------------------------------------
// The generic_keyword_low_entropy toggle: which family floor the keyword-bridge
// value is judged against.
// ---------------------------------------------------------------------------

#[test]
fn keyword_low_entropy_toggle_flips_a_mid_entropy_value() {
    let file = load();
    let t = DEFAULT_GENERIC_ENTROPY_THRESHOLD;
    // A len-20 bridge value at entropy 2.0 sits in the 1.5..2.8 band.
    // Toggle ON  -> judged against generic-keyword-secret (1.5) -> 2.0 >= 1.5 -> KEPT.
    assert!(!bridge_dropped(&file, 2.0, t, true, 20));
    // Toggle OFF -> judged against generic-secret len<=24 (2.8) -> 2.0 < 2.8 -> DROPPED.
    assert!(bridge_dropped(&file, 2.0, t, false, 20));
}

#[test]
fn keyword_low_entropy_toggle_is_noop_above_both_floors() {
    let file = load();
    let t = DEFAULT_GENERIC_ENTROPY_THRESHOLD;
    // At entropy 3.4 (len 20) the value clears BOTH the 1.5 keyword floor and the
    // 2.8 generic-secret floor, so the toggle changes nothing: KEPT either way.
    assert!(!bridge_dropped(&file, 3.4, t, true, 20));
    assert!(!bridge_dropped(&file, 3.4, t, false, 20));
    // And below BOTH floors (entropy 1.0) it is DROPPED either way.
    assert!(bridge_dropped(&file, 1.0, t, true, 20));
    assert!(bridge_dropped(&file, 1.0, t, false, 20));
}

// ---------------------------------------------------------------------------
// Cross-family invariants documented in the TOML header, asserted on the SHIPPED
// data (the src unit tests only reject synthetic BAD data — these guard the
// GOOD data still satisfies the contract).
// ---------------------------------------------------------------------------

#[test]
fn keyword_secret_is_the_single_lowest_floor() {
    let file = load();
    let min = file
        .family
        .iter()
        .flat_map(|f| f.bucket.iter().map(|b| b.floor))
        .fold(f64::INFINITY, f64::min);
    assert_eq!(min, 1.5, "keyword-anchored secrets carry the lowest bar");
    assert_eq!(
        family_floor(&file, GENERIC_KEYWORD_SECRET, 12),
        min,
        "the 1.5 minimum is owned by generic-keyword-secret"
    );
}

#[test]
fn every_family_floor_is_below_the_tier_a_default() {
    // The header contract: every calibrated family floor stays < 4.5 so the
    // Tier-A override can only ever RAISE, never coincide-and-mask.
    let file = load();
    for fam in &file.family {
        for b in &fam.bucket {
            assert!(
                b.floor < DEFAULT_GENERIC_ENTROPY_THRESHOLD,
                "family {} floor {} must stay below the Tier-A default {}",
                fam.detector,
                b.floor,
                DEFAULT_GENERIC_ENTROPY_THRESHOLD
            );
        }
    }
    assert!(file.default_floor < DEFAULT_GENERIC_ENTROPY_THRESHOLD);
}

#[test]
fn bucket_max_len_values_strictly_increase_and_only_last_is_catch_all() {
    let file = load();
    for fam in &file.family {
        assert!(!fam.bucket.is_empty(), "{} has no buckets", fam.detector);
        let last = fam.bucket.len() - 1;
        let mut prev = 0usize;
        for (i, b) in fam.bucket.iter().enumerate() {
            if i == last {
                assert_eq!(
                    b.max_len, None,
                    "{} final bucket must be the catch-all",
                    fam.detector
                );
            } else {
                let max = b
                    .max_len
                    .unwrap_or_else(|| panic!("{} non-final bucket omits max_len", fam.detector));
                assert!(
                    max > prev,
                    "{} max_len must strictly increase (got {max} after {prev})",
                    fam.detector
                );
                prev = max;
            }
            assert!(
                b.floor.is_finite() && b.floor >= 0.0,
                "{} floor {} must be finite and non-negative",
                fam.detector,
                b.floor
            );
        }
    }
}
