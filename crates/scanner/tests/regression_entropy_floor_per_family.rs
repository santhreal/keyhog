//! Regression: per-family generic-detector entropy floors.
//!
//! The low-entropy suppression gate (`adjudicate::generic_entropy_floor` →
//! `entropy_floors::family_floor`, backed by the shipped Tier-B
//! `rules/entropy-floors.toml`) decides, for a generic-detector candidate of a
//! given detector family and credential length, the minimum Shannon entropy the
//! value must clear to survive: a candidate whose entropy is STRICTLY below its
//! family floor is suppressed; at-or-above the floor it passes.
//!
//! Those floor functions are `pub(crate)`, so this black-box integration file
//! pins the SAME truth through the two surfaces that ARE public:
//!
//!  * the shipped Tier-B calibration DATA the binary compiles in
//!    (`rules/entropy-floors.toml`, the exact bytes `entropy_floors.rs`
//!    `include_str!`s) — parsed here and evaluated through a faithful copy of
//!    the documented `family_floor` bucket-selection algorithm, so any retune of
//!    a family floor or bucket boundary in the data trips a test; and
//!  * the real scanner (`CompiledScanner::scan_chunks_with_backend`) plus the
//!    public `entropy::shannon_entropy`, proving the floor gate actually lets a
//!    generic secret whose entropy sits AT the family floor through end to end.
//!
//! Every floor value and boundary asserted here mirrors the calibrated table in
//! `entropy_floors.rs`: api-key {<=24: 3.0, <=40: 2.8, else 3.5}, secret
//! {<=24: 2.8, <=40: 3.2, else 3.5}, password 2.5, database-url 2.0,
//! keyword-secret 1.5, and default 3.5 for any non-generic (service-anchored)
//! detector with no family entry.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::entropy::shannon_entropy;
use keyhog_scanner::{CompiledScanner, ScanBackend};

// ---------------------------------------------------------------------------
// Tier-B floor DATA contract: parse the SHIPPED rules file and evaluate it
// through a faithful copy of the documented `family_floor` algorithm.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct FloorFile {
    default_floor: f64,
    #[serde(default)]
    family: Vec<FamilyEntry>,
}

#[derive(serde::Deserialize)]
struct FamilyEntry {
    detector: String,
    bucket: Vec<FloorBucket>,
}

#[derive(Clone, Copy, serde::Deserialize)]
struct FloorBucket {
    #[serde(default)]
    max_len: Option<usize>,
    floor: f64,
}

/// The exact bytes `entropy_floors.rs` `include_str!`s, resolved from this
/// crate's manifest dir (`crates/scanner`) so the path is cwd-independent.
fn load_shipped_floor_file() -> FloorFile {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("rules")
        .join("entropy-floors.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read shipped {}: {e}", path.display()));
    toml::from_str(&raw).unwrap_or_else(|e| panic!("parse shipped entropy-floors.toml: {e}"))
}

/// Faithful copy of `EntropyFloorTable::family_floor`: first bucket (in file
/// order) whose `max_len >= len`, else the catch-all, else `default_floor` for a
/// detector with no family entry.
fn family_floor(table: &FloorFile, detector: &str, len: usize) -> f64 {
    match table.family.iter().find(|f| f.detector == detector) {
        None => table.default_floor,
        Some(fam) => fam
            .bucket
            .iter()
            .find(|b| b.max_len.is_none_or(|m| len <= m))
            .map_or(table.default_floor, |b| b.floor),
    }
}

/// The compiled default for the Tier-A `entropy_threshold` knob
/// (`ScanConfig::default().entropy_threshold == 4.5`).
const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.5;

/// Faithful copy of `adjudicate::generic_entropy_floor`: the Tier-A threshold
/// can only RAISE a family floor above the default, never lower it.
fn effective_floor(threshold: f64, detector: &str, len: usize, t: &FloorFile) -> f64 {
    let base = family_floor(t, detector, len);
    if threshold.is_finite() && threshold > DEFAULT_ENTROPY_THRESHOLD {
        base.max(threshold)
    } else {
        base
    }
}

/// Faithful copy of `adjudicate::generic_entropy_below_floor` (strict `<`).
fn below_floor(entropy: f64, threshold: f64, detector: &str, len: usize, t: &FloorFile) -> bool {
    entropy < effective_floor(threshold, detector, len, t)
}

// Detector-family ids (literals are fine in a test crate; the `detector_id_owner`
// gate only governs `src/`).
const GENERIC_API_KEY: &str = "generic-api-key";
const GENERIC_SECRET: &str = "generic-secret";
const GENERIC_PASSWORD: &str = "generic-password";
const GENERIC_DATABASE_URL: &str = "generic-database-url";
const GENERIC_KEYWORD_SECRET: &str = "generic-keyword-secret";

#[test]
fn default_floor_is_3_5() {
    let t = load_shipped_floor_file();
    assert_eq!(t.default_floor, 3.5, "shipped default_floor must be 3.5");
}

#[test]
fn family_set_is_exactly_the_five_generic_detectors() {
    let t = load_shipped_floor_file();
    let mut ids: Vec<&str> = t.family.iter().map(|f| f.detector.as_str()).collect();
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
        "entropy-floor families must be exactly the five generic detector ids"
    );
}

#[test]
fn api_key_floor_by_length_bucket() {
    let t = load_shipped_floor_file();
    // Short (<=24): 3.0
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 0), 3.0);
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 10), 3.0);
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 24), 3.0);
    // Mid (25..=40): 2.8
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 25), 2.8);
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 40), 2.8);
    // Long (>=41): back up to 3.5
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 41), 3.5);
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 100), 3.5);
}

#[test]
fn api_key_boundaries_step_at_24_25_and_40_41() {
    let t = load_shipped_floor_file();
    // 24->25 steps DOWN (3.0 -> 2.8): short bucket ends AT 24 inclusive.
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 24), 3.0);
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 25), 2.8);
    // 40->41 steps UP (2.8 -> 3.5): mid bucket ends AT 40 inclusive.
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 40), 2.8);
    assert_eq!(family_floor(&t, GENERIC_API_KEY, 41), 3.5);
}

#[test]
fn secret_floor_by_length_bucket() {
    let t = load_shipped_floor_file();
    // Short (<=24): 2.8 (stricter than api-key short; prose-prone)
    assert_eq!(family_floor(&t, GENERIC_SECRET, 0), 2.8);
    assert_eq!(family_floor(&t, GENERIC_SECRET, 24), 2.8);
    // Mid (25..=40): 3.2
    assert_eq!(family_floor(&t, GENERIC_SECRET, 25), 3.2);
    assert_eq!(family_floor(&t, GENERIC_SECRET, 40), 3.2);
    // Long (>=41): 3.5
    assert_eq!(family_floor(&t, GENERIC_SECRET, 41), 3.5);
    assert_eq!(family_floor(&t, GENERIC_SECRET, 200), 3.5);
}

#[test]
fn secret_boundaries_step_up_at_24_25_and_40_41() {
    let t = load_shipped_floor_file();
    // secret steps UP at both rungs (2.8 -> 3.2 -> 3.5).
    assert_eq!(family_floor(&t, GENERIC_SECRET, 24), 2.8);
    assert_eq!(family_floor(&t, GENERIC_SECRET, 25), 3.2);
    assert_eq!(family_floor(&t, GENERIC_SECRET, 40), 3.2);
    assert_eq!(family_floor(&t, GENERIC_SECRET, 41), 3.5);
}

#[test]
fn password_floor_is_2_5_at_every_length() {
    let t = load_shipped_floor_file();
    // Single catch-all bucket: length-invariant.
    assert_eq!(family_floor(&t, GENERIC_PASSWORD, 1), 2.5);
    assert_eq!(family_floor(&t, GENERIC_PASSWORD, 24), 2.5);
    assert_eq!(family_floor(&t, GENERIC_PASSWORD, 25), 2.5);
    assert_eq!(family_floor(&t, GENERIC_PASSWORD, 500), 2.5);
}

#[test]
fn database_url_floor_is_2_0_at_every_length() {
    let t = load_shipped_floor_file();
    assert_eq!(family_floor(&t, GENERIC_DATABASE_URL, 8), 2.0);
    assert_eq!(family_floor(&t, GENERIC_DATABASE_URL, 30), 2.0);
    assert_eq!(family_floor(&t, GENERIC_DATABASE_URL, 300), 2.0);
}

#[test]
fn keyword_secret_floor_is_the_lowest_of_any_family_1_5() {
    let t = load_shipped_floor_file();
    assert_eq!(family_floor(&t, GENERIC_KEYWORD_SECRET, 6), 1.5);
    assert_eq!(family_floor(&t, GENERIC_KEYWORD_SECRET, 12), 1.5);
    assert_eq!(family_floor(&t, GENERIC_KEYWORD_SECRET, 128), 1.5);
    // It really is the strict minimum across families.
    let all = [
        family_floor(&t, GENERIC_API_KEY, 30),
        family_floor(&t, GENERIC_SECRET, 30),
        family_floor(&t, GENERIC_PASSWORD, 30),
        family_floor(&t, GENERIC_DATABASE_URL, 30),
        t.default_floor,
    ];
    for f in all {
        assert!(
            f > 1.5,
            "keyword-secret floor 1.5 must be strictly below every other family floor (saw {f})"
        );
    }
}

#[test]
fn service_anchored_detectors_fall_through_to_default_3_5() {
    let t = load_shipped_floor_file();
    // aws/gcp/github/etc. are service-anchored (not `generic-*`), so they have NO
    // family entry and use `default_floor`. Empty id likewise.
    assert_eq!(family_floor(&t, "aws-access-key", 20), 3.5);
    assert_eq!(family_floor(&t, "gcp-api-key", 40), 3.5);
    assert_eq!(family_floor(&t, "github-classic-pat", 40), 3.5);
    assert_eq!(family_floor(&t, "stripe-secret-key", 32), 3.5);
    assert_eq!(family_floor(&t, "", 20), 3.5);
}

#[test]
fn bucket_max_len_values_strictly_increase_within_length_graded_families() {
    let t = load_shipped_floor_file();
    for detector in [GENERIC_API_KEY, GENERIC_SECRET] {
        let fam = t
            .family
            .iter()
            .find(|f| f.detector == detector)
            .unwrap_or_else(|| panic!("family {detector} present"));
        // api-key/secret: two graded rungs (24, 40) then the catch-all (None).
        let maxes: Vec<Option<usize>> = fam.bucket.iter().map(|b| b.max_len).collect();
        assert_eq!(
            maxes,
            vec![Some(24), Some(40), None],
            "{detector} buckets must be [<=24, <=40, catch-all]"
        );
    }
}

// ---------------------------------------------------------------------------
// Suppression DECISION semantics (mirror of `generic_entropy_below_floor`,
// strict `<`), driven by the shipped floor data + the public entropy fn.
// ---------------------------------------------------------------------------

#[test]
fn value_below_family_floor_is_suppressed() {
    let t = load_shipped_floor_file();
    // Entropy 0.0 (single repeated byte) is below EVERY family floor.
    let zero = shannon_entropy(b"aaaaaaaa");
    assert_eq!(zero, 0.0, "repeated-byte entropy must be exactly 0.0");
    assert!(below_floor(
        zero,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_PASSWORD,
        8,
        &t
    ));
    assert!(below_floor(
        zero,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_DATABASE_URL,
        8,
        &t
    ));
    assert!(below_floor(
        zero,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_KEYWORD_SECRET,
        8,
        &t
    ));
    // A value just under the password floor 2.5 is suppressed; just at/above is not.
    assert!(below_floor(
        2.49,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_PASSWORD,
        8,
        &t
    ));
    assert!(!below_floor(
        2.50,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_PASSWORD,
        8,
        &t
    ));
    assert!(!below_floor(
        2.51,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_PASSWORD,
        8,
        &t
    ));
}

#[test]
fn at_exactly_the_floor_passes_because_the_gate_is_strict_less_than() {
    let t = load_shipped_floor_file();
    // For each family, entropy == floor is NOT below floor (strict `<`).
    assert!(!below_floor(
        2.5,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_PASSWORD,
        8,
        &t
    ));
    assert!(!below_floor(
        2.0,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_DATABASE_URL,
        8,
        &t
    ));
    assert!(!below_floor(
        1.5,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_KEYWORD_SECRET,
        8,
        &t
    ));
    assert!(!below_floor(
        3.0,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_API_KEY,
        10,
        &t
    ));
    assert!(!below_floor(
        2.8,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_SECRET,
        10,
        &t
    ));
    // One notch below each floor IS suppressed.
    assert!(below_floor(
        2.99,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_API_KEY,
        10,
        &t
    ));
    assert!(below_floor(
        2.79,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_SECRET,
        10,
        &t
    ));
}

#[test]
fn length_bucket_changes_the_suppression_verdict_at_the_same_entropy() {
    let t = load_shipped_floor_file();
    // A 3.4-entropy api-key value: passes in the short/mid buckets (floors
    // 3.0/2.8) but is suppressed in the long bucket (floor 3.5). The floor
    // genuinely depends on credential length.
    assert!(!below_floor(
        3.4,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_API_KEY,
        24,
        &t
    )); // floor 3.0
    assert!(!below_floor(
        3.4,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_API_KEY,
        40,
        &t
    )); // floor 2.8
    assert!(below_floor(
        3.4,
        DEFAULT_ENTROPY_THRESHOLD,
        GENERIC_API_KEY,
        41,
        &t
    )); // floor 3.5
}

#[test]
fn tier_a_threshold_only_raises_floor_above_the_4_5_default() {
    let t = load_shipped_floor_file();
    // A stricter-than-default scan (threshold 5.0) RAISES the api-key short floor
    // from 3.0 to 5.0.
    assert_eq!(effective_floor(5.0, GENERIC_API_KEY, 10, &t), 5.0);
    // At or below the compiled default (4.5) the override is a no-op: the
    // calibrated family floor stands.
    assert_eq!(effective_floor(4.5, GENERIC_API_KEY, 10, &t), 3.0);
    assert_eq!(effective_floor(0.0, GENERIC_SECRET, 30, &t), 3.2);
    // A raised floor changes the verdict: entropy 4.0 passes at default but is
    // suppressed under a 5.0 threshold.
    assert!(!below_floor(4.0, 4.5, GENERIC_API_KEY, 10, &t));
    assert!(below_floor(4.0, 5.0, GENERIC_API_KEY, 10, &t));
}

// ---------------------------------------------------------------------------
// End-to-end: the REAL scanner + public `shannon_entropy`. A generic secret
// whose Shannon entropy sits AT the password floor (2.5) passes the gate.
// ---------------------------------------------------------------------------

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn credentials_for(scanner: &CompiledScanner, line: &str) -> Vec<String> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| m.credential.to_string())
        .collect()
}

#[test]
fn value_at_exactly_the_password_floor_surfaces_end_to_end() {
    // `gjbubxsu` has Shannon entropy of EXACTLY 2.5 bits/byte — identical to the
    // generic-password floor. Because the gate is strict `<`, an at-floor value
    // is NOT suppressed, so the real scanner surfaces it under a password keyword.
    let t = load_shipped_floor_file();
    assert_eq!(
        shannon_entropy(b"gjbubxsu"),
        2.5,
        "entropy anchor: this value must sit exactly at the password floor"
    );
    assert_eq!(family_floor(&t, GENERIC_PASSWORD, "gjbubxsu".len()), 2.5);
    assert!(
        !below_floor(2.5, DEFAULT_ENTROPY_THRESHOLD, GENERIC_PASSWORD, 8, &t),
        "at-floor value is not below floor"
    );

    let s = scanner();
    let creds = credentials_for(&s, "GRAPHITE_PASS=gjbubxsu");
    assert!(
        creds.iter().any(|c| c == "gjbubxsu"),
        "at-floor (entropy==2.5) generic secret must pass the low-entropy gate and \
         surface; got {creds:?}"
    );
}

#[test]
fn high_entropy_values_above_floor_surface_end_to_end() {
    // Random lowercase passwords whose entropy is at or above the password floor
    // all surface. Anchored to exact `shannon_entropy` values so the assertion is
    // "above floor => passes", not merely "non-empty".
    assert_eq!(shannon_entropy(b"ufnlbbavawsdeecn"), 3.5); // >= floor 2.5
    assert_eq!(shannon_entropy(b"krbykalt"), 2.75); // >= floor 2.5
    let s = scanner();
    for (line, val) in [
        ("password = \"ufnlbbavawsdeecn\"", "ufnlbbavawsdeecn"),
        ("JENKINS_PASS=krbykalt", "krbykalt"),
        ("SES_PASS=dzdvnffvqp", "dzdvnffvqp"),
    ] {
        let creds = credentials_for(&s, line);
        assert!(
            creds.iter().any(|c| c == val),
            "above-floor generic secret {val:?} must surface; got {creds:?}"
        );
    }
}

#[test]
fn shannon_entropy_matches_the_documented_range_endpoints() {
    // Ground the anchor function: a single repeated byte is 0.0 bits; a value
    // over an N-symbol uniform alphabet is log2(N). These are the exact endpoints
    // the floor table is calibrated against.
    assert_eq!(shannon_entropy(b""), 0.0);
    assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
    // 4 distinct bytes, uniform => 2.0 bits; 16 distinct uniform => 4.0 bits.
    assert_eq!(shannon_entropy(b"abcd"), 2.0);
    assert_eq!(shannon_entropy(b"abcdefghijklmnop"), 4.0);
}
