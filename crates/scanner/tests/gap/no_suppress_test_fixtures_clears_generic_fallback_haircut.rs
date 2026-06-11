//! MC-15 gap: `--no-suppress-test-fixtures` (`ScannerConfig.penalize_test_paths
//! = false`) must clear the path-keyed confidence haircut on the
//! **generic-secret fallback** too, not only on the named-detector / ML paths.
//!
//! The bug: `engine/fallback_generic.rs` historically baked the test-context
//! base confidence (0.25 for `TestCode`, 0.30 for `Documentation`) into
//! `base_conf` UNCONDITIONALLY — it consulted `scan_comments` for the Comment
//! arm but never `penalize_test_paths`. So a generic high-entropy secret in a
//! file whose path carried a `fixtures/` (or `tests/`, `testdata/`, …)
//! component was scored at 0.25 and fell below the 0.40 floor EVEN WITH the
//! opt-out flag set. On the bench this showed up as the SAME byte-identical
//! corpus scoring ~600 fewer findings under a `fixtures/`-named scan dir than
//! under a neutral `corpus/`/`data/` name, despite `--no-suppress-test-fixtures`
//! in both runs (MC-15).
//!
//! This test pins BOTH directions of the gate on the production
//! `CompiledScanner::compile(...).with_config(...).scan(...)` path:
//!   * penalize ON  (default): the `fixtures/` path DOES haircut the generic
//!     finding — its confidence is strictly below the neutral-path confidence,
//!     proving the path penalty is real (not silently removed).
//!   * penalize OFF (the flag): the `fixtures/` path and the neutral path score
//!     the generic finding IDENTICALLY — the opt-out clears the haircut.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::path::PathBuf;

/// Absolute path to the on-disk Tier-B detector TOML tree, from
/// `CARGO_MANIFEST_DIR` (gap submodules can't reach the `tests/support` helper).
fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// A high-entropy value with no service prefix, assigned to a generic
/// `api_secret` key. It is captured by the generic-secret assignment fallback
/// (the path under test), not by any anchored named detector. 48 mixed-case
/// alphanumerics → entropy well above the generic floor, length well above the
/// 16-char minimum, no `+`/`/`/`=` punctuation that would trip the
/// random-base64-blob gate.
const GENERIC_SECRET_LINE: &str =
    "api_secret = \"Zx9Kq2Wm7Lp4Rn8Tv3Yb6Hc1Df5Gj0Ks2Md4Pw7Qz9Xa3B\"";
const GENERIC_VALUE: &str = "Zx9Kq2Wm7Lp4Rn8Tv3Yb6Hc1Df5Gj0Ks2Md4Pw7Qz9Xa3B";

fn scanner_with(penalize_test_paths: bool) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut config = ScannerConfig::default();
    config.penalize_test_paths = penalize_test_paths;
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(config)
}

/// Scan `GENERIC_SECRET_LINE` as a file at `path`; return the confidence of the
/// generic finding that captured `GENERIC_VALUE`, or `None` if it was dropped.
fn generic_confidence(scanner: &CompiledScanner, path: &str) -> Option<f64> {
    let chunk = Chunk {
        data: GENERIC_SECRET_LINE.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    let matches: Vec<RawMatch> = scanner.scan(&chunk);
    matches
        .iter()
        // Pin the `generic-secret` fallback specifically — that is the
        // `engine/fallback_generic.rs` path whose `base_conf` MC-15 fixed.
        // (`generic-password` / `entropy-api-key` also fire on this value via
        // other paths and would mask the haircut if we took the max over all.)
        .filter(|m| {
            m.detector_id.as_ref() == "generic-secret"
                && m.credential.as_ref().contains(GENERIC_VALUE)
        })
        .filter_map(|m| m.confidence)
        .fold(None, |acc: Option<f64>, c| Some(acc.map_or(c, |a| a.max(c))))
}

const FIXTURE_PATH: &str = "project/fixtures/app.env";
const NEUTRAL_PATH: &str = "project/data/app.env";

/// Sanity anchor: the payload actually surfaces as a generic finding on a
/// neutral path under the default config. If this fails the rest of the suite
/// is meaningless (the payload stopped reaching the generic fallback), so it is
/// asserted explicitly rather than silently skipping.
#[test]
fn generic_secret_payload_surfaces_on_neutral_path() {
    let scanner = scanner_with(true);
    let conf = generic_confidence(&scanner, NEUTRAL_PATH)
        .expect("generic secret must surface on a neutral path under default config");
    assert!(
        conf >= 0.40,
        "neutral-path generic finding must clear the 0.40 floor; got {conf}"
    );
}

/// Default behaviour (penalize ON) is UNCHANGED: the `fixtures/` path keys a
/// real haircut, so the generic finding scores strictly lower than on a neutral
/// path (or is dropped below the floor entirely). This guards the fix from
/// silently disabling the penalty for everyone.
#[test]
fn fixtures_path_still_haircuts_generic_finding_when_penalize_on() {
    let scanner = scanner_with(true);
    let neutral = generic_confidence(&scanner, NEUTRAL_PATH)
        .expect("generic secret must surface on neutral path");
    let fixture = generic_confidence(&scanner, FIXTURE_PATH);

    match fixture {
        Some(fixture_conf) => assert!(
            fixture_conf < neutral,
            "with penalize ON, the fixtures/ path must haircut the generic finding \
             (fixture={fixture_conf} should be < neutral={neutral})"
        ),
        // Dropped below the floor by the haircut — an even stronger form of the
        // penalty, still consistent with "penalize ON downgrades fixtures".
        None => {}
    }
}

/// MC-15 FIX: with `penalize_test_paths = false` (the `--no-suppress-test-fixtures`
/// opt-out), the generic finding scores IDENTICALLY under the `fixtures/` path
/// and the neutral path — the path-keyed haircut is cleared on the generic
/// fallback, matching the named-detector / ML paths.
#[test]
fn no_suppress_test_fixtures_clears_generic_fallback_haircut() {
    let scanner = scanner_with(false);
    let neutral = generic_confidence(&scanner, NEUTRAL_PATH)
        .expect("generic secret must surface on neutral path with penalize OFF");
    let fixture = generic_confidence(&scanner, FIXTURE_PATH).expect(
        "generic secret must ALSO surface under fixtures/ when penalize is OFF \
         (the opt-out must clear the haircut so it stays above the floor)",
    );

    assert!(
        (fixture - neutral).abs() < 1e-9,
        "MC-15: with --no-suppress-test-fixtures, the fixtures/ path must NOT \
         haircut the generic finding; fixture={fixture} must equal neutral={neutral}"
    );
}
