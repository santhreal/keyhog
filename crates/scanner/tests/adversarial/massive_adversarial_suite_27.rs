//! Part 27 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates drake, drata, drift, drip, and dronahq detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DRAKE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv27_drake_normal_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv27_drake_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drake-api-credentials",
        "frake_api_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv27_drake_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake\u{200B}_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv27_drake_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_api_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv27_drake_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "dr\u{0430}ke_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 2. DRATA API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv27_drata_normal_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "drata_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv27_drata_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drata-api-token",
        "frata_token = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv27_drata_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "drata\u{200B}_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv27_drata_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "drata_token = \"00000000000000000000\u{00AD}00000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv27_drata_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "dr\u{0430}ta_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 3. DRIFT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv27_drift_normal_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_client_secret = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv27_drift_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drift-api-credentials",
        "frift_client_secret = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv27_drift_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift\u{200B}_client_secret = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv27_drift_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_client_secret = \"00000000000000000000\u{00AD}00000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv27_drift_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "dr\u{0456}ft_client_secret = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}
