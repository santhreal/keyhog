//! Part 35 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates flipside, flipt, and flutterwave detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FLIPSIDE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv35_flipside_normal_must_fire() {
    assert_detector_fires(
        "flipside-api-key",
        "flipside_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv35_flipside_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flipside-api-key",
        "glipside_key = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv35_flipside_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flipside-api-key",
        "flipside\u{200B}_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv35_flipside_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flipside-api-key",
        "flipside_key = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv35_flipside_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "flipside-api-key",
        "fl\u{0456}pside_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 2. FLIPT API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv35_flipt_normal_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv35_flipt_wrong_prefix_must_silent() {
    assert_detector_silent("flipt-api-token", "glipt_token = \"abcde12345abcde12345\"");
}

#[test]
fn adv35_flipt_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt\u{200B}_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv35_flipt_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "flipt_token = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv35_flipt_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "flipt-api-token",
        "fl\u{0456}pt_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. FLUTTERWAVE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv35_flutterwave_normal_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-00000000000000000000000000000000-X",
        "FLWSECK_TEST-00000000000000000000000000000000-X",
    );
}

#[test]
fn adv35_flutterwave_wrong_prefix_must_silent() {
    assert_detector_silent(
        "flutterwave-api-key",
        "GLWSECK_TEST-00000000000000000000000000000000-X",
    );
}

#[test]
fn adv35_flutterwave_evade_zwsp_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK\u{200B}_TEST-00000000000000000000000000000000-X",
        "FLWSECK_TEST-00000000000000000000000000000000-X",
    );
}

#[test]
fn adv35_flutterwave_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_TEST-00000000000000000000000000\u{00AD}000000-X",
        "FLWSECK_TEST-00000000000000000000000000000000-X",
    );
}

#[test]
fn adv35_flutterwave_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "flutterwave-api-key",
        "FLWSECK_T\u{0415}ST-00000000000000000000000000000000-X",
        "FLWSECK_TEST-00000000000000000000000000000000-X",
    );
}
