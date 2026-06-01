//! Part 29 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates dynatrace, easypost, and ebay detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DYNATRACE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv29_dynatrace_normal_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
        "dt0c01.000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv29_dynatrace_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dynatrace-api-token",
        "ct0c01.000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv29_dynatrace_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01\u{200B}.000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
        "dt0c01.000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv29_dynatrace_evade_soft_hyphen_evaded_must_stay_silent() {
    assert_detector_silent("dynatrace-api-token", "dt0c01.000000000000000000000000.0000000000000000000000000000\u{00AD}00000000000000000000000000000000");
}

#[test]
fn adv29_dynatrace_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dynatrace-api-token",
        "dt0c01.000000000000000000000000.000000000000000000000000000000000000000000000000000000000000000\u{0440}",
        "dt0c01.000000000000000000000000.0000000000000000000000000000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 2. EASYPOST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv29_easypost_normal_bare_must_stay_silent() {
    assert_detector_silent("easypost-api-key", "easypost_key = \"abcde12345abcde12345\"");
}

#[test]
fn adv29_easypost_wrong_prefix_must_silent() {
    assert_detector_silent(
        "easypost-api-key",
        "feasypost_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv29_easypost_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("easypost-api-key", "easypost\u{200B}_key = \"abcde12345abcde12345\"");
}

#[test]
fn adv29_easypost_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("easypost-api-key", "easypost_key = \"abcde12345abcde\u{00AD}12345\"");
}

#[test]
fn adv29_easypost_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("easypost-api-key", "easyp\u{043E}st_key = \"abcde12345abcde12345\"");
}

// =========================================================================
// 3. EBAY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv29_ebay_normal_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "ebay_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv29_ebay_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ebay-api-credentials",
        "fbay_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv29_ebay_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "ebay\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv29_ebay_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "ebay_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv29_ebay_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "ebay-api-credentials",
        "\u{0435}bay_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
