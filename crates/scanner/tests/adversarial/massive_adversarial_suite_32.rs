//! Part 32 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates fda, fedex, and figma detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FDA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv32_fda_normal_bare_must_stay_silent() {
    assert_detector_silent("fda-api", "fda_key = \"0000000000000000000000000000000000000000\"");
}

#[test]
fn adv32_fda_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fda-api",
        "gda_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv32_fda_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("fda-api", "fda\u{200B}_key = \"0000000000000000000000000000000000000000\"");
}

#[test]
fn adv32_fda_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("fda-api", "fda_key = \"000000000000000000000000000000\u{00AD}0000000000\"");
}

#[test]
fn adv32_fda_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("fda-api", "fd\u{0430}_key = \"0000000000000000000000000000000000000000\"");
}

// =========================================================================
// 2. FEDEX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv32_fedex_normal_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "fedex_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv32_fedex_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fedex-api-credentials",
        "gedex_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv32_fedex_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "fedex\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv32_fedex_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "fedex_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv32_fedex_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fedex-api-credentials",
        "f\u{0435}dex_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. FIGMA PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv32_figma_normal_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figma_token = \"figd_0000000000000000000000000000000000000000\"",
        "figd_0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv32_figma_wrong_prefix_must_silent() {
    assert_detector_silent(
        "figma-pat",
        "gigma_token = \"xigd_0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv32_figma_evade_zwsp_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figma\u{200B}_token = \"figd_0000000000000000000000000000000000000000\"",
        "figd_0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv32_figma_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "figma_token = \"figd_000000000000000000000000000000\u{00AD}00000000000000000000\"",
        "figd_0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv32_figma_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "figma-pat",
        "f\u{0456}gma_token = \"figd_0000000000000000000000000000000000000000\"",
        "figd_0000000000000000000000000000000000000000",
    );
}
