//! Part 34 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates fireworks, five9, fivetran, flagsmith, and flickr detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FIREWORKS AI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv34_fireworks_normal_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fireworks_key = \"fw_0000000000000000000000000000000000000000000000000000000000000000\"",
        "fw_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv34_fireworks_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fireworks-ai-api-key",
        "gireworks_key = \"fw_0000000000000000000000000000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv34_fireworks_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fireworks\u{200B}_key = \"fw_0000000000000000000000000000000000000000000000000000000000000000\"",
        "fw_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv34_fireworks_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "fireworks_key = \"fw_00000000000000000000000000000000000000000000\u{00AD}00000000000000000000\"",
        "fw_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv34_fireworks_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fireworks-ai-api-key",
        "f\u{0456}reworks_key = \"fw_0000000000000000000000000000000000000000000000000000000000000000\"",
        "fw_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 2. FIVE9 API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv34_five9_normal_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv34_five9_wrong_prefix_must_silent() {
    assert_detector_silent(
        "five9-api-credentials",
        "give9_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv34_five9_evade_zwsp_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv34_five9_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "five9_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv34_five9_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "five9-api-credentials",
        "f\u{0456}ve9_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. FIVETRAN API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv34_fivetran_normal_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "fivetran_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv34_fivetran_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fivetran-api-credentials",
        "givetran_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv34_fivetran_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "fivetran\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv34_fivetran_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "fivetran_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv34_fivetran_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fivetran-api-credentials",
        "f\u{0456}vetran_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
