//! Part 30 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates elasticsearch, elevenlabs, eloqua, env0, and epa detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ELEVENLABS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv30_elevenlabs_normal_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "elevenlabs_key = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv30_elevenlabs_wrong_prefix_must_silent() {
    assert_detector_silent(
        "elevenlabs-api-key",
        "dlevenlabs_key = \"00000000000000000000000000000000\"",
    );
}

#[test]
fn adv30_elevenlabs_evade_zwsp_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "elevenlabs\u{200B}_key = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv30_elevenlabs_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "elevenlabs_key = \"00000000000000000000\u{00AD}000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv30_elevenlabs_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "elevenlabs-api-key",
        "el\u{0435}venlabs_key = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

// =========================================================================
// 2. ENV0 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv30_env0_normal_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "env0_key = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv30_env0_wrong_prefix_must_silent() {
    assert_detector_silent(
        "env0-api-key",
        "dnv0_key = \"00000000000000000000000000000000\"",
    );
}

#[test]
fn adv30_env0_evade_zwsp_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "env0\u{200B}_key = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv30_env0_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "env0_key = \"00000000000000000000\u{00AD}000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv30_env0_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "env0-api-key",
        "env\u{043E}_key = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

// =========================================================================
// 3. EPA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv30_epa_normal_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "epa_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv30_epa_wrong_prefix_must_silent() {
    assert_detector_silent("epa-api-key", "fpa_key = \"abcde12345abcde12345\"");
}

#[test]
fn adv30_epa_evade_zwsp_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "epa\u{200B}_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv30_epa_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "epa_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv30_epa_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "epa-api-key",
        "\u{0435}pa_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
