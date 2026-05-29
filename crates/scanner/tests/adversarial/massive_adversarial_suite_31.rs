//! Part 31 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates fantom, fastly, fastspring, fathom, and fauna detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FANTOM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv31_fantom_normal_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv31_fantom_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fantom-api-credentials",
        "gantom_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv31_fantom_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom\u{200B}_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv31_fantom_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fantom_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv31_fantom_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fantom-api-credentials",
        "fant\u{043E}m_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 2. FASTLY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv31_fastly_normal_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "fastly_token = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv31_fastly_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fastly-api-token",
        "gastly_token = \"00000000000000000000000000000000\"",
    );
}

#[test]
fn adv31_fastly_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "fastly\u{200B}_token = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv31_fastly_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "fastly_token = \"00000000000000000000\u{00AD}000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv31_fastly_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fastly-api-token",
        "f\u{0430}stly_token = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

// =========================================================================
// 3. FATHOM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv31_fathom_normal_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv31_fathom_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fathom-api-key",
        "gathom_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv31_fathom_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom\u{200B}_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv31_fathom_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "fathom_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv31_fathom_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "fathom-api-key",
        "f\u{0430}thom_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
