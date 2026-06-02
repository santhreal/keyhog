//! Part 26 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates docusign, doordash, and doppler detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DOCUSIGN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv26_docusign_normal_bare_must_stay_silent() {
    assert_detector_silent(
        "docusign-api-key",
        "docusign_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv26_docusign_wrong_prefix_must_silent() {
    assert_detector_silent(
        "docusign-api-key",
        "focusign_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv26_docusign_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent(
        "docusign-api-key",
        "docusign\u{200B}_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv26_docusign_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent(
        "docusign-api-key",
        "docusign_key = \"000000000000000000000000000000\u{00AD}0000000000\"",
    );
}

#[test]
fn adv26_docusign_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent(
        "docusign-api-key",
        "d\u{043E}cusign_key = \"0000000000000000000000000000000000000000\"",
    );
}

// =========================================================================
// 2. DOORDASH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv26_doordash_normal_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "doordash_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv26_doordash_wrong_prefix_must_silent() {
    assert_detector_silent(
        "doordash-api-credentials",
        "foordash_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv26_doordash_evade_zwsp_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "doordash\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv26_doordash_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "doordash_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv26_doordash_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "doordash-api-credentials",
        "d\u{043E}\u{043E}rdash_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. DOPPLER SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv26_doppler_normal_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "dp.st.0000000000000000000000000000000000000000",
        "dp.st.0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv26_doppler_wrong_prefix_must_silent() {
    assert_detector_silent(
        "doppler-service-token",
        "ep.st.0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv26_doppler_evade_zwsp_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "dp.st\u{200B}.0000000000000000000000000000000000000000",
        "dp.st.0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv26_doppler_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "dp.st.0000000000000000000000\u{00AD}000000000000000000",
        "dp.st.0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv26_doppler_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "doppler-service-token",
        "dp.s\u{0442}.0000000000000000000000000000000000000000",
        "dp.st.0000000000000000000000000000000000000000",
    );
}
