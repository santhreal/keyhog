//! Part 21 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Codecov, Cohere, and Coinbase detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CODECOV UPLOAD TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv21_codecov_normal_must_fire() {
    assert_detector_fires(
        "codecov-token",
        "CODECOV_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_codecov_wrong_prefix_must_silent() {
    assert_detector_silent(
        "codecov-token",
        "DODECOV_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv21_codecov_evade_zwsp_must_fire() {
    assert_detector_fires(
        "codecov-token",
        "CODECOV\u{200B}_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_codecov_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "codecov-token",
        "CODECOV_TOKEN = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_codecov_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "codecov-token",
        "C\u{041E}DECOV_TOKEN = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 2. COHERE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv21_cohere_normal_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_abcde12345abcde12345abcde12345",
        "co_abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv21_cohere_wrong_prefix_must_silent() {
    assert_detector_silent("cohere-api-key", "do_abcde12345abcde12345abcde12345");
}

#[test]
fn adv21_cohere_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co\u{200B}_abcde12345abcde12345abcde12345",
        "co_abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv21_cohere_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "co_abcde12345abcde\u{00AD}12345abcde12345",
        "co_abcde12345abcde12345abcde12345",
    );
}

#[test]
fn adv21_cohere_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "cohere-api-key",
        "c\u{043E}_abcde12345abcde12345abcde12345",
        "co_abcde12345abcde12345abcde12345",
    );
}

// =========================================================================
// 3. COINBASE CLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv21_coinbase_normal_must_fire() {
    assert_detector_fires(
        "coinbase-api-key",
        "organizations/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
        "organizations/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_coinbase_wrong_prefix_must_silent() {
    assert_detector_silent(
        "coinbase-api-key",
        "morganization/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_coinbase_evade_zwsp_must_fire() {
    assert_detector_fires(
        "coinbase-api-key",
        "organizations\u{200B}/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
        "organizations/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_coinbase_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "coinbase-api-key",
        "organizations/00000000-0000-0000-0000-000000\u{00AD}000000/apiKeys/00000000-0000-0000-0000-000000000000",
        "organizations/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv21_coinbase_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "coinbase-api-key",
        "\u{043E}rganizations/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
        "organizations/00000000-0000-0000-0000-000000000000/apiKeys/00000000-0000-0000-0000-000000000000",
    );
}
