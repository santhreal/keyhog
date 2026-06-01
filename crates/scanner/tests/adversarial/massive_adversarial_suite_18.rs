//! Part 18 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Census, Censys, Checkly, and Checkout.com detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CENSUS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv18_census_normal_bare_must_stay_silent() {
    assert_detector_silent("census-api-key", "CENSUS_TOKEN = \"abcde12345abcde12345abcde1234512\"");
}

#[test]
fn adv18_census_wrong_prefix_must_silent() {
    assert_detector_silent(
        "census-api-key",
        "DENSUS_TOKEN = \"abcde12345abcde12345abcde1234512\"",
    );
}

#[test]
fn adv18_census_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("census-api-key", "CENSUS\u{200B}_TOKEN = \"abcde12345abcde12345abcde1234512\"");
}

#[test]
fn adv18_census_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("census-api-key", "CENSUS_TOKEN = \"abcde12345abcde\u{00AD}12345abcde1234512\"");
}

#[test]
fn adv18_census_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("census-api-key", "C\u{0415}NSUS_TOKEN = \"abcde12345abcde12345abcde1234512\"");
}

// =========================================================================
// 2. CENSYS API ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv18_censys_normal_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "censys_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv18_censys_wrong_prefix_must_silent() {
    assert_detector_silent(
        "censys-api-credentials",
        "densys_id = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv18_censys_evade_zwsp_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "censys\u{200B}_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv18_censys_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "censys_id = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv18_censys_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "censys-api-credentials",
        "cens\u{0443}s_id = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 3. CHECKLY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv18_checkly_normal_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "checkly_api_key = \"cu_abcde12345abcde12345abcde\"",
        "cu_abcde12345abcde12345abcde",
    );
}

#[test]
fn adv18_checkly_wrong_prefix_must_silent() {
    assert_detector_silent(
        "checkly-api-key",
        "dheckly_api_key = \"cx_abcde12345abcde12345abcde\"",
    );
}

#[test]
fn adv18_checkly_evade_zwsp_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "checkly\u{200B}_api_key = \"cu_abcde12345abcde12345abcde\"",
        "cu_abcde12345abcde12345abcde",
    );
}

#[test]
fn adv18_checkly_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "checkly_api_key = \"cu_abcde12345abcde\u{00AD}12345abcde\"",
        "cu_abcde12345abcde12345abcde",
    );
}

#[test]
fn adv18_checkly_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "checkly-api-key",
        "ch\u{0435}ckly_api_key = \"cu_abcde12345abcde12345abcde\"",
        "cu_abcde12345abcde12345abcde",
    );
}

// =========================================================================
// 4. CHECKOUT.COM SANDBOX SECRET KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv18_checkout_normal_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_abcde12345abcde12345abcde",
        "sk_sbox_abcde12345abcde12345abcde",
    );
}

#[test]
fn adv18_checkout_wrong_prefix_must_silent() {
    assert_detector_silent("checkout-com-api-key", "tk_sbox_abcde12345abcde12345abcde");
}

#[test]
fn adv18_checkout_evade_zwsp_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk\u{200B}_sbox_abcde12345abcde12345abcde",
        "sk_sbox_abcde12345abcde12345abcde",
    );
}

#[test]
fn adv18_checkout_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "sk_sbox_abcde12345abcde\u{00AD}12345abcde",
        "sk_sbox_abcde12345abcde12345abcde",
    );
}

#[test]
fn adv18_checkout_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "checkout-com-api-key",
        "s\u{043A}_sbox_abcde12345abcde12345abcde",
        "sk_sbox_abcde12345abcde12345abcde",
    );
}
