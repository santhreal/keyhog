//! Part 24 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates devto, dhl, digitalocean, and directus detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DEVTO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv24_devto_normal_bare_must_stay_silent() {
    assert_detector_silent(
        "devto-api-key",
        "devto_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv24_devto_wrong_prefix_must_silent() {
    assert_detector_silent(
        "devto-api-key",
        "fevto_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv24_devto_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent(
        "devto-api-key",
        "devto\u{200B}_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv24_devto_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent(
        "devto-api-key",
        "devto_key = \"000000000000000000000000000000\u{00AD}0000000000\"",
    );
}

#[test]
fn adv24_devto_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent(
        "devto-api-key",
        "d\u{0435}vto_key = \"0000000000000000000000000000000000000000\"",
    );
}

// =========================================================================
// 2. DHL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv24_dhl_normal_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "dhl_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv24_dhl_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dhl-api-credentials",
        "fehl_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv24_dhl_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "dhl\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv24_dhl_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "dhl_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv24_dhl_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "dh\u{0456}a_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. DIGITALOCEAN PERSONAL ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv24_digitalocean_normal_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "digitalocean_token = \"dop_v1_0000000000000000000000000000000000000000000000000000000000000000\"",
        "dop_v1_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv24_digitalocean_wrong_prefix_must_silent() {
    assert_detector_silent(
        "digitalocean-pat",
        "figitalocean_token = \"dxp_v1_0000000000000000000000000000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv24_digitalocean_evade_zwsp_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "digitalocean\u{200B}_token = \"dop_v1_0000000000000000000000000000000000000000000000000000000000000000\"",
        "dop_v1_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn adv24_digitalocean_evade_soft_hyphen_evaded_must_stay_silent() {
    assert_detector_silent("digitalocean-pat", "digitalocean_token = \"dop_v1_0000000000000000000000000000000000000000000000000000\u{00AD}0000000000\"");
}

#[test]
fn adv24_digitalocean_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "d\u{0456}gitalocean_token = \"dop_v1_0000000000000000000000000000000000000000000000000000000000000000\"",
        "dop_v1_0000000000000000000000000000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 4. DIRECTUS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv24_directus_normal_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "directus_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv24_directus_wrong_prefix_must_silent() {
    assert_detector_silent(
        "directus-api-token",
        "firectus_token = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv24_directus_evade_zwsp_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "directus\u{200B}_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv24_directus_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "directus_token = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv24_directus_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "d\u{0456}rectus_token = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
