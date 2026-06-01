//! Part 136 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates unitycloud, unleash, unsplash, uploadcare, uploadcare, ups, upstash, upstash, us, usda detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. UNITYCLOUD API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_unitycloud_api_key_normal_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "unitycloud-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{200B}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{00AD}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{200C}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{200D}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{FEFF}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{2060}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{180E}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{202E}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{202C}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

#[test]
fn adv136_unitycloud_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "unitycloud-api-key",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5\u{200E}Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
        "UCA-Z7aLR0tW7QWBqHSP89uZk8UIOiWtFvrodTd9E1rCPCUIz5Vd113Zzedwsvor3GP5aVL5ZUvY1zdWm2X6Jy9SV4lIFWGGBVcD5",
    );
}

// =========================================================================
// 2. UNLEASH API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_unleash_api_token_normal_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:production.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("unleash-api-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv136_unleash_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{200B}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{00AD}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{200C}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{200D}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{FEFF}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{2060}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{180E}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{202E}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{202C}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

#[test]
fn adv136_unleash_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "unleash-api-token",
        "default:produc\u{200E}tion.xElc1Ruuqf",
        "default:production.xElc1Ruuqf",
    );
}

// =========================================================================
// 3. UNSPLASH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_unsplash_api_key_normal_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "unsplash-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{200B}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{00AD}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{200C}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{200D}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{FEFF}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{2060}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{180E}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{202E}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{202C}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

#[test]
fn adv136_unsplash_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "unsplash-api-key",
        "UNSPLASHACCESSKEY=b56N2Squqb-gGnPqf5VOZ\u{200E}GsBl15UBi9LJhkMOwkSOxB",
        "b56N2Squqb-gGnPqf5VOZGsBl15UBi9LJhkMOwkSOxB",
    );
}

// =========================================================================
// 4. UPLOADCARE PUBLIC KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_uploadcare_public_key_normal_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "uploadcare-public-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{200B}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{00AD}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{200C}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{200D}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{FEFF}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{2060}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{180E}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{202E}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{202C}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

#[test]
fn adv136_uploadcare_public_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "uploadcare-public-key",
        "UPLOADCAREKEY=acbb7763f9b872d8\u{200E}aec7e11cbd083acb",
        "acbb7763f9b872d8aec7e11cbd083acb",
    );
}

// =========================================================================
// 5. UPLOADCARE SECRET KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_uploadcare_secret_key_normal_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "uploadcare-secret-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{200B}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{00AD}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{200C}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{200D}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{FEFF}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{2060}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{180E}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{202E}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{202C}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

#[test]
fn adv136_uploadcare_secret_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "uploadcare-secret-key",
        "UPLOADCARESECRET=4cced4550e9d69a5\u{200E}dd31e9633b313a70",
        "4cced4550e9d69a5dd31e9633b313a70",
    );
}

// =========================================================================
// 6. UPS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_ups_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ups-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{200B}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{00AD}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{200C}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{200D}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{FEFF}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{2060}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{180E}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{202E}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{202C}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

#[test]
fn adv136_ups_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "ups-api-credentials",
        "UPS_CLIENT_ID=MuWJoWBOkbfyPjcBZSvWvqav\u{200E}DQ2lPmnBM4y0W7Ue4SYoiaFv",
        "MuWJoWBOkbfyPjcBZSvWvqavDQ2lPmnBM4y0W7Ue4SYoiaFv",
    );
}

// =========================================================================
// 7. UPSTASH KAFKA CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_upstash_kafka_credentials_normal_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "upstash-kafka-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{200B}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{00AD}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{200C}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{200D}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{FEFF}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{2060}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{180E}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{202E}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{202C}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

#[test]
fn adv136_upstash_kafka_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "upstash-kafka-credentials",
        "https://afmi92zj0y0j\u{200E}msj-kafka.upstash.io",
        "https://afmi92zj0y0jmsj-kafka.upstash.io",
    );
}

// =========================================================================
// 8. UPSTASH REDIS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_upstash_redis_credentials_normal_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "upstash-redis-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{200B}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{00AD}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{200C}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{200D}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{FEFF}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{2060}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{180E}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{202E}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{202C}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

#[test]
fn adv136_upstash_redis_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "upstash-redis-credentials",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg43\u{200E}2szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
        "https://oswe2me24b7qa10jcxz311yz317wb07t7cg432szm2cskgnz-ocah11k8xtwpse6ylp-0qgn.upstash.io",
    );
}

// =========================================================================
// 9. US CENSUS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_us_census_api_key_normal_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "us-census-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_us_census_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{200B}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{00AD}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{200C}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{200D}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{FEFF}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{2060}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{180E}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{202E}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{202C}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

#[test]
fn adv136_us_census_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "us-census-api-key",
        "CENSUS_API_KEY=f009f7236f6fb315ba5b\u{200E}cbffbb3a884b68b8028e",
        "f009f7236f6fb315ba5bcbffbb3a884b68b8028e",
    );
}

// =========================================================================
// 10. USDA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv136_usda_api_key_normal_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "usda-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv136_usda_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{200B}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{00AD}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{200C}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{200D}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{FEFF}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{2060}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{180E}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{202E}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{202C}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}

#[test]
fn adv136_usda_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "usda-api-key",
        "USDA_API_KEY=1XcqoEeyy5Y9Vh0tDm\u{200E}TMEw04Uksa5KSO8uRS",
        "1XcqoEeyy5Y9Vh0tDmTMEw04Uksa5KSO8uRS",
    );
}
