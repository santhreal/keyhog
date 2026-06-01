//! Part 20 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Clio, Cloudflare, and Cloudinary detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CLIO CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv20_clio_normal_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv20_clio_wrong_prefix_must_silent() {
    assert_detector_silent(
        "clio-api-credentials",
        "DLIO_CLIENT_ID = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv20_clio_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO\u{200B}_CLIENT_ID = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv20_clio_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CLIO_CLIENT_ID = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv20_clio_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "clio-api-credentials",
        "CL\u{0406}O_CLIENT_ID = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 2. CLOUDFLARE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv20_cloudflare_api_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv20_cloudflare_api_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-api-token",
        "DF_API_TOKEN = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv20_cloudflare_api_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API\u{200B}_TOKEN = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv20_cloudflare_api_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_API_TOKEN = \"000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv20_cloudflare_api_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "cloudflare-api-token",
        "CF_AP\u{0406}_TOKEN = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 3. CLOUDFLARE GLOBAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv20_cloudflare_global_normal_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY = \"0000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000",
    );
}

#[test]
fn adv20_cloudflare_global_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudflare-global-api-key",
        "DLOUDFLARE_API_KEY = \"0000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv20_cloudflare_global_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE\u{200B}_API_KEY = \"0000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000",
    );
}

#[test]
fn adv20_cloudflare_global_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CLOUDFLARE_API_KEY = \"000000000000000000000000000000\u{00AD}0000000\"",
        "0000000000000000000000000000000000000",
    );
}

#[test]
fn adv20_cloudflare_global_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "cloudflare-global-api-key",
        "CL\u{041E}UDFLARE_API_KEY = \"0000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000",
    );
}

// =========================================================================
// 4. CLOUDINARY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv20_cloudinary_normal_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://000000:abcde12345@abcde12345",
        "cloudinary://000000:abcde12345@abcde12345",
    );
}

#[test]
fn adv20_cloudinary_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cloudinary-api-key",
        "dloudinary://000000:abcde12345@abcde12345",
    );
}

#[test]
fn adv20_cloudinary_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary\u{200B}://000000:abcde12345@abcde12345",
        "cloudinary://000000:abcde12345@abcde12345",
    );
}

#[test]
fn adv20_cloudinary_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cloudinary://000000:abcde\u{00AD}12345@abcde12345",
        "cloudinary://000000:abcde12345@abcde12345",
    );
}

#[test]
fn adv20_cloudinary_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "cloudinary-api-key",
        "cl\u{043E}udinary://000000:abcde12345@abcde12345",
        "cloudinary://000000:abcde12345@abcde12345",
    );
}
