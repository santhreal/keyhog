//! Part 15 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Blur, Blynk, Booking.com, Box, Braintree Public Key, Braintree Private Key,
//! Braintree Sandbox Key, Braze, Brazil Dados.gov.br, and Brevo detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. BLUR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_blur_normal_must_fire() {
    assert_detector_fires(
        "blur-api-key",
        "blur_api_key = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv15_blur_wrong_prefix_must_silent() {
    assert_detector_silent("blur-api-key", "slur_api_key = \"abcde1234567890abcde\"");
}

#[test]
fn adv15_blur_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blur-api-key",
        "blur\u{200B}_api_key = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv15_blur_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blur-api-key",
        "blur_api_key = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv15_blur_evade_homoglyph_evaded_must_stay_silent() {
    assert_detector_silent("blur-api-key", "bl\u{0443}r_api_key = \"abcde1234567890abcde\"");
}

// =========================================================================
// 2. BLYNK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_blynk_normal_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "blynk_auth = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_blynk_wrong_prefix_must_silent() {
    assert_detector_silent(
        "blynk-api-credentials",
        "klynk_auth = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv15_blynk_evade_zwsp_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "blynk\u{200B}_auth = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_blynk_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "blynk_auth = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_blynk_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "blynk-api-credentials",
        "bl\u{0443}nk_auth = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 3. BOOKING.COM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_booking_normal_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "booking_com_user = \"abcde12345\"",
        "abcde12345",
    );
}

#[test]
fn adv15_booking_wrong_prefix_must_silent() {
    assert_detector_silent(
        "booking-com-api-credentials",
        "hooking_com_user = \"abcde12345\"",
    );
}

#[test]
fn adv15_booking_evade_zwsp_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "booking_com\u{200B}_user = \"abcde12345\"",
        "abcde12345",
    );
}

#[test]
fn adv15_booking_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "booking_com_user = \"abcde\u{00AD}12345\"",
        "abcde12345",
    );
}

#[test]
fn adv15_booking_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "booking-com-api-credentials",
        "b\u{043E}\u{043E}king_com_user = \"abcde12345\"",
        "abcde12345",
    );
}

// =========================================================================
// 4. BOX DEVELOPER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_box_normal_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "box_developer_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv15_box_wrong_prefix_must_silent() {
    assert_detector_silent(
        "box-developer-token",
        "fox_developer_token = \"abcde1234567890abcde\"",
    );
}

#[test]
fn adv15_box_evade_zwsp_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "box\u{200B}_developer_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv15_box_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "box_developer_token = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv15_box_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "box-developer-token",
        "b\u{043E}x_developer_token = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 5. BRAINTREE PUBLIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_braintree_public_normal_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key = \"abcde123_abcde123_abcde123\"",
        "abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_public_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braintree-api-key",
        "craintree_public_key = \"abcde123_abcde123_abcde123\"",
    );
}

#[test]
fn adv15_braintree_public_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree\u{200B}_public_key = \"abcde123_abcde123_abcde123\"",
        "abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_public_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "braintree_public_key = \"abcde123_abcde123_abcde\u{00AD}123\"",
        "abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_public_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "braintree-api-key",
        "bra\u{0457}ntree_public_key = \"abcde123_abcde123_abcde123\"",
        "abcde123_abcde123_abcde123",
    );
}

// =========================================================================
// 6. BRAINTREE PRIVATE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_braintree_private_normal_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_braintree_private_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braintree-private-key",
        "craintree_private_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv15_braintree_private_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree\u{200B}_private_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_braintree_private_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "braintree_private_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_braintree_private_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "braintree-private-key",
        "bra\u{0457}ntree_private_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 7. BRAINTREE TOKENIZATION KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_braintree_token_normal_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_abcde123_abcde123_abcde123",
        "sandbox_abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braintree-sandbox-token",
        "randbox_abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox\u{200B}_abcde123_abcde123_abcde123",
        "sandbox_abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "sandbox_abcde123_abcde123_abcde\u{00AD}123",
        "sandbox_abcde123_abcde123_abcde123",
    );
}

#[test]
fn adv15_braintree_token_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "braintree-sandbox-token",
        "s\u{0430}ndbox_abcde123_abcde123_abcde123",
        "sandbox_abcde123_abcde123_abcde123",
    );
}

// =========================================================================
// 8. BRAZE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_braze_normal_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "braze_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv15_braze_wrong_prefix_must_silent() {
    assert_detector_silent(
        "braze-api-key",
        "craze_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv15_braze_evade_zwsp_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "braze\u{200B}_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv15_braze_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "braze_api_key = \"abcde123-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv15_braze_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "braze-api-key",
        "br\u{0430}ze_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 9. BRAZIL DADOS.GOV.BR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_dadosgovbr_normal_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "dados.gov.br_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv15_dadosgovbr_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brazil-dadosgovbr-api-key",
        "dados.gov.co_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
    );
}

#[test]
fn adv15_dadosgovbr_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "dados.gov.br\u{200B}_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv15_dadosgovbr_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "dados.gov.br_api_key = \"abcde123-abcd-1234-abcd-12345678\u{00AD}90ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

#[test]
fn adv15_dadosgovbr_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "brazil-dadosgovbr-api-key",
        "d\u{0430}dos.gov.br_api_key = \"abcde123-abcd-1234-abcd-1234567890ab\"",
        "abcde123-abcd-1234-abcd-1234567890ab",
    );
}

// =========================================================================
// 10. BREVO/SENDINBLUE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv15_brevo_normal_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
        "xkeysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_brevo_wrong_prefix_must_silent() {
    assert_detector_silent(
        "brevo-api-key",
        "ykeysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_brevo_evade_zwsp_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib\u{200B}-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
        "xkeysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_brevo_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xkeysib-abcde1234567890abcde1\u{00AD}23456789012abcde1234567890abcde123456789012",
        "xkeysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv15_brevo_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "brevo-api-key",
        "xk\u{0435}ysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
        "xkeysib-abcde1234567890abcde123456789012abcde1234567890abcde123456789012",
    );
}
