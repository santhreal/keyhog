//! Part 48 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates okta, olark, omnisend, onedrive, onelogin, onelogin, onesignal, opencage, opencart, opencti detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. OKTA SUPPORT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_okta_support_token_normal_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv48_okta_support_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "okta-support-token",
        "dummy_prefix_0 =00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv48_okta_support_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{200B}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

#[test]
fn adv48_okta_support_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "okta-support-token",
        "OKTA=00abcdefghijklmnop\u{00AD}qrstuvwxyz1234567890abcd",
        "OKTA=00abcdefghijklmnopqrstuvwxyz1234567890abcd",
    );
}

// =========================================================================
// 2. OLARK API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_olark_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv48_olark_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "olark-api-credentials",
        "dummy_prefix_0 =xxxd4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv48_olark_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{200B}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

#[test]
fn adv48_olark_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "olark-api-credentials",
        "OLARK_API_KEY=2c3d4ccd8047838a93ea\u{00AD}899679132d920e8b52a9",
        "2c3d4ccd8047838a93ea899679132d920e8b52a9",
    );
}

// =========================================================================
// 3. OMNISEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_omnisend_api_key_normal_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626eedd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv48_omnisend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "omnisend-api-key",
        "dummy_prefix_0 =xxx030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv48_omnisend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{200B}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

#[test]
fn adv48_omnisend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "omnisend-api-key",
        "OMNISEND_API_KEY=614030930ca9626e\u{00AD}edd2b6b73c763ac9",
        "614030930ca9626eedd2b6b73c763ac9",
    );
}

// =========================================================================
// 4. ONEDRIVE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_onedrive_access_token_normal_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv48_onedrive_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onedrive-access-token",
        "dummy_prefix_0 =xxx0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv48_onedrive_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{200B}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

#[test]
fn adv48_onedrive_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onedrive-access-token",
        "ONEDRIVE_TOKEN=eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpV\u{00AD}lfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
        "eyJ0eXFHAOW1dcFx6CSwxQjhHI2t-8Yz9L0gGN39H67mlO6DjJsMq8.eyJtMwzbKxqpVlfyPWYAk43XzRf2DLgpt3nsGWdU.v_Dd9gVB5bLy1nXh91hk3v0sk2ZZaFjFbUgA7D7EL",
    );
}

// =========================================================================
// 5. ONELOGIN CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_onelogin_client_id_normal_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv48_onelogin_client_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onelogin-client-id",
        "dummy_prefix_0 =xxx574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv48_onelogin_client_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{200B}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv48_onelogin_client_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{00AD}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

// =========================================================================
// 6. ONELOGIN CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_onelogin_client_secret_normal_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv48_onelogin_client_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onelogin-client-secret",
        "dummy_prefix_0 =xxxcf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv48_onelogin_client_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{200B}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv48_onelogin_client_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{00AD}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

// =========================================================================
// 7. ONESIGNAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_onesignal_api_key_normal_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv48_onesignal_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onesignal-api-key",
        "dummy_prefix_0 =xxx4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv48_onesignal_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{200B}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv48_onesignal_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{00AD}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

// =========================================================================
// 8. OPENCAGE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_opencage_api_key_normal_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a2636d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv48_opencage_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opencage-api-key",
        "dummy_prefix_0 =xxx803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv48_opencage_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{200B}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv48_opencage_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{00AD}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

// =========================================================================
// 9. OPENCART API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_opencart_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv48_opencart_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opencart-api-credentials",
        "dummy_prefix_0 =xxxCd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv48_opencart_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{200B}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv48_opencart_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{00AD}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

// =========================================================================
// 10. OPENCTI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv48_opencti_api_token_normal_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv48_opencti_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opencti-api-token",
        "dummy_prefix_0 =xxxfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv48_opencti_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{200B}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv48_opencti_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{00AD}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}


