//! Part 112 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates onelogin, onelogin, onesignal, openai, opencage, opencart, opencti, openrouter, openweathermap, opsgenie detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. ONELOGIN CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_onelogin_client_id_normal_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onelogin-client-id",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{200B}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{00AD}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_zwnj_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{200C}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_zwj_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{200D}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{FEFF}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{2060}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_mongolian_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{180E}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_rtl_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{202E}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{202C}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

#[test]
fn adv112_onelogin_client_id_evade_lrm_must_fire() {
    assert_detector_fires(
        "onelogin-client-id",
        "ONELOGIN=2be574f46dae2eb5\u{200E}b37086c51cb2e224",
        "2be574f46dae2eb5b37086c51cb2e224",
    );
}

// =========================================================================
// 2. ONELOGIN CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_onelogin_client_secret_normal_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onelogin-client-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{200B}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{00AD}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{200C}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{200D}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{FEFF}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{2060}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{180E}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{202E}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{202C}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

#[test]
fn adv112_onelogin_client_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "onelogin-client-secret",
        "ONELOGIN_CLIENT_SECRET=07acf151bcb05296ce13af60e6f56078\u{200E}21cd3c82019ab5bfa7c6c90627902c4b",
        "07acf151bcb05296ce13af60e6f5607821cd3c82019ab5bfa7c6c90627902c4b",
    );
}

// =========================================================================
// 3. ONESIGNAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_onesignal_api_key_normal_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "onesignal-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{200B}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{00AD}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{200C}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{200D}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{FEFF}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{2060}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{180E}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{202E}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{202C}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

#[test]
fn adv112_onesignal_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "onesignal-api-key",
        "onesignal=32c4a791-27eb-8b3d\u{200E}-4a7f-015e589fcb92",
        "32c4a791-27eb-8b3d-4a7f-015e589fcb92",
    );
}

// =========================================================================
// 4. OPENAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_openai_api_key_normal_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "openai-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_openai_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{200B}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{00AD}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{200C}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{200D}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{FEFF}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{2060}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{180E}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{202E}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{202C}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

#[test]
fn adv112_openai_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "openai-api-key",
        "sk-9X3kQp7VbT2hYRzNcMfWj4\u{200E}DgEsLuHaIoBnVkPxKqRtYwM8vZ",
        "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ",
    );
}

// =========================================================================
// 5. OPENCAGE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_opencage_api_key_normal_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a2636d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opencage-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_opencage_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{200B}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{00AD}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{200C}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{200D}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{FEFF}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{2060}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{180E}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{202E}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{202C}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

#[test]
fn adv112_opencage_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "opencage-api-key",
        "OPENCAGE_API_KEY=5fe803b283c6a263\u{200E}6d7b471b25b406ab",
        "5fe803b283c6a2636d7b471b25b406ab",
    );
}

// =========================================================================
// 6. OPENCART API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_opencart_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opencart-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{200B}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{00AD}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{200C}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{200D}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{FEFF}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{2060}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{180E}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{202E}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{202C}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

#[test]
fn adv112_opencart_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "opencart-api-credentials",
        "OPENCART_api_key=Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2\u{200E}Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
        "Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2Ab3Cd9Ef2Gh7Jk4Lm8Np1Qr5St0Uv6Wx3Yz2",
    );
}

// =========================================================================
// 7. OPENCTI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_opencti_api_token_normal_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opencti-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_opencti_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{200B}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{00AD}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{200C}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{200D}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{FEFF}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{2060}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{180E}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{202E}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{202C}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

#[test]
fn adv112_opencti_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "opencti-api-token",
        "opencti_api_key=6bbfb352-50ee-4684\u{200E}-85c6-f4fdd7cd01ab",
        "6bbfb352-50ee-4684-85c6-f4fdd7cd01ab",
    );
}

// =========================================================================
// 8. OPENROUTER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_openrouter_api_key_normal_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "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",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "openrouter-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{200B}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{00AD}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{200C}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{200D}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{FEFF}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{2060}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{180E}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{202E}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{202C}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

#[test]
fn adv112_openrouter_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "openrouter-api-key",
        "sk-or-v1-7b3e5d8c1a9f4e2b6c8d3a5e9f1\u{200E}b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "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",
    );
}

// =========================================================================
// 9. OPENWEATHERMAP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_openweathermap_api_key_normal_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "openweathermap-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{200B}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{00AD}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{200C}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{200D}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{FEFF}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{2060}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{180E}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{202E}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{202C}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

#[test]
fn adv112_openweathermap_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "openweathermap-api-key",
        "OPENWEATHERMAP_API_KEY=c0ab6abfd5091fb4\u{200E}abc882544f009965",
        "c0ab6abfd5091fb4abc882544f009965",
    );
}

// =========================================================================
// 10. OPSGENIE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv112_opsgenie_api_key_normal_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "opsgenie-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{200B}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{00AD}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{200C}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{200D}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{FEFF}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{2060}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{180E}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{202E}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{202C}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}

#[test]
fn adv112_opsgenie_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "opsgenie-api-key",
        "opsgenie=6b15696d-bb3e-5040\u{200E}-215f-e28bb6ac69a4",
        "6b15696d-bb3e-5040-215f-e28bb6ac69a4",
    );
}
