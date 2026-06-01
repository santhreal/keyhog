//! Part 79 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates crisp, crowdin, crowdstrike, cryptocompare, customerio, cyberark, cypress, dacast, daily, data detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CRISP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_crisp_api_key_normal_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "crisp-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_crisp_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{200B}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{00AD}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{200C}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{200D}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{FEFF}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{2060}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{180E}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{202E}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{202C}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

#[test]
fn adv79_crisp_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "crisp-api-key",
        "CRISP_API_KEY=a5e95c2c-2e61-575f\u{200E}-5f7f-8f3b3462918d",
        "a5e95c2c-2e61-575f-5f7f-8f3b3462918d",
    );
}

// =========================================================================
// 2. CROWDIN API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_crowdin_api_token_normal_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "crowdin-api-token",
        "dummy_prefix_0 = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{200B}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{00AD}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{200C}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{200D}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{FEFF}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{2060}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{180E}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{202E}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{202C}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

#[test]
fn adv79_crowdin_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "crowdin-api-token",
        "CROWDIN_API_TOKEN = 3b70df2c347b7e02b642\u{200E}198793dc0b8a9827bb4c",
        "3b70df2c347b7e02b642198793dc0b8a9827bb4c",
    );
}

// =========================================================================
// 3. CROWDSTRIKE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_crowdstrike_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "crowdstrike-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{200B}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{00AD}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{200C}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{200D}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{FEFF}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{2060}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{180E}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{202E}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{202C}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_crowdstrike_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "crowdstrike-api-credentials",
        "FALCON_CLIENT_ID=e8b57db06c18562a\u{200E}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

// =========================================================================
// 4. CRYPTOCOMPARE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_cryptocompare_api_key_normal_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cryptocompare-api-key",
        "dummy_prefix_0:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{200B}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{00AD}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{200C}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{200D}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{FEFF}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{2060}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{180E}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{202E}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{202C}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

#[test]
fn adv79_cryptocompare_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cryptocompare-api-key",
        "cryptocompare-apikey:I0KlQV3zt8j3ItZq\u{200E}VtLrUbpqepvgWw1r",
        "I0KlQV3zt8j3ItZqVtLrUbpqepvgWw1r",
    );
}

// =========================================================================
// 5. CUSTOMERIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_customerio_api_key_normal_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "customerio-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_customerio_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv79_customerio_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "customerio-api-key",
        "CIO_SITE_ID=Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

// =========================================================================
// 6. CYBERARK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_cyberark_credentials_normal_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cyberark-credentials",
        "dummy_prefix_0 = xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{200B}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{00AD}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{200C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{200D}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{FEFF}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{2060}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{180E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{202E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{202C}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv79_cyberark_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "cyberark-credentials",
        "cyberark.appid = Kp4Qx7Rm2S\u{200E}n5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 7. CYPRESS RECORD KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_cypress_record_key_normal_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cypress-record-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_cypress_record_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{200B}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{00AD}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{200C}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{200D}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{FEFF}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{2060}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{180E}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{202E}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{202C}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

#[test]
fn adv79_cypress_record_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "cypress-record-key",
        "CYPRESS_RECORD_KEY=42136df0-709e-8c36\u{200E}-3ba2-01818f559a75",
        "42136df0-709e-8c36-3ba2-01818f559a75",
    );
}

// =========================================================================
// 8. DACAST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_dacast_api_key_normal_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dacast-api-key",
        "dummy_prefix_0 = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_dacast_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{200B}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{00AD}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{200C}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{200D}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{FEFF}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{2060}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{180E}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{202E}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{202C}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

#[test]
fn adv79_dacast_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "dacast-api-key",
        "DACAST_apikey = e8b57db06c18562a\u{200E}458356bda6c62f31",
        "e8b57db06c18562a458356bda6c62f31",
    );
}

// =========================================================================
// 9. DAILY CO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_daily_co_api_key_normal_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "daily-co-api-key",
        "dummy_prefix_0 = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{200B}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{00AD}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{200C}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{200D}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{FEFF}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{2060}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{180E}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{202E}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{202C}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

#[test]
fn adv79_daily_co_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "daily-co-api-key",
        "DAILY_API_KEY = a223af74096e28e3dda4f9d71fd2d696\u{200E}644154aeb843d9d779616433e1e04344",
        "a223af74096e28e3dda4f9d71fd2d696644154aeb843d9d779616433e1e04344",
    );
}

// =========================================================================
// 10. DATA GOV API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv79_data_gov_api_key_normal_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "data-gov-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{200B}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{00AD}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{200C}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{200D}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{FEFF}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{2060}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{180E}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{202E}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{202C}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}

#[test]
fn adv79_data_gov_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "data-gov-api-key",
        "DATA_GOV_API_KEY=eTYgKA2x9CnbU5koNVhJxrgwg\u{200E}Jgzxmvr7ZA7pxHtVr3KoU1UGV",
        "eTYgKA2x9CnbU5koNVhJxrgwgJgzxmvr7ZA7pxHtVr3KoU1UGV",
    );
}
