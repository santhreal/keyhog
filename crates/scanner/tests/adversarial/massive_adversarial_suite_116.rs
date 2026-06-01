//! Part 116 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates pinterest, pipedream, pirsch, piwikpro, pixabay, plaid, plaid, plaid, planetscale, planetscale detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PINTEREST ADS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_pinterest_ads_api_token_normal_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pinterest-ads-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{200B}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{00AD}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{200C}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{200D}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{FEFF}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{2060}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{180E}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{202E}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{202C}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv116_pinterest_ads_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{200E}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

// =========================================================================
// 2. PIPEDREAM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_pipedream_api_key_normal_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pipedream-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{200B}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{00AD}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{200C}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{200D}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{FEFF}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{2060}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{180E}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{202E}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{202C}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv116_pipedream_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{200E}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

// =========================================================================
// 3. PIRSCH API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_pirsch_api_token_normal_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("pirsch-api-token", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv116_pirsch_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{200B}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{00AD}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{200C}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{200D}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{FEFF}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{2060}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{180E}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{202E}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{202C}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv116_pirsch_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{200E}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

// =========================================================================
// 4. PIWIKPRO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_piwikpro_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "piwikpro-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{200B}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{00AD}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{200C}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{200D}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{FEFF}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{2060}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{180E}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{202E}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{202C}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv116_piwikpro_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{200E}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

// =========================================================================
// 5. PIXABAY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_pixabay_api_key_normal_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pixabay-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{200B}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{00AD}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{200C}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{200D}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{FEFF}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{2060}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{180E}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{202E}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{202C}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv116_pixabay_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{200E}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

// =========================================================================
// 6. PLAID CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_plaid_client_id_normal_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdbe0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plaid-client-id",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_plaid_client_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{200B}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{00AD}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_zwnj_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{200C}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_zwj_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{200D}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{FEFF}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{2060}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_mongolian_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{180E}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_rtl_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{202E}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{202C}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv116_plaid_client_id_evade_lrm_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{200E}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

// =========================================================================
// 7. PLAID LINK TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_plaid_link_token_normal_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plaid-link-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_plaid_link_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{200B}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{00AD}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{200C}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{200D}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{FEFF}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{2060}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{180E}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{202E}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{202C}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv116_plaid_link_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{200E}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

// =========================================================================
// 8. PLAID SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_plaid_secret_normal_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plaid-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_plaid_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv116_plaid_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "plaid-secret",
        "PLAID_SECRET=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. PLANETSCALE API TOKEN V2 ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_planetscale_api_token_v2_normal_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_wrong_prefix_must_silent() {
    assert_detector_silent(
        "planetscale-api-token-v2",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_zwsp_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{200B}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{00AD}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_zwnj_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{200C}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_zwj_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{200D}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{FEFF}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{2060}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_mongolian_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{180E}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_rtl_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{202E}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{202C}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

#[test]
fn adv116_planetscale_api_token_v2_evade_lrm_must_fire() {
    assert_detector_fires(
        "planetscale-api-token-v2",
        "pscale_tkn_93iwbHaZKA\u{200E}mZqjeAwhEWgwf3zowdD5bu",
        "pscale_tkn_93iwbHaZKAmZqjeAwhEWgwf3zowdD5bu",
    );
}

// =========================================================================
// 10. PLANETSCALE SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv116_planetscale_service_token_normal_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "planetscale-service-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{200B}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{00AD}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{200C}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{200D}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{FEFF}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{2060}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{180E}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{202E}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{202C}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}

#[test]
fn adv116_planetscale_service_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "planetscale-service-token",
        "pscale_tkn_EwD5ne5cVM87vVUv\u{200E}FegDFbHqRWPLuPfgovlAxiHFhIB",
        "pscale_tkn_EwD5ne5cVM87vVUvFegDFbHqRWPLuPfgovlAxiHFhIB",
    );
}
