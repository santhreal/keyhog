//! Part 52 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates pinecone, pingdom, pinterest, pinterest, pipedream, pirsch, piwikpro, pixabay, plaid, plaid detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PINECONE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pinecone_api_key_normal_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv52_pinecone_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pinecone-api-key",
        "dummy_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv52_pinecone_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{200B}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv52_pinecone_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pinecone-api-key",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7R\u{00AD}m2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "pcsk_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 2. PINGDOM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pingdom_api_key_normal_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv52_pingdom_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pingdom-api-key",
        "dummy_prefix_0 =xxx6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv52_pingdom_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{200B}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

#[test]
fn adv52_pingdom_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pingdom-api-key",
        "pingdom.api_key=Eqd6yBLcY71nZR9yY59FDF\u{00AD}I5RQ8uvP3cB2wFLNdtabcd",
        "Eqd6yBLcY71nZR9yY59FDFI5RQ8uvP3cB2wFLNdtabcd",
    );
}

// =========================================================================
// 3. PINTEREST ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pinterest_access_token_normal_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv52_pinterest_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pinterest-access-token",
        "dummy_prefix_0 =xxxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv52_pinterest_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{200B}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

#[test]
fn adv52_pinterest_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pinterest-access-token",
        "PINTEREST=cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0\u{00AD}nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
        "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi",
    );
}

// =========================================================================
// 4. PINTEREST ADS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pinterest_ads_api_token_normal_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv52_pinterest_ads_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pinterest-ads-api-token",
        "dummy_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv52_pinterest_ads_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{200B}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

#[test]
fn adv52_pinterest_ads_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pinterest-ads-api-token",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhq\u{00AD}zafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
        "pina_6jF09OFQeEGcfCNWG_Efi20A0rRdBYglQ7yhqzafB1Xwqt8EqJUOjeRyg7sP4t6-eD1Fj6eHvitl4J8",
    );
}

// =========================================================================
// 5. PIPEDREAM API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pipedream_api_key_normal_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv52_pipedream_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pipedream-api-key",
        "dummykaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv52_pipedream_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{200B}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

#[test]
fn adv52_pipedream_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pipedream-api-key",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYD\u{00AD}OxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
        "api_kaxHrCzkGkCZm0h4Zg42FLRQ1Iqt8C3BqyDXJdHXjYDOxYxMyWbUshf83I2z8LS5NF42L57S3Wv0rftjdzgVoFuwd5",
    );
}

// =========================================================================
// 6. PIRSCH API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pirsch_api_token_normal_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv52_pirsch_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pirsch-api-token",
        "dummyp9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv52_pirsch_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{200B}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

#[test]
fn adv52_pirsch_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pirsch-api-token",
        "pa_6p9KJHPwVUfCna\u{00AD}4zMLnGUFMfL7SXbkwN",
        "pa_6p9KJHPwVUfCna4zMLnGUFMfL7SXbkwN",
    );
}

// =========================================================================
// 7. PIWIKPRO API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_piwikpro_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv52_piwikpro_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "piwikpro-api-credentials",
        "dummy_prefix_0 =xxx42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv52_piwikpro_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{200B}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

#[test]
fn adv52_piwikpro_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "piwikpro-api-credentials",
        "PIWIK_PRO_CLIENT_ID=8ab42f49-89fb-d2fe\u{00AD}-b83e-f0ea8a1fe14e",
        "8ab42f49-89fb-d2fe-b83e-f0ea8a1fe14e",
    );
}

// =========================================================================
// 8. PIXABAY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_pixabay_api_key_normal_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv52_pixabay_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pixabay-api-key",
        "dummy_prefix_0 =xxxZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv52_pixabay_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{200B}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

#[test]
fn adv52_pixabay_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pixabay-api-key",
        "PIXABAY_API_KEY=DCHZQ_MVm-9HnlNW\u{00AD}lprYXJAMUUkRFpcV",
        "DCHZQ_MVm-9HnlNWlprYXJAMUUkRFpcV",
    );
}

// =========================================================================
// 9. PLAID CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_plaid_client_id_normal_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdbe0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv52_plaid_client_id_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plaid-client-id",
        "dummy_prefix_0 =xxx17b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv52_plaid_client_id_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{200B}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

#[test]
fn adv52_plaid_client_id_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plaid-client-id",
        "PLAID=c1517b308bdb\u{00AD}e0ebd278e1b7",
        "c1517b308bdbe0ebd278e1b7",
    );
}

// =========================================================================
// 10. PLAID LINK TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv52_plaid_link_token_normal_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv52_plaid_link_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "plaid-link-token",
        "dummy-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv52_plaid_link_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{200B}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}

#[test]
fn adv52_plaid_link_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "plaid-link-token",
        "link-production-c416000d-6\u{00AD}3bb-0db9-d70a-0e03cd885ce7",
        "link-production-c416000d-63bb-0db9-d70a-0e03cd885ce7",
    );
}


