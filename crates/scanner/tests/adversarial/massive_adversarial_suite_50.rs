//! Part 50 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates packagist, packer, paddle, pagerduty, paloalto, pandadoc, pandora, papertrail, pardot, particle detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PACKAGIST API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_packagist_api_token_normal_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv50_packagist_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "packagist-api-token",
        "dummy_prefix_0 =xxx5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv50_packagist_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{200B}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

#[test]
fn adv50_packagist_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "packagist-api-token",
        "PACKAGIST_API_KEY=a6a5effa36c91d47cb12\u{00AD}be92bd74e20b3148bf5b",
        "a6a5effa36c91d47cb12be92bd74e20b3148bf5b",
    );
}

// =========================================================================
// 2. PACKER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_packer_credentials_normal_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv50_packer_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "packer-credentials",
        "dummy_prefix_0 =xxx1f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv50_packer_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{200B}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

#[test]
fn adv50_packer_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "packer-credentials",
        "HCP_CLIENT_ID=2741f27f-279a-1657\u{00AD}-afb4-30b08a3d35d0",
        "2741f27f-279a-1657-afb4-30b08a3d35d0",
    );
}

// =========================================================================
// 3. PADDLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_paddle_api_key_normal_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv50_paddle_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paddle-api-key",
        "dummylive_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv50_paddle_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{200B}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv50_paddle_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paddle-api-key",
        "pdl_live_apikey_Kp4Qx7Rm\u{00AD}2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "pdl_live_apikey_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. PAGERDUTY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_pagerduty_api_key_normal_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv50_pagerduty_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pagerduty-api-key",
        "dummy_prefix_0 =xxx4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv50_pagerduty_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{200B}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv50_pagerduty_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{00AD}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

// =========================================================================
// 5. PALOALTO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_paloalto_api_key_normal_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv50_paloalto_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paloalto-api-key",
        "dummy_prefix_0 =xxx3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv50_paloalto_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{200B}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv50_paloalto_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{00AD}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

// =========================================================================
// 6. PANDADOC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_pandadoc_api_key_normal_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv50_pandadoc_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pandadoc-api-key",
        "dummy_prefix_0 =xxxd3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv50_pandadoc_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{200B}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv50_pandadoc_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{00AD}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

// =========================================================================
// 7. PANDORA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_pandora_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipKhDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv50_pandora_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pandora-api-credentials",
        "dummy_prefix_0 =xxx5pipKhDrZzqli",
    );
}

#[test]
fn adv50_pandora_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{200B}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv50_pandora_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{00AD}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

// =========================================================================
// 8. PAPERTRAIL API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_papertrail_api_token_normal_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv50_papertrail_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "papertrail-api-token",
        "dummy_prefix_0 =xxxe5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv50_papertrail_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv50_papertrail_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. PARDOT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_pardot_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv50_pardot_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pardot-api-credentials",
        "dummy_prefix_0 =xxxKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv50_pardot_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{200B}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv50_pardot_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{00AD}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

// =========================================================================
// 10. PARTICLE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv50_particle_api_token_normal_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv50_particle_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "particle-api-token",
        "dummy_prefix_0 =xxxddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv50_particle_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{200B}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv50_particle_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{00AD}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}


