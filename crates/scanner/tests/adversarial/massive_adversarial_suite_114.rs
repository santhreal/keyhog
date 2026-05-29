//! Part 114 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates pagerduty, paloalto, pandadoc, pandora, papertrail, pardot, particle, passbase, paychex, payload detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. PAGERDUTY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_pagerduty_api_key_normal_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pagerduty-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{200B}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{00AD}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{200C}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{200D}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{FEFF}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{2060}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{180E}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{202E}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{202C}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

#[test]
fn adv114_pagerduty_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pagerduty-api-key",
        "PAGERDUTY_API_KEY=k7p4qx9rm2sn5tb8\u{200E}vw3yz0a6b8c4d1f3",
        "k7p4qx9rm2sn5tb8vw3yz0a6b8c4d1f3",
    );
}

// =========================================================================
// 2. PALOALTO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_paloalto_api_key_normal_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paloalto-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{200B}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{00AD}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{200C}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{200D}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{FEFF}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{2060}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{180E}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{202E}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{202C}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

#[test]
fn adv114_paloalto_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "paloalto-api-key",
        "PALOALTO_API_KEY=/7j3M6glXEI5gvG5RRuI\u{200E}QjBARCDxbz8wJWl3EiPP",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    );
}

// =========================================================================
// 3. PANDADOC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_pandadoc_api_key_normal_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pandadoc-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{200B}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{00AD}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{200C}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{200D}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{FEFF}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{2060}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{180E}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{202E}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{202C}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

#[test]
fn adv114_pandadoc_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "pandadoc-api-key",
        "PANDADOC_API_KEY=9a6d3f4b584413eda52b0e42239102d6\u{200E}05f5c8d843fdcbe6891a202d4a1432e9",
        "9a6d3f4b584413eda52b0e42239102d605f5c8d843fdcbe6891a202d4a1432e9",
    );
}

// =========================================================================
// 4. PANDORA API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_pandora_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipKhDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pandora-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{200B}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{00AD}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{200C}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{200D}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{FEFF}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{2060}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{180E}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{202E}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{202C}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

#[test]
fn adv114_pandora_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "pandora-api-credentials",
        "PANDORACLIENTID=Ot15pipK\u{200E}hDrZzqli",
        "Ot15pipKhDrZzqli",
    );
}

// =========================================================================
// 5. PAPERTRAIL API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_papertrail_api_token_normal_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "papertrail-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv114_papertrail_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "papertrail-api-token",
        "PAPERTRAIL_API_TOKEN=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 6. PARDOT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_pardot_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "pardot-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{200B}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{00AD}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{200C}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{200D}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{FEFF}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{2060}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{180E}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{202E}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{202C}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

#[test]
fn adv114_pardot_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "pardot-api-credentials",
        "PARDOT_BUSINESS_UNIT_ID=0UvKp4mN8\u{200E}qR2sT6vX0",
        "0UvKp4mN8qR2sT6vX0",
    );
}

// =========================================================================
// 7. PARTICLE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_particle_api_token_normal_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "particle-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_particle_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{200B}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{00AD}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{200C}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{200D}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{FEFF}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{2060}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{180E}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{202E}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{202C}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

#[test]
fn adv114_particle_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "particle-api-token",
        "PARTICLE_ACCESS_TOKEN=148ddd535501d0d2be7e\u{200E}63b142409d7f6a0e6c7f",
        "148ddd535501d0d2be7e63b142409d7f6a0e6c7f",
    );
}

// =========================================================================
// 8. PASSBASE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_passbase_api_key_normal_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJEc_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "passbase-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_passbase_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{200B}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{00AD}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{200C}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{200D}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{FEFF}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{2060}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{180E}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{202E}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{202C}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

#[test]
fn adv114_passbase_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "passbase-api-key",
        "X-API-KEY=7VVpvY_rJE\u{200E}c_G33gXrRw",
        "7VVpvY_rJEc_G33gXrRw",
    );
}

// =========================================================================
// 9. PAYCHEX API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_paychex_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDahGSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "paychex-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{200B}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{00AD}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{200C}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{200D}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{FEFF}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{2060}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{180E}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{202E}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{202C}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

#[test]
fn adv114_paychex_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "paychex-api-credentials",
        "PAYCHEX_CLIENT_ID=L979NZXDah\u{200E}GSlqozkR8h",
        "L979NZXDahGSlqozkR8h",
    );
}

// =========================================================================
// 10. PAYLOAD CMS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv114_payload_cms_api_key_normal_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "payload-cms-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{200B}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{00AD}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{200C}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{200D}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{FEFF}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{2060}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{180E}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{202E}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{202C}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}

#[test]
fn adv114_payload_cms_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "payload-cms-api-key",
        "PAYLOAD_API_KEY=c191374f-c337-41b5\u{200E}-4a8b-64b48783d13f",
        "c191374f-c337-41b5-4a8b-64b48783d13f",
    );
}


