//! Part 123 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates rippling, rocketmatter, rollbar, rome2rio, rootly, routee, rubygems, rudder, rudderstack, salesforce detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. RIPPLING API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rippling_api_key_normal_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rippling-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rippling_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{200B}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{00AD}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{200C}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{200D}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{FEFF}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{2060}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{180E}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{202E}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{202C}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv123_rippling_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{200E}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

// =========================================================================
// 2. ROCKETMATTER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rocketmatter_api_key_normal_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rocketmatter-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{200B}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{00AD}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{200C}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{200D}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{FEFF}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{2060}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{180E}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{202E}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{202C}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv123_rocketmatter_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{200E}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

// =========================================================================
// 3. ROLLBAR ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rollbar_access_token_normal_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rollbar-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{200B}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{00AD}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{200C}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{200D}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{FEFF}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{2060}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{180E}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{202E}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{202C}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv123_rollbar_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{200E}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

// =========================================================================
// 4. ROME2RIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rome2rio_api_key_normal_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rome2rio-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{200B}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{00AD}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{200C}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{200D}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{FEFF}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{2060}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{180E}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{202E}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{202C}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv123_rome2rio_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{200E}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

// =========================================================================
// 5. ROOTLY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rootly_api_token_normal_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rootly-api-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rootly_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{200B}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{00AD}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{200C}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{200D}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{FEFF}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{2060}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{180E}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{202E}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{202C}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv123_rootly_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{200E}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

// =========================================================================
// 6. ROUTEE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_routee_api_key_normal_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b2565062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("routee-api-key", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv123_routee_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{200B}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{00AD}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{200C}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{200D}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{FEFF}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{2060}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{180E}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{202E}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{202C}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv123_routee_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{200E}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

// =========================================================================
// 7. RUBYGEMS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rubygems_api_key_normal_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rubygems-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{200B}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{00AD}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{200C}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{200D}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{FEFF}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{2060}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{180E}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{202E}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{202C}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv123_rubygems_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{200E}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

// =========================================================================
// 8. RUDDER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rudder_api_token_normal_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rudder-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rudder_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{200B}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{00AD}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{200C}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{200D}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{FEFF}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{2060}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{180E}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{202E}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{202C}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv123_rudder_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{200E}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

// =========================================================================
// 9. RUDDERSTACK SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_rudderstack_service_token_normal_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdBeM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rudderstack-service-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{200B}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{00AD}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{200C}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{200D}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{FEFF}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{2060}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{180E}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{202E}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{202C}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv123_rudderstack_service_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{200E}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

// =========================================================================
// 10. SALESFORCE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv123_salesforce_access_token_normal_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "salesforce-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{200B}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{00AD}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{200C}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{200D}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{FEFF}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{2060}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{180E}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{202E}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{202C}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv123_salesforce_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{200E}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}
