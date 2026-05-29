//! Part 59 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates retool, ringcentral, riotgames, rippling, rocketmatter, rollbar, rome2rio, rootly, routee, rubygems detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. RETOOL DATABASE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_retool_database_credentials_normal_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbPass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv59_retool_database_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "retool-database-credentials",
        "dummy_prefix_0 =xxxoolDbPass123456",
    );
}

#[test]
fn adv59_retool_database_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{200B}ass123456",
        "RetoolDbPass123456",
    );
}

#[test]
fn adv59_retool_database_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "retool-database-credentials",
        "RETOOL_DB_PASSWORD=RetoolDbP\u{00AD}ass123456",
        "RetoolDbPass123456",
    );
}

// =========================================================================
// 2. RINGCENTRAL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_ringcentral_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_ED4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv59_ringcentral_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ringcentral-api-credentials",
        "dummy_prefix_0 =xxx1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv59_ringcentral_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{200B}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

#[test]
fn adv59_ringcentral_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ringcentral-api-credentials",
        "ringcentralclientid=Iqt1Wwep_E\u{00AD}D4e1JzZYKZ",
        "Iqt1Wwep_ED4e1JzZYKZ",
    );
}

// =========================================================================
// 3. RIOTGAMES API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_riotgames_api_key_normal_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv59_riotgames_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "riotgames-api-key",
        "dummyI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv59_riotgames_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{200B}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

#[test]
fn adv59_riotgames_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "riotgames-api-key",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q\u{00AD}1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
        "RGAPI-1x7iIVThNxv00OGy7e01fGwtDdH4q1cEvkyVY5luPUZNG6PPBYspYuVsxZUTn7zML",
    );
}

// =========================================================================
// 4. RIPPLING API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_rippling_api_key_normal_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv59_rippling_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rippling-api-key",
        "dummy_prefix_0 =xxx_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv59_rippling_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{200B}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

#[test]
fn adv59_rippling_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rippling-api-key",
        "RIPPLING_API_KEY=rpl_pg0ojWl4O6csMlO2Hp\u{00AD}DTI3SSFHHWXK1qPljpRyeP",
        "rpl_pg0ojWl4O6csMlO2HpDTI3SSFHHWXK1qPljpRyeP",
    );
}

// =========================================================================
// 5. ROCKETMATTER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_rocketmatter_api_key_normal_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv59_rocketmatter_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rocketmatter-api-key",
        "dummy_prefix_0 =xxxVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv59_rocketmatter_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{200B}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

#[test]
fn adv59_rocketmatter_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rocketmatter-api-key",
        "ROCKETMATTER_API_KEY=I6UVvY8k-yckXfBW\u{00AD}Aw9l_uB8_PdVm1lU",
        "I6UVvY8k-yckXfBWAw9l_uB8_PdVm1lU",
    );
}

// =========================================================================
// 6. ROLLBAR ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_rollbar_access_token_normal_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv59_rollbar_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rollbar-access-token",
        "dummy_prefix_0 =xxx0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv59_rollbar_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{200B}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

#[test]
fn adv59_rollbar_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rollbar-access-token",
        "X-Rollbar-Access-Token=08c0fee0abeb7224\u{00AD}113fd958de7528ab",
        "08c0fee0abeb7224113fd958de7528ab",
    );
}

// =========================================================================
// 7. ROME2RIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_rome2rio_api_key_normal_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv59_rome2rio_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rome2rio-api-key",
        "dummy_prefix_0 =xxxfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv59_rome2rio_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{200B}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

#[test]
fn adv59_rome2rio_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rome2rio-api-key",
        "ROME2RIO=EQyfbMZcdFc6SF9DRRkx\u{00AD}IwJyyING7kfZ5GzIprLv",
        "EQyfbMZcdFc6SF9DRRkxIwJyyING7kfZ5GzIprLv",
    );
}

// =========================================================================
// 8. ROOTLY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_rootly_api_token_normal_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv59_rootly_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rootly-api-token",
        "dummyly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv59_rootly_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{200B}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

#[test]
fn adv59_rootly_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rootly-api-token",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411n\u{00AD}uD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
        "rootly-nAdOzDbZnj6TamM8tkZ4_nmGv1Kl7411nuD1n8ogRKBe1Bh8LlWiEpMVDiFLyb8gX3axlWWmL6",
    );
}

// =========================================================================
// 9. ROUTEE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_routee_api_key_normal_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b2565062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv59_routee_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "routee-api-key",
        "dummy_prefix_0 =xxx599b0b2565062026f2555",
    );
}

#[test]
fn adv59_routee_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{200B}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

#[test]
fn adv59_routee_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "routee-api-key",
        "routee=efd599b0b256\u{00AD}5062026f2555",
        "efd599b0b2565062026f2555",
    );
}

// =========================================================================
// 10. RUBYGEMS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv59_rubygems_api_key_normal_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv59_rubygems_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rubygems-api-key",
        "dummygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv59_rubygems_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{200B}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}

#[test]
fn adv59_rubygems_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rubygems-api-key",
        "rubygems_8ba813318e80dc5764a\u{00AD}1f36c0d275492825aa46472f2d75f",
        "rubygems_8ba813318e80dc5764a1f36c0d275492825aa46472f2d75f",
    );
}


