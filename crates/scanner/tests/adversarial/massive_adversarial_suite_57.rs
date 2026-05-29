//! Part 57 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates rabbitmq, rabbitmq, radar, railway, railway, rapyd, raygun, recurly, reddit, reddit detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. RABBITMQ CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_rabbitmq_credentials_normal_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPass123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv57_rabbitmq_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rabbitmq-credentials",
        "dummy_prefix_0://user:xxxretPass123456@rabbitmq.example.com:5672/vhost",
    );
}

#[test]
fn adv57_rabbitmq_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{200B}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

#[test]
fn adv57_rabbitmq_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rabbitmq-credentials",
        "amqp://user:SecretPa\u{00AD}ss123456@rabbitmq.example.com:5672/vhost",
        "SecretPass123456",
    );
}

// =========================================================================
// 2. RABBITMQ MANAGEMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_rabbitmq_management_credentials_normal_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`nsHW",
        "`nsHW",
    );
}

#[test]
fn adv57_rabbitmq_management_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rabbitmq-management-credentials",
        "dummy_prefix_0 =xxxHW",
    );
}

#[test]
fn adv57_rabbitmq_management_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{200B}sHW",
        "`nsHW",
    );
}

#[test]
fn adv57_rabbitmq_management_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rabbitmq-management-credentials",
        "RABBITMQ_USER=`n\u{00AD}sHW",
        "`nsHW",
    );
}

// =========================================================================
// 3. RADAR IO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_radar_io_api_key_normal_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv57_radar_io_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "radar-io-api-key",
        "dummylive_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv57_radar_io_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{200B}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

#[test]
fn adv57_radar_io_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "radar-io-api-key",
        "prj_live_eZXI8wIQE11eWntR0gMw\u{00AD}rohdFkqbTcI4npM6AovMe5Wowx31UK",
        "prj_live_eZXI8wIQE11eWntR0gMwrohdFkqbTcI4npM6AovMe5Wowx31UK",
    );
}

// =========================================================================
// 4. RAILWAY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_railway_api_token_normal_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv57_railway_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "railway-api-token",
        "dummy_prefix_0 =xxxe5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv57_railway_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv57_railway_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 5. RAILWAY DEPLOY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_railway_deploy_token_normal_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv57_railway_deploy_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "railway-deploy-token",
        "dummy_prefix_0 =xxxf0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv57_railway_deploy_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{200B}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv57_railway_deploy_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{00AD}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

// =========================================================================
// 6. RAPYD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_rapyd_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560acc53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv57_rapyd_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rapyd-api-credentials",
        "dummy_prefix_0 =xxxd33f560acc53abefd6d1c",
    );
}

#[test]
fn adv57_rapyd_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{200B}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv57_rapyd_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{00AD}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

// =========================================================================
// 7. RAYGUN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_raygun_api_key_normal_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-SaJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv57_raygun_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "raygun-api-key",
        "dummy_prefix_0 =xxxPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv57_raygun_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{200B}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv57_raygun_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{00AD}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

// =========================================================================
// 8. RECURLY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_recurly_api_key_normal_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv57_recurly_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "recurly-api-key",
        "dummy_prefix_0 =xxx68b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv57_recurly_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{200B}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv57_recurly_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{00AD}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

// =========================================================================
// 9. REDDIT ADS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_reddit_ads_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv57_reddit_ads_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "reddit-ads-api-credentials",
        "dummy_prefix_0 =xxxmN8qR2sT6vX0z",
    );
}

#[test]
fn adv57_reddit_ads_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{200B}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv57_reddit_ads_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{00AD}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

// =========================================================================
// 10. REDDIT CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv57_reddit_client_credentials_normal_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmyqw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv57_reddit_client_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "reddit-client-credentials",
        "dummy_prefix_0 =xxxPDmyqw9g786",
    );
}

#[test]
fn adv57_reddit_client_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{200B}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv57_reddit_client_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{00AD}qw9g786",
        "Lg1PDmyqw9g786",
    );
}


