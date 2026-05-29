//! Part 121 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates railway, railway, rapyd, raygun, recurly, reddit, reddit, redis, redis, remitly detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. RAILWAY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_railway_api_token_normal_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "railway-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_railway_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv121_railway_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "railway-api-token",
        "RAILWAY_API_TOKEN=9f3e5b8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. RAILWAY DEPLOY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_railway_deploy_token_normal_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "railway-deploy-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{200B}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{00AD}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{200C}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{200D}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{FEFF}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{2060}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{180E}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{202E}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{202C}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

#[test]
fn adv121_railway_deploy_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "railway-deploy-token",
        "RAILWAY_TOKEN=5b6f0b69-5f6b-8bfc\u{200E}-2209-8840057e3182",
        "5b6f0b69-5f6b-8bfc-2209-8840057e3182",
    );
}

// =========================================================================
// 3. RAPYD API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_rapyd_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560acc53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rapyd-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{200B}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{00AD}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{200C}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{200D}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{FEFF}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{2060}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{180E}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{202E}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{202C}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

#[test]
fn adv121_rapyd_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "rapyd-api-credentials",
        "RAPYD_API_KEY=799d33f560ac\u{200E}c53abefd6d1c",
        "799d33f560acc53abefd6d1c",
    );
}

// =========================================================================
// 4. RAYGUN API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_raygun_api_key_normal_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-SaJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "raygun-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_raygun_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{200B}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{00AD}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{200C}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{200D}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{FEFF}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{2060}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{180E}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{202E}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{202C}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

#[test]
fn adv121_raygun_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "raygun-api-key",
        "RAYGUN_API_KEY=zHHPHPTJ-S\u{200E}aJd915YTMi",
        "zHHPHPTJ-SaJd915YTMi",
    );
}

// =========================================================================
// 5. RECURLY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_recurly_api_key_normal_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "recurly-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_recurly_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{200B}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{00AD}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{200C}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{200D}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{FEFF}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{2060}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{180E}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{202E}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{202C}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv121_recurly_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "recurly-api-key",
        "RECURLY_API_KEY=25168b919a519680\u{200E}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

// =========================================================================
// 6. REDDIT ADS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_reddit_ads_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "reddit-ads-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{200B}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{00AD}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{200C}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{200D}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{FEFF}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{2060}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{180E}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{202E}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{202C}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

#[test]
fn adv121_reddit_ads_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "reddit-ads-api-credentials",
        "reddit_ads_client_id=kP4mN8qR\u{200E}2sT6vX0z",
        "kP4mN8qR2sT6vX0z",
    );
}

// =========================================================================
// 7. REDDIT CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_reddit_client_credentials_normal_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmyqw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "reddit-client-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{200B}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{00AD}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{200C}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{200D}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{FEFF}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{2060}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{180E}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{202E}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{202C}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

#[test]
fn adv121_reddit_client_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "reddit-client-credentials",
        "REDDIT_CLIENT_ID=Lg1PDmy\u{200E}qw9g786",
        "Lg1PDmyqw9g786",
    );
}

// =========================================================================
// 8. REDIS CLOUD V2 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_redis_cloud_v2_api_key_normal_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e5219091134d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "redis-cloud-v2-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{200B}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{00AD}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{200C}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{200D}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{FEFF}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{2060}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{180E}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{202E}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{202C}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

#[test]
fn adv121_redis_cloud_v2_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "redis-cloud-v2-api-key",
        "REDIS_CLOUD_V2_API_KEY=d1935adc5f2e52190911\u{200E}34d0fb1b5822c47225da",
        "d1935adc5f2e5219091134d0fb1b5822c47225da",
    );
}

// =========================================================================
// 9. REDIS LABS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_redis_labs_api_key_normal_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72aaf77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "redis-labs-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{200B}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{00AD}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{200C}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{200D}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{FEFF}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{2060}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{180E}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{202E}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{202C}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

#[test]
fn adv121_redis_labs_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "redis-labs-api-key",
        "REDIS_LABS_API_KEY=517cfd95dfd9f72a\u{200E}af77a72c5fadfc74",
        "517cfd95dfd9f72aaf77a72c5fadfc74",
    );
}

// =========================================================================
// 10. REMITLY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv121_remitly_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "remitly-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{200B}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{00AD}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{200C}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{200D}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{FEFF}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{2060}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{180E}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{202E}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{202C}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}

#[test]
fn adv121_remitly_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "remitly-api-credentials",
        "REMITLYSECRET=L_7WqtXx_S2EwRDJn_OAdB13uj-8I0\u{200E}8qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
        "L_7WqtXx_S2EwRDJn_OAdB13uj-8I08qHBVCJL2W7pHG9-TxaHPMP9_9jW9x",
    );
}


