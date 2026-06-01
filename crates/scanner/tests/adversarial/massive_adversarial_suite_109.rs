//! Part 109 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates nasa, nats, near, neon, neon, neptune, netlify, netlify, newrelic, newrelic detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. NASA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_nasa_api_key_normal_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nasa-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_nasa_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{200B}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{00AD}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{200C}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{200D}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{FEFF}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{2060}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{180E}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{202E}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{202C}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv109_nasa_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{200E}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

// =========================================================================
// 2. NATS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_nats_credentials_normal_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPass123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nats-credentials",
        "dummy_prefix_0 =xats://user:xxxxxxxxxxxxxxxx@nats.example.com:4222",
    );
}

#[test]
fn adv109_nats_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{200B}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{00AD}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{200C}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{200D}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{FEFF}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{2060}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{180E}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{202E}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{202C}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv109_nats_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{200E}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

// =========================================================================
// 3. NEAR API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_near_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-ood2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "near-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_near_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{200B}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{00AD}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{200C}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{200D}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{FEFF}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{2060}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{180E}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{202E}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{202C}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv109_near_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{200E}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

// =========================================================================
// 4. NEON API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_neon_api_key_normal_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "neon-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_neon_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200D}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{FEFF}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{2060}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{180E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv109_neon_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 5. NEON SERVERLESS DRIVER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_neon_serverless_driver_token_normal_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPass123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "neon-serverless-driver-token",
        "dummy_prefix_0 =xostgresql://neondb:xxxxxxxxxxxxxxxx@ep-demo.us-east-2.aws.neon.tech/neondb",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{200B}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{00AD}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{200C}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{200D}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{FEFF}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{2060}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{180E}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{202E}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{202C}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv109_neon_serverless_driver_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{200E}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

// =========================================================================
// 6. NEPTUNE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_neptune_api_token_normal_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "neptune-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_neptune_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{200B}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{00AD}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{200C}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{200D}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{FEFF}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{2060}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{180E}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{202E}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{202C}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv109_neptune_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{200E}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

// =========================================================================
// 7. NETLIFY BUILD HOOK ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_netlify_build_hook_normal_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_wrong_prefix_must_silent() {
    assert_detector_silent(
        "netlify-build-hook",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_zwsp_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{200B}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{00AD}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_zwnj_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{200C}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_zwj_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{200D}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{FEFF}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{2060}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_mongolian_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{180E}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_rtl_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{202E}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{202C}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

#[test]
fn adv109_netlify_build_hook_evade_lrm_must_fire() {
    assert_detector_fires(
        "netlify-build-hook",
        "https://api.netlify.com/build_hooks/\u{200E}f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
        "https://api.netlify.com/build_hooks/f6b93ba3-06a8-5cd8-44c8-76c1a0a29b9d",
    );
}

// =========================================================================
// 8. NETLIFY PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_netlify_pat_normal_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "netlify-pat",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_netlify_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv109_netlify_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "netlify-pat",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "nfp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 9. NEWRELIC LICENSE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_newrelic_license_key_normal_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "newrelic-license-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{200B}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{00AD}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{200C}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{200D}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{FEFF}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{2060}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{180E}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{202E}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{202C}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

#[test]
fn adv109_newrelic_license_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "newrelic-license-key",
        "NEW_RELIC_LICENSE_KEY=5d8c1a9f4e2b6c8d3a5e\u{200E}9f1b7c4d7b3ea9e2f5b8",
        "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8",
    );
}

// =========================================================================
// 10. NEWRELIC USER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv109_newrelic_user_api_key_normal_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("newrelic-user-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv109_newrelic_user_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{200B}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{00AD}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{200C}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{200D}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{FEFF}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{2060}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{180E}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{202E}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{202C}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}

#[test]
fn adv109_newrelic_user_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "newrelic-user-api-key",
        "NRAK-2EYOINJXROC\u{200E}0URJH7T52XQYNDJX",
        "NRAK-2EYOINJXROC0URJH7T52XQYNDJX",
    );
}
