//! Part 45 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates mysql, n8n, n8n, namely, nasa, nats, near, neon, neon, neptune detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MYSQL CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_mysql_connection_string_normal_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv45_mysql_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mysql-connection-string",
        "dummy_prefix_0://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv45_mysql_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{200B}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

#[test]
fn adv45_mysql_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mysql-connection-string",
        "mysql://dbuser:Np3DnCDi23\u{00AD}1ZUBYp@prod-db.example.com",
        "mysql://dbuser:Np3DnCDi231ZUBYp@prod-db.example.com",
    );
}

// =========================================================================
// 2. N8N API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_n8n_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv45_n8n_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "n8n-api-credentials",
        "dummyapi_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv45_n8n_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{200B}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

#[test]
fn adv45_n8n_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "n8n-api-credentials",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg\u{00AD}9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
        "n8n_api_alFu6SgZhwTbajU4in8ejVeg9ucWprq5qMhFaGXEVtKs02YuWIKgaPLI",
    );
}

// =========================================================================
// 3. N8N WEBHOOK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_n8n_webhook_credentials_normal_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv45_n8n_webhook_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "n8n-webhook-credentials",
        "dummy_prefix_0 =8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv45_n8n_webhook_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{200B}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

#[test]
fn adv45_n8n_webhook_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "n8n-webhook-credentials",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9\u{00AD}d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
        "https://n8n.example.com/webhook/8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d?token=8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d",
    );
}

// =========================================================================
// 4. NAMELY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_namely_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXTQr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv45_namely_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "namely-api-credentials",
        "dummy_prefix_0 =xxxnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv45_namely_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{200B}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

#[test]
fn adv45_namely_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "namely-api-credentials",
        "NAMELY_API_KEY=iLTnnJ2eXT\u{00AD}Qr7V8YOPWz",
        "iLTnnJ2eXTQr7V8YOPWz",
    );
}

// =========================================================================
// 5. NASA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_nasa_api_key_normal_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv45_nasa_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nasa-api-key",
        "dummy_prefix_0 =xxx82xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv45_nasa_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{200B}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

#[test]
fn adv45_nasa_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nasa-api-key",
        "NASA_API_KEY=Yx482xEg9Fb5nAWX0m3I\u{00AD}sojQXbBJgYW38rW9Pz9D",
        "Yx482xEg9Fb5nAWX0m3IsojQXbBJgYW38rW9Pz9D",
    );
}

// =========================================================================
// 6. NATS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_nats_credentials_normal_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPass123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv45_nats_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nats-credentials",
        "dummy_prefix_0 =xats://user:xxxretPass123456@nats.example.com:4222",
    );
}

#[test]
fn adv45_nats_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{200B}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

#[test]
fn adv45_nats_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nats-credentials",
        "NATS_URL=nats://user:SecretPa\u{00AD}ss123456@nats.example.com:4222",
        "SecretPass123456",
    );
}

// =========================================================================
// 7. NEAR API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_near_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-ood2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv45_near_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "near-api-credentials",
        "dummy_prefix_0 =xxxjl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv45_near_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{200B}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

#[test]
fn adv45_near_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "near-api-credentials",
        "NEAR_ACCOUNT_ID=9majl158zg-oo\u{00AD}d2kxt4u_.near",
        "9majl158zg-ood2kxt4u_.near",
    );
}

// =========================================================================
// 8. NEON API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_neon_api_key_normal_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv45_neon_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "neon-api-key",
        "dummy_prefix_0 =xxxe5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv45_neon_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv45_neon_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "neon-api-key",
        "NEON_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. NEON SERVERLESS DRIVER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_neon_serverless_driver_token_normal_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPass123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv45_neon_serverless_driver_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "neon-serverless-driver-token",
        "dummy_prefix_0 =xostgresql://neondb:xxxretPass123456@ep-demo.us-east-2.aws.neon.tech/neondb",
    );
}

#[test]
fn adv45_neon_serverless_driver_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{200B}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

#[test]
fn adv45_neon_serverless_driver_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "neon-serverless-driver-token",
        "NEON_DATABASE_URL=postgresql://neondb:SecretPa\u{00AD}ss123456@ep-demo.us-east-2.aws.neon.tech/neondb",
        "SecretPass123456",
    );
}

// =========================================================================
// 10. NEPTUNE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv45_neptune_api_token_normal_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv45_neptune_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "neptune-api-token",
        "dummy_prefix_0 =xxxq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv45_neptune_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{200B}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}

#[test]
fn adv45_neptune_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "neptune-api-token",
        "NEPTUNE_API_TOKEN=L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83\u{00AD}n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
        "L2Vq6GK3z1UsQ5g8jBQmYXxTC0cEJcZ83n2tcOhktobehu8/ZtSIy8bEB/EJ3yPB+U=",
    );
}


