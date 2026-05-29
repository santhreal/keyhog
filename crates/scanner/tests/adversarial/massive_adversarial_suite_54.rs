//! Part 54 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates polygon, polytomic, portkey, postgresql, posthog, postmark, postmark, power, powerbi, powerschool detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. POLYGON API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_polygon_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc2524b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv54_polygon_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "polygon-api-credentials",
        "dummy_prefix_0 =xxx679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv54_polygon_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{200B}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

#[test]
fn adv54_polygon_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "polygon-api-credentials",
        "polygonapikey=1a9679ce735bc252\u{00AD}4b5591c5d933feb2",
        "1a9679ce735bc2524b5591c5d933feb2",
    );
}

// =========================================================================
// 2. POLYTOMIC API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_polytomic_api_key_normal_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv54_polytomic_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "polytomic-api-key",
        "dummy_prefix_0 =xxx51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv54_polytomic_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{200B}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

#[test]
fn adv54_polytomic_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "polytomic-api-key",
        "POLYTOMIC_API_KEY=aec51681-9963-c39a\u{00AD}-1dca-dd7658e6395a",
        "aec51681-9963-c39a-1dca-dd7658e6395a",
    );
}

// =========================================================================
// 3. PORTKEY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_portkey_api_key_normal_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv54_portkey_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "portkey-api-key",
        "dummyGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv54_portkey_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{200B}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

#[test]
fn adv54_portkey_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "portkey-api-key",
        "pk-SGCmR9nq82QroR\u{00AD}8eUzNlOh8xfR4XOrMZ",
        "pk-SGCmR9nq82QroR8eUzNlOh8xfR4XOrMZ",
    );
}

// =========================================================================
// 4. POSTGRESQL CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_postgresql_connection_string_normal_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv54_postgresql_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "postgresql-connection-string",
        "dummy_prefix_0://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
    );
}

#[test]
fn adv54_postgresql_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{200B}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv54_postgresql_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{00AD}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

// =========================================================================
// 5. POSTHOG API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_posthog_api_key_normal_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv54_posthog_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "posthog-api-key",
        "dummyMHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv54_posthog_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{200B}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv54_posthog_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{00AD}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

// =========================================================================
// 6. POSTMARK SERVER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_postmark_server_token_normal_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv54_postmark_server_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "postmark-server-token",
        "dummy_prefix_0 =xxxe5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv54_postmark_server_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv54_postmark_server_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 7. POSTMARK WEBHOOK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_postmark_webhook_credentials_normal_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv54_postmark_webhook_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "postmark-webhook-credentials",
        "dummyXEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv54_postmark_webhook_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{200B}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv54_postmark_webhook_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{00AD}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

// =========================================================================
// 8. POWER AUTOMATE CONNECTOR CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_power_automate_connector_credentials_normal_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv54_power_automate_connector_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "power-automate-connector-credentials",
        "dummy_prefix_0 =xxxZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv54_power_automate_connector_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{200B}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv54_power_automate_connector_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{00AD}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

// =========================================================================
// 9. POWERBI CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_powerbi_credentials_normal_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv54_powerbi_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "powerbi-credentials",
        "dummy_prefix_0 =xxx45678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv54_powerbi_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{200B}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv54_powerbi_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{00AD}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

// =========================================================================
// 10. POWERSCHOOL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv54_powerschool_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv54_powerschool_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "powerschool-api-credentials",
        "dummy_prefix_0 =xxx68b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv54_powerschool_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{200B}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv54_powerschool_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{00AD}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}


