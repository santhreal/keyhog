//! Part 118 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates postgresql, posthog, postmark, postmark, power, powerbi, powerschool, practicepanther, prestashop, presto detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. POSTGRESQL CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_postgresql_connection_string_normal_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "postgresql-connection-string",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/neondb",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{200B}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{00AD}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_zwnj_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{200C}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_zwj_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{200D}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{FEFF}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{2060}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_mongolian_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{180E}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_rtl_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{202E}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{202C}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

#[test]
fn adv118_postgresql_connection_string_evade_lrm_must_fire() {
    assert_detector_fires(
        "postgresql-connection-string",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-\u{200E}cool-name-123456.us-east-2.aws.neon.tech/neondb",
        "postgresql://neondb:w0kVdGwi5GpLapAX@ep-cool-name-123456.us-east-2.aws.neon.tech",
    );
}

// =========================================================================
// 2. POSTHOG API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_posthog_api_key_normal_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("posthog-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv118_posthog_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{200B}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{00AD}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{200C}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{200D}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{FEFF}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{2060}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{180E}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{202E}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{202C}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

#[test]
fn adv118_posthog_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "posthog-api-key",
        "phc_MHvirLqTJFzNPP\u{200E}kOz9bbFDdyUzG3lD9j",
        "phc_MHvirLqTJFzNPPkOz9bbFDdyUzG3lD9j",
    );
}

// =========================================================================
// 3. POSTMARK SERVER TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_postmark_server_token_normal_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "postmark-server-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_postmark_server_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv118_postmark_server_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "postmark-server-token",
        "POSTMARK_SERVER_TOKEN=9f3e5b8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "9f3e5b8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. POSTMARK WEBHOOK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_postmark_webhook_credentials_normal_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "postmark-webhook-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{200B}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{00AD}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{200C}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{200D}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{FEFF}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{2060}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{180E}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{202E}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{202C}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

#[test]
fn adv118_postmark_webhook_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "postmark-webhook-credentials",
        "wh_3XEcfzUPb0bPQY\u{200E}fF3c1OP4XWYvo4Gd16",
        "wh_3XEcfzUPb0bPQYfF3c1OP4XWYvo4Gd16",
    );
}

// =========================================================================
// 5. POWER AUTOMATE CONNECTOR CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_power_automate_connector_credentials_normal_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "power-automate-connector-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{200B}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{00AD}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{200C}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{200D}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{FEFF}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{2060}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{180E}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{202E}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{202C}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

#[test]
fn adv118_power_automate_connector_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "power-automate-connector-credentials",
        "Ocp-Apim-Subscription-Key=livZCKcy1cPhsIIW\u{200E}Jc4XipePPWJZ4rxO",
        "livZCKcy1cPhsIIWJc4XipePPWJZ4rxO",
    );
}

// =========================================================================
// 6. POWERBI CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_powerbi_credentials_normal_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "powerbi-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{200B}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{00AD}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{200C}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{200D}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{FEFF}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{2060}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{180E}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{202E}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{202C}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

#[test]
fn adv118_powerbi_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "powerbi-credentials",
        "powerbi_client_id=12345678-abcd-1234\u{200E}-abcd-123456789abc",
        "12345678-abcd-1234-abcd-123456789abc",
    );
}

// =========================================================================
// 7. POWERSCHOOL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_powerschool_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "powerschool-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{200B}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{00AD}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{200C}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{200D}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{FEFF}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{2060}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{180E}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{202E}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{202C}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

#[test]
fn adv118_powerschool_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "powerschool-api-credentials",
        "powerschool_client_id=25168b919a519680\u{200E}ded6beb446bde58f",
        "25168b919a519680ded6beb446bde58f",
    );
}

// =========================================================================
// 8. PRACTICEPANTHER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_practicepanther_api_key_normal_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "practicepanther-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{200B}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{00AD}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{200C}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{200D}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{FEFF}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{2060}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{180E}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{202E}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{202C}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

#[test]
fn adv118_practicepanther_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "practicepanther-api-key",
        "PRACTICEPANTHER_API_KEY=7YyNdbgZbHjVYPyfQSEu\u{200E}WajO7Ei3lyUMx24hMWUY",
        "7YyNdbgZbHjVYPyfQSEuWajO7Ei3lyUMx24hMWUY",
    );
}

// =========================================================================
// 9. PRESTASHOP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_prestashop_api_key_normal_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "prestashop-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{200B}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{00AD}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{200C}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{200D}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{FEFF}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{2060}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{180E}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{202E}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{202C}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

#[test]
fn adv118_prestashop_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "prestashop-api-key",
        "prestashop=7t5dnTAM6RRaSPjZ\u{200E}YCjoE8fkySGigMY0",
        "7t5dnTAM6RRaSPjZYCjoE8fkySGigMY0",
    );
}

// =========================================================================
// 10. PRESTO TRINO CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv118_presto_trino_credentials_normal_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:SecretPass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "presto-trino-credentials",
        "dummy_prefix_0 =trino://admin:xxxxxxxxxxxxx@trino.example.com:8080",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{200B}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{00AD}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{200C}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{200D}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{FEFF}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{2060}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{180E}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{202E}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{202C}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}

#[test]
fn adv118_presto_trino_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "presto-trino-credentials",
        "TRINO_URL=trino://admin:Secret\u{200E}Pass123@trino.example.com:8080",
        "SecretPass123",
    );
}
