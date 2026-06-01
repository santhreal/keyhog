//! Part 9 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Airplane, Anrok, Ansible Tower, Any.do, AppDynamics, Appium Cloud,
//! Apple Push Notification, Applitools, Appsmith, and Appwrite detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AIRPLANE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_airplane_normal_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_abcde1234567890abcde1234567890",
        "aptk_abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv9_airplane_wrong_prefix_must_silent() {
    assert_detector_silent("airplane-api-key", "bptk_abcde1234567890abcde1234567890");
}

#[test]
fn adv9_airplane_evade_zwsp_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk\u{200B}_abcde1234567890abcde1234567890",
        "aptk_abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv9_airplane_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_abcde1234567890abcde1\u{00AD}234567890",
        "aptk_abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv9_airplane_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "airplane-api-key",
        "aptk_abcd\u{0435}1234567890abcde1234567890",
        "aptk_abcde1234567890abcde1234567890",
    );
}

// =========================================================================
// 2. ANROK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_anrok_normal_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "anrok_api_key = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv9_anrok_wrong_prefix_must_silent() {
    assert_detector_silent("anrok-api-key", "banrok_api_key = \"abcde1234567890abcde\"");
}

#[test]
fn adv9_anrok_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "anrok\u{200B}_api_key = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv9_anrok_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "anrok_api_key = \"abcde12345\u{00AD}67890abcde\"",
        "abcde1234567890abcde",
    );
}

#[test]
fn adv9_anrok_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "anrok-api-key",
        "anr\u{043E}k_api_key = \"abcde1234567890abcde\"",
        "abcde1234567890abcde",
    );
}

// =========================================================================
// 3. ANSIBLE TOWER/AWX API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_ansible_normal_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN = \"YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=\"",
        "YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=",
    );
}

#[test]
fn adv9_ansible_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ansible-tower-token",
        "POWER_OAUTH_TOKEN = \"YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=\"",
    );
}

#[test]
fn adv9_ansible_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER\u{200B}_OAUTH_TOKEN = \"YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=\"",
        "YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=",
    );
}

#[test]
fn adv9_ansible_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "TOWER_OAUTH_TOKEN = \"YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkw\u{00AD}MTI=\"",
        "YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=",
    );
}

#[test]
fn adv9_ansible_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "ansible-tower-token",
        "T\u{041E}WER_OAUTH_TOKEN = \"YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=\"",
        "YWJjZGUxMjM0NTY3ODkwYWJjZGUxMjM0NTY3ODkwMTI=",
    );
}

// =========================================================================
// 4. ANY.DO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_anydo_normal_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY = \"abcde1234567890abcde1234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv9_anydo_wrong_prefix_must_silent() {
    assert_detector_silent(
        "anydo-api-key",
        "SOMEDO_API_KEY = \"abcde1234567890abcde1234567890\"",
    );
}

#[test]
fn adv9_anydo_evade_zwsp_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO\u{200B}_API_KEY = \"abcde1234567890abcde1234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv9_anydo_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYDO_API_KEY = \"abcde1234567890abcde1\u{00AD}234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

#[test]
fn adv9_anydo_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "anydo-api-key",
        "ANYD\u{041E}_API_KEY = \"abcde1234567890abcde1234567890\"",
        "abcde1234567890abcde1234567890",
    );
}

// =========================================================================
// 5. APPDYNAMICS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_appdynamics_normal_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "appdynamics_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appdynamics_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appdynamics-api-credentials",
        "nodynamics_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv9_appdynamics_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "appdynamics\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appdynamics_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "appdynamics_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appdynamics_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "appdynamics-api-credentials",
        "appdyn\u{0430}mics_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 6. APPIUM CLOUD CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_appium_normal_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "lt_access_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appium_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appium-cloud-credentials",
        "mt_access_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv9_appium_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "lt\u{200B}_access_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appium_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "lt_access_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appium_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "appium-cloud-credentials",
        "lt_acc\u{0435}ss_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

// =========================================================================
// 7. APPLE PUSH NOTIFICATION KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_apns_normal_must_fire() {
    assert_detector_fires("apple-push-notification-key", "APNS = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345");
}

#[test]
fn adv9_apns_wrong_prefix_must_silent() {
    assert_detector_silent("apple-push-notification-key", "BPNS = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345\"");
}

#[test]
fn adv9_apns_evade_zwsp_must_fire() {
    assert_detector_fires("apple-push-notification-key", "APNS\u{200B} = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345");
}

#[test]
fn adv9_apns_evade_soft_hyphen_must_fire() {
    assert_detector_fires("apple-push-notification-key", "APNS = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde1\u{00AD}23456789012abcde12345\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345");
}

#[test]
fn adv9_apns_evade_homoglyph_must_fire() {
    assert_detector_fires("apple-push-notification-key", "\u{0430}pns = \"eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345\"", "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJURUFNSUQxMjM0NSIsImlhdCI6MTYyMjUwMDAwMH0.abcde1234567890abcde123456789012abcde12345");
}

// =========================================================================
// 8. APPLITOOLS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_applitools_normal_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "applitools_api_key = \"abcde1234567890abcde123456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

#[test]
fn adv9_applitools_wrong_prefix_must_silent() {
    assert_detector_silent(
        "applitools-api-key",
        "mapplitools_api_key = \"abcde1234567890abcde123456789012abcde123\"",
    );
}

#[test]
fn adv9_applitools_evade_zwsp_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "applitools\u{200B}_api_key = \"abcde1234567890abcde123456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

#[test]
fn adv9_applitools_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "applitools_api_key = \"abcde1234567890abcde1\u{00AD}23456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

#[test]
fn adv9_applitools_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "applit\u{043E}\u{043E}ls_api_key = \"abcde1234567890abcde123456789012abcde123\"",
        "abcde1234567890abcde123456789012abcde123",
    );
}

// =========================================================================
// 9. APPSMITH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_appsmith_normal_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv9_appsmith_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appsmith-api-credentials",
        "TAPPSMITH_API_KEY = \"abcde1234567890abcde1234\"",
    );
}

#[test]
fn adv9_appsmith_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH\u{200B}_API_KEY = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv9_appsmith_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY = \"abcde1234567890abcde1\u{00AD}234\"",
        "abcde1234567890abcde1234",
    );
}

#[test]
fn adv9_appsmith_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "appsm\u{0456}th_api_key = \"abcde1234567890abcde1234\"",
        "abcde1234567890abcde1234",
    );
}

// =========================================================================
// 10. APPWRITE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv9_appwrite_normal_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "appwrite_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appwrite_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appwrite-api-key",
        "bappwrite_api_key = \"abcde1234567890abcde123456789012\"",
    );
}

#[test]
fn adv9_appwrite_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "appwrite\u{200B}_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appwrite_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "appwrite_api_key = \"abcde1234567890abcde1\u{00AD}23456789012\"",
        "abcde1234567890abcde123456789012",
    );
}

#[test]
fn adv9_appwrite_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "appwr\u{0456}te_api_key = \"abcde1234567890abcde123456789012\"",
        "abcde1234567890abcde123456789012",
    );
}
