//! Part 66 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates apple, applitools, appsmith, appwrite, arbitrum, arduino, asana, assemblyai, atlantis, australia detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. APPLE PUSH NOTIFICATION KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_apple_push_notification_key_normal_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "apple-push-notification-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{200B}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{00AD}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{200C}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{200D}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{FEFF}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{2060}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{180E}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{202E}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{202C}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_apple_push_notification_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "apple-push-notification-key",
        "APNS=Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Q\u{200E}m2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3Yz.Vk9Bn3Lp7Qm2Rs5Tw8Yz.Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 2. APPLITOOLS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_applitools_api_key_normal_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "applitools-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_applitools_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_applitools_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "applitools-api-key",
        "APPLITOOLS_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. APPSMITH API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_appsmith_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appsmith-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appsmith_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "appsmith-api-credentials",
        "APPSMITH_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. APPWRITE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_appwrite_api_key_normal_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "appwrite-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv66_appwrite_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "appwrite-api-key",
        "APPWRITE_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 5. ARBITRUM API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_arbitrum_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "arbitrum-api-credentials",
        "dummyTRUM_RPC_URL xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{200B}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{00AD}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{200C}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{200D}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{FEFF}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{2060}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{180E}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{202E}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{202C}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv66_arbitrum_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "arbitrum-api-credentials",
        "ARBITRUM_RPC_URL https://arb-mainnet.g.alchem\u{200E}y.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "https://arb-mainnet.g.alchemy.com/v2/Kp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 6. ARDUINO IOT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_arduino_iot_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "arduino-iot-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_arduino_iot_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "arduino-iot-api-credentials",
        "ARDUINO_CLIENT_ID=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 7. ASANA PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_asana_pat_normal_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "asana-pat",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_asana_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{200B}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{00AD}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{200C}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{200D}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{FEFF}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{2060}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{180E}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{202E}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{202C}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

#[test]
fn adv66_asana_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "asana-pat",
        "ASANA_ACCESS_TOKEN=1/4827193056718294/Kp7QxR\u{200E}4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
        "1/4827193056718294/Kp7QxR4mN9sBv2Ta5Yc8Wh3Lj6Dz1FgU",
    );
}

// =========================================================================
// 8. ASSEMBLYAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_assemblyai_api_key_normal_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "assemblyai-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_assemblyai_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "assemblyai-api-key",
        "ASSEMBLYAI_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. ATLANTIS CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_atlantis_credentials_normal_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "atlantis-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

#[test]
fn adv66_atlantis_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "atlantis-credentials",
        "ATLANTIS_GH_TOKEN=ghp_Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2SnTbW3Yz",
        "ghp_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2SnTbW3Yz",
    );
}

// =========================================================================
// 10. AUSTRALIA DATA GOV API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv66_australia_data_gov_api_key_normal_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "australia-data-gov-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{200B}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{00AD}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{200C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{200D}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{FEFF}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{2060}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{180E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{202E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{202C}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}

#[test]
fn adv66_australia_data_gov_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "australia-data-gov-api-key",
        "data.gov.au_API_KEY=7b3e5d8c-1a9f-4e2b\u{200E}-6c8d-3a5e9f1b7c4d",
        "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d",
    );
}
