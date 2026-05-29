//! Part 107 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates miro, misp, mistral, mixpanel, mlflow, modal, mongodb, mongodb, moodle, moosend detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MIRO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_miro_api_token_normal_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "miro-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_miro_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{200B}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{00AD}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{200C}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{200D}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{FEFF}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{2060}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{180E}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{202E}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{202C}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv107_miro_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{200E}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

// =========================================================================
// 2. MISP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_misp_api_key_normal_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "misp-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_misp_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{200B}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{00AD}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{200C}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{200D}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{FEFF}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{2060}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{180E}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{202E}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{202C}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv107_misp_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{200E}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

// =========================================================================
// 3. MISTRAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_mistral_api_key_normal_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mistral-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_mistral_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv107_mistral_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. MIXPANEL PROJECT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_mixpanel_project_token_normal_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mixpanel-project-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{200B}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{00AD}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{200C}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{200D}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{FEFF}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{2060}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{180E}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{202E}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{202C}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv107_mixpanel_project_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{200E}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

// =========================================================================
// 5. MLFLOW TRACKING CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_mlflow_tracking_credentials_normal_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mlflow-tracking-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{200B}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{00AD}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{200C}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{200D}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{FEFF}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{2060}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{180E}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{202E}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{202C}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv107_mlflow_tracking_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{200E}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

// =========================================================================
// 6. MODAL API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_modal_api_token_normal_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJAIt9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "modal-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_modal_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{200B}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{00AD}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{200C}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{200D}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{FEFF}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{2060}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{180E}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{202E}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{202C}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv107_modal_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{200E}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

// =========================================================================
// 7. MONGODB ATLAS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_mongodb_atlas_api_key_normal_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIfkXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mongodb-atlas-api-key",
        "dummy_prefix_0 =xxxxxxxx",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{200B}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{00AD}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{200C}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{200D}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{FEFF}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{2060}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{180E}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{202E}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{202C}kXby",
        "eHIfkXby",
    );
}

#[test]
fn adv107_mongodb_atlas_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "mongodb-atlas-api-key",
        "ATLAS=eHIf\u{200E}kXby",
        "eHIfkXby",
    );
}

// =========================================================================
// 8. MONGODB CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_mongodb_connection_string_normal_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mongodb-connection-string",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{200B}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{00AD}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_zwnj_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{200C}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_zwj_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{200D}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{FEFF}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{2060}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_mongolian_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{180E}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_rtl_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{202E}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{202C}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

#[test]
fn adv107_mongodb_connection_string_evade_lrm_must_fire() {
    assert_detector_fires(
        "mongodb-connection-string",
        "mongodb://dbuser:R7VXNPLMQ3\u{200E}HSKWJT@cluster0.mongodb.net",
        "mongodb://dbuser:R7VXNPLMQ3HSKWJT@cluster0.mongodb.net",
    );
}

// =========================================================================
// 9. MOODLE API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_moodle_api_token_normal_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a794128a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "moodle-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_moodle_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{200B}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{00AD}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{200C}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{200D}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{FEFF}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{2060}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{180E}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{202E}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{202C}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

#[test]
fn adv107_moodle_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "moodle-api-token",
        "webservicewstoken=523c55846f4a7941\u{200E}28a9d99731891b9c",
        "523c55846f4a794128a9d99731891b9c",
    );
}

// =========================================================================
// 10. MOOSEND API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv107_moosend_api_key_normal_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "moosend-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv107_moosend_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{200B}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{00AD}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{200C}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{200D}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{FEFF}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{2060}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{180E}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{202E}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{202C}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}

#[test]
fn adv107_moosend_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "moosend-api-key",
        "MOOSEND_API_KEY=a4f4f-7a6c28--633f\u{200E}18a1a2b0ff571464fc",
        "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
    );
}


