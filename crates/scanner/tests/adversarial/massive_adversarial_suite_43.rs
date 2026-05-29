//! Part 43 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates microsoft, microsoft, minio, minio, miro, misp, mistral, mixpanel, mlflow, modal detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. MICROSOFT TEAMS API ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_microsoft_teams_api_normal_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv43_microsoft_teams_api_wrong_prefix_must_silent() {
    assert_detector_silent(
        "microsoft-teams-api",
        "dummy_prefix_0 =xxxKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv43_microsoft_teams_api_evade_zwsp_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{200B}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

#[test]
fn adv43_microsoft_teams_api_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "microsoft-teams-api",
        "teams api key=5dhKzM-gAg-SRhZqJ_-oU2\u{00AD}nsnWNYVs9UueLFXIZsabcd",
        "5dhKzM-gAg-SRhZqJ_-oU2nsnWNYVs9UueLFXIZsabcd",
    );
}

// =========================================================================
// 2. MICROSOFT TRANSLATOR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_microsoft_translator_api_key_normal_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b037569d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv43_microsoft_translator_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "microsoft-translator-api-key",
        "dummy_prefix_0 =xxxd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv43_microsoft_translator_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{200B}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

#[test]
fn adv43_microsoft_translator_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "microsoft-translator-api-key",
        "MS_TRANSLATOR_KEY=1dcd0b60e5b03756\u{00AD}9d8c72e160975b2c",
        "1dcd0b60e5b037569d8c72e160975b2c",
    );
}

// =========================================================================
// 3. MINIO ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_minio_access_key_normal_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69pixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv43_minio_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "minio-access-key",
        "dummy_prefix_0 =xxx69pixmZ8oC",
    );
}

#[test]
fn adv43_minio_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{200B}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

#[test]
fn adv43_minio_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "minio-access-key",
        "MINIO_ACCESS_KEY=0vp69p\u{00AD}ixmZ8oC",
        "0vp69pixmZ8oC",
    );
}

// =========================================================================
// 4. MINIO PRESIGNED CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_minio_presigned_credentials_normal_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminuser12345",
        "adminuser12345",
    );
}

#[test]
fn adv43_minio_presigned_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "minio-presigned-credentials",
        "dummy_prefix_0 =xxxinuser12345",
    );
}

#[test]
fn adv43_minio_presigned_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{200B}er12345",
        "adminuser12345",
    );
}

#[test]
fn adv43_minio_presigned_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "minio-presigned-credentials",
        "MINIO_ROOT_USER=adminus\u{00AD}er12345",
        "adminuser12345",
    );
}

// =========================================================================
// 5. MIRO API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_miro_api_token_normal_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv43_miro_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "miro-api-token",
        "dummy_prefix_0 =xxxrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv43_miro_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{200B}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

#[test]
fn adv43_miro_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "miro-api-token",
        "MIRO_TOKEN=xqqrnTQ9zmXf4THQ2PtTcMPcajfl\u{00AD}0YZ1MENUO2Paabcdefghijklmnop",
        "xqqrnTQ9zmXf4THQ2PtTcMPcajfl0YZ1MENUO2Paabcdefghijklmnop",
    );
}

// =========================================================================
// 6. MISP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_misp_api_key_normal_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv43_misp_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "misp-api-key",
        "dummy_prefix_0 =xxxc812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv43_misp_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{200B}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

#[test]
fn adv43_misp_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "misp-api-key",
        "mispauthkey=5a2c812ddcec9d17ccea\u{00AD}e0f42eec7ed26cee806c",
        "5a2c812ddcec9d17cceae0f42eec7ed26cee806c",
    );
}

// =========================================================================
// 7. MISTRAL API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_mistral_api_key_normal_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv43_mistral_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mistral-api-key",
        "dummy_prefix_0 =xxxQx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv43_mistral_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv43_mistral_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mistral-api-key",
        "MISTRAL_API_KEY=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 8. MIXPANEL PROJECT TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_mixpanel_project_token_normal_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv43_mixpanel_project_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mixpanel-project-token",
        "dummy_prefix_0 =xxx04d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv43_mixpanel_project_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{200B}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

#[test]
fn adv43_mixpanel_project_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mixpanel-project-token",
        "mixpaneltoken=c3204d9a091c90da\u{00AD}70b2eb73d026b376",
        "c3204d9a091c90da70b2eb73d026b376",
    );
}

// =========================================================================
// 9. MLFLOW TRACKING CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_mlflow_tracking_credentials_normal_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv43_mlflow_tracking_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "mlflow-tracking-credentials",
        "dummy_prefix_0 =xxxZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv43_mlflow_tracking_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{200B}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

#[test]
fn adv43_mlflow_tracking_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "mlflow-tracking-credentials",
        "MLFLOW_TRACKING_USERNAME=JcLZllEQlfGHhqpC\u{00AD}Jb0Z7BH8qYiTYKVs",
        "JcLZllEQlfGHhqpCJb0Z7BH8qYiTYKVs",
    );
}

// =========================================================================
// 10. MODAL API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv43_modal_api_token_normal_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJAIt9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv43_modal_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "modal-api-token",
        "dummy_prefix_0 =xxxA28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv43_modal_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{200B}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}

#[test]
fn adv43_modal_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "modal-api-token",
        "MODAL_API_KEY=nO4A28jeJA\u{00AD}It9uH2hn1l",
        "nO4A28jeJAIt9uH2hn1l",
    );
}


