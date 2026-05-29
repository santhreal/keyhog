//! Part 69 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates azure, azure, azure, azure, azure, azure, azure, azure, backblaze, baidu detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. AZURE DEVOPS PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_devops_pat_normal_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-devops-pat",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxZ",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200B}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{00AD}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200C}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200D}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{FEFF}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{2060}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{180E}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{202E}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{202C}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_devops_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-devops-pat",
        "AZURE_DEVOPS=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7\u{200E}Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Z",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 2. AZURE FUNCTIONS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_functions_key_normal_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-functions-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_functions_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv69_azure_functions_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-functions-key",
        "https://myapp.azurewebsites.net/api/HttpTrigger?code=Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3Yz",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 3. AZURE GOVERNMENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_government_credentials_normal_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-government-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv69_azure_government_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-government-credentials",
        "AZURE_GOVERNMENT_CLIENT_SECRET=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 4. AZURE IOT CONNECTION STRING ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_iot_connection_string_normal_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-iot-connection-string",
        "dummy_prefix_0 =prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200B}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{00AD}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200C}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200D}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{FEFF}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{2060}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{180E}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202E}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{202C}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

#[test]
fn adv69_azure_iot_connection_string_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-iot-connection-string",
        "HostName=prod-hub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=Kp4Qx7Rm2Sn5Tb8Vw3YzKp\u{200E}4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpZQ",
    );
}

// =========================================================================
// 5. AZURE KEY VAULT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_key_vault_credentials_normal_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-vault.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-key-vault-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{200B}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{00AD}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{200C}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{200D}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{FEFF}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{2060}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{180E}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{202E}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{202C}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

#[test]
fn adv69_azure_key_vault_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-key-vault-credentials",
        "https://prod-app-va\u{200E}ult.vault.azure.net/",
        "https://prod-app-vault.vault.azure.net/",
    );
}

// =========================================================================
// 6. AZURE OPENAI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_openai_api_key_normal_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-openai-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_openai_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-openai-api-key",
        "AZURE_OPENAI_API_KEY=7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 7. AZURE STORAGE ACCOUNT KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_storage_account_key_normal_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-storage-account-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{200B}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{00AD}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{200C}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{200D}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{FEFF}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{2060}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{180E}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{202E}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{202C}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

#[test]
fn adv69_azure_storage_account_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-storage-account-key",
        "AZURE_STORAGE_KEY=to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJO\u{200E}rb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
        "to8PuP8XWbrLmr4e+y/DLH/Hhsl6ArMtSIkCSqL7lSJOrb59CUVd0Hqb0tV/RxYsX8L5UrwFv1eFWPQ9pE++O/==",
    );
}

// =========================================================================
// 8. AZURE SUBSCRIPTION KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_azure_subscription_key_normal_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "azure-subscription-key",
        "dummy_prefix_0: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{200B}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{00AD}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{200C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{200D}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{FEFF}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{2060}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{180E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{202E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{202C}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv69_azure_subscription_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "azure-subscription-key",
        "Ocp-Apim-Subscription-Key: 7b3e5d8c1a9f4e2b\u{200E}6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 9. BACKBLAZE B2 APP KEY V2 ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_backblaze_b2_app_key_v2_normal_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_wrong_prefix_must_silent() {
    assert_detector_silent(
        "backblaze-b2-app-key-v2",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_zwsp_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{200B}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{00AD}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_zwnj_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{200C}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_zwj_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{200D}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{FEFF}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{2060}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_mongolian_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{180E}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_rtl_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{202E}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{202C}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

#[test]
fn adv69_backblaze_b2_app_key_v2_evade_lrm_must_fire() {
    assert_detector_fires(
        "backblaze-b2-app-key-v2",
        "K00MKp4Qx7Rm2S\u{200E}n5Tb8Vw3YzKp4Qx",
        "K00MKp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx",
    );
}

// =========================================================================
// 10. BAIDU MAPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv69_baidu_maps_api_key_normal_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "baidu-maps-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{200B}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{00AD}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{200C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{200D}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{FEFF}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{2060}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{180E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{202E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{202C}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}

#[test]
fn adv69_baidu_maps_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "baidu-maps-api-key",
        "BAIDU_MAPS_KEY=Kp4Qx7Rm2Sn5\u{200E}Tb8Vw3YzKp4Q",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Q",
    );
}


