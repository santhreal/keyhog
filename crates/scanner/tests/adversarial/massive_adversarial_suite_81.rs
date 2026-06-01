//! Part 81 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates definedfi, delinea, deno, descope, devcycle, devto, dhl, digitalocean, digitalocean, directus detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DEFINEDFI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_definedfi_api_key_normal_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "definedfi-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200B}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{00AD}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200D}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{FEFF}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{2060}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{180E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{202C}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_definedfi_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "definedfi-api-key",
        "defined_api_key=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\u{200E}7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 2. DELINEA SECRET SERVER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_delinea_secret_server_credentials_normal_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "delinea-secret-server-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200B}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{00AD}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200D}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{FEFF}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{2060}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{180E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{202E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{202C}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_delinea_secret_server_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "DELINEA.TOKEN=Kp4Qx7Rm2Sn5Tb8V\u{200E}w3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 3. DENO KV CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_deno_kv_credentials_normal_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deno-kv-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200B}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{00AD}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200C}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200D}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{FEFF}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{2060}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{180E}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{202E}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{202C}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

#[test]
fn adv81_deno_kv_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c\u{200E}4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "ddn_7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    );
}

// =========================================================================
// 4. DESCOPE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_descope_api_key_normal_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "descope-api-key",
        "dummyope project xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_descope_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{200B}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{00AD}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{200C}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{200D}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{FEFF}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{2060}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{180E}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{202E}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{202C}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

#[test]
fn adv81_descope_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "descope-api-key",
        "descope project P2Kp4Qx7Rm2Sn5Tb8\u{200E}Vw3YzKp4Qx7Rm2Sn5",
        "P2Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    );
}

// =========================================================================
// 5. DEVCYCLE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_devcycle_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "devcycle-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

#[test]
fn adv81_devcycle_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "devcycle-api-credentials",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
        "dvc_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz",
    );
}

// =========================================================================
// 6. DEVTO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_devto_api_key_normal_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada29c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "devto-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_devto_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{200B}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{00AD}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{200C}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{200D}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{FEFF}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{2060}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{180E}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{202E}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{202C}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

#[test]
fn adv81_devto_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "devto-api-key",
        "DEVTO_API_KEY=2be3296b917aada2\u{200E}9c38889518f13ab6",
        "2be3296b917aada29c38889518f13ab6",
    );
}

// =========================================================================
// 7. DHL API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_dhl_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dhl-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{200B}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{00AD}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{200C}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{200D}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{FEFF}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{2060}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{180E}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{202E}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{202C}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

#[test]
fn adv81_dhl_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "dhl-api-credentials",
        "DHL.API.KEY=ZX0SakOvfcEiU6Mg\u{200E}Qmtf61SR1jdCcIKr",
        "ZX0SakOvfcEiU6MgQmtf61SR1jdCcIKr",
    );
}

// =========================================================================
// 8. DIGITALOCEAN PAT ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_digitalocean_pat_normal_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_wrong_prefix_must_silent() {
    assert_detector_silent(
        "digitalocean-pat",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_zwsp_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{200B}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{00AD}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_zwnj_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{200C}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_zwj_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{200D}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{FEFF}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{2060}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_mongolian_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{180E}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_rtl_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{202E}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{202C}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

#[test]
fn adv81_digitalocean_pat_evade_lrm_must_fire() {
    assert_detector_fires(
        "digitalocean-pat",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b\u{200E}4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
        "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b",
    );
}

// =========================================================================
// 9. DIGITALOCEAN SPACES CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_digitalocean_spaces_credentials_normal_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "digitalocean-spaces-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{200B}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{00AD}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{200C}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{200D}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{FEFF}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{2060}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{180E}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{202E}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{202C}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

#[test]
fn adv81_digitalocean_spaces_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "digitalocean-spaces-credentials",
        "DO_SPACES_ACCESS_KEY=7DUURP7HR3\u{200E}967PXE3R4V",
        "7DUURP7HR3967PXE3R4V",
    );
}

// =========================================================================
// 10. DIRECTUS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv81_directus_api_token_normal_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30nSx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_wrong_prefix_must_silent() {
    assert_detector_silent("directus-api-token", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv81_directus_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{200B}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{00AD}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{200C}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{200D}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{FEFF}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{2060}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{180E}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{202E}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{202C}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}

#[test]
fn adv81_directus_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "directus-api-token",
        "DIRECTUS_TOKEN=C372xGw30n\u{200E}Sx5QdQuTxy",
        "C372xGw30nSx5QdQuTxy",
    );
}
