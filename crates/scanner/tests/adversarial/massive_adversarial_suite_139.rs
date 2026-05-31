//! Part 139 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates wrike, writer, x2y2, xata, xmatters, yandex, zapier, zapier, zendesk, zendesk detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. WRIKE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_wrike_access_token_normal_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "wrike-access-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_wrike_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{200B}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{00AD}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{200C}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{200D}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{FEFF}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{2060}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{180E}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{202E}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{202C}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

#[test]
fn adv139_wrike_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "wrike-access-token",
        "WRIKE_ACCESS_TOKEN=2XE9ph0wHZ8cNfI\u{200E}MR56S5DHN4Pzoa4",
        "2XE9ph0wHZ8cNfIMR56S5DHN4Pzoa4",
    );
}

// =========================================================================
// 2. WRITER API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_writer_api_key_normal_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("writer-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv139_writer_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{200B}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{00AD}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{200C}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{200D}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{FEFF}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{2060}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{180E}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{202E}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{202C}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

#[test]
fn adv139_writer_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "writer-api-key",
        "sk-8e85a2fc-0787-93\u{200E}49-5f0b-0600feee8683",
        "sk-8e85a2fc-0787-9349-5f0b-0600feee8683",
    );
}

// =========================================================================
// 3. X2Y2 API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_x2y2_api_key_normal_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "x2y2-api-key",
        "dummy_prefix_0:                                                    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{200B}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{00AD}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{200C}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{200D}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{FEFF}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{2060}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{180E}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{202E}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{202C}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

#[test]
fn adv139_x2y2_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "x2y2-api-key",
        "X-API-KEY                                          :                                                    JSuKxKWNfd898GujYX9p66-_M\u{200E}1knu3xIPTZfsus5cByqlnilvi7",
        "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
    );
}

// =========================================================================
// 4. XATA WORKSPACE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_xata_workspace_api_key_normal_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "xata-workspace-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{200B}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{00AD}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{200C}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{200D}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{FEFF}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{2060}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{180E}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{202E}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{202C}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

#[test]
fn adv139_xata_workspace_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "xata-workspace-api-key",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleC\u{200E}MZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
        "xau_8Di0DmOErHN_6oo82G98TQNTA815Z2aehzSbTPleCMZDqE5t6dg7eCqnGgBeji47hhMMJHbC0F0KrhnyFYTAyW",
    );
}

// =========================================================================
// 5. XMATTERS API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_xmatters_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "xmatters-api-credentials",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{200B}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{00AD}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{200C}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{200D}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{FEFF}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{2060}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{180E}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{202E}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{202C}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

#[test]
fn adv139_xmatters_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "xmatters-api-credentials",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQ\u{200E}QK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
        "xm-api-key-ses4A0YOsJsXAr9Tkkxaj4Y147YQQK2Ir1T0zvUGxNOWOXcrq21uoRWgJovdAchsBAo",
    );
}

// =========================================================================
// 6. YANDEX TRANSLATE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_yandex_translate_api_key_normal_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "yandex-translate-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{200B}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{00AD}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{200C}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{200D}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{FEFF}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{2060}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{180E}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{202E}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{202C}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

#[test]
fn adv139_yandex_translate_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "yandex-translate-api-key",
        "trnsl.1.1.54796602T665349Z.d20\u{200E}cc47c.5ca127c5317179907a1abc99",
        "trnsl.1.1.54796602T665349Z.d20cc47c.5ca127c5317179907a1abc99",
    );
}

// =========================================================================
// 7. ZAPIER NLA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_zapier_nla_api_key_normal_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zapier-nla-api-key",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{200B}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{00AD}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{200C}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{200D}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{FEFF}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{2060}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{180E}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{202E}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{202C}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

#[test]
fn adv139_zapier_nla_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "zapier-nla-api-key",
        "sk_ac_P8X0zoBwkHBwcsrYI\u{200E}XJ7KZkSG0y3WidORnWoyJp9",
        "sk_ac_P8X0zoBwkHBwcsrYIXJ7KZkSG0y3WidORnWoyJp9",
    );
}

// =========================================================================
// 8. ZAPIER WEBHOOK URL ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_zapier_webhook_url_normal_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zapier-webhook-url",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{200B}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{00AD}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{200C}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_zwj_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{200D}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{FEFF}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{2060}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{180E}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_rtl_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{202E}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{202C}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

#[test]
fn adv139_zapier_webhook_url_evade_lrm_must_fire() {
    assert_detector_fires(
        "zapier-webhook-url",
        "https://hooks.zapier.com/hooks/ca\u{200E}tch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
        "https://hooks.zapier.com/hooks/catch/72839156/Kp4Qx7Rm2Sn5Tb8Vw3Yz/",
    );
}

// =========================================================================
// 9. ZENDESK API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_zendesk_api_token_normal_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zendesk-api-token",
        "dummy_prefix_0:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{200B}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{00AD}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{200C}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{200D}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{FEFF}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{2060}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{180E}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{202E}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{202C}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

#[test]
fn adv139_zendesk_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "zendesk-api-token",
        "agent@subdomain.zendesk.com/token:5wSb6t3sE96nM6VaHoI2\u{200E}GWl6bp7zB8loar6sPi5w",
        "5wSb6t3sE96nM6VaHoI2GWl6bp7zB8loar6sPi5w",
    );
}

// =========================================================================
// 10. ZENDESK CHAT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv139_zendesk_chat_credentials_normal_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "zendesk-chat-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{200B}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{00AD}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{200C}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{200D}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{FEFF}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{2060}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{180E}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{202E}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{202C}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}

#[test]
fn adv139_zendesk_chat_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "zendesk-chat-credentials",
        "ZOPIMSECRET=a8ad2fc7e8a7d712\u{200E}303a5288a071d1c7",
        "a8ad2fc7e8a7d712303a5288a071d1c7",
    );
}
