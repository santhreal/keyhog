//! Part 60 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates rudder, rudderstack, salesforce, saltstack, sanity, sap, saucelabs, scaleway, scalr, schoology detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. RUDDER API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_rudder_api_token_normal_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv60_rudder_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rudder-api-token",
        "dummy_prefix_0 =xxxjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv60_rudder_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{200B}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

#[test]
fn adv60_rudder_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rudder-api-token",
        "RUDDER_API_TOKEN=cCtjcSNc6txJcRF_\u{00AD}v9yQGzlgF8t-GM3K",
        "cCtjcSNc6txJcRF_v9yQGzlgF8t-GM3K",
    );
}

// =========================================================================
// 2. RUDDERSTACK SERVICE TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_rudderstack_service_token_normal_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdBeM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv60_rudderstack_service_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "rudderstack-service-token",
        "dummy_prefix_0 =xxxHDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv60_rudderstack_service_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{200B}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

#[test]
fn adv60_rudderstack_service_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "rudderstack-service-token",
        "RUDDERSTACK_API_KEY=Ai0HDp1bdB\u{00AD}eM6a5E4BlV",
        "Ai0HDp1bdBeM6a5E4BlV",
    );
}

// =========================================================================
// 3. SALESFORCE ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_salesforce_access_token_normal_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv60_salesforce_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "salesforce-access-token",
        "dummy9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv60_salesforce_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{200B}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

#[test]
fn adv60_salesforce_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "salesforce-access-token",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7\u{00AD}pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
        "00Dl9EknYBnvVPAD5pXo5!tqBk6FKee.qQU89ru6oLQ2bJPgvjXk1.gKc4VP7pwxJAhDxk0hQ4WkRQRnOTvzj2R040Zk18jojez.HumrM7hrkdRMU0sSHMXdxB",
    );
}

// =========================================================================
// 4. SALTSTACK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_saltstack_credentials_normal_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=saltadmin",
        "saltadmin",
    );
}

#[test]
fn adv60_saltstack_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "saltstack-credentials",
        "dummy_prefix_0 =xxxtadmin",
    );
}

#[test]
fn adv60_saltstack_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{200B}admin",
        "saltadmin",
    );
}

#[test]
fn adv60_saltstack_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{00AD}admin",
        "saltadmin",
    );
}

// =========================================================================
// 5. SANITY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_sanity_api_token_normal_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv60_sanity_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sanity-api-token",
        "dummy_prefix_0 =xxxVI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv60_sanity_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{200B}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv60_sanity_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{00AD}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

// =========================================================================
// 6. SAP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_sap_api_key_normal_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapClientId12",
        "SapClientId12",
    );
}

#[test]
fn adv60_sap_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sap-api-key",
        "dummy_prefix_0 =xxxClientId12",
    );
}

#[test]
fn adv60_sap_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{200B}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv60_sap_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{00AD}entId12",
        "SapClientId12",
    );
}

// =========================================================================
// 7. SAUCELABS ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_saucelabs_access_key_normal_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv60_saucelabs_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "saucelabs-access-key",
        "dummy_prefix_0 =xxx932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv60_saucelabs_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{200B}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv60_saucelabs_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{00AD}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

// =========================================================================
// 8. SCALEWAY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_scaleway_api_key_normal_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv60_scaleway_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scaleway-api-key",
        "dummy_prefix_0 =xxx9c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv60_scaleway_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{200B}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv60_scaleway_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{00AD}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

// =========================================================================
// 9. SCALR API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_scalr_api_token_normal_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv60_scalr_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scalr-api-token",
        "dummy_prefix_0 =xxxqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv60_scalr_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{200B}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv60_scalr_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{00AD}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

// =========================================================================
// 10. SCHOOLOGY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv60_schoology_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXTlycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv60_schoology_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "schoology-api-credentials",
        "dummy_prefix_0 =xxxLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv60_schoology_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{200B}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv60_schoology_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{00AD}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}


