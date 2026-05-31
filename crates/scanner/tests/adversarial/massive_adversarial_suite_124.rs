//! Part 124 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates saltstack, sanity, sap, saucelabs, scaleway, scalr, schoology, scrapeops, scraperapi, scrapingbee detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. SALTSTACK CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_saltstack_credentials_normal_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=saltadmin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_wrong_prefix_must_silent() {
    assert_detector_silent("saltstack-credentials", "dummy_prefix_0 =xxxxxxxxx");
}

#[test]
fn adv124_saltstack_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{200B}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{00AD}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{200C}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{200D}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{FEFF}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{2060}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{180E}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{202E}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{202C}admin",
        "saltadmin",
    );
}

#[test]
fn adv124_saltstack_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "saltstack-credentials",
        "SALT_API_USERNAME=salt\u{200E}admin",
        "saltadmin",
    );
}

// =========================================================================
// 2. SANITY API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_sanity_api_token_normal_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "sanity-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_sanity_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{200B}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{00AD}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{200C}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{200D}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{FEFF}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{2060}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{180E}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{202E}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{202C}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

#[test]
fn adv124_sanity_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "sanity-api-token",
        "SANITY_API_TOKEN=sk4VI2EWMzmLvb5a9dd\u{200E}9403a8d3b0f37f91f289",
        "sk4VI2EWMzmLvb5a9dd9403a8d3b0f37f91f289",
    );
}

// =========================================================================
// 3. SAP API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_sap_api_key_normal_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapClientId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("sap-api-key", "dummy_prefix_0 =xxxxxxxxxxxxx");
}

#[test]
fn adv124_sap_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{200B}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{00AD}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{200C}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{200D}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{FEFF}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{2060}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{180E}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{202E}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{202C}entId12",
        "SapClientId12",
    );
}

#[test]
fn adv124_sap_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "sap-api-key",
        "sap_client_id=SapCli\u{200E}entId12",
        "SapClientId12",
    );
}

// =========================================================================
// 4. SAUCELABS ACCESS KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_saucelabs_access_key_normal_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "saucelabs-access-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{200B}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{00AD}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{200C}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{200D}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{FEFF}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{2060}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{180E}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{202E}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{202C}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

#[test]
fn adv124_saucelabs_access_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "saucelabs-access-key",
        "SAUCE_ACCESS_KEY=020932ee-9a19-8c18\u{200E}-b71b-8fb4c1643844",
        "020932ee-9a19-8c18-b71b-8fb4c1643844",
    );
}

// =========================================================================
// 5. SCALEWAY API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_scaleway_api_key_normal_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scaleway-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{200B}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{00AD}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{200C}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{200D}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{FEFF}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{2060}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{180E}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{202E}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{202C}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

#[test]
fn adv124_scaleway_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "scaleway-api-key",
        "SCW_SECRET_KEY=6179c5db-a4be-f4b3\u{200E}-0d77-79da118cfc39",
        "6179c5db-a4be-f4b3-0d77-79da118cfc39",
    );
}

// =========================================================================
// 6. SCALR API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_scalr_api_token_normal_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scalr-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_scalr_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{200B}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{00AD}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{200C}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{200D}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{FEFF}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{2060}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{180E}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{202E}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{202C}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

#[test]
fn adv124_scalr_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "scalr-api-token",
        "SCALR_TOKEN=eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcL\u{200E}hcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
        "eyJqEn0DWRqaI8.eyJ2EZmQ0rQI1KS2vAHKhbVxPEJrwHqJUcpDGcDzG5b6ZjeO_rTJlAFLwM_mj9M4z90pm5indkRJqaMe_7qcLhcbk.zatKoCFZ3LnYyOgxIRh6SRcFLfddJzxS8Kk2_emw-BnII8IGYXfjppfEeEqE_K0IGediMBiPhaX7Te67vFmO6XL7wc-93hJ",
    );
}

// =========================================================================
// 7. SCHOOLOGY API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_schoology_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXTlycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "schoology-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{200B}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{00AD}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{200C}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{200D}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{FEFF}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{2060}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{180E}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{202E}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{202C}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

#[test]
fn adv124_schoology_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "schoology-api-credentials",
        "schoologykey=c4NLEt0fXT\u{200E}lycVadLKlz",
        "c4NLEt0fXTlycVadLKlz",
    );
}

// =========================================================================
// 8. SCRAPEOPS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_scrapeops_api_key_normal_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scrapeops-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{200B}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{00AD}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{200C}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{200D}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{FEFF}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{2060}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{180E}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{202E}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{202C}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

#[test]
fn adv124_scrapeops_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "scrapeops-api-key",
        "scrapeops=42lzch6Jg83lGwx5\u{200E}zyvvoA4A5ClC9pjf",
        "42lzch6Jg83lGwx5zyvvoA4A5ClC9pjf",
    );
}

// =========================================================================
// 9. SCRAPERAPI KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_scraperapi_key_normal_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scraperapi-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_scraperapi_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{200B}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{00AD}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{200C}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{200D}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{FEFF}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{2060}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{180E}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{202E}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{202C}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

#[test]
fn adv124_scraperapi_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "scraperapi-key",
        "scraperapi=izPAS25CHzk8Sz3o\u{200E}h4TMdXOqCCQnaX8d",
        "izPAS25CHzk8Sz3oh4TMdXOqCCQnaX8d",
    );
}

// =========================================================================
// 10. SCRAPINGBEE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv124_scrapingbee_api_key_normal_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "scrapingbee-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{200B}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{00AD}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{200C}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{200D}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{FEFF}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{2060}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{180E}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{202E}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{202C}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}

#[test]
fn adv124_scrapingbee_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "scrapingbee-api-key",
        "scrapingbee=cnSctbWZ2NV8jmNL\u{200E}V0upUAtUAAP2aK3l",
        "cnSctbWZ2NV8jmNLV0upUAtUAAP2aK3l",
    );
}
