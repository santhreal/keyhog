//! Part 83 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates drake, drata, drift, drip, dronahq, dropbox, druid, duckdb, dune, dwolla detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DRAKE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_drake_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drake-api-credentials",
        "dummy_prefix_0 =xxxxxx",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{200B}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{00AD}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{200C}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{200D}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{FEFF}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{2060}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{180E}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{202E}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{202C}104",
        "739104",
    );
}

#[test]
fn adv83_drake_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "drake-api-credentials",
        "drake_account_number=739\u{200E}104",
        "739104",
    );
}

// =========================================================================
// 2. DRATA API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_drata_api_token_normal_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drata-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_drata_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{200B}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{00AD}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{200C}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{200D}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{FEFF}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{2060}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{180E}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{202E}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{202C}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

#[test]
fn adv83_drata_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "drata-api-token",
        "DRATA_API_KEY=01ac616f8fd0ba84a167fe482ed4a92c\u{200E}8c8050eed40ef171cc2784d638b34fa7",
        "01ac616f8fd0ba84a167fe482ed4a92c8c8050eed40ef171cc2784d638b34fa7",
    );
}

// =========================================================================
// 3. DRIFT API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_drift_api_credentials_normal_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drift-api-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{200B}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{00AD}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{200C}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{200D}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{FEFF}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{2060}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{180E}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{202E}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{202C}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

#[test]
fn adv83_drift_api_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "drift-api-credentials",
        "drift_token=drft_rFfveashtVcNiYVn2\u{200E}TeAS7lqX9gfWuy4VQ3UZPLd",
        "drft_rFfveashtVcNiYVn2TeAS7lqX9gfWuy4VQ3UZPLd",
    );
}

// =========================================================================
// 4. DRIP API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_drip_api_token_normal_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA79ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "drip-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_drip_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{200B}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{00AD}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{200C}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{200D}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{FEFF}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{2060}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{180E}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{202E}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{202C}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

#[test]
fn adv83_drip_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "drip-api-token",
        "drip_api_token=kEnydx9qWCA7\u{200E}9ISjs8JHUdKF0",
        "kEnydx9qWCA79ISjs8JHUdKF0",
    );
}

// =========================================================================
// 5. DRONAHQ CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_dronahq_credentials_normal_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dronahq-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{200B}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{00AD}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{200C}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{200D}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{FEFF}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{2060}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{180E}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{202E}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{202C}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

#[test]
fn adv83_dronahq_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "dronahq-credentials",
        "DRONAHQ_API_KEY=4zL3oHL8ceu01i\u{200E}6H97f_EjDeVIho",
        "4zL3oHL8ceu01i6H97f_EjDeVIho",
    );
}

// =========================================================================
// 6. DROPBOX ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_dropbox_access_token_normal_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dropbox-access-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{200B}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{00AD}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{200C}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{200D}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{FEFF}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{2060}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{180E}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{202E}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{202C}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

#[test]
fn adv83_dropbox_access_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yI\u{200E}oX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
        "sl.9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaB1yIoX0aBcDeFgHiJkLmNoPqRsTuVwXy1234567890AbCdEfGhIjKlMnOpQrStUv",
    );
}

// =========================================================================
// 7. DRUID CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_druid_credentials_normal_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEbht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "druid-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_druid_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{200B}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{00AD}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{200C}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{200D}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{FEFF}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{2060}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{180E}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{202E}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{202C}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

#[test]
fn adv83_druid_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "druid-credentials",
        "DRUID_PASSWORD=AFHzLDdEb\u{200E}ht+JO%$Qr",
        "AFHzLDdEbht+JO%$Qr",
    );
}

// =========================================================================
// 8. DUCKDB CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_duckdb_credentials_normal_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "duckdb-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{200B}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{00AD}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{200C}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{200D}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{FEFF}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{2060}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{180E}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{202E}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{202C}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

#[test]
fn adv83_duckdb_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "duckdb-credentials",
        "MOTHERDUCK_TOKEN=blu17rNy8H6\u{200E}h8l7qgATtLF",
        "blu17rNy8H6h8l7qgATtLF",
    );
}

// =========================================================================
// 9. DUNE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_dune_api_key_normal_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dune-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_dune_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{200B}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{00AD}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{200C}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{200D}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{FEFF}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{2060}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{180E}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{202E}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{202C}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

#[test]
fn adv83_dune_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key=466426fae9480469\u{200E}a7737ec218a5dca3",
        "466426fae9480469a7737ec218a5dca3",
    );
}

// =========================================================================
// 10. DWOLLA CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv83_dwolla_client_credentials_normal_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dwolla-client-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{200B}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{00AD}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{200C}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{200D}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{FEFF}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{2060}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{180E}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{202E}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{202C}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}

#[test]
fn adv83_dwolla_client_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "DWOLLA_CLIENT_ID=Kp4Qx7Rm2Sn\u{200E}5Tb8Vw3YzKp4",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4",
    );
}


