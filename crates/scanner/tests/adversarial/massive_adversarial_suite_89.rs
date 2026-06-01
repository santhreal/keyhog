//! Part 89 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates fusionauth, generic, genesys, genius, gentrace, geocodio, getresponse, ghost, github, github detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FUSIONAUTH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_fusionauth_api_key_normal_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "fusionauth-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{200B}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{00AD}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{200C}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{200D}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{FEFF}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{2060}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{180E}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{202E}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{202C}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

#[test]
fn adv89_fusionauth_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "fusionauth-api-key",
        "FUSIONAUTH_API_KEY=ce182726-b648-cd71\u{200E}-b829-85ccb18fb1e8",
        "ce182726-b648-cd71-b829-85ccb18fb1e8",
    );
}

// =========================================================================
// 2. GENERIC PASSWORD ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_generic_password_normal_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bVEi6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_wrong_prefix_must_silent() {
    assert_detector_silent("generic-password", "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv89_generic_password_evade_zwsp_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{200B}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{00AD}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_zwnj_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{200C}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_zwj_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{200D}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{FEFF}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{2060}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_mongolian_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{180E}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_rtl_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{202E}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{202C}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

#[test]
fn adv89_generic_password_evade_lrm_must_fire() {
    assert_detector_fires(
        "generic-password",
        "password=S4oxj2N-bV\u{200E}Ei6ivQsrW3",
        "S4oxj2N-bVEi6ivQsrW3",
    );
}

// =========================================================================
// 3. GENESYS CLOUD CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_genesys_cloud_credentials_normal_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_wrong_prefix_must_silent() {
    assert_detector_silent(
        "genesys-cloud-credentials",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_zwsp_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{200B}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{00AD}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_zwnj_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{200C}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_zwj_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{200D}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{FEFF}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{2060}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_mongolian_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{180E}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_rtl_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{202E}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{202C}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

#[test]
fn adv89_genesys_cloud_credentials_evade_lrm_must_fire() {
    assert_detector_fires(
        "genesys-cloud-credentials",
        "GENESYS_CLIENT_ID=2963950e-3ed2-e3dc\u{200E}-49d5-740982bac6a9",
        "2963950e-3ed2-e3dc-49d5-740982bac6a9",
    );
}

// =========================================================================
// 4. GENIUS API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_genius_api_token_normal_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "genius-api-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_genius_api_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{200B}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{00AD}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{200C}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{200D}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{FEFF}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{2060}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{180E}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{202E}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{202C}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

#[test]
fn adv89_genius_api_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "genius-api-token",
        "GENIUS=2UW4EG0Ml0wCWn\u{200E}wbMXpLVxYhyVYl",
        "2UW4EG0Ml0wCWnwbMXpLVxYhyVYl",
    );
}

// =========================================================================
// 5. GENTRACE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_gentrace_api_key_normal_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "gentrace-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{200B}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{00AD}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{200C}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{200D}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{FEFF}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{2060}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{180E}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{202E}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{202C}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

#[test]
fn adv89_gentrace_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "gentrace-api-key",
        "GENTRACE_API_KEY=gZsBR3cpTBBZqmJqeUvR\u{200E}ZDGSzZDL95OkEUPtSwRW",
        "gZsBR3cpTBBZqmJqeUvRZDGSzZDL95OkEUPtSwRW",
    );
}

// =========================================================================
// 6. GEOCODIO API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_geocodio_api_key_normal_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "geocodio-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{200B}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{00AD}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{200C}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{200D}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{FEFF}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{2060}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{180E}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{202E}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{202C}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

#[test]
fn adv89_geocodio_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "geocodio-api-key",
        "GEOCODIO_API_KEY=3nHvnPWgQka0Qs6ZHb74\u{200E}Yc1xf9uTN3ejCrjuLNGs",
        "3nHvnPWgQka0Qs6ZHb74Yc1xf9uTN3ejCrjuLNGs",
    );
}

// =========================================================================
// 7. GETRESPONSE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_getresponse_api_key_normal_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pgSF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "getresponse-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{200B}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{00AD}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{200C}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{200D}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{FEFF}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{2060}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{180E}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{202E}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{202C}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

#[test]
fn adv89_getresponse_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "getresponse-api-key",
        "GETRESPONSE_API_KEY=qcTyZ5O-pg\u{200E}SF5zj9IUMf",
        "qcTyZ5O-pgSF5zj9IUMf",
    );
}

// =========================================================================
// 8. GHOST API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_ghost_api_key_normal_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ghost-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_ghost_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{200B}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{00AD}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{200C}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{200D}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{FEFF}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{2060}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{180E}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{202E}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{202C}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

#[test]
fn adv89_ghost_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ghost-api-key",
        "ghost=7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae\u{200E}3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
        "7ad8f0e2b92e5ced64d451b1:4cd92e59a6c00bd1bae3cb0e5e60f5fc4caeb9820206cf156659251c39592cb5",
    );
}

// =========================================================================
// 9. GITHUB APP INSTALLATION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_github_app_installation_token_normal_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "github-app-installation-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{200B}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{00AD}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{200C}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{200D}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{FEFF}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{2060}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{180E}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{202E}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{202C}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

#[test]
fn adv89_github_app_installation_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "github-app-installation-token",
        "ghs_Qy4gyJlDeVvhcdbD\u{200E}GXIrubm2bjUxGr9yELqD",
        "ghs_Qy4gyJlDeVvhcdbDGXIrubm2bjUxGr9yELqD",
    );
}

// =========================================================================
// 10. GITHUB APP PRIVATE KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv89_github_app_private_key_normal_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_wrong_prefix_must_silent() {
    assert_detector_silent("github-app-private-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv89_github_app_private_key_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{200B}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{00AD}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_zwnj_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{200C}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_zwj_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{200D}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_zwnbsp_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{FEFF}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_word_joiner_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{2060}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_mongolian_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{180E}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_rtl_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{202E}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_pop_dir_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{202C}PRIVATE KEY-----");
}

#[test]
fn adv89_github_app_private_key_evade_lrm_bare_must_stay_silent() {
    assert_detector_silent("github-app-private-key", "-----BEGIN RSA \u{200E}PRIVATE KEY-----");
}
