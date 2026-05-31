//! Part 110 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates nexus, ngrok, ngrok, nih, noaa, nomad, notion, notion, notion, novu detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. NEXUS API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_nexus_api_key_normal_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nexus-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_nexus_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{200B}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{00AD}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{200C}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{200D}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{FEFF}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{2060}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{180E}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{202E}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{202C}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

#[test]
fn adv110_nexus_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "nexus-api-key",
        "NEXUS_API_KEY=926820561f663070c952112c7f4f5fa4\u{200E}6b37c427601aa7dc9e98614469cca8c1",
        "926820561f663070c952112c7f4f5fa46b37c427601aa7dc9e98614469cca8c1",
    );
}

// =========================================================================
// 2. NGROK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_ngrok_api_key_normal_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ngrok-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{200B}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{00AD}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{200C}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{200D}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{FEFF}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{2060}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{180E}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{202E}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{202C}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

#[test]
fn adv110_ngrok_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "ngrok-api-key",
        "NGROK_API_KEY=JBtug0uFLI4S6P3lTr5L\u{200E}Rbu4nzD7wx3SQrs23tOu",
        "JBtug0uFLI4S6P3lTr5LRbu4nzD7wx3SQrs23tOu",
    );
}

// =========================================================================
// 3. NGROK AUTH TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_ngrok_auth_token_normal_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "ngrok-auth-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{200B}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{00AD}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{200C}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{200D}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{FEFF}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{2060}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{180E}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{202E}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{202C}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

#[test]
fn adv110_ngrok_auth_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "ngrok-auth-token",
        "NGROK_AUTHTOKEN=6vFSd5rDCFSM5K5OrRo4\u{200E}JGIdLLsIfXAuWO+bvvn/",
        "6vFSd5rDCFSM5K5OrRo4JGIdLLsIfXAuWO+bvvn/",
    );
}

// =========================================================================
// 4. NIH PUBMED API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_nih_pubmed_api_key_normal_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nih-pubmed-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{200B}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{00AD}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{200C}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{200D}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{FEFF}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{2060}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{180E}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{202E}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{202C}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

#[test]
fn adv110_nih_pubmed_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "nih-pubmed-api-key",
        "NIH_PUBMED_API_KEY=9Uz0vRSvRD4VZ7SSmy\u{200E}Pz32hJL459hzkhCEwA",
        "9Uz0vRSvRD4VZ7SSmyPz32hJL459hzkhCEwA",
    );
}

// =========================================================================
// 5. NOAA API CONFIG ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_noaa_api_config_normal_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_wrong_prefix_must_silent() {
    assert_detector_silent(
        "noaa-api-config",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_noaa_api_config_evade_zwsp_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{200B})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{00AD})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_zwnj_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{200C})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_zwj_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{200D})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{FEFF})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{2060})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_mongolian_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{180E})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_rtl_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{202E})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{202C})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

#[test]
fn adv110_noaa_api_config_evade_lrm_must_fire() {
    assert_detector_fires(
        "noaa-api-config",
        "User-Agent=mDnz,U!<T$2Zy#c?d:8E\u{200E})H37Auqweather.govz)Y",
        "mDnz,U!<T$2Zy#c?d:8E)H37Auqweather.govz)Y",
    );
}

// =========================================================================
// 6. NOMAD ACL TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_nomad_acl_token_normal_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "nomad-acl-token",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{200B}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{00AD}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{200C}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{200D}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{FEFF}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{2060}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{180E}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{202E}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{202C}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

#[test]
fn adv110_nomad_acl_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "nomad-acl-token",
        "NOMAD_TOKEN=5a625743-ca5c-c65a\u{200E}-3857-c02b98f8b8b5",
        "5a625743-ca5c-c65a-3857-c02b98f8b8b5",
    );
}

// =========================================================================
// 7. NOTION API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_notion_api_key_normal_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_wrong_prefix_must_silent() {
    assert_detector_silent(
        "notion-api-key",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_notion_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{200B}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{00AD}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{200C}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{200D}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{FEFF}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{2060}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{180E}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{202E}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{202C}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

#[test]
fn adv110_notion_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "notion-api-key",
        "NOTION_API_KEY=secret_9X3kQp7VbT2hYRzNcM\u{200E}fWj4DgEsLuHaIoBnVkPxKqRtY",
        "secret_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtY",
    );
}

// =========================================================================
// 8. NOTION INTEGRATION TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_notion_integration_token_normal_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_wrong_prefix_must_silent() {
    assert_detector_silent(
        "notion-integration-token",
        "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_notion_integration_token_evade_zwsp_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200B}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{00AD}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_zwnj_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200C}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_zwj_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200D}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{FEFF}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{2060}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_mongolian_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{180E}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_rtl_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202E}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{202C}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_integration_token_evade_lrm_must_fire() {
    assert_detector_fires(
        "notion-integration-token",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3Yz\u{200E}Kp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "ntn_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

// =========================================================================
// 9. NOTION OAUTH SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_notion_oauth_secret_normal_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_wrong_prefix_must_silent() {
    assert_detector_silent(
        "notion-oauth-secret",
        "dummy_prefix_0 =xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_zwsp_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{200B}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{00AD}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_zwnj_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{200C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_zwj_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{200D}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{FEFF}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{2060}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_mongolian_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{180E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_rtl_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{202E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{202C}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

#[test]
fn adv110_notion_oauth_secret_evade_lrm_must_fire() {
    assert_detector_fires(
        "notion-oauth-secret",
        "NOTION_CLIENT_SECRET=secret_Kp4Qx7Rm2Sn5Tb8Vw3\u{200E}YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
        "secret_Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3YzKpRm",
    );
}

// =========================================================================
// 10. NOVU API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv110_novu_api_key_normal_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_wrong_prefix_must_silent() {
    assert_detector_silent("novu-api-key", "dummyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
}

#[test]
fn adv110_novu_api_key_evade_zwsp_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{200B}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{00AD}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_zwnj_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{200C}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_zwj_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{200D}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_zwnbsp_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{FEFF}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_word_joiner_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{2060}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_mongolian_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{180E}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_rtl_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{202E}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_pop_dir_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{202C}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}

#[test]
fn adv110_novu_api_key_evade_lrm_must_fire() {
    assert_detector_fires(
        "novu-api-key",
        "nvu_JYpcTUFDffTRWN\u{200E}apX7YqCQNvLP5lpJRX",
        "nvu_JYpcTUFDffTRWNapX7YqCQNvLP5lpJRX",
    );
}
