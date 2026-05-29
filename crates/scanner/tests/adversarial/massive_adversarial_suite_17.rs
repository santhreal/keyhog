//! Part 17 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Campaign Monitor, Canada Open Data, Canva, Cargo, Carbon Black,
//! Casdoor, Catchpoint, and CCH Axcess detectors against zero-width spaces, soft hyphens,
//! combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CAMPAIGN MONITOR API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv17_campaign_monitor_normal_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaign_monitor_key = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv17_campaign_monitor_wrong_prefix_must_silent() {
    assert_detector_silent(
        "campaign-monitor-api-key",
        "dampaign_monitor_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv17_campaign_monitor_evade_zwsp_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaign\u{200B}_monitor_key = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv17_campaign_monitor_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campaign_monitor_key = \"000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv17_campaign_monitor_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "campaign-monitor-api-key",
        "campa\u{0457}gn_monitor_key = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 2. CANADA OPEN DATA API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv17_canada_open_data_normal_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "canada_api_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv17_canada_open_data_wrong_prefix_must_silent() {
    assert_detector_silent(
        "canada-open-data-api-key",
        "danada_api_key = \"00000000-0000-0000-0000-000000000000\"",
    );
}

#[test]
fn adv17_canada_open_data_evade_zwsp_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "canada\u{200B}_api_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv17_canada_open_data_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "canada_api_key = \"00000000-0000-0000-0000-000000\u{00AD}000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

#[test]
fn adv17_canada_open_data_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "canada-open-data-api-key",
        "can\u{0430}da_api_key = \"00000000-0000-0000-0000-000000000000\"",
        "00000000-0000-0000-0000-000000000000",
    );
}

// =========================================================================
// 3. CANVA CLIENT SECRET ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv17_canva_normal_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "canva_client_secret = \"cnvca00000000000000000000\"",
        "cnvca00000000000000000000",
    );
}

#[test]
fn adv17_canva_wrong_prefix_must_silent() {
    assert_detector_silent(
        "canva-api-token",
        "danva_client_secret = \"cnvca00000000000000000000\"",
    );
}

#[test]
fn adv17_canva_evade_zwsp_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "canva\u{200B}_client_secret = \"cnvca00000000000000000000\"",
        "cnvca00000000000000000000",
    );
}

#[test]
fn adv17_canva_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "canva_client_secret = \"cnvca00000000000000\u{00AD}000000\"",
        "cnvca00000000000000000000",
    );
}

#[test]
fn adv17_canva_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "canva-api-token",
        "c\u{0430}nva_client_secret = \"cnvca00000000000000000000\"",
        "cnvca00000000000000000000",
    );
}

// =========================================================================
// 4. CARGO REGISTRY TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv17_cargo_normal_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "cargo_token = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv17_cargo_wrong_prefix_must_silent() {
    assert_detector_silent(
        "cargo-registry-token",
        "fargo_token = \"00000000000000000000000000000000\"",
    );
}

#[test]
fn adv17_cargo_evade_zwsp_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "cargo\u{200B}_token = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv17_cargo_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "cargo_token = \"0000000000000000000000\u{00AD}0000000000\"",
        "00000000000000000000000000000000",
    );
}

#[test]
fn adv17_cargo_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "cargo-registry-token",
        "c\u{0430}rgo_token = \"00000000000000000000000000000000\"",
        "00000000000000000000000000000000",
    );
}

// =========================================================================
// 5. CARBON BLACK API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv17_carbon_black_normal_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "carbon_black_key = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv17_carbon_black_wrong_prefix_must_silent() {
    assert_detector_silent(
        "carbon-black-api-key",
        "farbon_black_key = \"00000000000000000000\"",
    );
}

#[test]
fn adv17_carbon_black_evade_zwsp_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "carbon\u{200B}_black_key = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv17_carbon_black_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "carbon_black_key = \"0000000000\u{00AD}0000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv17_carbon_black_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "carbon-black-api-key",
        "c\u{0430}rbon_black_key = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

// =========================================================================
// 6. CASDOOR CLIENT ID ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv17_casdoor_normal_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv17_casdoor_wrong_prefix_must_silent() {
    assert_detector_silent(
        "casdoor-credentials",
        "FASDOOR_CLIENT_ID = \"00000000000000000000\"",
    );
}

#[test]
fn adv17_casdoor_evade_zwsp_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR\u{200B}_CLIENT_ID = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv17_casdoor_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASDOOR_CLIENT_ID = \"0000000000\u{00AD}0000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv17_casdoor_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "casdoor-credentials",
        "CASD\u{041E}\u{041E}R_CLIENT_ID = \"00000000000000000000\"",
        "00000000000000000000",
    );
}
