//! Part 23 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates definedfi, delinea, deno, descope, and devcycle detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

use super::oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DEFINEDFI API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv23_definedfi_normal_bare_must_stay_silent() {
    assert_detector_silent("definedfi-api-key", "definedfi_key = \"0000000000000000000000000000000000000000\"");
}

#[test]
fn adv23_definedfi_wrong_prefix_must_silent() {
    assert_detector_silent(
        "definedfi-api-key",
        "refinedfi_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv23_definedfi_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("definedfi-api-key", "definedfi\u{200B}_key = \"0000000000000000000000000000000000000000\"");
}

#[test]
fn adv23_definedfi_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("definedfi-api-key", "definedfi_key = \"000000000000000000000000000000\u{00AD}0000000000\"");
}

#[test]
fn adv23_definedfi_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("definedfi-api-key", "def\u{0456}nedfi_key = \"0000000000000000000000000000000000000000\"");
}

// =========================================================================
// 2. DELINEA SECRET SERVER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv23_delinea_normal_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "delinea_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv23_delinea_wrong_prefix_must_silent() {
    assert_detector_silent(
        "delinea-secret-server-credentials",
        "felinea_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv23_delinea_evade_zwsp_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "delinea\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv23_delinea_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "delinea_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv23_delinea_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "delinea-secret-server-credentials",
        "del\u{0456}nea_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. DENO KV CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv23_deno_normal_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "deno_kv_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv23_deno_wrong_prefix_must_silent() {
    assert_detector_silent(
        "deno-kv-credentials",
        "feno_kv_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv23_deno_evade_zwsp_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "deno\u{200B}_kv_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv23_deno_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "deno_kv_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv23_deno_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "deno-kv-credentials",
        "d\u{0435}no_kv_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 4. DESCOPE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv23_descope_normal_bare_must_stay_silent() {
    assert_detector_silent("descope-api-key", "descope_key = \"0000000000000000000000000000000000000000\"");
}

#[test]
fn adv23_descope_wrong_prefix_must_silent() {
    assert_detector_silent(
        "descope-api-key",
        "fescope_key = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv23_descope_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("descope-api-key", "descope\u{200B}_key = \"0000000000000000000000000000000000000000\"");
}

#[test]
fn adv23_descope_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("descope-api-key", "descope_key = \"000000000000000000000000000000\u{00AD}0000000000\"");
}

#[test]
fn adv23_descope_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("descope-api-key", "d\u{0435}scope_key = \"0000000000000000000000000000000000000000\"");
}

// =========================================================================
// 5. DEVCYCLE API CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv23_devcycle_normal_bare_must_stay_silent() {
    assert_detector_silent("devcycle-api-credentials", "devcycle_client_id = \"abcde12345abcde12345\"");
}

#[test]
fn adv23_devcycle_wrong_prefix_must_silent() {
    assert_detector_silent(
        "devcycle-api-credentials",
        "fevcycle_client_id = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv23_devcycle_evade_zwsp_bare_must_stay_silent() {
    assert_detector_silent("devcycle-api-credentials", "devcycle\u{200B}_client_id = \"abcde12345abcde12345\"");
}

#[test]
fn adv23_devcycle_evade_soft_hyphen_bare_must_stay_silent() {
    assert_detector_silent("devcycle-api-credentials", "devcycle_client_id = \"abcde12345abcde\u{00AD}12345\"");
}

#[test]
fn adv23_devcycle_evade_homoglyph_bare_must_stay_silent() {
    assert_detector_silent("devcycle-api-credentials", "d\u{0435}vcycle_client_id = \"abcde12345abcde12345\"");
}
