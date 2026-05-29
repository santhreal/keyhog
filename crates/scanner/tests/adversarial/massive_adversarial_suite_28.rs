//! Part 28 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates dropbox, druid, duckdb, dune, and dwolla detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. DROPBOX ACCESS TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv28_dropbox_normal_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "dropbox_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv28_dropbox_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dropbox-access-token",
        "cropbox_token = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv28_dropbox_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "dropbox\u{200B}_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv28_dropbox_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "dropbox_token = \"00000000000000000000\u{00AD}00000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv28_dropbox_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dropbox-access-token",
        "dropb\u{043E}x_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 2. DUNE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv28_dune_normal_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv28_dune_wrong_prefix_must_silent() {
    assert_detector_silent("dune-api-key", "fune_api_key = \"abcde12345abcde12345\"");
}

#[test]
fn adv28_dune_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune\u{200B}_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv28_dune_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "dune_api_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv28_dune_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dune-api-key",
        "d\u{0443}ne_api_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. DWOLLA CLIENT CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv28_dwolla_normal_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "dwolla_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv28_dwolla_wrong_prefix_must_silent() {
    assert_detector_silent(
        "dwolla-client-credentials",
        "fwolla_key = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv28_dwolla_evade_zwsp_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "dwolla\u{200B}_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv28_dwolla_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "dwolla_key = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv28_dwolla_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "dwolla-client-credentials",
        "dw\u{043E}lla_key = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
