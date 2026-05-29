//! Part 33 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates filebase, finicity, and firebase detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. FILEBASE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv33_filebase_normal_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "filebase_key = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv33_filebase_wrong_prefix_must_silent() {
    assert_detector_silent(
        "filebase-api-key",
        "gilebase_key = \"00000000000000000000\"",
    );
}

#[test]
fn adv33_filebase_evade_zwsp_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "filebase\u{200B}_key = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv33_filebase_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "filebase_key = \"0000000000\u{00AD}0000000000\"",
        "00000000000000000000",
    );
}

#[test]
fn adv33_filebase_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "filebase-api-key",
        "f\u{0456}lebase_key = \"00000000000000000000\"",
        "00000000000000000000",
    );
}

// =========================================================================
// 2. FINICITY PARTNER CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv33_finicity_normal_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "finicity_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv33_finicity_wrong_prefix_must_silent() {
    assert_detector_silent(
        "finicity-partner-credentials",
        "ginicity_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv33_finicity_evade_zwsp_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "finicity\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv33_finicity_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "finicity_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv33_finicity_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "finicity-partner-credentials",
        "f\u{0456}nicity_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

// =========================================================================
// 3. FIREBASE STORAGE CREDENTIALS ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv33_firebase_normal_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "firebase_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv33_firebase_wrong_prefix_must_silent() {
    assert_detector_silent(
        "firebase-storage-credentials",
        "girebase_password = \"abcde12345abcde12345\"",
    );
}

#[test]
fn adv33_firebase_evade_zwsp_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "firebase\u{200B}_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv33_firebase_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "firebase_password = \"abcde12345abcde\u{00AD}12345\"",
        "abcde12345abcde12345",
    );
}

#[test]
fn adv33_firebase_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "firebase-storage-credentials",
        "f\u{0456}rebase_password = \"abcde12345abcde12345\"",
        "abcde12345abcde12345",
    );
}
