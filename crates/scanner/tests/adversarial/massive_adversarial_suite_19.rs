//! Part 19 of massive, handwritten, deep adversarial integration test suite.
//!
//! Evaluates Chipper Cash, ChromaDB, CircleCI, and Clerk detectors against
//! zero-width spaces, soft hyphens, combining marks, homoglyphs, and control characters.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::{assert_detector_fires, assert_detector_silent};

// =========================================================================
// 1. CHIPPER CASH API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv19_chippercash_normal_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv19_chippercash_wrong_prefix_must_silent() {
    assert_detector_silent(
        "chippercash-api-key",
        "DHIPPER_API_KEY = \"abcde12345abcde12345abcde1234512\"",
    );
}

#[test]
fn adv19_chippercash_evade_zwsp_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER\u{200B}_API_KEY = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv19_chippercash_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CHIPPER_API_KEY = \"abcde12345abcde\u{00AD}12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

#[test]
fn adv19_chippercash_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "chippercash-api-key",
        "CH\u{0406}PPER_API_KEY = \"abcde12345abcde12345abcde1234512\"",
        "abcde12345abcde12345abcde1234512",
    );
}

// =========================================================================
// 2. CHROMADB API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv19_chromadb_normal_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN = \"abcde12345\"",
        "abcde12345",
    );
}

#[test]
fn adv19_chromadb_wrong_prefix_must_silent() {
    assert_detector_silent("chromadb-api-key", "DHROMA_AUTH_TOKEN = \"abcde12345\"");
}

#[test]
fn adv19_chromadb_evade_zwsp_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA\u{200B}_AUTH_TOKEN = \"abcde12345\"",
        "abcde12345",
    );
}

#[test]
fn adv19_chromadb_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHROMA_AUTH_TOKEN = \"abcde\u{00AD}12345\"",
        "abcde12345",
    );
}

#[test]
fn adv19_chromadb_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "chromadb-api-key",
        "CHR\u{041E}MA_AUTH_TOKEN = \"abcde12345\"",
        "abcde12345",
    );
}

// =========================================================================
// 3. CIRCLECI API TOKEN ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv19_circleci_normal_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "circleci_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv19_circleci_wrong_prefix_must_silent() {
    assert_detector_silent(
        "circleci-api-token",
        "dircleci_token = \"0000000000000000000000000000000000000000\"",
    );
}

#[test]
fn adv19_circleci_evade_zwsp_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "circleci\u{200B}_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv19_circleci_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "circleci_token = \"000000000000000000000000000000\u{00AD}0000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

#[test]
fn adv19_circleci_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "circleci-api-token",
        "circl\u{0435}ci_token = \"0000000000000000000000000000000000000000\"",
        "0000000000000000000000000000000000000000",
    );
}

// =========================================================================
// 4. CLERK PUBLISHABLE API KEY ADVERSARIAL TESTS
// =========================================================================

#[test]
fn adv19_clerk_normal_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_00000000000000000000000000000000",
        "pk_live_00000000000000000000000000000000",
    );
}

#[test]
fn adv19_clerk_wrong_prefix_must_silent() {
    assert_detector_silent("clerk-api-key", "ak_live_00000000000000000000000000000000");
}

#[test]
fn adv19_clerk_evade_zwsp_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live\u{200B}_00000000000000000000000000000000",
        "pk_live_00000000000000000000000000000000",
    );
}

#[test]
fn adv19_clerk_evade_soft_hyphen_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_live_0000000000000000000000\u{00AD}0000000000",
        "pk_live_00000000000000000000000000000000",
    );
}

#[test]
fn adv19_clerk_evade_homoglyph_must_fire() {
    assert_detector_fires(
        "clerk-api-key",
        "pk_l\u{0456}ve_00000000000000000000000000000000",
        "pk_live_00000000000000000000000000000000",
    );
}
