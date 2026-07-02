//! Regression contract for the scanner's detector keyword -> id index/lookup.
//!
//! Two layers are pinned here, both to CONCRETE expected values:
//!
//!   1. The pure keyword-classification primitives that the phase-2 generic
//!      bridge and the named-detector owner set are built from
//!      (`engine::phase2_generic::keywords`, `generic_keyword_owner`), exposed
//!      through `keyhog_scanner::testing::*_for_test`. These are host-independent
//!      (no accelerator, no I/O): the prefilter-stem priority chain, the compact
//!      exact-vs-suffix keyword comparators, the assignment-keyword normalizer,
//!      the secret-suffix classifier, the leading-assignment-key extractor, the
//!      binary-search owner check, and the span-owner boundary expansion.
//!
//!   2. The end-to-end keyword -> detector-id mapping: a real `CompiledScanner`
//!      built from the on-disk detector TOMLs, scanned on the ALWAYS-AVAILABLE
//!      `ScanBackend::CpuFallback` so the assertion never assumes a GPU/SIMD
//!      accelerator. Every token used is a contract-verified firing positive
//!      (`crates/scanner/tests/contracts/*.toml`), so the exact detector id it
//!      resolves to is a fact, not a guess.
//!
//! Every assertion checks a specific value (exact stem string, exact bool, exact
//! `Option<String>`, exact detector-id string) — never a bare `is_empty`/`len`.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{
    assignment_keyword_owned_by_named_detector_for_test, compact_keyword_ends_with_for_test,
    compact_keyword_eq_for_test, generic_keyword_prefilter_stem_for_test,
    is_service_anchored_detector_for_test, is_service_specific_detector_for_test,
    keyword_span_owned_by_named_detector_for_test, leading_assignment_key_for_test,
    normalize_assignment_keyword_for_test,
    normalized_assignment_keyword_has_secret_suffix_for_test,
};
use keyhog_scanner::{is_entropy_detector, CompiledScanner, ScanBackend};

// ---------------------------------------------------------------------------
// End-to-end scan harness (CpuFallback => host-independent, no accelerator).
// ---------------------------------------------------------------------------

fn detector_dir() -> std::path::PathBuf {
    // `CARGO_MANIFEST_DIR` = crates/scanner; the on-disk Tier-B detector TOMLs
    // live at <repo>/detectors, matching tests/support/paths.rs::detector_dir.
    let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn build_scanner() -> CompiledScanner {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("on-disk detectors directory loadable");
    CompiledScanner::compile(detectors).expect("scanner compiles from detector corpus")
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("probe.txt".into()),
            ..Default::default()
        },
    }
}

/// Detector ids of every CpuFallback match whose surfaced credential contains
/// `credential`. CpuFallback is always available, so this is accelerator-free;
/// the tokens used all carry a distinctive literal (`ghp_`, `AKIA`, `password`)
/// so CpuFallback (which lacks the Hyperscan-only no-literal detectors) still
/// fires them.
fn cpu_ids_for(scanner: &CompiledScanner, text: &str, credential: &str) -> Vec<String> {
    scanner.clear_fragment_cache();
    let c = chunk(text);
    scanner
        .scan_with_backend(&c, ScanBackend::CpuFallback)
        .iter()
        .filter(|m| m.credential.as_ref().contains(credential))
        .map(|m| m.detector_id.as_ref().to_string())
        .collect()
}

// ===========================================================================
// Layer 1a — generic_keyword_prefilter_stem: PRIORITY-ORDERED contains chain
//   secret > pass > pwd > token > webhook > key > auth > credential > self
// ===========================================================================

#[test]
fn prefilter_stem_secret_wins_over_later_stems() {
    // `secret` is first in the chain, so any keyword containing it collapses to
    // `secret` even when it also contains `key`/`token`.
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("secret_key"),
        "secret"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("client_secret"),
        "secret"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("secret_token"),
        "secret"
    );
}

#[test]
fn prefilter_stem_key_beats_auth() {
    // `auth_key` contains BOTH `key` and `auth`; `key` precedes `auth` in the
    // chain, so the stem is `key` — the exact precedence the doc-comment pins.
    assert_eq!(generic_keyword_prefilter_stem_for_test("auth_key"), "key");
    assert_eq!(generic_keyword_prefilter_stem_for_test("apikey"), "key");
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("encryption_key"),
        "key"
    );
}

#[test]
fn prefilter_stem_pass_pwd_token_webhook_auth_credential() {
    assert_eq!(generic_keyword_prefilter_stem_for_test("password"), "pass");
    assert_eq!(generic_keyword_prefilter_stem_for_test("api_pwd"), "pwd");
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("access_token"),
        "token"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("webhook_url"),
        "webhook"
    );
    // `authorization` contains `auth` but none of the earlier stems.
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("authorization"),
        "auth"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("credentials"),
        "credential"
    );
}

#[test]
fn prefilter_stem_unknown_keyword_is_the_keyword_itself() {
    // No stem substring matches, so the keyword keeps its exact spelling — a
    // keyword-list expansion can never become invisible to the prefilter.
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("vendorname"),
        "vendorname"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("license"),
        "license"
    );
}

// ===========================================================================
// Layer 1b — compact keyword comparators (case-fold, drop `_`/`-`/`.`)
// ===========================================================================

#[test]
fn compact_keyword_eq_is_exact_and_separator_insensitive() {
    // Separator-insensitive EXACT equality.
    assert!(compact_keyword_eq_for_test("API_KEY", "apikey"));
    assert!(compact_keyword_eq_for_test("api-key", "apikey"));
    assert!(compact_keyword_eq_for_test("api.key", "apikey"));
    // A trailing extra char breaks EXACT equality (no suffix/prefix slop).
    assert!(!compact_keyword_eq_for_test("apikeys", "apikey"));
    // A superstring is not exactly equal to a shorter needle.
    assert!(!compact_keyword_eq_for_test("keyvault", "key"));
}

#[test]
fn compact_keyword_ends_with_is_suffix_not_exact() {
    // Genuine suffix hits.
    assert!(compact_keyword_ends_with_for_test("secret_key", "key"));
    assert!(compact_keyword_ends_with_for_test("clientSecret", "secret"));
    assert!(compact_keyword_ends_with_for_test("apikey", "key"));
    // `keyvault` starts with `key` but does NOT end with it.
    assert!(!compact_keyword_ends_with_for_test("keyvault", "key"));
    // Non-suffix and too-short keyword both fail.
    assert!(!compact_keyword_ends_with_for_test("keyx", "key"));
    assert!(!compact_keyword_ends_with_for_test("ky", "key"));
}

// ===========================================================================
// Layer 1c — normalize_assignment_keyword: case-fold, collapse `_`/`-`/`.`,
//            trim leading/trailing separators, drop unrecognized bytes.
// ===========================================================================

#[test]
fn normalize_assignment_keyword_folds_case_and_collapses_separators() {
    assert_eq!(
        normalize_assignment_keyword_for_test("SEGMENT_WRITE_KEY").as_deref(),
        Some("segment_write_key")
    );
    assert_eq!(
        normalize_assignment_keyword_for_test("segment-write-key").as_deref(),
        Some("segment_write_key")
    );
    assert_eq!(
        normalize_assignment_keyword_for_test("segment.write.key").as_deref(),
        Some("segment_write_key")
    );
    // Doubled separators collapse to a single `_`.
    assert_eq!(
        normalize_assignment_keyword_for_test("API__KEY").as_deref(),
        Some("api_key")
    );
    // Leading + trailing separators are trimmed.
    assert_eq!(
        normalize_assignment_keyword_for_test("_key_").as_deref(),
        Some("key")
    );
}

#[test]
fn normalize_assignment_keyword_boundaries() {
    // No alphanumeric byte => None.
    assert_eq!(normalize_assignment_keyword_for_test("!!!"), None);
    assert_eq!(normalize_assignment_keyword_for_test("   "), None);
    // `!` is neither alnum nor a recognized separator, so it is silently
    // dropped WITHOUT inserting a `_` boundary: the two runs fuse.
    assert_eq!(
        normalize_assignment_keyword_for_test("key!value").as_deref(),
        Some("keyvalue")
    );
}

// ===========================================================================
// Layer 1d — normalized_assignment_keyword_has_secret_suffix: last-`_`-segment
//            set {key,secret,token,password,passwd,pwd} OR ends_with
//            {key,secret,token,password}.
// ===========================================================================

#[test]
fn secret_suffix_segment_match_set() {
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "api_key"
    ));
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "client_secret"
    ));
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "access_token"
    ));
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "db_password"
    ));
    // `passwd` counts ONLY as a whole last-`_`-segment.
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "my_passwd"
    ));
}

#[test]
fn secret_suffix_endswith_vs_segment_split_and_negatives() {
    // No underscore + not an ends_with member: `passwd`/`pwd` are NOT in the
    // ends_with set, so a fused `mypasswd` is NOT a secret suffix (adversarial
    // twin of `my_passwd`, which IS).
    assert!(!normalized_assignment_keyword_has_secret_suffix_for_test(
        "mypasswd"
    ));
    // ends_with set catches the no-separator `apikey`.
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "apikey"
    ));
    // Bare service markers claim no credential slot.
    assert!(!normalized_assignment_keyword_has_secret_suffix_for_test(
        "segment"
    ));
    assert!(!normalized_assignment_keyword_has_secret_suffix_for_test(
        "webhook"
    ));
}

// ===========================================================================
// Layer 1e — leading_assignment_key: pull `key` from `key=`/`key:`/`key~`.
// ===========================================================================

#[test]
fn leading_assignment_key_requires_a_terminator() {
    assert_eq!(
        leading_assignment_key_for_test("api_key=secret").as_deref(),
        Some("api_key")
    );
    assert_eq!(
        leading_assignment_key_for_test("api-key: val").as_deref(),
        Some("api-key")
    );
    assert_eq!(
        leading_assignment_key_for_test("foo~bar").as_deref(),
        Some("foo")
    );
    // No `=`/`:`/`~` terminator => None.
    assert_eq!(leading_assignment_key_for_test("no_terminator"), None);
    // Leading terminator (empty key) => None.
    assert_eq!(leading_assignment_key_for_test("=value"), None);
}

// ===========================================================================
// Layer 1f — named-detector owner set: binary-search EXACT membership +
//            span boundary expansion.
// ===========================================================================

#[test]
fn owner_membership_is_exact_match_only() {
    let owned = ["segment_write_key", "stripe_secret"];
    // Exact hit.
    assert!(assignment_keyword_owned_by_named_detector_for_test(
        &owned,
        "segment_write_key"
    ));
    // A prefix of an owned key is NOT owned.
    assert!(!assignment_keyword_owned_by_named_detector_for_test(
        &owned,
        "segment_write"
    ));
    // A superstring of an owned key is NOT owned.
    assert!(!assignment_keyword_owned_by_named_detector_for_test(
        &owned,
        "segment_write_keys"
    ));
    // An empty owner set owns nothing.
    assert!(!assignment_keyword_owned_by_named_detector_for_test(
        &[],
        "segment_write_key"
    ));
    // UNSORTED input is still handled (the facade sorts through a BTreeSet).
    let unsorted = ["b_key", "a_key"];
    assert!(assignment_keyword_owned_by_named_detector_for_test(
        &unsorted, "a_key"
    ));
}

#[test]
fn owner_span_bounds_guard_and_expansion() {
    let owned = ["segment_write_key"];
    let line = "segment_write_key=abc";
    // Exact span over the owned key.
    assert!(keyword_span_owned_by_named_detector_for_test(
        &owned, line, 0, 17
    ));
    // Inverted bounds (start > end) fail closed.
    assert!(!keyword_span_owned_by_named_detector_for_test(
        &owned, line, 5, 3
    ));
    // End past the line length fails closed.
    assert!(!keyword_span_owned_by_named_detector_for_test(
        &owned, line, 0, 1000
    ));
    // A sub-span (`write`) expands left/right over assignment-key bytes to the
    // full owned key and is owned.
    assert!(keyword_span_owned_by_named_detector_for_test(
        &owned, line, 8, 13
    ));
    // Same expansion on an UNOWNED assignment stays unowned.
    let unowned_line = "random_value=abc";
    assert!(!keyword_span_owned_by_named_detector_for_test(
        &owned,
        unowned_line,
        0,
        6
    ));
}

// ===========================================================================
// Layer 1g — detector-id family predicates.
// ===========================================================================

#[test]
fn service_anchored_predicate_matches_expected_ids_and_equals_specific() {
    // Service-anchored (named) detectors.
    for id in ["github-classic-pat", "aws-access-key", "stripe-api-key"] {
        assert!(
            is_service_anchored_detector_for_test(id),
            "{id} must be service-anchored"
        );
        // The resolution predicate must stay IDENTICAL to the canonical one
        // (the two were a drift-prone duplicate before consolidation).
        assert_eq!(
            is_service_specific_detector_for_test(id),
            is_service_anchored_detector_for_test(id),
            "{id}: service-specific must equal service-anchored"
        );
    }
    // Generic / entropy / private-key families are NOT service-anchored.
    for id in [
        "generic-password",
        "generic-secret",
        "entropy",
        "entropy-token",
        "private-key",
    ] {
        assert!(
            !is_service_anchored_detector_for_test(id),
            "{id} must NOT be service-anchored"
        );
        assert_eq!(
            is_service_specific_detector_for_test(id),
            is_service_anchored_detector_for_test(id),
            "{id}: service-specific must equal service-anchored"
        );
    }
}

#[test]
fn is_entropy_detector_family_boundary() {
    assert!(is_entropy_detector("entropy"));
    assert!(is_entropy_detector("entropy-token"));
    assert!(is_entropy_detector("entropy-generic"));
    // Generic and named detectors are NOT the entropy family.
    assert!(!is_entropy_detector("generic-secret"));
    assert!(!is_entropy_detector("generic-password"));
    assert!(!is_entropy_detector("github-classic-pat"));
    assert!(!is_entropy_detector("private-key"));
}

// ===========================================================================
// Layer 2 — end-to-end keyword -> detector-id, CpuFallback (no accelerator).
//   Tokens are contract-verified positives from tests/contracts/*.toml.
// ===========================================================================

#[test]
fn github_ghp_token_maps_to_github_classic_pat() {
    // Contract positive: crates/scanner/tests/contracts/github-classic-pat.toml.
    let token = "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";
    let scanner = build_scanner();
    let ids = cpu_ids_for(&scanner, &format!("GH_TOKEN={token}"), token);
    assert!(
        ids.iter().any(|id| id == "github-classic-pat"),
        "ghp_ token must map to github-classic-pat; got {ids:?}"
    );
    // The generic password bridge must NOT claim a service-anchored PAT.
    assert!(
        !ids.iter().any(|id| id == "generic-password"),
        "ghp_ token must not surface under generic-password; got {ids:?}"
    );
}

#[test]
fn aws_akia_token_maps_to_aws_access_key() {
    // Contract positive: crates/scanner/tests/contracts/aws-access-key.toml
    // (AKIA keys have NO trailing checksum).
    let token = "AKIAQYLPMN5HFIQR7XYA";
    let scanner = build_scanner();
    let ids = cpu_ids_for(&scanner, token, token);
    assert!(
        ids.iter().any(|id| id == "aws-access-key"),
        "AKIA token must map to aws-access-key; got {ids:?}"
    );
}

#[test]
fn password_keyword_maps_to_generic_password() {
    // Contract positive: crates/scanner/tests/contracts/generic-password.toml.
    let credential = "S4oxj2N-bVEi6ivQsrW3";
    let scanner = build_scanner();
    let ids = cpu_ids_for(&scanner, &format!("password={credential}"), credential);
    assert!(
        ids.iter().any(|id| id == "generic-password"),
        "password= anchor must map to generic-password; got {ids:?}"
    );
}

#[test]
fn github_token_id_is_backend_invariant_cpu_vs_default() {
    // The keyword -> id mapping for a literal-anchored detector must be the same
    // on the always-available CpuFallback and on whatever backend the default
    // `scan()` selects — no accelerator assumption, pure parity.
    let token = "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";
    let scanner = build_scanner();
    let text = format!("GH_TOKEN={token}");

    let cpu_ids = cpu_ids_for(&scanner, &text, token);

    scanner.clear_fragment_cache();
    let default_ids: Vec<String> = scanner
        .scan(&chunk(&text))
        .iter()
        .filter(|m| m.credential.as_ref().contains(token))
        .map(|m| m.detector_id.as_ref().to_string())
        .collect();

    assert!(
        cpu_ids.iter().any(|id| id == "github-classic-pat"),
        "CpuFallback must surface github-classic-pat; got {cpu_ids:?}"
    );
    assert!(
        default_ids.iter().any(|id| id == "github-classic-pat"),
        "default backend must surface github-classic-pat; got {default_ids:?}"
    );
}
