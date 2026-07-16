//! Regression contract for the scanner's entropy keyword classification
//! (`crates/scanner/src/entropy/keywords.rs` + the `engine::phase2_generic::
//! keywords` normalizer it delegates to). Every assertion pins a CONCRETE
//! expected value observed from the source, driven only through the public
//! `keyhog_scanner::testing` `_for_test` facades.
//!
//! Owner crate: keyhog-scanner (imports ONLY keyhog_scanner + std).

use std::collections::HashSet;

use keyhog_scanner::testing::{
    assignment_keyword_for_line_for_test, compact_keyword_ends_with_for_test,
    compact_keyword_eq_for_test, generic_keyword_prefilter_stem_for_test,
    is_likely_concatenation_fragment_for_test, is_likely_innocuous_line_for_test,
    normalize_assignment_keyword_for_test,
    normalized_assignment_keyword_has_secret_suffix_for_test,
    normalized_assignment_keyword_is_credential_for_test, xml_assignment_tag_for_test,
};

/// The canonical compact credential-keyword set (`CREDENTIAL_COMPACT_KEYWORDS`
/// in entropy/keywords.rs), transcribed from source. The count and dedup
/// contract, plus per-entry membership, are locked below.
const CREDENTIAL_COMPACT: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "secret",
    "credential",
    "bearer",
    "authorization",
    "apikey",
    "accesskey",
    "authkey",
    "privatekey",
    "signingkey",
    "encryptionkey",
    "masterkey",
    "secretkey",
    "sessionkey",
    "clientsecret",
    "appsecret",
    "salt",
    "nonce",
    "seed",
    "hmacsalt",
    "hmacseed",
    "passwordsalt",
];

#[test]
fn credential_compact_list_has_exactly_26_unique_entries() {
    // Count contract: the canonical set is 26 entries.
    assert_eq!(CREDENTIAL_COMPACT.len(), 26);
    // Dedup contract: no duplicate spellings in the canonical set.
    let unique: HashSet<&&str> = CREDENTIAL_COMPACT.iter().collect();
    assert_eq!(unique.len(), 26);
}

#[test]
fn every_canonical_compact_keyword_is_recognized_as_credential() {
    // Membership contract: every one of the 26 canonical spellings, passed as
    // an already-normalized key, classifies as a credential slot.
    for &keyword in CREDENTIAL_COMPACT {
        assert!(
            normalized_assignment_keyword_is_credential_for_test(keyword),
            "canonical compact keyword `{keyword}` must be credential",
        );
    }
    // Concrete count: all 26 pass.
    let recognized = CREDENTIAL_COMPACT
        .iter()
        .filter(|k| normalized_assignment_keyword_is_credential_for_test(k))
        .count();
    assert_eq!(recognized, 26);
}

#[test]
fn plain_non_secret_keys_are_not_credential() {
    // Negative twins: common config keys must NOT be treated as credential.
    let non_credential = [
        "username", "host", "url", "port", "timeout", "region", "version", "hostname", "endpoint",
        "filename",
    ];
    for key in non_credential {
        assert!(
            !normalized_assignment_keyword_is_credential_for_test(key),
            "`{key}` must not be classified credential",
        );
    }
    let rejected = non_credential
        .iter()
        .filter(|k| !normalized_assignment_keyword_is_credential_for_test(k))
        .count();
    assert_eq!(rejected, 10);
}

#[test]
fn separated_secret_suffix_keys_are_credential() {
    // The separated-secret-suffix branch: last `_`-segment in the credential
    // word set makes the whole key credential.
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "api_key"
    ));
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "app_secret"
    ));
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "auth_token"
    ));
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "user_password"
    ));
    // A `_`-prefixed non-secret last segment is NOT credential via this branch,
    // and the compact fold ("segmentname") is not in the list either.
    assert!(!normalized_assignment_keyword_is_credential_for_test(
        "segment_name"
    ));
}

#[test]
fn credential_classification_folds_case_via_compact_branch() {
    // Case handling: an upper-case spelling with no `_` folds through the
    // compact branch (which lower-cases) and is still recognized.
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "PASSWORD"
    ));
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "APIKEY"
    ));
    // Upper-case separated form: the `_`-segment branch is case-sensitive and
    // misses, but the compact fold ("apikey") still catches it -> credential.
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "API_KEY"
    ));
}

#[test]
fn salt_nonce_seed_suffix_is_credential_including_broad_match() {
    // The compact branch's `ends_with(salt|nonce|seed)` suffix arms.
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "randomsalt"
    ));
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "csrfnonce"
    ));
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "prngseed"
    ));
    // Adversarial: the suffix arm is a raw byte `ends_with`, so a non-secret
    // word that happens to end in "salt" ("basalt") is ALSO classified
    // credential. This pins the documented (over-broad) contract, not a wish.
    assert!(normalized_assignment_keyword_is_credential_for_test(
        "basalt"
    ));
    // Boundary negative: "assault" ends in "ault", not "salt".
    assert!(!normalized_assignment_keyword_is_credential_for_test(
        "assault"
    ));
}

#[test]
fn normalize_folds_three_compound_spellings_to_one_token() {
    // SCREAMING_SNAKE, kebab, and dotted spellings all collapse to the same
    // lower-snake token.
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
}

#[test]
fn normalize_collapses_runs_trims_edges_and_rejects_empty() {
    // Consecutive separators collapse to a single `_`.
    assert_eq!(
        normalize_assignment_keyword_for_test("api__key").as_deref(),
        Some("api_key")
    );
    // Leading and trailing separators are trimmed (leading never emits, trailing popped).
    assert_eq!(
        normalize_assignment_keyword_for_test("_api_key_").as_deref(),
        Some("api_key")
    );
    // Empty and all-separator inputs normalize to None.
    assert_eq!(normalize_assignment_keyword_for_test(""), None);
    assert_eq!(normalize_assignment_keyword_for_test("___"), None);
}

#[test]
fn secret_suffix_classifier_truth_table() {
    // Last `_`-segment match.
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "segment_write_key"
    ));
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "app_secret"
    ));
    // Bare `ends_with` fallback (no underscore).
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "mytoken"
    ));
    assert!(normalized_assignment_keyword_has_secret_suffix_for_test(
        "adminpassword"
    ));
    // Negatives: a bare service marker has no secret suffix.
    assert!(!normalized_assignment_keyword_has_secret_suffix_for_test(
        "segment"
    ));
    assert!(!normalized_assignment_keyword_has_secret_suffix_for_test(
        "region"
    ));
}

#[test]
fn compact_eq_is_exact_and_ends_with_is_suffix() {
    // Exact-equality helper: case-fold + drop `_`/`-`/`.`, then EXACT match.
    assert!(compact_keyword_eq_for_test("API_KEY", "apikey"));
    assert!(compact_keyword_eq_for_test("api-key", "apikey"));
    assert!(compact_keyword_eq_for_test("KEY", "key"));
    // Exact helper rejects a superstring.
    assert!(!compact_keyword_eq_for_test("keyvault", "key"));

    // Suffix helper: matches a trailing run only.
    assert!(compact_keyword_ends_with_for_test("access_key", "key"));
    assert!(compact_keyword_ends_with_for_test("api-key", "key"));
    // The documented distinction: a prefix "key" is NOT a suffix match.
    assert!(!compact_keyword_ends_with_for_test("keyvault", "key"));
}

#[test]
fn prefilter_stem_follows_priority_ordered_contains_chain() {
    // secret > pass > pwd > token > webhook > key > auth > credential > self.
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("secret_key"),
        "secret"
    );
    assert_eq!(generic_keyword_prefilter_stem_for_test("password"), "pass");
    assert_eq!(generic_keyword_prefilter_stem_for_test("pwd"), "pwd");
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("auth_token"),
        "token"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("webhook_url"),
        "webhook"
    );
    // `auth_key` contains both "auth" and "key"; "key" is checked first.
    assert_eq!(generic_keyword_prefilter_stem_for_test("auth_key"), "key");
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("authorization"),
        "auth"
    );
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("credential"),
        "credential"
    );
    // Unknown keyword keeps its exact spelling (recall-preserving fallback).
    assert_eq!(
        generic_keyword_prefilter_stem_for_test("segment"),
        "segment"
    );
}

#[test]
fn innocuous_line_gate_drops_imports_uris_and_digests() {
    // Import-like declarations.
    assert!(is_likely_innocuous_line_for_test("import os"));
    // Bare URI.
    assert!(is_likely_innocuous_line_for_test(
        "https://api.example.com/v1/users"
    ));
    // Algo-labelled digest, case-insensitive.
    assert!(is_likely_innocuous_line_for_test("SHA256:abcdefabcdef"));
    assert!(is_likely_innocuous_line_for_test("sha256:abcdefabcdef"));
    // Bare 40-hex git SHA (boundary: exactly 40 chars).
    assert!(is_likely_innocuous_line_for_test(
        "0123456789abcdef0123456789abcdef01234567"
    ));
    // Boundary negative: 41 hex chars is not a git SHA shape.
    assert!(!is_likely_innocuous_line_for_test(
        "0123456789abcdef0123456789abcdef012345678"
    ));
    // Adversarial: a URI that CARRIES a credential assignment is NOT dropped.
    assert!(!is_likely_innocuous_line_for_test(
        "https://example.com/?password=hunter2secretvalue"
    ));
    // Plain assignment is not innocuous.
    assert!(!is_likely_innocuous_line_for_test("api_key = abc123def456"));
}

#[test]
fn concatenation_fragment_gate_truth_table() {
    // Balanced quoted run with a `+` concat-glue suffix.
    assert!(is_likely_concatenation_fragment_for_test("\"abc\" +"));
    // Balanced quoted run with nothing after -> fragment.
    assert!(is_likely_concatenation_fragment_for_test("\"abc\""));
    // Line ending in a `-\` continuation.
    assert!(is_likely_concatenation_fragment_for_test("some-value-\\"));
    // Negative twin: a real keyed assignment is not a fragment.
    assert!(!is_likely_concatenation_fragment_for_test(
        "password = \"realvalue123456\""
    ));
    // Negative: an unquoted assignment line.
    assert!(!is_likely_concatenation_fragment_for_test("token = abc123"));
}

#[test]
fn xml_assignment_tag_truth_table() {
    // Well-formed element with matching close returns the tag name.
    assert_eq!(
        xml_assignment_tag_for_test("<password>secret123</password>").as_deref(),
        Some("password")
    );
    // Close/comment/PI markers are rejected.
    assert_eq!(xml_assignment_tag_for_test("</password>"), None);
    assert_eq!(xml_assignment_tag_for_test("<!-- a comment -->"), None);
    // Mismatched close tag -> None.
    assert_eq!(xml_assignment_tag_for_test("<password>x</other>"), None);
    // No angle brackets -> None.
    assert_eq!(xml_assignment_tag_for_test("plain text = value"), None);
}

#[test]
fn assignment_keyword_for_line_short_circuits_and_falls_back() {
    // Credential key short-circuits to itself.
    assert_eq!(
        assignment_keyword_for_line_for_test("password = hunter2").as_deref(),
        Some("password")
    );
    assert_eq!(
        assignment_keyword_for_line_for_test("api_key: abc123def").as_deref(),
        Some("api_key")
    );
    // No credential key present: the rightmost non-credential key is the fallback.
    assert_eq!(
        assignment_keyword_for_line_for_test("host = localhost").as_deref(),
        Some("host")
    );
    // XML tag takes precedence over `=`/`:` scanning.
    assert_eq!(
        assignment_keyword_for_line_for_test("<client_secret>xyz</client_secret>").as_deref(),
        Some("client_secret")
    );
}

#[cfg(feature = "entropy")]
#[test]
fn keyword_is_credential_anchor_truth_table() {
    use keyhog_scanner::testing::keyword_is_credential_anchor_for_test;
    // The no-keyword sentinel is NOT an anchor.
    assert!(!keyword_is_credential_anchor_for_test(
        "none (high-entropy)"
    ));
    // Credential-normalizing keywords anchor.
    assert!(keyword_is_credential_anchor_for_test("api_key"));
    assert!(keyword_is_credential_anchor_for_test("token"));
    assert!(keyword_is_credential_anchor_for_test("bearer"));
    // A plain non-credential key is not an anchor.
    assert!(!keyword_is_credential_anchor_for_test("hostname"));
}
