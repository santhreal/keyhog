//! Durable guard against detector-id drift.
//!
//! Every service-anchored constant in this file MUST resolve to a real id in
//! the embedded `detectors/*.toml` corpus. A constant whose string drifts
//! from the detector it names becomes a DEAD predicate: the scanner logic
//! keyed on it silently matches nothing. This is exactly the latent bug the
//! removed `stripe-api-key` const was (the real id is `stripe-secret-key`),
//! and the same class the `github-fine-grained-pat`/`gitlab-token`/
//! `slack-token` validator labels were. The synthetic entropy-family ids and
//! the family prefixes are the ONLY non-corpus values, and they are
//! enumerated + asserted absent from the corpus so a future typo cannot hide
//! among them.
//!
//! Adding a new detector-id const requires listing it in `corpus_backed_consts`
//! (real detector) or `synthetic_consts` (entropy family), otherwise it is
//! not guarded, which is itself the maintenance contract these tests pin.

use super::*;
use crate::detector_catalog::bundled_detector_ids;

/// Every const that MUST name a real embedded detector. cfg-gated to mirror
/// each const's own feature gate so the list compiles under every feature set.
fn corpus_backed_consts() -> Vec<(&'static str, &'static str)> {
    let v = vec![
        ("GENERIC_SECRET", GENERIC_SECRET),
        ("GENERIC_KEYWORD_SECRET", GENERIC_KEYWORD_SECRET),
        ("GENERIC_API_KEY", GENERIC_API_KEY),
        ("GENERIC_PASSWORD", GENERIC_PASSWORD),
        ("PRIVATE_KEY", PRIVATE_KEY),
        ("GITHUB_CLASSIC_PAT", GITHUB_CLASSIC_PAT),
        ("GITHUB_PAT_FINE_GRAINED", GITHUB_PAT_FINE_GRAINED),
        ("GITLAB_PERSONAL_ACCESS_TOKEN", GITLAB_PERSONAL_ACCESS_TOKEN),
        ("NPM_ACCESS_TOKEN", NPM_ACCESS_TOKEN),
        ("PYPI_API_TOKEN", PYPI_API_TOKEN),
        ("SLACK_BOT_TOKEN", SLACK_BOT_TOKEN),
        ("STRIPE_SECRET_KEY", STRIPE_SECRET_KEY),
    ];
    v
}

/// Synthetic finding ids are assigned by active detector TOML metadata.
/// Only the namespace itself is non-corpus data, so assert it has no corpus
/// collision.
fn synthetic_consts() -> Vec<(&'static str, &'static str)> {
    vec![("ENTROPY", ENTROPY)]
}

#[test]
fn every_corpus_backed_const_names_a_real_embedded_detector() {
    let corpus = bundled_detector_ids().expect("embedded detector corpus must load fail-closed");
    let missing: Vec<String> = corpus_backed_consts()
        .into_iter()
        .filter(|(_, id)| !corpus.contains(*id))
        .map(|(name, id)| format!("{name} = {id:?}"))
        .collect();
    assert!(
        missing.is_empty(),
        "detector-id consts naming NO embedded detector (dead predicates): {missing:?}"
    );
}

#[test]
fn stripe_secret_key_const_is_the_real_id_not_the_removed_phantom() {
    // The exact divergence this guard exists for: the const resolves to the
    // real `stripe-secret-key` detector, and the removed `stripe-api-key`
    // phantom names NO detector.
    let corpus = bundled_detector_ids().unwrap();
    assert_eq!(STRIPE_SECRET_KEY, "stripe-secret-key");
    assert!(corpus.contains("stripe-secret-key"));
    assert!(
        !corpus.contains("stripe-api-key"),
        "the removed phantom id must not exist"
    );
}

#[test]
fn renamed_checksum_label_consts_resolve_to_real_detectors() {
    let corpus = bundled_detector_ids().unwrap();

    assert_eq!(GITHUB_PAT_FINE_GRAINED, "github-pat-fine-grained");
    assert!(corpus.contains(GITHUB_PAT_FINE_GRAINED));
    assert!(!corpus.contains("github-fine-grained-pat"));

    assert_eq!(GITLAB_PERSONAL_ACCESS_TOKEN, "gitlab-personal-access-token");
    assert!(corpus.contains(GITLAB_PERSONAL_ACCESS_TOKEN));
    assert!(!corpus.contains("gitlab-token"));

    assert_eq!(SLACK_BOT_TOKEN, "slack-bot-token");
    assert!(corpus.contains(SLACK_BOT_TOKEN));
    assert!(!corpus.contains("slack-token"));
}

#[test]
fn synthetic_finding_ids_are_absent_from_the_toml_corpus() {
    let corpus = bundled_detector_ids().unwrap();
    for (name, id) in synthetic_consts() {
        assert!(
            !corpus.contains(id),
            "{name} = {id:?} is a synthetic finding id; it must not collide with a TOML detector"
        );
        assert!(
            id == ENTROPY || id.starts_with(ENTROPY_PREFIX),
            "{name} = {id:?} must be an entropy-family synthetic id"
        );
    }
}

#[test]
fn family_prefixes_are_prefixes_not_detector_ids() {
    let corpus = bundled_detector_ids().unwrap();
    for (name, prefix) in [
        ("GENERIC_PREFIX", GENERIC_PREFIX),
        ("ENTROPY_PREFIX", ENTROPY_PREFIX),
    ] {
        assert!(
            prefix.ends_with('-'),
            "{name} = {prefix:?} must end with '-'"
        );
        assert!(
            !corpus.contains(prefix),
            "{name} is a family prefix, not a detector id"
        );
    }
    assert!(GENERIC_SECRET.starts_with(GENERIC_PREFIX));
    assert!(GENERIC_API_KEY.starts_with(GENERIC_PREFIX));
    assert!("entropy-generic".starts_with(ENTROPY_PREFIX));
}

#[test]
fn family_predicates_classify_the_real_ids_correctly() {
    // Generic
    assert!(is_generic_detector(GENERIC_SECRET));
    assert!(is_generic_detector(GENERIC_PASSWORD));
    assert!(!is_generic_detector(GITHUB_CLASSIC_PAT));
    assert!(!is_generic_detector(STRIPE_SECRET_KEY));

    // Entropy (ENTROPY is always compiled; the "entropy-" family via prefix)
    assert!(is_entropy_detector(ENTROPY));
    assert!(is_entropy_detector("entropy-generic"));
    assert!(!is_entropy_detector(GENERIC_SECRET));
    assert!(!is_entropy_detector(GITHUB_CLASSIC_PAT));

    // Named execution class: reporting service does not select it.
    assert!(is_service_anchored_detector(GITHUB_CLASSIC_PAT));
    assert!(is_service_anchored_detector(STRIPE_SECRET_KEY));
    assert!(is_service_anchored_detector(SLACK_BOT_TOKEN));
    assert!(is_service_anchored_detector(GITLAB_PERSONAL_ACCESS_TOKEN));
    assert!(!is_service_anchored_detector(GENERIC_SECRET));
    assert!(!is_service_anchored_detector(ENTROPY));
    assert!(!is_service_anchored_detector(PRIVATE_KEY));
    assert!(is_service_anchored_detector("bearer-authorization"));

    // Private-key fallback
    assert!(is_private_key_fallback(PRIVATE_KEY));
    assert!(!is_private_key_fallback(GITHUB_CLASSIC_PAT));

    // Unrelated generic detectors are not members. Membership itself is
    // corpus-declared and pinned below.
    assert!(!is_structural_password_slot_detector(GITHUB_CLASSIC_PAT));
    assert!(!is_structural_password_slot_detector(GENERIC_SECRET));
}

/// The detector-wide structural-password-slot family is declared in TOML
/// and applies to every pattern. Generic Password instead declares the bit
/// on its exact ODBC pattern, so its keyword bridge and sibling patterns
/// retain Tier-B shape gates.
#[test]
fn structural_password_slot_family_is_toml_declared() {
    use std::collections::BTreeSet;
    let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
    let members: BTreeSet<&str> = specs
        .iter()
        .filter(|s| s.structural_password_slot)
        .map(|s| s.id.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "bearer-authorization",
        "cli-password-flag",
        "sql-password",
        "url-credentials",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        members, expected,
        "structural_password_slot TOML declarations drifted from the known family"
    );
    // And the predicate agrees with the declaration for each member.
    for id in &expected {
        assert!(
            is_structural_password_slot_detector(id),
            "predicate must classify declared member `{id}` as a structural password slot"
        );
    }
    let generic_password = specs
        .iter()
        .find(|spec| spec.id == "generic-password")
        .expect("generic-password detector exists");
    let structural_patterns: Vec<usize> = generic_password
        .patterns
        .iter()
        .enumerate()
        .filter_map(|(index, pattern)| pattern.structural_password_slot.then_some(index))
        .collect();
    assert_eq!(
        structural_patterns,
        vec![1, 2],
        "the ODBC and credential-bearing URL patterns prove structural password slots"
    );
}

/// The weak-anchor family membership is DECLARED in the detector TOMLs
/// (`weak_anchor = true`), read back through `DetectorSpec::weak_anchor`
/// (DET-0; migrated out of the `rules/detector-classification.toml`
/// `weak_anchor` list). Pins the EXACT member set against the embedded corpus
/// so adding/removing the flag on any detector, or a typo'd id, fails
/// loudly here, preserving the "see the whole family at a glance" view the
/// centralized list gave.
#[test]
fn weak_anchor_family_is_toml_declared() {
    use std::collections::BTreeSet;
    let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
    let members: BTreeSet<&str> = specs
        .iter()
        .filter(|s| s.weak_anchor)
        .map(|s| s.id.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "activecampaign-api-key",
        "adobe-api-key",
        "aerisweather-api-credentials",
        "alchemy-api-key",
        "azure-openai-api-key",
        "bamboohr-api-key",
        "base-api-credentials",
        "calendly-api-key",
        "census-api-key",
        "chef-automate-token",
        "crowdin-api-token",
        "etherscan-api-key",
        "flickr-api-key",
        "foundation-api-key",
        "getresponse-api-key",
        "github-oauth-secret",
        "rudder-api-token",
        "sonarcloud-token",
        "spotify-client-credentials",
        "workato-api-credentials",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        members, expected,
        "weak_anchor TOML declarations drifted from the known family"
    );
}

/// WHY: the structurally named OAuth assignment is not a weak anchor. Runtime
/// coverage must preserve its value floor and detector-owned negative shapes.
#[test]
fn oauth_client_secret_runtime_boundaries_are_explicit() {
    let detector = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded corpus loads")
        .into_iter()
        .find(|detector| detector.id == "oauth-client-secret")
        .expect("OAuth client-secret detector exists");
    assert!(
        !detector.weak_anchor,
        "a named client_secret assignment must not enable generic Tier-B gates"
    );
    let scanner = crate::CompiledScanner::compile(vec![detector])
        .expect("OAuth client-secret detector compiles");
    let credentials = |payload: &str| {
        scanner
            .scan(&keyhog_core::Chunk::from(payload))
            .expect("OAuth fixture scans")
            .into_iter()
            .filter(|finding| finding.detector_id.as_ref() == "oauth-client-secret")
            .map(|finding| finding.credential.as_ref().to_owned())
            .collect::<Vec<_>>()
    };

    for (payload, expected) in [
        ("client_secret=A7f9K2m4P8q1R6t3V5x0", "A7f9K2m4P8q1R6t3V5x0"),
        (
            "clientSecret: \"9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e\"",
            "9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e",
        ),
        (
            "CLIENT_SECRET = C113nt53KR3TN6N90yVuAgICxIRwsObLi0E67/N8eRN=",
            "C113nt53KR3TN6N90yVuAgICxIRwsObLi0E67/N8eRN=",
        ),
    ] {
        assert_eq!(
            credentials(payload),
            vec![expected],
            "named OAuth fixture must preserve the exact credential span"
        );
    }

    for payload in [
        "client_secret=A7f9K2m4P8q1R6t3V5x",
        "client_secret=${OAUTH_CLIENT_SECRET}",
        "client_secret=b15decee-d2f0-15f2-0f1c-fcbb05d0bb15",
        "client_secret=00000000000000000000",
    ] {
        assert!(
            credentials(payload).is_empty(),
            "non-secret OAuth value class must stay rejected: {payload}"
        );
    }
}

/// The private-key-block family membership is DECLARED in the detector TOMLs
/// (`private_key_block = true`), read back through
/// `DetectorSpec::private_key_block` (DET-0; migrated out of the
/// `rules/detector-classification.toml` `private_key_block` list). Pins the
/// EXACT member set and confirms the predicate agrees.
#[test]
fn private_key_block_family_is_toml_declared() {
    use std::collections::BTreeSet;
    let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
    let members: BTreeSet<&str> = specs
        .iter()
        .filter(|s| s.private_key_block)
        .map(|s| s.id.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "github-app-private-key",
        "google-artifact-registry-key",
        "private-key",
        "ssh-private-key",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        members, expected,
        "private_key_block TOML declarations drifted from the known family"
    );
    for id in &expected {
        assert!(
            is_private_key_block_detector(id),
            "predicate must classify declared member `{id}` as a private-key block"
        );
    }
}

#[test]
fn new_detector_requires_no_scanner_source_edits() {
    let toml_source = r#"
id = "custom-vendor-test-token"
name = "Custom Vendor Test Token"
service = "customvendor"
severity = "high"
keywords = ["custom_vendor_test_token"]
min_confidence = 0.1

[ml]
match_mode = "disabled"
entropy_mode = "disabled"
weight = 0.0
context_radius_lines = 0

[match_confidence]
literal_prefix_weight = 0.35
context_anchor_weight = 0.20
entropy_weight = 0.20
high_entropy_partial_weight = 0.12
moderate_entropy_threshold = 3.0
moderate_entropy_weight = 0.05
low_entropy_penalty_floor = 2.0
low_entropy_min_match_length = 10
low_entropy_penalty_multiplier = 0.60
keyword_nearby_weight = 0.10
sensitive_file_weight = 0.10
companion_weight = 0.05
very_high_entropy_margin = 1.3
named_anchor_floor = 0.55
assignment_context_multiplier = 1.0
string_literal_context_multiplier = 0.9
unknown_context_multiplier = 0.8
documentation_context_multiplier = 0.3
comment_context_multiplier = 0.4
test_context_multiplier = 0.3
encrypted_context_multiplier = 0.05
soft_context_suppression_threshold = 0.5
encrypted_context_suppression_threshold = 0.2

[match_confidence.post_match]
placeholder_multiplier = 0.1
minimum_byte_diversity = 0.2
low_diversity_multiplier = 0.5
maximum_repeat_ratio = 0.5
degenerate_run_min_length = 8
degenerate_repeat_multiplier = 0.1
fixture_path_multiplier = 0.5
ml_context_reapply_below = 0.5

[[patterns]]
regex = "custom_token_[a-zA-Z0-9]{32}"
description = "Custom vendor token shape"

[[tests]]
test_positive = "custom_vendor_test_token = \"custom_token_0123456789abcdef0123456789abcdef\""
"#;
    let spec: keyhog_core::DetectorSpec =
        toml::from_str(toml_source).expect("custom detector spec parses");
    assert_eq!(spec.id, "custom-vendor-test-token");
    assert_eq!(spec.min_confidence, Some(0.1));

    let scanner = crate::CompiledScanner::compile(vec![spec])
        .expect("custom detector compiles into scanner without source edits");
    let chunk = keyhog_core::Chunk {
        data: "custom_vendor_test_token = \"custom_token_0123456789abcdef0123456789abcdef\"".into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };
    let findings = scanner.scan(&chunk).expect("scan succeeds");
    assert!(
        !findings.is_empty(),
        "custom detector without scanner source edits must fire"
    );
    assert_eq!(findings[0].detector_id.as_ref(), "custom-vendor-test-token");
}
