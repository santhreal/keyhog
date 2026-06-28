//! Migrated from suppression::shape module-root tests (KH-GAP-004).

use keyhog_scanner::testing::shape::{
    generic_base64_candidate_is_ambiguous, looks_like_credential_colliding_punctuation,
    looks_like_dotted_source_identifier, looks_like_filename_reference,
    looks_like_generic_random_base64_blob_decoy, looks_like_kebab_config_identifier,
    looks_like_public_evidence_identifier, looks_like_punctuation_decorated_identifier,
    looks_like_syntactic_punctuation_marker, looks_like_train_case_prose_identifier,
    public_noncredential_shape_full, public_noncredential_shape_weak_anchor,
};

#[test]
fn public_evidence_identifier_stays_case_insensitive_after_zero_alloc_rewrite() {
    // Taxonomy infixes (was upper.contains, now ci_find) — match in ANY case.
    assert!(looks_like_public_evidence_identifier("CWE_79-input-validation"));
    assert!(looks_like_public_evidence_identifier("cwe_79-input-validation"));
    assert!(looks_like_public_evidence_identifier("RFC_7519-spec-ref"));
    assert!(looks_like_public_evidence_identifier("doc-OWASP_A03-note"));
    // `-ISSUE-` / `_ISSUE_` infix, case-insensitive.
    assert!(looks_like_public_evidence_identifier("project-ISSUE-1024"));
    assert!(looks_like_public_evidence_identifier("project-issue-1024"));
    // Authority prose markers (was lower.contains, now ci_find) — any case.
    assert!(looks_like_public_evidence_identifier("authority-attestation"));
    assert!(looks_like_public_evidence_identifier("Authority-Attestation"));
    // `pw.`-prefixed (was lower.starts_with, now starts_with_ignore_ascii_case).
    assert!(looks_like_public_evidence_identifier("PW.row-range-1"));

    // Negatives: no taxonomy/authority marker, and the alphabet guard rejects
    // out-of-set bytes.
    assert!(!looks_like_public_evidence_identifier("issuetracker-onlypage"));
    assert!(!looks_like_public_evidence_identifier("plainrandomtoken"));
    // Contains a space (outside [A-Za-z0-9_-.:/=]) — rejected by the guard.
    assert!(!looks_like_public_evidence_identifier("CWE_79 input validation"));
    // Too short (<6).
    assert!(!looks_like_public_evidence_identifier("cwe_1"));
}

#[test]
fn public_evidence_crypto_and_fixture_subshapes_stay_case_insensitive() {
    // Password-KDF algorithm names (crypto arm, now eq_ignore_ascii_case — was
    // to_ascii_lowercase) — match in any case, exact (not substring).
    assert!(looks_like_public_evidence_identifier("argon2id"));
    assert!(looks_like_public_evidence_identifier("Argon2"));
    assert!(looks_like_public_evidence_identifier("BCRYPT"));
    assert!(looks_like_public_evidence_identifier("pbkdf2"));
    // Not in the KDF set.
    assert!(!looks_like_public_evidence_identifier("argon3"));
    assert!(!looks_like_public_evidence_identifier("sha256")); // a digest, not a KDF

    // `<PREFIX>-…-fixture` provenance labels (fixture arm, now
    // ends_with_ignore_ascii_case for the suffix — body parts still lowercase).
    assert!(looks_like_public_evidence_identifier("AB7-foo-fixture"));
    assert!(looks_like_public_evidence_identifier("X9-bar-baz-fixture"));
    // Prefix must be uppercase-led + carry a digit; a lowercase prefix fails.
    assert!(!looks_like_public_evidence_identifier("lower-test-fixture"));
    // No `-fixture` suffix at all.
    assert!(!looks_like_public_evidence_identifier("AB7-foo-bar"));
}

#[test]
fn dotted_source_identifier_stays_case_insensitive_after_zero_alloc_rewrite() {
    // Receiver match (now eq_ignore_ascii_case, no to_ascii_lowercase alloc):
    // a known source receiver in ANY case suppresses.
    assert!(looks_like_dotted_source_identifier("this.apiToken"));
    assert!(looks_like_dotted_source_identifier("THIS.apiToken"));
    assert!(looks_like_dotted_source_identifier("Config.serviceKey"));
    assert!(looks_like_dotted_source_identifier("PROCESS.env"));

    // Non-receiver path: needs BOTH a camelCase segment AND a credential word
    // (now via ci_find, case-insensitive) — uppercase keyword still matches.
    assert!(looks_like_dotted_source_identifier("svc.getSecretKey"));
    assert!(looks_like_dotted_source_identifier("auth.parseTOKENvalue"));

    // Negatives unchanged: a 6th segment is out of the 2..=5 range; a dotted
    // value with a camel segment but NO credential word is not suppressed; an
    // empty segment is rejected.
    assert!(!looks_like_dotted_source_identifier("a.b.c.d.e.f"));
    assert!(!looks_like_dotted_source_identifier("foo.getUserName"));
    assert!(!looks_like_dotted_source_identifier("foo..bar"));
    // A real dotted token with non-identifier bytes is not a source identifier.
    assert!(!looks_like_dotted_source_identifier("sk-live.AbC+9/dEf"));
}

#[test]
fn tier_a_markers_are_syntactic_only() {
    // Grammar tokens that are never a credential body - suppressed for any
    // detector.
    assert!(looks_like_syntactic_punctuation_marker("--api-secret"));
    assert!(looks_like_syntactic_punctuation_marker("&password"));
    assert!(looks_like_syntactic_punctuation_marker("@api_key"));
    assert!(looks_like_syntactic_punctuation_marker("$API_KEY"));
    assert!(looks_like_syntactic_punctuation_marker("Password:"));
    // NOT markers: real credential bodies that merely start with a sigil
    // (tower's `@gAdtFo%B!...` has a non-identifier tail) or carry edge
    // punctuation handled by the Tier-B set.
    assert!(!looks_like_syntactic_punctuation_marker(
        "@gAdtFo%B!tcnSl+A"
    ));
    assert!(!looks_like_syntactic_punctuation_marker(
        "SnowFlakePass123!"
    ));
    assert!(!looks_like_syntactic_punctuation_marker("/7j3M6glXEI5gvG5"));
}

#[test]
fn tier_b_collision_keeps_real_bang_passwords() {
    // `/`-led base64 (paloalto/line) and `!`-led secrets (keystonejs) are
    // FP-shaped for unanchored generic matches. A trailing `!` is suppressed
    // only when it is a TS non-null source identifier.
    assert!(looks_like_credential_colliding_punctuation(
        "/7j3M6glXEI5gvG5"
    ));
    assert!(looks_like_credential_colliding_punctuation(
        "!t1c!_Axt_7ARTF"
    ));
    assert!(looks_like_credential_colliding_punctuation(
        "privateAccessToken!"
    ));
    // A password ending `!` is common; this is what lets snowflake/sourcetree
    // surface in a JSON envelope via the generic detector.
    assert!(!looks_like_credential_colliding_punctuation(
        "SnowFlakePass123!"
    ));
    assert!(!looks_like_credential_colliding_punctuation(
        "SourceTreePass1234!"
    ));
    // A plain token isn't decoration.
    assert!(!looks_like_credential_colliding_punctuation(
        "Vk9Bn3Lp7Qm2Rs5"
    ));
}

#[test]
fn anchored_password_ending_in_bang_is_not_suppressed_by_either_tier() {
    // The named-detector path applies only the Tier-A marker; the combined
    // (fallback) filter applies both. A real password ending `!` must pass
    // BOTH so snowflake.password=SnowFlakePass123! surfaces.
    let v = "SnowFlakePass123!";
    assert!(!looks_like_syntactic_punctuation_marker(v));
    assert!(!looks_like_credential_colliding_punctuation(v));
    assert!(!looks_like_punctuation_decorated_identifier(v));
}

#[test]
fn train_case_policy_prose_is_structural_even_when_bigrams_look_random() {
    for value in [
        "ConfigMap-values-carry-non-secret-Tier-A-runtime-knobs-only",
        "ConfigMapXYZ-values-carry-non-secret-runtime-knobs-only",
    ] {
        assert!(
            looks_like_train_case_prose_identifier(value),
            "connector-bearing policy prose must be suppressed before randomness scoring: {value}"
        );
    }
}

#[test]
fn entropy_value_reference_shapes_live_in_shape_owner() {
    assert!(looks_like_kebab_config_identifier("project-api-key"));
    assert!(!looks_like_kebab_config_identifier("AbC/+/base64-token"));
    assert!(looks_like_filename_reference("production.keystore"));
    assert!(looks_like_filename_reference("SERVICE.YAML"));
    assert!(!looks_like_filename_reference("not_a_file_reference"));
}

#[test]
fn generic_base64_policy_shapes_live_in_shape_owner() {
    let value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789++//ZZAB==";
    assert!(looks_like_generic_random_base64_blob_decoy(value, 4.7));
    assert!(!looks_like_generic_random_base64_blob_decoy(value, 4.8));
    assert!(!generic_base64_candidate_is_ambiguous(value, 4.7));
    assert!(generic_base64_candidate_is_ambiguous(value, 4.8));
}

#[test]
fn train_case_gate_requires_connector_bearing_prose() {
    for value in [
        "a8x-9fk-2qz-7mw-random-bytes",
        "Qxzvbnm-Kprtwyl-Jhgfdsaz-Mnbvcxzq",
    ] {
        assert!(
            !looks_like_train_case_prose_identifier(value),
            "hyphenated non-prose token must not trip the policy-prose gate: {value}"
        );
    }
}

#[test]
fn public_noncredential_shape_names_every_shared_public_gate() {
    for (value, reason) in [
        (
            "ConfigMap-values-carry-non-secret-Tier-A-runtime-knobs-only",
            "train_case_prose_identifier",
        ),
        (
            "vyre-runtime-release-policy:v2",
            "public_version_identifier",
        ),
        ("[sources.BLAKE3_SPEC]", "public_reference_selector"),
        (
            "official-author-documentation",
            "public_metadata_identifier",
        ),
        (
            "CWE_400_RESOURCE_CONSUMPTIONRFC_9457_PROBLEM_DETAILS",
            "public_evidence_identifier",
        ),
        (
            "docs/optimization/ROADMAP.mdPERF_ROADMAP_2026-05-01.md",
            "public_artifact_reference",
        ),
        (
            "publish-vyre-${VERSION}-weir-${BUILD}",
            "shell_template_value",
        ),
        (
            "%3Cimg%20src=x%20onerror=alert%281%29%3E",
            "percent_encoded_markup",
        ),
        ("onfocus=", "html_event_handler_fragment"),
    ] {
        assert_eq!(
            public_noncredential_shape_full(value),
            Some(reason),
            "public-shape owner must name {value}"
        );
    }
}

#[test]
fn weak_anchor_public_shape_scope_does_not_suppress_service_domains() {
    for value in [
        "dev12345.service-now.com",
        "my-project-12345.appspot.com",
        "54mjwwtk73-7zxl11dknajfhduuh2afa51xv6hqbd9rzkboo2a0tqfke6a9zxu7poeyzriabsbi3-qxkd2z00m2ynphds.workday.com",
    ] {
        assert_eq!(
            public_noncredential_shape_weak_anchor(value),
            None,
            "weak-anchor public shape scope must not suppress service domains: {value}"
        );
    }
    for (value, reason) in [
        (
            "vyre-runtime-release-policy:v2",
            "public_version_identifier",
        ),
        (
            "publish-vyre-${VERSION}-weir-${BUILD}",
            "shell_template_value",
        ),
        (
            "%3Cimg%20src=x%20onerror=alert%281%29%3E",
            "percent_encoded_markup",
        ),
    ] {
        assert_eq!(
            public_noncredential_shape_weak_anchor(value),
            Some(reason),
            "weak-anchor scope must still suppress confirmed public shapes: {value}"
        );
    }
}
