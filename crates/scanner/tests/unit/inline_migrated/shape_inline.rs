//! Migrated from suppression::shape module-root tests (KH-GAP-004).

use keyhog_scanner::testing::shape::{
    generic_base64_candidate_is_ambiguous, looks_like_credential_colliding_punctuation,
    looks_like_filename_reference, looks_like_generic_random_base64_blob_decoy,
    looks_like_kebab_config_identifier, looks_like_punctuation_decorated_identifier,
    looks_like_syntactic_punctuation_marker, looks_like_train_case_prose_identifier,
    public_noncredential_shape_full, public_noncredential_shape_weak_anchor,
};

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
