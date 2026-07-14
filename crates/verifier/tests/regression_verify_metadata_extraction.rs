//! Coverage for the verifier's response-metadata extraction
//! (`verify::response::extract_metadata`) (previously UNTESTED live code).
//!
//! After a credential verifies Live, `extract_metadata` pulls operator-facing
//! metadata (account name, email, plan, …) out of the JSON response body via
//! each detector's `MetadataSpec`. `json_path` uses the detector TOML rooted
//! selector grammar. Only reviewed semantic roles and scalar values may enter
//! reports. Public values remain exact, hashed values cross as SHA-256, and
//! secret values do not cross the boundary.

use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, DedupedMatch, MatchLocation, MetadataSpec, ProviderEvidenceSensitivity,
    ReportFormat, SensitiveString, Severity, VerificationResult,
};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use sha2::{Digest, Sha256};

fn spec(name: &str, json_path: &str) -> MetadataSpec {
    MetadataSpec {
        name: name.to_string(),
        json_path: json_path.to_string(),
        sensitivity: ProviderEvidenceSensitivity::Public,
    }
}

fn classified_spec(
    name: &str,
    json_path: &str,
    sensitivity: ProviderEvidenceSensitivity,
) -> MetadataSpec {
    MetadataSpec {
        name: name.to_string(),
        json_path: json_path.to_string(),
        sensitivity,
    }
}

#[test]
fn extracts_a_present_nested_value() {
    let specs = [spec("account", "$.data.name")];
    let meta = TestApi
        .extract_metadata_for_test(&specs, r#"{"data":{"name":"acme-corp"}}"#)
        .expect("valid metadata response");
    assert_eq!(meta.get("account").map(String::as_str), Some("acme-corp"));
}

#[test]
fn missing_selector_yields_no_entry() {
    let specs = [spec("account", "$.data.name")];
    let metadata = TestApi
        .extract_metadata_for_test(&specs, r#"{"data":{"other":1}}"#)
        .expect("valid metadata response");
    assert!(metadata.is_empty());
}

#[test]
fn non_json_body_is_a_metadata_contract_error() {
    let specs = [spec("account", "$.data.name")];
    let error = TestApi
        .extract_metadata_for_test(&specs, "this is not json at all")
        .expect_err("metadata selectors require a JSON response");
    assert!(error.contains("metadata selector `$.data.name`"), "{error}");
}

#[test]
fn multiple_specs_each_extract_independently() {
    let specs = [spec("account", "$.name"), spec("email", "$.contact.email")];
    let meta = TestApi
        .extract_metadata_for_test(&specs, r#"{"name":"acme","contact":{"email":"a@b.co"}}"#)
        .expect("valid metadata response");
    assert_eq!(meta.get("account").map(String::as_str), Some("acme"));
    assert_eq!(meta.get("email").map(String::as_str), Some("a@b.co"));
    assert_eq!(meta.len(), 2);
}

#[test]
fn value_types_render_via_the_contract_string_mapping() {
    // String -> raw, Number -> decimal, Bool -> "true"/"false".
    let specs = [
        spec("plan", "$.plan"),
        spec("seats", "$.seats"),
        spec("active", "$.active"),
    ];
    let meta = TestApi
        .extract_metadata_for_test(&specs, r#"{"plan":"pro","seats":25,"active":true}"#)
        .expect("valid metadata response");
    assert_eq!(meta.get("plan").map(String::as_str), Some("pro"));
    assert_eq!(meta.get("seat_count").map(String::as_str), Some("25"));
    assert_eq!(meta.get("active").map(String::as_str), Some("true"));
}

#[test]
fn empty_specs_yield_empty_metadata_even_on_rich_json() {
    let meta = TestApi
        .extract_metadata_for_test(&[], r#"{"name":"acme","seats":25}"#)
        .expect("empty selector list needs no JSON contract");
    assert!(
        meta.is_empty(),
        "no specs => no metadata regardless of body"
    );
}

#[test]
fn root_selector_extracts_a_scalar_document() {
    let specs = [spec("account", "$")];
    let meta = TestApi
        .extract_metadata_for_test(&specs, r#""just-a-string""#)
        .expect("root selector");
    assert_eq!(
        meta.get("account").map(String::as_str),
        Some("just-a-string")
    );
}

#[test]
fn invalid_selector_is_not_reported_as_missing_metadata() {
    let specs = [spec("account", "/data/name")];
    let error = TestApi
        .extract_metadata_for_test(&specs, r#"{"data":{"name":"acme"}}"#)
        .expect_err("invalid selector must be explicit");
    assert!(error.contains("invalid response selector"), "{error}");
}

#[test]
fn unknown_semantic_role_fails_closed() {
    let specs = [spec("provider_dynamic_field", "$.value")];
    let error = TestApi
        .extract_metadata_for_test(&specs, r#"{"value":"visible"}"#)
        .expect_err("unreviewed report key must be rejected");
    assert!(
        error.contains("not a supported provider evidence role"),
        "{error}"
    );
    assert!(
        !error.contains("visible"),
        "errors must not echo response values"
    );
}

#[test]
fn duplicate_canonical_role_fails_even_when_response_fields_are_missing() {
    let specs = [
        spec("account_id", "$.current"),
        spec("accountID", "$.legacy"),
    ];
    let error = TestApi
        .extract_metadata_for_test(&specs, r#"{"other":"value"}"#)
        .expect_err("duplicate canonical role must not depend on response shape");
    assert!(error.contains("repeats provider evidence role \"account_id\""));
    assert!(!error.contains("value"));
}

#[test]
fn composite_public_value_fails_without_echoing_nested_secrets() {
    const NESTED_SECRET: &str = "provider-secret-must-not-report";
    let specs = [spec("data", "$.data")];
    let body = format!(r#"{{"data":{{"access_token":"{NESTED_SECRET}","new_key":1}}}}"#);
    let error = TestApi
        .extract_metadata_for_test(&specs, &body)
        .expect_err("provider objects must not become report metadata");
    assert!(error.contains("selected a JSON object"), "{error}");
    assert!(
        !error.contains(NESTED_SECRET),
        "errors must not echo provider data"
    );
    assert!(
        !error.contains("new_key"),
        "response keys must not become schema"
    );
}

#[test]
fn composite_hashed_value_preserves_safe_evidence() {
    let specs = [classified_spec(
        "data",
        "$.data",
        ProviderEvidenceSensitivity::Hashed,
    )];
    let metadata = TestApi
        .extract_metadata_for_test(
            &specs,
            r#"{"data":{"account":"acct-123","scopes":["read","write"]}}"#,
        )
        .expect("structured hashed evidence remains supported");
    let expected = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            br#"{"account":"acct-123","scopes":["read","write"]}"#
        ))
    );
    assert_eq!(metadata.get("data"), Some(&expected));
    assert!(!metadata.values().any(|value| value.contains("acct-123")));
}

#[test]
fn public_hashed_and_secret_fields_serialize_through_the_report_boundary() {
    const RAW_SECRET: &str = "provider-token-value-never-report";
    let specs = [
        classified_spec("email", "$.email", ProviderEvidenceSensitivity::Public),
        classified_spec(
            "accountID",
            "$.account_id",
            ProviderEvidenceSensitivity::Hashed,
        ),
        classified_spec(
            "login",
            "$.access_token",
            ProviderEvidenceSensitivity::Secret,
        ),
        classified_spec(
            "scope",
            "$.credential_echo",
            ProviderEvidenceSensitivity::Public,
        ),
    ];
    let body = format!(
        r#"{{"email":"operator@example.test","account_id":"acct-123","access_token":"{RAW_SECRET}","credential_echo":"prefix-fixture-credential-suffix","provider_added":"unreviewed"}}"#
    );
    let metadata = TestApi
        .extract_metadata_for_test(&specs, &body)
        .expect("classified scalar evidence");
    let expected_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"acct-123")));
    assert_eq!(
        metadata,
        HashMap::from([
            ("email".to_string(), "operator@example.test".to_string()),
            ("account_id".to_string(), expected_hash.clone()),
            (
                "scope".to_string(),
                "prefix-fixture-credential-suffix".to_string(),
            ),
        ])
    );

    let finding = TestApi.build_finding(report_group(), VerificationResult::Live, metadata);
    let reports = [
        render(ReportFormat::Json, &finding),
        render(
            ReportFormat::Sarif {
                skip_summary: Vec::new(),
            },
            &finding,
        ),
        render(
            ReportFormat::Html {
                skip_summary: Vec::new(),
                metadata: None,
            },
            &finding,
        ),
        render(
            ReportFormat::Text {
                color: false,
                example_suppressions: 0,
                dogfood_active: false,
            },
            &finding,
        ),
    ];
    for report in reports {
        assert!(report.contains("operator@example.test"));
        assert!(report.contains(&expected_hash));
        assert!(!report.contains(RAW_SECRET));
        assert!(!report.contains("access_token"));
        assert!(!report.contains("provider_added"));
        assert!(!report.contains("unreviewed"));
        assert!(!report.contains("prefix-fixture-credential-suffix"));
    }

    let csv = render(ReportFormat::Csv, &finding);
    assert!(!csv.contains(RAW_SECRET));
    assert!(!csv.contains("access_token"));
    assert!(!csv.contains("provider_added"));
    assert!(!csv.contains("unreviewed"));
    assert!(!csv.contains("prefix-fixture-credential-suffix"));
}

#[test]
fn unclassified_legacy_field_defaults_to_hashed() {
    let specs = [MetadataSpec {
        name: "account_id".to_string(),
        json_path: "$.account_id".to_string(),
        sensitivity: Default::default(),
    }];
    let metadata = TestApi
        .extract_metadata_for_test(&specs, r#"{"account_id":"legacy-account"}"#)
        .expect("legacy metadata remains usable without plaintext exposure");
    let expected = format!("sha256:{}", hex::encode(Sha256::digest(b"legacy-account")));
    assert_eq!(metadata.get("account_id"), Some(&expected));
    assert!(!metadata.values().any(|value| value == "legacy-account"));
}

#[test]
fn detector_toml_sensitivity_is_typed_and_rejects_typos() {
    for (wire, expected) in [
        ("public", ProviderEvidenceSensitivity::Public),
        ("hashed", ProviderEvidenceSensitivity::Hashed),
        ("secret", ProviderEvidenceSensitivity::Secret),
    ] {
        let spec: MetadataSpec = toml::from_str(&format!(
            "name = \"account_id\"\njson_path = \"$.account.id\"\nsensitivity = \"{wire}\""
        ))
        .expect("supported sensitivity parses");
        assert_eq!(spec.sensitivity, expected);
    }

    let error = toml::from_str::<MetadataSpec>(
        "name = \"account_id\"\njson_path = \"$.account.id\"\nsensitivity = \"plaintext\"",
    )
    .expect_err("unknown sensitivity must fail detector parsing");
    assert!(error.to_string().contains("unknown variant `plaintext`"));
}

fn render(format: ReportFormat, finding: &keyhog_core::VerifiedFinding) -> String {
    let mut output = Vec::new();
    write_report(&mut output, format, std::slice::from_ref(finding)).expect("report renders");
    String::from_utf8(output).expect("report is UTF-8")
}

fn report_group() -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from("evidence-boundary"),
        detector_name: Arc::from("Evidence boundary"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: SensitiveString::from("fixture-credential"),
        credential_hash: [7u8; 32].into(),
        primary_location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("fixture.env")),
            line: Some(4),
            offset: 12,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        companions: HashMap::new(),
        confidence: Some(1.0),
    }
}
