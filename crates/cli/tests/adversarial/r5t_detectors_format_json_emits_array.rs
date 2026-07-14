//! R5-T adversarial non-scan: canonical detector JSON exposes the live corpus
//! and detector-owned policy.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_detectors_format_json_emits_corpus_and_policy() {
    let output = Command::new(binary())
        .args(["detectors", "--format", "json"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("detectors --format json");
    let arr = parsed
        .as_array()
        .expect("detectors --format json must be a JSON array");

    // Truth, not shape: the array length must equal the live embedded detector
    // count the binary itself reports, the two surfaces (JSON array and
    // `embedded_detector_count`) must agree exactly, never just "non-empty".
    let expected = keyhog_core::embedded_detector_count();
    assert!(expected > 0, "embedded_detector_count() returned 0");
    assert_eq!(
        arr.len(),
        expected,
        "`detectors --format json` emitted {} entries but the binary embeds {expected} detectors; \
         the JSON listing and the embedded corpus disagree.",
        arr.len()
    );

    // Each element carries identity, patterns, verification, and its
    // detector-local policy.
    let first = &arr[0];
    for field in [
        "id",
        "name",
        "service",
        "severity",
        "keywords",
        "patterns",
        "companions",
        "verify",
        "verification",
        "test_contracts",
        "policy",
    ] {
        assert!(
            first.get(field).is_some(),
            "`detectors --format json` element is missing the documented `{field}` field: {first}"
        );
    }
    assert!(
        first["id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "`detectors --format json` element `id` must be a non-empty string: {first}"
    );
    assert!(
        first["verify"].is_boolean(),
        "`detectors --format json` element `verify` must be a boolean per the documented shape: {first}"
    );

    let aws = arr
        .iter()
        .find(|detector| detector["id"] == "aws-access-key")
        .expect("aws-access-key declaration in detector listing");
    assert_eq!(
        aws["simdsieve_prefixes"],
        serde_json::json!(["AKIA", "ASIA"]),
        "detector JSON must expose detector-owned accelerator prefixes"
    );
    assert_eq!(
        aws["verification"]["allowed_domains"],
        serde_json::json!(["sts.amazonaws.com"]),
        "detector JSON must expose the declared verification policy"
    );
    assert_eq!(
        aws["test_contracts"],
        serde_json::json!([{"positive": true, "negative": true}]),
        "detector JSON must expose test coverage without fixture bytes"
    );
    assert!(
        !serde_json::to_string(&aws["test_contracts"])
            .expect("test contract summary serializes")
            .contains("AKIAQYLPMN5HFIQR7XYA"),
        "detector introspection must not expose fixture credentials"
    );

    let password = arr
        .iter()
        .find(|detector| detector["id"] == "generic-password")
        .expect("generic-password policy in detector listing");
    assert_eq!(
        password["policy"]["bpe_enabled"], false,
        "generic-password must expose detector-owned BPE disablement"
    );
    assert!(
        password["policy"]["bpe_max_bytes_per_token"].is_null(),
        "disabled BPE policy must not retain a magic ceiling: {password}"
    );

    let generic_secret = arr
        .iter()
        .find(|detector| detector["id"] == "generic-secret")
        .expect("generic-secret policy in detector listing");
    assert_eq!(
        generic_secret["policy"]["max_len"], 512,
        "detector JSON must expose the generic bridge ceiling from its owning TOML"
    );

    let generic_api_key = arr
        .iter()
        .find(|detector| detector["id"] == "generic-api-key")
        .expect("generic-api-key policy in detector listing");
    assert_eq!(
        generic_api_key["policy"]["decoded_hex_key_material_lengths"],
        serde_json::json!([32, 48]),
        "detector JSON must expose transport-decoded widths from detector TOML"
    );
    assert_eq!(
        generic_api_key["policy"]["entropy_policy_priority"], 80,
        "detector JSON must expose overlapping keyword policy ownership"
    );
    assert_eq!(
        generic_api_key["policy"]["canonical_hex_key_material"][1]["lengths"],
        serde_json::json!([64]),
        "detector JSON must expose direct canonical-hex policy"
    );
}
