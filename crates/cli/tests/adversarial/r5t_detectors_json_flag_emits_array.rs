//! R5-T adversarial non-scan: detectors --json emits JSON array.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_detectors_json_flag_emits_array() {
    let output = Command::new(binary())
        .args(["detectors", "--json"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("detectors --json");
    let arr = parsed
        .as_array()
        .expect("detectors --json must be a JSON array");

    // Truth, not shape: the array length must equal the live embedded detector
    // count the binary itself reports — the two surfaces (`--json` array and
    // `embedded_detector_count`) must agree exactly, never just "non-empty".
    let expected = keyhog_core::embedded_detector_count();
    assert!(expected > 0, "embedded_detector_count() returned 0");
    assert_eq!(
        arr.len(),
        expected,
        "`detectors --json` emitted {} entries but the binary embeds {expected} detectors; \
         the JSON listing and the embedded corpus disagree.",
        arr.len()
    );

    // Each element must carry the documented object shape (args.rs `--json`
    // contract: id/name/service/severity/keywords/patterns/companions/verify).
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
    ] {
        assert!(
            first.get(field).is_some(),
            "`detectors --json` element is missing the documented `{field}` field: {first}"
        );
    }
    assert!(
        first["id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "`detectors --json` element `id` must be a non-empty string: {first}"
    );
    assert!(
        first["verify"].is_boolean(),
        "`detectors --json` element `verify` must be a boolean per the documented shape: {first}"
    );
}
