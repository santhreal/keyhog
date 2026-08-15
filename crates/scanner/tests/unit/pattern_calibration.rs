use serde_json::{json, Value};

fn artifact() -> Value {
    json!({
        "schema_version": 1,
        "identity_schema": "detector-corpus-v1:detector-id:pattern-index:candidate-channel:source-role:context-class",
        "model_version": crate::ml_scorer::model_version(),
        "detector_digest": "0123456789abcdef",
        "floors": {
            "blocking_score": 0.4,
            "minimum_positive_support": 2,
            "minimum_negative_support": 2,
            "minimum_recall": 1.0,
            "maximum_brier_score": 0.25,
            "maximum_ece": 0.1
        },
        "entries": [{
            "detector_id": "fixture-detector",
            "pattern_index": 3,
            "candidate_channel": "pattern",
            "source_role": "structured-assignment-value",
            "context_class": "vendor-pattern",
            "metrics": {
                "f1": 1.0,
                "precision": 1.0,
                "recall": 1.0,
                "recall_at_blocking_floor": 1.0,
                "brier_score": 0.02,
                "ece": 0.01,
                "positive_support": 4,
                "negative_support": 4
            }
        }]
    })
}

fn evaluate(
    value: &Value,
    digest: u64,
    pattern: u32,
    role: &str,
    context: &str,
) -> Result<bool, String> {
    crate::testing::pattern_calibration_key_for_test(
        &serde_json::to_string(value).expect("serialize test artifact"),
        digest,
        "fixture-detector",
        pattern,
        "pattern",
        role,
        context,
    )
}

#[test]
fn exact_supported_key_allows_lowering_and_every_identity_component_is_required() {
    let value = artifact();
    assert!(evaluate(
        &value,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .expect("valid artifact"));
    assert!(!crate::testing::pattern_calibration_key_for_test(
        &serde_json::to_string(&value).expect("serialize test artifact"),
        0x0123_4567_89ab_cdef,
        "fixture-detector",
        3,
        "entropy",
        "structured-assignment-value",
        "vendor-pattern",
    )
    .expect("valid artifact"));
    assert!(!crate::testing::pattern_calibration_key_for_test(
        &serde_json::to_string(&value).expect("serialize test artifact"),
        0x0123_4567_89ab_cdef,
        "other-detector",
        3,
        "pattern",
        "structured-assignment-value",
        "vendor-pattern",
    )
    .expect("valid artifact"));
    assert!(crate::testing::pattern_calibration_key_for_test(
        &serde_json::to_string(&value).expect("serialize test artifact"),
        0x0123_4567_89ab_cdef,
        "fixture-detector:reassembled",
        3,
        "pattern",
        "structured-assignment-value",
        "vendor-pattern",
    )
    .expect("runtime-owned reassembly suffix resolves to its detector owner"));
    assert!(!crate::testing::pattern_calibration_key_for_test(
        &serde_json::to_string(&value).expect("serialize test artifact"),
        0x0123_4567_89ab_cdef,
        "fixture-detector:other",
        3,
        "pattern",
        "structured-assignment-value",
        "vendor-pattern",
    )
    .expect("unsupported synthetic suffix abstains"));

    for (digest, pattern, role, context) in [
        (
            0x1123_4567_89ab_cdef,
            3,
            "structured-assignment-value",
            "vendor-pattern",
        ),
        (
            0x0123_4567_89ab_cdef,
            4,
            "structured-assignment-value",
            "vendor-pattern",
        ),
        (0x0123_4567_89ab_cdef, 3, "string-literal", "vendor-pattern"),
        (
            0x0123_4567_89ab_cdef,
            3,
            "structured-assignment-value",
            "test-fixture",
        ),
    ] {
        assert!(!evaluate(&value, digest, pattern, role, context).expect("valid artifact"));
    }
}

#[test]
fn missing_class_support_recall_brier_and_ece_each_abstain() {
    for (field, replacement) in [
        ("positive_support", json!(0)),
        ("negative_support", json!(0)),
        ("recall", json!(0.75)),
        ("recall_at_blocking_floor", json!(0.75)),
        ("brier_score", json!(0.251)),
        ("ece", json!(0.101)),
    ] {
        let mut value = artifact();
        value["entries"][0]["metrics"][field] = replacement;
        assert!(
            !evaluate(
                &value,
                0x0123_4567_89ab_cdef,
                3,
                "structured-assignment-value",
                "vendor-pattern"
            )
            .expect("valid but unsupported metrics"),
            "{field} must independently block lowering"
        );
    }
}

#[test]
fn stale_or_ambiguous_artifacts_fail_closed() {
    let mut stale_schema = artifact();
    stale_schema["schema_version"] = json!(2);
    assert!(evaluate(
        &stale_schema,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());

    let mut stale_model = artifact();
    stale_model["model_version"] = json!("moe-v0-stale");
    assert!(evaluate(
        &stale_model,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());

    let mut stale_but_well_formed_model = artifact();
    stale_but_well_formed_model["model_version"] = json!("moe-v1-0000000000000000");
    assert!(!evaluate(
        &stale_but_well_formed_model,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .expect("well-formed stale model abstains"));

    let mut stale_identity = artifact();
    stale_identity["identity_schema"] = json!("detector-corpus-v0");
    assert!(evaluate(
        &stale_identity,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());

    for invalid_context in ["unattributed", "live-verification"] {
        let mut invalid_scanner_context = artifact();
        invalid_scanner_context["entries"][0]["context_class"] = json!(invalid_context);
        assert!(evaluate(
            &invalid_scanner_context,
            0x0123_4567_89ab_cdef,
            3,
            "structured-assignment-value",
            invalid_context
        )
        .is_err());
    }

    let mut duplicate = artifact();
    let repeated = duplicate["entries"][0].clone();
    duplicate["entries"]
        .as_array_mut()
        .expect("entry array")
        .push(repeated);
    assert!(evaluate(
        &duplicate,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());
}

#[test]
fn serving_parser_rejects_oversized_and_empty_attributed_artifacts() {
    let mut oversized = artifact();
    let entry = oversized["entries"][0].clone();
    oversized["entries"] = Value::Array(vec![
        entry;
        crate::pattern_calibration_contract::MAX_ENTRIES + 1
    ]);
    assert!(evaluate(
        &oversized,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());

    let mut empty_attributed = artifact();
    empty_attributed["entries"] = json!([]);
    assert!(evaluate(
        &empty_attributed,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());

    let mut missing_digest = artifact();
    missing_digest["entries"] = json!([]);
    missing_digest
        .as_object_mut()
        .expect("artifact object")
        .remove("detector_digest");
    assert!(evaluate(
        &missing_digest,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());

    let mut populated_without_digest = artifact();
    populated_without_digest["detector_digest"] = Value::Null;
    assert!(evaluate(
        &populated_without_digest,
        0x0123_4567_89ab_cdef,
        3,
        "structured-assignment-value",
        "vendor-pattern"
    )
    .is_err());
}

/// WHY: the build script hashes exact calibration bytes. Windows checkout
/// conversion must not turn an LF-authored artifact into CRLF and invalidate
/// the model-card receipt before compilation begins.
#[test]
fn calibration_identity_artifacts_have_lf_checkout_policy() {
    let attributes = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.gitattributes"));
    for path in [
        "crates/scanner/src/model_card.json",
        "crates/scanner/src/pattern_calibration.json",
    ] {
        assert!(
            attributes
                .lines()
                .any(|line| line == format!("{path} text eol=lf")),
            "{path} must remain byte-identical across Windows and Unix checkouts"
        );
    }
}
