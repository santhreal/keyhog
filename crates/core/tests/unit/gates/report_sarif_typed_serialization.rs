//! Gate SARIF reporter serialization: typed properties and notifications on the hot path.

#[test]
fn report_sarif_uses_typed_properties_and_notifications() {
    let reporter_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/sarif.rs");
    let types_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/sarif_types.rs");
    let reporter = std::fs::read_to_string(reporter_path).expect("SARIF reporter source readable");
    let types = std::fs::read_to_string(types_path).expect("SARIF types source readable");
    let reporter_prod = reporter
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let types_prod = types
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for required in [
        "struct SarifResultProperties",
        "struct SarifRuleProperties",
        "struct SarifInvocation",
        "struct SarifNotification",
    ] {
        assert!(
            types_prod.contains(required),
            "missing typed SARIF owner: {required}"
        );
    }

    assert!(
        !types_prod.contains("serde_json::Map<String, serde_json::Value>"),
        "SARIF result/rule properties must not be dynamic serde_json maps"
    );
    assert!(
        !reporter_prod.contains("serde_json::Map")
            && !reporter_prod.contains("serde_json::Value")
            && !reporter_prod.contains("serde_json::json!"),
        "SARIF reporter must populate typed structs instead of dynamic serde_json values"
    );
}
