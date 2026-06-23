//! Gate SARIF type/model cleanup: no stringly result levels or logical-location kinds.

#[test]
fn report_sarif_uses_typed_enums_and_split_result_builders() {
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
        "enum SarifLevel",
        "enum SarifLogicalLocationKind",
        "pub(super) level: SarifLevel",
        "pub(super) kind: SarifLogicalLocationKind",
    ] {
        assert!(
            types_prod.contains(required),
            "missing typed SARIF enum contract: {required}"
        );
    }

    for required in [
        "fn related_locations(finding: &VerifiedFinding) -> Vec<SarifLocation>",
        "fn result_properties(finding: &VerifiedFinding) -> SarifResultProperties",
        "fn result_fixes(finding: &VerifiedFinding) -> Option<Vec<SarifFix>>",
    ] {
        assert!(
            reporter_prod.contains(required),
            "build_sarif_result must delegate to {required}"
        );
    }

    for forbidden in [
        "level: Self::severity_to_level(finding.severity).to_string()",
        "kind: \"commit\".to_string()",
        "kind: \"author\".to_string()",
        "kind: \"date\".to_string()",
    ] {
        assert!(
            !reporter_prod.contains(forbidden),
            "SARIF reporter regressed to stringly serialization: {forbidden}"
        );
    }
}
