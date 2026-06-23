#[test]
fn auto_fix_remediation_uses_canonical_severity_label() {
    let action = keyhog_core::testing::CoreTestApi::remediation_action_for(
        &keyhog_core::testing::TestApi,
        "unknown-detector",
        "unknown-service",
        keyhog_core::Severity::ClientSafe,
    );

    assert!(
        action.contains("Public by design"),
        "client-safe remediation must be found through Severity::as_str(), got {action:?}"
    );
}
