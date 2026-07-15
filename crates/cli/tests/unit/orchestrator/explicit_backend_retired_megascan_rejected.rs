use keyhog::testing::{CliTestApi as _, API};

fn supported_values_message(error: &anyhow::Error) -> bool {
    let supported = keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES.join(", ");
    error
        .to_string()
        .contains(&format!("Supported values: {supported}"))
}

#[test]
fn explicit_backend_retired_megascan_names_are_rejected() {
    for retired in ["mega-scan", "megascan", "gpu-mega-scan", "rule-pipeline"] {
        let error = API
            .explicit_backend_override(Some(retired))
            .expect_err("retired backend spelling must fail instead of selecting auto");
        assert!(
            supported_values_message(&error),
            "retired backend spelling {retired:?} must name the canonical choices: {error}"
        );
    }
}
