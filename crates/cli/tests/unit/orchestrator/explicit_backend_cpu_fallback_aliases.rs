use keyhog::testing::{CliTestApi as _, API};

fn supported_values_message(error: &anyhow::Error) -> bool {
    let supported = keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES.join(", ");
    error
        .to_string()
        .contains(&format!("Supported values: {supported}"))
}

#[test]
fn retired_scalar_backend_alias_is_rejected() {
    let error = API
        .explicit_backend_override(Some("scalar"))
        .expect_err("the retired scalar alias must not bypass the canonical CLI value set");
    assert!(
        supported_values_message(&error),
        "the rejection must name the canonical replacements; got {error}"
    );
}
