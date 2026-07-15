use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::ScanBackend;

fn supported_values_message(error: &anyhow::Error) -> bool {
    let supported = keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES.join(", ");
    error
        .to_string()
        .contains(&format!("Supported values: {supported}"))
}

#[test]
fn explicit_backend_simd_uses_the_canonical_cli_value() {
    assert_eq!(
        API.explicit_backend_override(Some("simd")).unwrap(),
        Some(ScanBackend::SimdCpu)
    );
}

#[test]
fn retired_hyperscan_label_is_rejected_in_the_public_cli() {
    let error = API
        .explicit_backend_override(Some("hyperscan"))
        .expect_err("internal Hyperscan label must not remain a silent CLI shim");
    assert!(
        supported_values_message(&error),
        "the rejection must name the canonical replacements; got {error}"
    );
}
