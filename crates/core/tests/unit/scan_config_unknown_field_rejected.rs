//! Law 10: a typo'd or misplaced field in a user-authored `[scan]` config
//! must fail closed instead of being silently ignored.

use keyhog_core::ScanConfig;

#[test]
fn scan_config_rejects_unknown_field() {
    let toml = r#"
min_confidence = 0.5
not_a_scan_field = 42
"#;
    let err = toml::from_str::<ScanConfig>(toml).expect_err("must reject unknown field");
    let msg = format!("{err}");
    assert!(
        msg.contains("not_a_scan_field") || msg.contains("unknown"),
        "expected error to name the unknown field; got: {msg}"
    );
}
