//! R2-M8 harness integration: core contract wiring count gate.

#[test]
fn contract_mod_has_ten_modules() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/contract/mod.rs"),
    )
    .expect("contract/mod.rs");
    assert_eq!(
        src.matches("mod ").count(),
        10,
        "contract/mod.rs must declare one mod per contract test file"
    );
}
