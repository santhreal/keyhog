//! LR2-A8 harness integration: core gap wiring complete

#[test]
fn gap_mod_has_ten_modules() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gap/mod.rs"),
    ).expect("gap/mod.rs");
    assert_eq!(src.matches("pub mod ").count(), 10);
}
