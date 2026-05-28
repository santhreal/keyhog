//! KH-GAP-140: CLI ships empty `property/` and `concurrent/` mods — STANDARD categories 3/5 missing.

use std::path::PathBuf;

#[test]
fn property_and_concurrent_categories_have_tests() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    for category in ["property", "concurrent"] {
        let mod_rs = base.join(category).join("mod.rs");
        let src = std::fs::read_to_string(&mod_rs).unwrap_or_default();
        let has_test_files = std::fs::read_dir(base.join(category))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .any(|e| e.path().extension().is_some_and(|x| x == "rs") && e.file_name() != "mod.rs")
            })
            .unwrap_or(false);
        assert!(
            has_test_files || src.contains("pub mod"),
            "tests/{category}/ must ship at least one test module per STANDARD Test Contract"
        );
    }
}
