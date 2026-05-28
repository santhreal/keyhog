//! KH-GAP-122: R3.2-SCAN migrated 12 inline test bodies to
//! `tests/unit/inline_migrated/` but never wired the module into `tests/unit/mod.rs`.

use std::path::PathBuf;

#[test]
fn inline_migrated_module_registered_in_unit_harness() {
    let unit_mod = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/unit/mod.rs");
    let content = std::fs::read_to_string(&unit_mod).expect("unit/mod.rs readable");
    assert!(
        content.contains("inline_migrated"),
        "KH-GAP-122: tests/unit/inline_migrated/ exists (12 modules) but is not \
         `pub mod inline_migrated` in tests/unit/mod.rs — migrated bodies are dead"
    );
}
