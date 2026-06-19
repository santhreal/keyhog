use std::fs;
use std::path::PathBuf;

#[test]
fn all_tests_wires_a3_pipeline_unit() {
    let lib_rs =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let unit_mod =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/unit/mod.rs"))
            .unwrap();
    assert!(lib_rs.contains("#[path = \"../tests/unit/mod.rs\"]"));
    assert!(unit_mod.contains("a3_pipeline"));
}
