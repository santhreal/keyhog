use std::fs;
use std::path::PathBuf;

#[test]
fn mod_rs_reexports_scan_loop_and_postprocess() {
    let mod_rs =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/pipeline/mod.rs"))
            .unwrap();
    assert!(mod_rs.contains("context_window"));
    assert!(mod_rs.contains("scan_loop"));
    assert!(mod_rs.contains("postprocess"));
    assert!(mod_rs.contains("should_suppress_known_example_credential"));
    assert!(mod_rs.contains("is_within_hex_context"));
}
