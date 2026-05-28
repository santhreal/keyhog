//! KH-GAP-142: Macro e2e binaries (`e2e_binary`, `break_it`, `live_verify`) sit outside `all_tests`.

#[test]
fn macro_e2e_targets_wired_in_all_tests_harness() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/all_tests.rs"),
    )
    .expect("all_tests.rs");
    for module in ["e2e_binary", "break_it", "live_verify"] {
        assert!(
            src.contains(module),
            "all_tests must declare `mod {module};` so macro e2e runs in the primary harness"
        );
    }
}
