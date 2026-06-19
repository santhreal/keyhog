//! LR2-A8 harness integration: gate/ wired in scanner library tests.

#[test]
fn all_tests_source_declares_gate() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("lib.rs");
    assert!(
        src.contains("#[path = \"../tests/gate/mod.rs\"]"),
        "scanner library test harness must export gate module"
    );
}
