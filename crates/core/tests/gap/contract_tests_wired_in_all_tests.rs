//! SARIF/JSON contract tests must be reachable from the `all_tests` harness.
//! Orphan contract modules give a false green matrix while reporters drift.

#[test]
fn contract_module_is_wired_in_all_tests() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/all_tests.rs"))
        .expect("all_tests.rs");

    assert!(
        src.contains("pub mod contract"),
        "all_tests.rs must declare `pub mod contract;` so SARIF/JSON contract tests run in CI"
    );
}
