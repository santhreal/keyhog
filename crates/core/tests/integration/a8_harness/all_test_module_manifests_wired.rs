//! Core test tree wiring guard.
//!
//! Cargo does not auto-discover files below `tests/<dir>/`; a sibling `.rs`
//! file or nested module directory only compiles when the parent manifest
//! declares it. This keeps core unit/adversarial/property shards from becoming
//! invisible coverage while `all_tests` still passes.

#[test]
fn all_core_test_module_manifests_are_wired() {
    super::mod_wiring::assert_all_test_module_manifests_wired();
}
