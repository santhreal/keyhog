//! LR2-A8 harness integration: scanner test files are reachable.

#[test]
fn every_scanner_test_module_file_is_wired() {
    super::mod_wiring::assert_all_scanner_test_module_files_are_wired();
}
