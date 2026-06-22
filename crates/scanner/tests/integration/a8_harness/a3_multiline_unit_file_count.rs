//! LR2-A8 harness integration: a3_multiline unit files are wired.

#[test]
fn a3_multiline_unit_files_are_declared() {
    super::mod_wiring::assert_suite_sibling_files_are_wired("unit/a3_multiline");
}
