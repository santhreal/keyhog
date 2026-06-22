//! LR2-A8 harness integration: a3 adversarial decode files are wired.

#[test]
fn a3_adversarial_decode_files_are_declared() {
    super::mod_wiring::assert_suite_sibling_files_are_wired("adversarial/a3_decode");
}
