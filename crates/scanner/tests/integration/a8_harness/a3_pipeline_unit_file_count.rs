//! LR2-A8 harness integration: a3_pipeline unit slice preserved

#[test]
fn a3_pipeline_unit_files_are_declared() {
    super::mod_wiring::assert_suite_sibling_files_are_wired("unit/a3_pipeline");
}
