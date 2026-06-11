//! LR2-A8 harness integration: the core `contract/` suite must register every
//! test file in its `mod.rs`, so no SARIF/JSON contract test sits on disk
//! un-compiled.
//!
//! Replaces the brittle `contract_mod_has_ten_modules` count gate, which was
//! itself never wired into the harness (so it never ran), was misnamed (file
//! `contract_mod_eight_entries`, function `..._has_ten_modules`), and asserted a
//! hardcoded count that no longer matched the suite.

#[test]
fn contract_mod_registers_every_test_file() {
    super::mod_wiring::assert_suite_fully_wired("contract");
}
