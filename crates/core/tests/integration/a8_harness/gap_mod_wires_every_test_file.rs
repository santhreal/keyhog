//! LR2-A8 harness integration: the core `gap/` suite must register every test
//! file in its `mod.rs`, so no gap oracle sits on disk un-compiled.
//!
//! Replaces the brittle `gap_mod_has_ten_modules` count gate, which asserted a
//! hardcoded count of `pub mod` lines: it broke whenever a module was added and
//! tolerated orphan files whenever the count still matched.

#[test]
fn gap_mod_registers_every_test_file() {
    super::mod_wiring::assert_suite_fully_wired("gap");
}
