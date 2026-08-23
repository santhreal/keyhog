//! Invariant: every non-blocking subcommand, invoked with NO arguments,
//! terminates cleanly with a documented exit code and no panic, under every
//! profile. Scan, scan-system, watch, and daemon would scan or run indefinitely.
//! Install compiles and publishes a real execution generation into the host
//! cache. Dedicated bounded tests cover those commands.
//!
//! This is the "does the command even start on a weird box" sweep. 13 x 16 =
//! 208 distinct tests.

use crate::reliability::harness::{
    assert_clean_exit, assert_documented_exit, assert_no_ansi, assert_no_panic, run, Profile,
};

pub fn noargs_invariant(profile: Profile, sub: &str) {
    let o = run(profile, &[sub]);
    assert_clean_exit(&o);
    assert_no_panic(&o);
    assert_documented_exit(&o);
    if !profile.forces_color() {
        assert_no_ansi(&o);
    }
}

crate::kh_matrix!(
    crate::reliability::surface_noargs::noargs_invariant,
    detectors => "detectors",
    action_report => "action-report",
    explain => "explain",
    diff => "diff",
    calibrate => "calibrate",
    config => "config",
    completion => "completion",
    backend => "backend",
    doctor => "doctor",
    bloom_diagnostic => "bloom-diagnostic",
    uninstall => "uninstall",
    hook => "hook",
    compile_execution_packs => "compile-execution-packs",
);
