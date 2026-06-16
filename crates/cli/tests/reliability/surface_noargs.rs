//! Invariant: every non-blocking subcommand, invoked with NO arguments,
//! terminates cleanly with a documented exit code and no panic, under every
//! profile. (scan/scan-system/watch/daemon are excluded here: with no args
//! they would scan the cwd or run forever; their no-arg behavior is covered by
//! dedicated tests with bounded inputs.)
//!
//! This is the "does the command even start on a weird box" sweep. 11 × 16 =
//! 176 distinct tests.

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
    explain => "explain",
    diff => "diff",
    calibrate => "calibrate",
    completion => "completion",
    backend => "backend",
    doctor => "doctor",
    update => "update",
    repair => "repair",
    uninstall => "uninstall",
    hook => "hook",
);
