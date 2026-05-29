//! Invariant: a real, valid invocation of each quick subcommand succeeds (or
//! returns a documented code) and stays clean under every hostile profile.
//! This exercises the actual happy path - version, completions, detector list,
//! backend probe, doctor - on a weird box, where many tools quietly misbehave.
//!
//! 12 invocations × 16 profiles = 192 distinct tests.

use crate::reliability::harness::{
    assert_clean_exit, assert_documented_exit, assert_no_ansi, assert_no_panic, run, Profile,
};

pub fn valid_invocation(profile: Profile, args: &[&str]) {
    let o = run(profile, args);
    assert_clean_exit(&o);
    assert_no_panic(&o);
    assert_documented_exit(&o);
    if !profile.forces_color() {
        assert_no_ansi(&o);
    }
    // A successful informational command must actually emit something; total
    // silence on success is itself a UX defect (looks like a hang/no-op).
    if o.code == Some(0) {
        assert!(
            !o.stdout.trim().is_empty() || !o.stderr.trim().is_empty(),
            "{}: exited 0 but produced no output at all",
            o.what
        );
    }
}

crate::kh_matrix!(
    crate::reliability::surface_valid::valid_invocation,
    version_short => &["-V"][..],
    version_long => &["--version"][..],
    completion_bash => &["completion", "bash"][..],
    completion_zsh => &["completion", "zsh"][..],
    completion_fish => &["completion", "fish"][..],
    completion_pwsh => &["completion", "powershell"][..],
    completion_elvish => &["completion", "elvish"][..],
    detectors_list => &["detectors"][..],
    backend_probe => &["backend"][..],
    doctor_health => &["doctor"][..],
    uninstall_dryrun => &["uninstall"][..],
    calibrate_show => &["calibrate"][..],
);
