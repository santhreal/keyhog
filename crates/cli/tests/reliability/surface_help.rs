//! Invariant: `keyhog <subcommand> --help` works under EVERY hostile profile.
//!
//! `--help` is the cheapest promise a CLI makes; it must hold with HOME unset,
//! a read-only cwd, TERM=dumb, a 1-column terminal, a bogus forced backend.
//! Each cell asserts: clean exit, exit 0, usage text present, zero ANSI leak,
//! no panic. 15 subcommands × 16 profiles = 240 distinct tests.

use crate::reliability::harness::{
    assert_clean_exit, assert_no_ansi, assert_no_panic, run, Profile,
};

pub fn help_invariant(profile: Profile, sub: &str) {
    let o = run(profile, &[sub, "--help"]);
    assert_clean_exit(&o);
    assert_no_panic(&o);
    assert_eq!(
        o.code,
        Some(0),
        "{}: `--help` must exit 0, got {:?}\nstderr:\n{}",
        o.what,
        o.code,
        o.stderr.chars().take(400).collect::<String>()
    );
    let lo = o.stdout.to_lowercase();
    assert!(
        lo.contains("usage") || lo.contains("options") || o.stdout.contains(sub),
        "{}: `--help` printed no usage/options text:\n{}",
        o.what,
        o.stdout.chars().take(300).collect::<String>()
    );
    // ANSI is a leak only when color wasn't explicitly forced. Under
    // CLICOLOR_FORCE, colored help is the requested behavior.
    if !profile.forces_color() {
        assert_no_ansi(&o);
    }
}

crate::kh_matrix!(
    crate::reliability::surface_help::help_invariant,
    scan => "scan",
    hook => "hook",
    detectors => "detectors",
    explain => "explain",
    diff => "diff",
    calibrate => "calibrate",
    watch => "watch",
    completion => "completion",
    backend => "backend",
    doctor => "doctor",
    update => "update",
    repair => "repair",
    uninstall => "uninstall",
    scan_system => "scan-system",
    daemon => "daemon",
);
