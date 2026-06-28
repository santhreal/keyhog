//! Invariant: an unknown flag is rejected cleanly for EVERY subcommand under
//! EVERY profile. clap parses before the subcommand runs, so this is safe even
//! for daemon/watch/scan-system (no long-running work executes).
//!
//! A premium CLI: exits 2 (usage error), names the offending flag or prints a
//! usage hint, never panics, never leaks ANSI. 17 x 16 = 272 distinct tests.

use crate::reliability::harness::{
    assert_clean_exit, assert_no_ansi, assert_no_panic, run, Profile,
};

const BOGUS_FLAG: &str = "--definitely-not-a-real-keyhog-flag";

pub fn badflag_invariant(profile: Profile, sub: &str) {
    let o = run(profile, &[sub, BOGUS_FLAG]);
    assert_clean_exit(&o);
    assert_no_panic(&o);
    assert_eq!(
        o.code,
        Some(2),
        "{}: an unknown flag must exit 2 (usage error), got {:?}\nstdout:\n{}\nstderr:\n{}",
        o.what,
        o.code,
        o.stdout.chars().take(200).collect::<String>(),
        o.stderr.chars().take(400).collect::<String>()
    );
    // clap routes errors to stderr; stdout must stay empty so a wrapper piping
    // stdout doesn't capture an error as data.
    assert!(
        o.stdout.trim().is_empty(),
        "{}: usage error wrote to stdout (should be stderr-only):\n{}",
        o.what,
        o.stdout.chars().take(300).collect::<String>()
    );
    let hint = o.stderr.to_lowercase();
    assert!(
        hint.contains("unexpected")
            || hint.contains("unknown")
            || hint.contains("usage")
            || hint.contains("help")
            || hint.contains("error"),
        "{}: usage error gave no actionable hint:\n{}",
        o.what,
        o.stderr.chars().take(300).collect::<String>()
    );
    // Under CLICOLOR_FORCE clap colors its error output by design; only treat
    // ANSI as a leak when color was not force-requested.
    if !profile.forces_color() {
        assert_no_ansi(&o);
    }
}

crate::kh_matrix!(
    crate::reliability::surface_badflag::badflag_invariant,
    scan => "scan",
    hook => "hook",
    detectors => "detectors",
    explain => "explain",
    diff => "diff",
    calibrate => "calibrate",
    config => "config",
    watch => "watch",
    completion => "completion",
    backend => "backend",
    doctor => "doctor",
    update => "update",
    repair => "repair",
    uninstall => "uninstall",
    scan_system => "scan-system",
    daemon => "daemon",
    calibrate_autoroute => "calibrate-autoroute",
);
