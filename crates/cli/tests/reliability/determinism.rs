//! Invariant: a command with no time/randomness in its output is byte-identical
//! across two runs under the same profile. Nondeterministic output (HashMap
//! iteration order, unstable sorts) breaks diffing, caching, and golden-file
//! review - a real "behaves inconsistently" defect even when nothing errors.
//!
//! 6 deterministic invocations × 16 profiles = 96 distinct tests.

use crate::reliability::harness::{assert_no_panic, run, Profile};

pub fn deterministic(profile: Profile, args: &[&str]) {
    let a = run(profile, args);
    let b = run(profile, args);
    assert_no_panic(&a);
    assert_no_panic(&b);
    assert_eq!(
        a.code, b.code,
        "{}: exit code differs between identical runs ({:?} vs {:?})",
        a.what, a.code, b.code
    );
    assert_eq!(
        a.stdout, b.stdout,
        "{}: stdout is NOT deterministic across two identical runs.\n--- run A (first 600) ---\n{}\n--- run B (first 600) ---\n{}",
        a.what,
        a.stdout.chars().take(600).collect::<String>(),
        b.stdout.chars().take(600).collect::<String>()
    );
}

crate::kh_matrix!(
    crate::reliability::determinism::deterministic,
    version => &["--version"][..],
    completion_bash => &["completion", "bash"][..],
    completion_zsh => &["completion", "zsh"][..],
    detectors_list => &["detectors"][..],
    scan_help => &["scan", "--help"][..],
    badflag => &["scan", "--definitely-not-a-real-keyhog-flag"][..],
);
