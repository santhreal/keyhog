//! Migrated from `src/hardening.rs` inline tests (KH-GAP-004).
//!
//! The compiled-pattern cache filename check in `hardening` reuses the single
//! crate-wide `git_lfs::SHA256_HEX_LEN` owner (64 hex = 32-byte sha256). The
//! migrated one-place assertion lives here; the rest lock distinct always-on
//! (non-lockdown) hardening behaviour that the existing `apply_*` unit tests do
//! not cover.

use keyhog_core::{apply_protections, git_lfs::SHA256_HEX_LEN, HardeningReport};

#[test]
fn hardening_cache_check_reuses_git_lfs_sha256_owner() {
    // Both the git-LFS oid recogniser and the compiled-cache filename check
    // must see the same 64. A drift would silently misclassify cache files.
    assert_eq!(SHA256_HEX_LEN, 64);
}

#[test]
fn default_hardening_report_is_all_false_and_empty() {
    let report = HardeningReport::default();
    assert!(!report.no_core_dumps);
    assert!(!report.no_ptrace);
    assert!(!report.mlocked);
    assert!(!report.coredump_filter_safe);
    assert_eq!(report.failures.len(), 0);
}

#[test]
fn non_lockdown_mode_never_mlocks() {
    // mlockall is a lockdown-only (costly) protection; the always-on tier must
    // never pin memory.
    let report = apply_protections(false);
    assert!(!report.mlocked);
}

#[test]
fn non_lockdown_mode_never_scans_the_disk_cache_gate() {
    // The persistence-cache fail-closed gate is lockdown-only. In default mode
    // no failure may reference the disk-cache violation, regardless of any
    // platform prctl outcome.
    let report = apply_protections(false);
    assert!(
        !report
            .failures
            .iter()
            .any(|f| f.contains("lockdown disk cache")),
        "default (non-lockdown) mode must not run the disk-cache gate; failures were {:?}",
        report.failures
    );
}
