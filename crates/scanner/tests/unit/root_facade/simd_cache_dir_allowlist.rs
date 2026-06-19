//! Allowlist policy for the explicit Hyperscan compile-cache dir.
//!
//! The validation accepts a custom cache dir only under `$HOME` or a per-uid
//! dir beneath the SYSTEM TEMP ROOT. The temp root was previously hardcoded to
//! `/tmp`, so a host with `TMPDIR=/var/tmp` (or a custom tmpfs) wrongly rejected
//! a cache dir under its real temp root. The fix resolves the root via
//! `std::env::temp_dir()` (honors `$TMPDIR`, else `/tmp`) and routes the check
//! through the pure `cache_dir_under_allowed_root`, tested here via the hidden
//! `testing` re-export. There is no cache-dir env mutation, so this is
//! race-free under parallel tests.

#![cfg(feature = "simd")]

use keyhog_scanner::testing::cache_dir_under_allowed_root;
use std::path::Path;

const UID: u32 = 1000;

#[test]
fn accepts_paths_under_home() {
    let home = Path::new("/home/dev");
    let temp = Path::new("/tmp");
    assert!(cache_dir_under_allowed_root(
        Path::new("/home/dev/.cache/keyhog"),
        home,
        temp,
        UID
    ));
    // The home root itself is allowed.
    assert!(cache_dir_under_allowed_root(home, home, temp, UID));
}

#[test]
fn accepts_per_uid_dir_under_the_given_temp_root() {
    let home = Path::new("/home/dev");
    // Default temp root.
    assert!(cache_dir_under_allowed_root(
        Path::new("/tmp/keyhog-cache-1000/db"),
        home,
        Path::new("/tmp"),
        UID
    ));
    // THE regression: a non-`/tmp` `$TMPDIR` (e.g. /var/tmp) must be honored,
    // not rejected. This was the hardcoded-`/tmp` bug.
    assert!(cache_dir_under_allowed_root(
        Path::new("/var/tmp/keyhog-cache-1000/db"),
        home,
        Path::new("/var/tmp"),
        UID
    ));
}

#[test]
fn rejects_outside_home_and_temp() {
    let home = Path::new("/home/dev");
    let temp = Path::new("/tmp");
    // Arbitrary system path.
    assert!(!cache_dir_under_allowed_root(
        Path::new("/etc/keyhog"),
        home,
        temp,
        UID
    ));
    // Another user's home.
    assert!(!cache_dir_under_allowed_root(
        Path::new("/home/other/.cache/keyhog"),
        home,
        temp,
        UID
    ));
    // Right temp root but a DIFFERENT uid's dir (no cross-user cache reuse).
    assert!(!cache_dir_under_allowed_root(
        Path::new("/tmp/keyhog-cache-1001/db"),
        home,
        temp,
        UID
    ));
    // The bare temp root (not the per-uid subdir) is not allowed.
    assert!(!cache_dir_under_allowed_root(
        Path::new("/tmp/something-else"),
        home,
        temp,
        UID
    ));
}
