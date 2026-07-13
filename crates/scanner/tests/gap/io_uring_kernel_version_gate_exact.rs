//! Gap test: the io_uring kernel-version gate has an exact 5.1 boundary.
//!
//! `detect_io_uring` only attempts an `io_uring::IoUring::new` after confirming
//! the running kernel is 5.1+ (where the io_uring syscall surface stabilized).
//! That version check used to be an inline closure over `/proc/.../osrelease`,
//! so the boundary (>= 5.1, and fail-closed on anything unparseable) had no
//! test. It is now the pure `kernel_supports_io_uring(&str)` seam, pin its
//! exact truth table without needing a real kernel.
//!
//! Linux-only: the seam (and its facade) only compile under
//! `cfg(target_os = "linux")`, which is the CI build target.
#![cfg(target_os = "linux")]

use keyhog_scanner::testing::kernel_supports_io_uring_for_test as supports;

#[test]
fn five_one_is_the_inclusive_minimum() {
    assert!(
        supports("5.1.0-generic"),
        "5.1 is the first io_uring kernel"
    );
    assert!(!supports("5.0.99"), "5.0.x is below the 5.1 floor");
}

#[test]
fn newer_majors_pass_and_older_majors_fail() {
    assert!(supports("6.8.0-arch1-1"), "kernel 6.x is above the floor");
    assert!(supports("5.15.0-126-generic"), "5.15 is above 5.1");
    assert!(!supports("4.19.0"), "kernel 4.x is below the floor");
}

#[test]
fn unparseable_osrelease_fails_closed() {
    assert!(!supports("5"), "a single component cannot be 5.<minor>");
    assert!(!supports("x.y"), "non-numeric major/minor fails closed");
    assert!(!supports(""), "empty osrelease fails closed");
}

#[test]
fn surrounding_whitespace_is_trimmed() {
    assert!(
        supports("  6.1.0  \n"),
        "osrelease is trimmed before parsing"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin a handful of points; these SWEEP the gate. For any
// well-formed `major.minor.patch` osrelease the result is EXACTLY the `(major,
// minor) >= (5, 1)` tuple order, an implementation-independent characterization of
// the 5.1 floor (and it proves the patch/suffix is irrelevant). Plus: surrounding
// whitespace never changes the verdict, and any single-component or non-numeric
// string fails closed (never a spurious io_uring attempt on an unknown kernel).
// Traced against `kernel_supports_io_uring`. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A well-formed version is supported iff `(major, minor) >= (5, 1)`: swept
    /// densely across the 5.0/5.1 boundary and both sides of major 5.
    #[test]
    fn wellformed_version_matches_the_5_1_floor(
        major in 3u32..9,
        minor in 0u32..6,
        patch in 0u32..300,
    ) {
        let v = format!("{major}.{minor}.{patch}-generic");
        let expected = (major, minor) >= (5, 1);
        prop_assert_eq!(supports(&v), expected);
    }

    /// Surrounding whitespace/newlines are trimmed before parsing, so they never
    /// change the verdict.
    #[test]
    fn surrounding_whitespace_does_not_change_the_verdict(
        major in 3u32..9,
        minor in 0u32..6,
    ) {
        let v = format!("{major}.{minor}.0");
        let padded = format!("  {v}  \n\t");
        prop_assert_eq!(supports(&padded), supports(&v));
    }

    /// A single numeric component (no minor), a non-numeric major/minor, or an empty
    /// string all fail closed.
    #[test]
    fn single_component_or_nonnumeric_fails_closed(
        n in 0u32..100_000,
        s in "[a-zA-Z]{1,6}",
    ) {
        let single = n.to_string();
        prop_assert!(!supports(&single), "single component {single:?} has no minor");
        let nonnumeric = format!("{s}.{s}");
        prop_assert!(!supports(&nonnumeric), "non-numeric {nonnumeric:?} must fail closed");
        prop_assert!(!supports(""));
    }
}
