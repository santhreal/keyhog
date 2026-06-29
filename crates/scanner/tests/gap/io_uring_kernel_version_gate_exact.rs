//! Gap test: the io_uring kernel-version gate has an exact 5.1 boundary.
//!
//! `detect_io_uring` only attempts an `io_uring::IoUring::new` after confirming
//! the running kernel is 5.1+ (where the io_uring syscall surface stabilized).
//! That version check used to be an inline closure over `/proc/.../osrelease`,
//! so the boundary (>= 5.1, and fail-closed on anything unparseable) had no
//! test. It is now the pure `kernel_supports_io_uring(&str)` seam — pin its
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
