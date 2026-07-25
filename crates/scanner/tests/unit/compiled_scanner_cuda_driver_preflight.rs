//! CUDA driver-loader regressions for CPU-only release hosts.

use super::load_dynamic_library;

/// Locks out reintroducing cudarc's aborting missing-library path by proving a
/// nonexistent driver soname becomes an ordinary diagnostic before CUDA code runs.
#[test]
fn missing_driver_soname_returns_error_instead_of_panicking() {
    let error = load_dynamic_library(c"libkeyhog-definitely-missing-cuda-driver.so")
        .expect_err("a synthetic missing CUDA driver must fail closed");

    assert!(error.contains("libkeyhog-definitely-missing-cuda-driver.so"));
    assert!(
        error.contains("cannot open shared object file") || error.contains("dynamic-loader error"),
        "loader diagnostic must explain why the CUDA soname is unavailable: {error}"
    );
}

/// Locks out a preflight that rejects every soname, which would silently remove
/// CUDA from autoroute even when the platform dynamic loader is healthy.
#[test]
fn dynamic_loader_accepts_a_known_linux_runtime_library() {
    load_dynamic_library(c"libc.so.6")
        .expect("the Linux C runtime must remain discoverable through the same loader path");
}
