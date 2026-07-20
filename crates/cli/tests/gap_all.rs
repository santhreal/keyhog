//! Standalone integration-test binary for the heavy `gap` suite.
//!
//! `gap` tests spawn the real `keyhog` binary many times and were the dominant
//! consumer of the monolithic `all_tests` wall time. Keeping them in their own
//! binary lets `all_tests` stay under the CI time budget while the `gap` suite
//! still runs in CI as `cargo test -p keyhog --test gap_all`.

#[path = "e2e/support.rs"]
pub mod support;

#[path = "gap/mod.rs"]
pub mod gap;
