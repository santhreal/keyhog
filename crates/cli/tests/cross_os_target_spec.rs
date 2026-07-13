//! Standalone bounded test binary for the CROSS-OS target spec.
//!
//! The contracts live in `tests/target_spec/cross_os_contracts.rs`. As with
//! `target_spec_org_contracts.rs`, each `.rs` directly under `tests/` is its own
//! test binary, and a file nested in a subdirectory only compiles when a sibling
//! top-level file pulls it in. We include it with `#[path]` so the cross-OS
//! assertions run as their own fast, isolated binary (no link into the large
//! `all_tests` aggregator that drives OOM-SIGKILL (see `all_tests.rs`)).
//!
//! MIXED target spec: the file carries BOTH
//!   * GREEN coherence pins (run on every OS, must stay passing) that lock the
//!     DELIBERATE cross-OS divergences in place so no later edit silently erases
//!     one (e.g. the Windows running-.exe uninstall error), and
//!   * a portability target that tracks the concrete cross-OS BUILD blocker the
//!     dogfood surfaced: `vyre*` dependencies must be registry pins or
//!     repo-contained paths, never tree-escaping Santh NFS paths. It is green
//!     now that Keyhog pins the published Vyre `0.6.2` crates.

#[path = "target_spec/cross_os_contracts.rs"]
mod cross_os_contracts;
