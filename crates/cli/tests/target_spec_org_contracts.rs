//! Standalone bounded test binary for the ORGANIZATION-CONTRACT target spec.
//!
//! The actual contracts live in `tests/target_spec/org_contracts.rs` (the
//! task's named location). This top-level file is the binary entry point: each
//! `.rs` directly under `tests/` is its own test binary (see `all_tests.rs` 
//! standalone binaries bound peak memory and link size), and a file nested in a
//! subdirectory only compiles when a sibling top-level file declares it. We pull
//! it in with `#[path]` rather than adding it to the big `all_tests` aggregator
//! so these pure source/org assertions run as their own fast, isolated binary.
//!
//! These tests are TARGET SPEC: they are EXPECTED TO FAIL today where the
//! organization contract is violated. A red result here is the org worklist,
//! not a broken build (Law 6). Do not weaken them to pass (Law 9).

#[path = "target_spec/org_contracts.rs"]
mod org_contracts;
