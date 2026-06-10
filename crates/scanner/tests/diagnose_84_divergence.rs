//! Placeholder for the historical issue-84 divergence diagnostic.
//!
//! The original one-off diagnostic was Git LFS backed. Keeping a valid Rust
//! target here preserves direct `cargo test --test diagnose_84_divergence`
//! invocations while avoiding parser failures in non-LFS checkouts.

#[test]
#[ignore = "historical Git LFS diagnostic payload is not vendored in this checkout"]
fn diagnose_84_divergence_payload_missing() {}
