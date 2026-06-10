//! Placeholder for the historical SecretBench divergence diagnostic.
//!
//! The original ad-hoc diagnostic was checked in through Git LFS. Environments
//! without Git LFS saw only the pointer file, which made Cargo parse
//! `version https://git-lfs...` as Rust and fail before tests could run. Keep
//! the target name for callers, but make the missing payload explicit.

#[test]
#[ignore = "historical Git LFS diagnostic payload is not vendored in this checkout"]
fn diagnose_sb_divergence_payload_missing() {}
