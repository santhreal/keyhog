//! Shared helpers for scanner integration tests.
//!
//! Each `tests/*.rs` file is its own integration-test crate that pulls this
//! tree in via `mod support;`. A given runner uses only the submodules it
//! needs, so any helper unused by *that* binary trips `dead_code` — an
//! artifact of cargo's per-binary test compilation, not real dead code (every
//! helper here is exercised by at least one runner). Silence it tree-wide
//! rather than scatter per-item attributes.
#![allow(dead_code)]

pub mod contracts;
pub mod gpu_gate;
pub mod megakernel_waiver;
pub mod paths;
