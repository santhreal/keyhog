//! Shared helpers for scanner integration tests.
//!
//! Each `tests/*.rs` file is its own integration-test crate that pulls this
//! tree in via `mod support;`. A given runner uses only the submodules it
//! needs, so any helper unused by *that* binary trips `dead_code` — an
//! artifact of cargo's per-binary test compilation, not real dead code (every
//! helper here is exercised by at least one runner). Silence it tree-wide
//! rather than scatter per-item attributes.
#![allow(dead_code)]

use keyhog_scanner::CompiledScanner;

pub mod contracts;
pub mod gpu_gate;
pub mod paths;

pub fn compile_full_detector_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&paths::detector_dir()).expect("detectors");
    CompiledScanner::compile(detectors).expect("compile")
}
