//! Shared filesystem path helpers for scanner integration tests.

use std::path::PathBuf;

/// Returns the absolute path to `crates/scanner/../detectors` (the on-disk Tier-B
/// detector TOML directory), computed from `CARGO_MANIFEST_DIR` so tests stay
/// stable across `cargo test`, `cargo nextest`, and remote runners that move cwd.
pub fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}
