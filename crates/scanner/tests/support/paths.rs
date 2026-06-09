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

/// Returns the absolute path to the on-disk `benchmarks/corpora/mirror/corpus`
/// tree (real-world source files used as representative scan input), computed
/// from `CARGO_MANIFEST_DIR` so measurement tests stay stable regardless of cwd.
/// Returns `None` if the tree is absent (e.g. a checkout without benchmark
/// corpora) so callers can fall back to a synthetic payload instead of failing.
pub fn corpus_dir() -> Option<PathBuf> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("benchmarks");
    d.push("corpora");
    d.push("mirror");
    d.push("corpus");
    d.is_dir().then_some(d)
}
