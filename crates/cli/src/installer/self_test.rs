//! The `keyhog doctor` scan-engine self test.
//!
//! History: this module was the network half of a self-updater. `keyhog update`
//! and `keyhog repair` installed signed binaries from a GitHub release asset
//! bundle. That channel was retired - no workflow builds, signs, or uploads
//! release binaries any more, and KeyHog ships through crates.io only. Both
//! subcommands and all of the download, signature, and asset-selection code
//! were deleted rather than left pointing at a dead channel, because each
//! consumer searched BACKWARD for a release that still carried a complete
//! bundle: a dead channel did not fail, it silently installed a long-stale
//! binary. `scripts/gates/release_channel_coherence.py` fails the build if an
//! asset-consuming path reappears without a workflow that produces the assets.

use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};
use keyhog_scanner::{hw_probe::ScanBackend, CompiledScanner};

/// Prove the scan engine works end to end on this host: compile a bundled
/// detector, scan a chunk carrying a planted credential, and confirm it
/// round-trips through compile -> scan -> extract -> report. GPU health has
/// its own doctor probes. Uses a unique prefix so it neither collides with a
/// real detector nor trips example or placeholder suppression.
pub(crate) fn scan_engine_self_test() -> Result<bool> {
    // Self-test detector compile + scan: doctor's compute phase, profiled as
    // preprocessing.
    let _self_test_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    const PLANTED: &str = "KHDOCTOR_A1b2C3d4E5f6";
    let detector =
        toml::from_str::<DetectorFile>(include_str!("../../data/doctor-self-test-detector.toml"))
            .context("bundled doctor self-test detector TOML is invalid")?
            .detector;
    let scanner = CompiledScanner::compile_with_gpu_policy(
        vec![detector],
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )?;
    let chunk = Chunk {
        data: format!("api_secret = {PLANTED}").into(),
        metadata: ChunkMetadata {
            source_type: "doctor".into(),
            path: Some("doctor-selftest.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback)?;
    Ok(matches.iter().any(|m| m.credential.as_ref() == PLANTED))
}
