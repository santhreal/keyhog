//! Pipeline parity: the fused parallel read+scan path and the coalesced batch
//! pipeline must produce the identical finding set on a filesystem scan.
//!
//! The fused path (default for CPU/SIMD filesystem scans) scans every chunk
//! independently on the global rayon pool and skips the per-batch
//! `scan_chunk_boundaries` pass — which is a no-op for the filesystem source's
//! 128 KiB-overlapping windows anyway. This test is the parity guard for that
//! claim: same corpus, same detectors, the two pipelines must agree exactly.

use super::support::{make_detector, make_orchestrator, make_orchestrator_with_args};
use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::Source;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

/// 40 files, every 4th carrying the planted secret the test detector matches;
/// the rest are noise so both the hit and no-hit chunk paths are exercised.
fn planted_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    for i in 0..40 {
        let p = dir.path().join(format!("file_{i:02}.env"));
        let mut f = std::fs::File::create(&p).expect("create fixture");
        if i % 4 == 0 {
            writeln!(f, "API_TOKEN=STATIC_SECRET_{i}00042").expect("write secret");
        } else {
            writeln!(f, "harmless = \"ordinary config value number {i}\"").expect("write noise");
        }
    }
    dir
}

/// The DISTINCT findings of a scan (deduped by detector/credential/file/line).
/// scan_sources returns pre-dedup RawMatch — one planted secret yields several
/// raw matches across the named/generic-assignment/entropy stages — so the
/// parity claim is over the distinct set, not raw multiplicity.
fn scan_findings(dir: &Path, batch_pipeline: bool) -> BTreeSet<(String, String, String, String)> {
    let detectors = vec![make_detector()];
    let orch = if batch_pipeline {
        let args = ScanArgs::try_parse_from(["scan", "--batch-pipeline"]).expect("parse args");
        make_orchestrator_with_args(detectors, args)
    } else {
        make_orchestrator(detectors)
    };
    let sources: Vec<Box<dyn Source>> = vec![Box::new(keyhog_sources::FilesystemSource::new(
        dir.to_path_buf(),
    ))];
    API.scan_orchestrator_scan_sources_for_test(&orch, sources, false, None)
        .expect("scan sources")
        .into_iter()
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.to_string(),
                m.location.file_path.as_deref().unwrap_or("").to_string(),
                format!("{:?}", m.location.line),
            )
        })
        .collect()
}

#[test]
fn fused_and_batch_pipelines_agree_on_filesystem_scan() {
    let dir = planted_dir();

    // The test orchestrator constructor pins deterministic SIMD routing so the
    // fused path engages regardless of whether the test host has a GPU.

    let fused = scan_findings(dir.path(), false);
    let batch = scan_findings(dir.path(), true);

    // The core claim: the two pipelines surface the identical finding set.
    assert_eq!(
        fused, batch,
        "fused and coalesced batch pipelines must produce the identical distinct finding set"
    );
    // Sanity floor: every one of the 10 secret-bearing files must contribute
    // at least its planted credential (exact multiplicity is an internal
    // pre-dedup detail and intentionally not pinned here).
    assert!(
        fused.len() >= 10,
        "expected at least 10 distinct findings from 10 planted files, got {}",
        fused.len()
    );
}
