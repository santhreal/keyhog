//! Per-pattern fallback hot-set profile on the real mirror corpus. Answers the
//! decisive question for anchor-localization: of the 77-85% of phase-2 time
//! `scan_phase2_patterns` costs, WHICH detectors burn it, and are they
//! prefix-anchorable (localizable to windows) or no-literal whole-chunk walks?
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner \
//!     --test phase2_pattern_profile -- --ignored --nocapture

use super::support::paths::{corpus_dir, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{set_profile_enabled, CompiledScanner, ScanBackend};
use std::path::PathBuf;

fn collect_files(root: &PathBuf, limit: usize) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    files.push(b);
                    if files.len() >= limit {
                        return files;
                    }
                }
            }
        }
    }
    files
}

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "phase2-profile".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn phase2_pattern_profile_mirror() {
    set_profile_enabled(true);
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let Some(root) = corpus_dir() else {
        eprintln!("phase2_pattern_profile: mirror corpus absent — skipping");
        return;
    };
    let files = collect_files(&root, 8000);
    eprintln!("phase2_pattern_profile: {} mirror files", files.len());

    // Regime B: ~16 KiB concatenated chunks (the stated target file size).
    let mut chunks_16k: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::new();
    for f in &files {
        cur.extend_from_slice(f);
        cur.push(b'\n');
        if cur.len() >= 16 * 1024 {
            chunks_16k.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        chunks_16k.push(cur);
    }

    // Warm + discard, then a timed pass.
    for (i, c) in chunks_16k.iter().enumerate() {
        let chunk = chunk_of(c, &format!("16k-{i}"));
        let _ = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    }
    scanner.phase2_profile_dump("warmup-discard");

    for (i, c) in chunks_16k.iter().enumerate() {
        let chunk = chunk_of(c, &format!("16k-{i}"));
        let _ = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    }
    eprintln!("regime B: {} 16-KiB chunks", chunks_16k.len());
    scanner.phase2_profile_dump("mirror-16kib");
}
