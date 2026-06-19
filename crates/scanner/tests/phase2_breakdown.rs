//! Real-corpus phase-2 per-pass breakdown for the small-file regime that the
//! on-GPU detection rewrite targets (`docs/EXECUTION_PLAN.md`). Scans the
//! mirror corpus (15k real secret-detection fixtures, ~138-byte median) plus a
//! 16 KiB-concatenated variant, and dumps the accumulated [hot, confirmed,
//! phase2-capture, generic, entropy, ml] split. CPU backend — phase-2 is
//! backend-independent (proven by `backend_crossover_sweep`), so this isolates
//! the CPU work the rewrite must move to the GPU.
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner \
//!     --features gpu --test phase2_breakdown -- --ignored --nocapture

mod support;
use support::paths::{corpus_dir, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{
    profile_dump, profile_reset, set_profile_enabled, CompiledScanner, ScanBackend,
};
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

fn chunk_of(bytes: Vec<u8>, label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(&bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "phase2-breakdown".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn phase2_breakdown_mirror() {
    set_profile_enabled(true);
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    let Some(root) = corpus_dir() else {
        eprintln!("phase2_breakdown: mirror corpus absent — skipping");
        return;
    };
    let files = collect_files(&root, 8000);
    eprintln!("phase2_breakdown: {} mirror files", files.len());
    let total_bytes: usize = files.iter().map(Vec::len).sum();

    // Regime A: raw small files (real ~138-byte median — the per-file overhead
    // regime; one scan_prepared_with_triggered call per file).
    profile_reset();
    for (i, f) in files.iter().enumerate() {
        let chunk = chunk_of(f.clone(), &format!("small-{i}"));
        let _ = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    }
    eprintln!(
        "regime A: {} small files, {} KiB total",
        files.len(),
        total_bytes / 1024
    );
    profile_dump("mirror-small-files");

    // Regime B: concatenated into ~16 KiB chunks (the stated 16 KB-file target;
    // per-file fixed cost amortized over a realistic file size).
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
    profile_reset();
    for (i, c) in chunks_16k.iter().enumerate() {
        let chunk = chunk_of(c.clone(), &format!("16k-{i}"));
        let _ = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    }
    eprintln!("regime B: {} 16-KiB chunks", chunks_16k.len());
    profile_dump("mirror-16kib-chunks");
}
