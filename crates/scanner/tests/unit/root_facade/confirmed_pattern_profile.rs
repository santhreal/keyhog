//! Per-pattern confirmed-pass profile: which triggered detectors dominate
//! `extract_confirmed_patterns` (~18-22% of phase-2), and would localizing the
//! whole-chunk extract to AC trigger positions help (like the fallback localizer)?
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner \
//!     --test confirmed_pattern_profile -- --ignored --nocapture

use super::support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{set_profile_enabled, CompiledScanner, ScanBackend};

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "confirmed-profile".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn confirmed_pattern_profile_mirror() {
    set_profile_enabled(true);
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = corpus_files(&root, 8000);

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

    for (i, c) in chunks_16k.iter().enumerate() {
        let chunk = chunk_of(c, &format!("16k-{i}"));
        let _ = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    }
    scanner.confirmed_profile_dump("warmup-discard");
    for (i, c) in chunks_16k.iter().enumerate() {
        let chunk = chunk_of(c, &format!("16k-{i}"));
        let _ = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    }
    eprintln!("regime B: {} 16-KiB chunks", chunks_16k.len());
    scanner.confirmed_profile_dump("mirror-16kib");
}
