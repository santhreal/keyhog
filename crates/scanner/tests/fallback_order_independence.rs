//! Does the final finding set depend on the ORDER fallback patterns are
//! extracted? If NOT, an O(text) literal prefilter (which marks the active set
//! in a different order than the RegexSet) is safe to adopt — the key blocker
//! for a much faster prefilter. Scans each corpus chunk with the fallback
//! extraction order normal vs reversed and asserts identical findings.

mod support;
use support::paths::{corpus_dir, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "order-indep".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn canonical(matches: &[Vec<RawMatch>]) -> Vec<(String, String, String)> {
    let mut v: Vec<(String, String, String)> = matches
        .iter()
        .flatten()
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.to_string(),
                format!("{:?}", m.location),
            )
        })
        .collect();
    v.sort();
    v
}

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

#[test]
#[ignore = "diagnostic: run with --ignored --nocapture"]
fn fallback_order_independence() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = collect_files(&root, 6000);
    // Raw small files + 16 KiB chunks, the two regimes.
    let mut chunks: Vec<Vec<u8>> = files.clone();
    let mut cur = Vec::new();
    for f in &files {
        cur.extend_from_slice(f);
        cur.push(b'\n');
        if cur.len() >= 16 * 1024 {
            chunks.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }

    let mut diverged = 0;
    for (i, c) in chunks.iter().enumerate() {
        let chunk = chunk_of(c, &format!("c-{i}"));
        scanner.tuning().set_fallback_reverse(Some(false));
        scanner.clear_fragment_cache();
        let normal = canonical(
            &scanner
                .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback),
        );
        scanner.tuning().set_fallback_reverse(Some(true));
        scanner.clear_fragment_cache();
        let reversed = canonical(
            &scanner
                .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback),
        );
        if normal != reversed {
            diverged += 1;
            if diverged <= 5 {
                eprintln!(
                    "== ORDER-DEPENDENT divergence on chunk {i} ({} bytes) ==",
                    c.len()
                );
                use std::collections::BTreeSet;
                let n: BTreeSet<_> = normal.iter().collect();
                let r: BTreeSet<_> = reversed.iter().collect();
                for only in n.difference(&r) {
                    eprintln!("  only-in-normal: {only:?}");
                }
                for only in r.difference(&n) {
                    eprintln!("  only-in-reversed: {only:?}");
                }
            }
        }
    }
    scanner.tuning().set_fallback_reverse(None);
    eprintln!(
        "fallback_order_independence: {} chunks, {diverged} order-dependent",
        chunks.len()
    );
    assert_eq!(
        diverged, 0,
        "fallback finding set depends on extraction order"
    );
}
