//! End-to-end scan throughput of the mirror corpus — the headline number the
//! phase-2 breakdown doesn't capture (it excludes phase-1 trigger collection,
//! preprocessing, and post-process decode recursion). Compares ALL fallback +
//! confirmed optimizations ON vs OFF so the cumulative real-world impact is
//! visible, not just the per-pass share.
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner --test fullscan_throughput \
//!     -- --ignored --nocapture

mod support;
use support::paths::{corpus_dir, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{
    set_confirmed_suffix_gate, set_decode_focus, set_fallback_homoglyph_gate,
    set_prefilter_truncate, CompiledScanner, ScanBackend,
};
use std::path::PathBuf;
use std::time::Instant;

fn collect_files(root: &PathBuf, limit: usize) -> Vec<Vec<u8>> {
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
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
            source_type: "throughput".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn one_scan(scanner: &CompiledScanner, chunks: &[Chunk]) -> f64 {
    scanner.clear_fragment_cache();
    let t = Instant::now();
    for c in chunks {
        let _ = scanner.scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::CpuFallback);
    }
    t.elapsed().as_secs_f64() * 1000.0
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// INTERLEAVED A/B: alternate gate-off and gate-on scans within one loop so
/// thermal drift and cache state affect both equally; report medians.
fn ab_interleaved(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    bytes: usize,
    configure: &dyn Fn(bool),
) {
    // Warm both configs.
    configure(false);
    let _ = one_scan(scanner, chunks);
    configure(true);
    let _ = one_scan(scanner, chunks);
    let reps = 9;
    let mut off = Vec::new();
    let mut on = Vec::new();
    for _ in 0..reps {
        configure(false);
        off.push(one_scan(scanner, chunks));
        configure(true);
        on.push(one_scan(scanner, chunks));
    }
    let (mo, mn) = (median(off), median(on));
    let mbps = |ms: f64| (bytes as f64 / 1e6) / (ms / 1000.0);
    let delta = 100.0 * (mn - mo) / mo;
    eprintln!(
        "  OFF {mo:>8.1} ms ({:>5.1} MB/s)   ON {mn:>8.1} ms ({:>5.1} MB/s)   ON vs OFF: {delta:+.1}%",
        mbps(mo),
        mbps(mn)
    );
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn fullscan_throughput_mirror() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = collect_files(&root, 8000);

    // Regime B: 16 KiB chunks.
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
    let bytes16: usize = chunks_16k.iter().map(Vec::len).sum();
    let chunks: Vec<Chunk> = chunks_16k
        .iter()
        .enumerate()
        .map(|(i, c)| chunk_of(c, &format!("16k-{i}")))
        .collect();

    // Isolate each opt. "on=false" => that opt off; baseline has BOTH off.
    let fallback_only = |on: bool| {
        set_fallback_homoglyph_gate(Some(on));
        set_confirmed_suffix_gate(Some(false));
    };
    let confirmed_only = |on: bool| {
        set_fallback_homoglyph_gate(Some(false));
        set_confirmed_suffix_gate(Some(on));
    };
    let both = |on: bool| {
        set_fallback_homoglyph_gate(Some(on));
        set_confirmed_suffix_gate(Some(on));
    };
    // Decode-recursion focus: homoglyph fold + confirmed gate stay at their
    // shipped default (on); toggle ONLY the focus restriction.
    let decode_focus = |on: bool| {
        set_fallback_homoglyph_gate(Some(true));
        set_confirmed_suffix_gate(Some(true));
        set_decode_focus(Some(on));
    };
    // Prefilter {N,}->{N} truncation: keeps the always-active prefilter RegexSet
    // on the lazy-DFA. Other opts at shipped default; isolates the truncation.
    let prefilter_trunc = |on: bool| {
        set_fallback_homoglyph_gate(Some(true));
        set_confirmed_suffix_gate(Some(true));
        set_decode_focus(Some(true));
        set_prefilter_truncate(Some(on));
    };
    eprintln!(
        "=== {} 16-KiB chunks ({} KiB), interleaved median of 9 ===",
        chunks.len(),
        bytes16 / 1024
    );
    eprint!("fallback localizer  ");
    ab_interleaved(&scanner, &chunks, bytes16, &fallback_only);
    eprint!("confirmed gate      ");
    ab_interleaved(&scanner, &chunks, bytes16, &confirmed_only);
    eprint!("both                ");
    ab_interleaved(&scanner, &chunks, bytes16, &both);
    eprint!("decode focus        ");
    ab_interleaved(&scanner, &chunks, bytes16, &decode_focus);
    eprint!("prefilter truncate  ");
    ab_interleaved(&scanner, &chunks, bytes16, &prefilter_trunc);

    set_fallback_homoglyph_gate(None);
    set_confirmed_suffix_gate(None);
    set_decode_focus(None);
    set_prefilter_truncate(None);
}
