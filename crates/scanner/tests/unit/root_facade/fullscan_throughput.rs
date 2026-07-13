//! End-to-end scan throughput of the mirror corpus, the headline number the
//! phase-2 breakdown doesn't capture (it excludes phase-1 trigger collection,
//! preprocessing, and post-process decode recursion). Compares ALL fallback +
//! confirmed optimizations ON vs OFF so the cumulative real-world impact is
//! visible, not just the per-pass share.
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner --test fullscan_throughput \
//!     -- --ignored --nocapture

use super::support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::time::Instant;

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
    let files = corpus_files(&root, 8000);

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
        keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(on));
        keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, Some(false));
    };
    let confirmed_only = |on: bool| {
        keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(false));
        keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, Some(on));
    };
    let both = |on: bool| {
        keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(on));
        keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, Some(on));
    };
    // Decode-recursion focus: homoglyph fold + confirmed gate stay at their
    // shipped default (on); toggle ONLY the focus restriction.
    let decode_focus = |on: bool| {
        keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(true));
        keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, Some(true));
        keyhog_scanner::testing::set_decode_focus(&scanner, Some(on));
    };
    // Prefilter {N,}->{N} truncation: keeps the always-active prefilter RegexSet
    // on the lazy-DFA. Other opts at shipped default; isolates the truncation.
    let prefilter_trunc = |on: bool| {
        keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, Some(true));
        keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, Some(true));
        keyhog_scanner::testing::set_decode_focus(&scanner, Some(true));
        keyhog_scanner::testing::set_prefilter_truncate(&scanner, Some(on));
    };
    eprintln!(
        "=== {} 16-KiB chunks ({} KiB), interleaved median of 9 ===",
        chunks.len(),
        bytes16 / 1024
    );
    eprint!("phase-2 localizer  ");
    ab_interleaved(&scanner, &chunks, bytes16, &fallback_only);
    eprint!("confirmed gate      ");
    ab_interleaved(&scanner, &chunks, bytes16, &confirmed_only);
    eprint!("both                ");
    ab_interleaved(&scanner, &chunks, bytes16, &both);
    eprint!("decode focus        ");
    ab_interleaved(&scanner, &chunks, bytes16, &decode_focus);
    eprint!("prefilter truncate  ");
    ab_interleaved(&scanner, &chunks, bytes16, &prefilter_trunc);

    keyhog_scanner::testing::set_phase2_homoglyph_gate(&scanner, None);
    keyhog_scanner::testing::set_confirmed_suffix_gate(&scanner, None);
    keyhog_scanner::testing::set_decode_focus(&scanner, None);
    keyhog_scanner::testing::set_prefilter_truncate(&scanner, None);
}
