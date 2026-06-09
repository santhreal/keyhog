//! Real-GPU correctness gate for vyre's region-attributed presence kernel
//! (`GpuLiteralSet::scan_presence_by_region`).
//!
//! The region-presence kernel is the dense-output optimization for keyhog's
//! coalesced GPU phase-1: instead of appending an `(id,start,end)` triple per hit
//! through a single global atomic counter (which collapses a ~554 MB/s scan to
//! ~4.4 MB/s on match-dense input and forces a large triple readback), it sets one
//! idempotent presence bit per `(region, pattern)` — staying near the scan
//! ceiling — and returns the per-file trigger bitmap keyhog already reduces to.
//!
//! This test asserts the new kernel is RECALL-IDENTICAL to the trusted triple path
//! it replaces: for the same coalesced haystack + region layout, the per-region
//! presence bitmap MUST equal the per-region reduction of `GpuLiteralSet::scan`'s
//! triples. If they ever diverge, the optimization is dropping (or inventing) a
//! per-file trigger — a recall bug — and this gate fails.
//!
//! Run (requires the GPU stack):
//!   cargo test --profile release-fast --features gpu -p keyhog-scanner \
//!     --test gpu_region_presence_parity -- --nocapture

#![cfg(feature = "gpu")]

mod support;
use support::paths::detector_dir;

use keyhog_scanner::CompiledScanner;

/// `presence_bitmap_words(pattern_count)` — mirrors vyre's row stride so the test
/// indexes the per-region bitmap the same way the kernel lays it out.
fn presence_words(pattern_count: usize) -> usize {
    pattern_count.div_ceil(32).max(1)
}

/// Largest region index `r` with `region_starts[r] <= pos` (the kernel's
/// binary-search attribution, computed straightforwardly on the host).
fn region_of(region_starts: &[u32], pos: u32) -> usize {
    let mut r = 0usize;
    for (idx, &start) in region_starts.iter().enumerate() {
        if start <= pos {
            r = idx;
        } else {
            break;
        }
    }
    r
}

#[test]
fn region_presence_equals_per_region_reduction_of_scan_triples() {
    use vyre_driver_wgpu::WgpuBackend;

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(matcher) = scanner.gpu_matcher() else {
        eprintln!("SKIP: no gpu_matcher (gpu_literals absent)");
        return;
    };
    let backend = match WgpuBackend::shared() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no wgpu backend ({e})");
            return;
        }
    };

    let pattern_count = matcher.pattern_lengths.len();
    let words = presence_words(pattern_count);

    // Build a coalesced haystack of independent "files", each carrying different
    // well-known secret-literal prefixes (present in the detector literal set), so
    // different regions fire different patterns — exercising region attribution.
    // Separators (NUL) between files prevent cross-file literal matches, exactly
    // like keyhog's coalesce buffer. region_starts[0] must be 0.
    let files: Vec<&str> = vec![
        "key = AKIAQYLPMN5HFIQR7BBB end",            // region 0: AWS
        "pat: ghp_xYz1234ABCD5678efgh9ijkl0123mnop", // region 1: github
        "nothing to see here, plain prose only",     // region 2: (likely none)
        "stripe sk_live_4eC39HqLyjWDarjtT1zdp7dc x",  // region 3: stripe
        "aws AKIAQYLPMN5HFIQR7BBB and ghp_xYz1234ABCD5678efgh9ijkl0123mnop", // region 4: both
    ];
    // Lowercase to match keyhog's literal-set fold (the matcher's literals are
    // lowercased); the AC literal automaton is case-folded on this buffer.
    let mut haystack: Vec<u8> = Vec::new();
    let mut region_starts: Vec<u32> = Vec::new();
    for f in &files {
        region_starts.push(haystack.len() as u32);
        haystack.extend_from_slice(f.to_ascii_lowercase().as_bytes());
        // 4 NUL separators: no detector literal contains NUL, so no match spans.
        haystack.extend_from_slice(&[0u8; 4]);
    }
    assert_eq!(region_starts[0], 0, "region_starts[0] must be 0");
    let region_count = region_starts.len();

    // Trusted path: scan() triples, reduced to a per-region presence bitmap.
    let max_matches: u32 = 1_000_000;
    let triples = matcher
        .scan(backend.as_ref(), &haystack, max_matches)
        .expect("gpu scan (triples)");
    let mut expected = vec![0u32; region_count * words];
    for m in &triples {
        // Attribute by start; a literal never spans a separator, so region(start)
        // == region(end-1) == the kernel's end-position attribution.
        let r = region_of(&region_starts, m.start);
        let pid = m.pattern_id as usize;
        expected[r * words + (pid >> 5)] |= 1u32 << (pid & 31);
    }

    // New path: region-attributed presence bitmap, directly from the kernel.
    let actual = matcher
        .scan_presence_by_region(backend.as_ref(), &haystack, &region_starts)
        .expect("gpu scan_presence_by_region");

    assert_eq!(
        actual.len(),
        region_count * words,
        "region-presence bitmap length {region_count}×{words} mismatch",
    );

    if actual != expected {
        // Surface the first divergent (region, word) for a debuggable failure.
        for r in 0..region_count {
            for w in 0..words {
                let a = actual[r * words + w];
                let e = expected[r * words + w];
                if a != e {
                    panic!(
                        "region-presence != scan-triple reduction at region {r} word {w}: \
                         presence=0x{a:08x} expected=0x{e:08x} (xor=0x{:08x}). \
                         The dense-output kernel dropped or invented a per-file trigger.",
                        a ^ e
                    );
                }
            }
        }
        panic!("region-presence != expected but no per-word diff found (length-only?)");
    }

    let fired_regions = (0..region_count)
        .filter(|&r| (0..words).any(|w| actual[r * words + w] != 0))
        .count();
    assert!(
        fired_regions >= 3,
        "expected >=3 regions to fire patterns (AWS/github/stripe/both); got {fired_regions}. \
         Either the literal set changed or the kernel under-fired.",
    );
    eprintln!(
        "region-presence parity OK: {region_count} regions, {} triples, {fired_regions} regions fired, {words} words/region",
        triples.len()
    );
}

/// End-to-end gate for the WIRED production path: a coalesced multi-chunk scan
/// through the scanner's actual GPU backend (region-presence phase-1 when the
/// backend self-test passes) must produce the same findings as the SIMD path.
/// Also reports which backend was acquired and whether region-presence engaged.
#[test]
fn wired_gpu_region_presence_matches_simd_recall() {
    use keyhog_core::{Chunk, ChunkMetadata};
    use keyhog_scanner::ScanBackend;

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    if scanner.gpu_backend_label().is_none() {
        eprintln!("SKIP: no GPU backend acquired");
        return;
    }
    let backend_label = scanner.gpu_backend_label().unwrap_or("?");
    let active = scanner.gpu_region_presence_active();
    eprintln!("WIRED region-presence: backend={backend_label} region_presence_active={active}");

    let mk = |text: &str, path: &str| Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "region-presence-e2e".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    // Multi-chunk batch with secrets in different chunks + empties between them,
    // so per-chunk attribution matters (a global bitmap would over/under-trigger).
    let chunks = vec![
        mk("const AWS = \"AKIAQYLPMN5HFIQR7BBB\";", "a.rs"),
        mk("// nothing here", "b.txt"),
        mk("pat = \"ghp_xYz1234ABCD5678efgh9ijkl0123mnop\"", "c.py"),
        mk("plain prose only, no credentials", "d.md"),
        mk("stripe = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"", "e.yml"),
    ];

    let collect = |b: ScanBackend| -> std::collections::BTreeSet<(String, usize)> {
        scanner
            .scan_chunks_with_backend(&chunks, b)
            .iter()
            .flat_map(|c| {
                c.iter()
                    .map(|m| (m.credential.as_ref().to_string(), m.location.offset))
            })
            .collect()
    };

    let simd = collect(ScanBackend::SimdCpu);
    let gpu = collect(ScanBackend::Gpu);

    // GPU may legitimately degrade to SIMD (no adapter) → both empty is a skip.
    if gpu.is_empty() && simd.is_empty() {
        eprintln!("SKIP: both backends empty (no adapter / no findings)");
        return;
    }
    assert_eq!(
        gpu, simd,
        "WIRED GPU path (region_presence_active={active}, backend={backend_label}) recall != SIMD.\n  \
         gpu-only={:?}\n  simd-only={:?}",
        gpu.difference(&simd).collect::<Vec<_>>(),
        simd.difference(&gpu).collect::<Vec<_>>(),
    );
    eprintln!("WIRED recall parity OK: {} findings via {backend_label}", gpu.len());
}

/// The production path SHARDS batches > 8.38 MiB and dispatches each slice with a
/// `region_base` offset against the whole-batch region table. The small-chunk
/// parity tests only ever hit one shard (base 0), so this test exercises the
/// multi-shard `region_base` mechanism directly: splitting the haystack at a
/// region boundary and OR-ing the two `region_base`-offset dispatches MUST equal a
/// single whole-buffer dispatch (no match straddles a separator-guarded boundary).
#[test]
fn sharded_region_presence_equals_single_dispatch() {
    use vyre_driver_wgpu::WgpuBackend;

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(matcher) = scanner.gpu_matcher() else {
        eprintln!("SKIP: no gpu_matcher");
        return;
    };
    let backend = match WgpuBackend::shared() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no wgpu backend ({e})");
            return;
        }
    };
    let pattern_count = matcher.pattern_lengths.len();
    let words = presence_words(pattern_count);

    // Files with secrets, NUL-separated; record region_starts and a split point at
    // a region boundary (so no literal match straddles the split).
    let files: [&str; 6] = [
        "a akiaqylpmn5hfiqr7bbb a",
        "b ghp_xyz1234abcd5678efgh9ijkl0123mnop b",
        "c sk_live_4ec39hqlyjwdarjtt1zdp7dc c",
        "d nothing here d",
        "e akiaqylpmn5hfiqr7ccc e",
        "f ghp_zzz1234abcd5678efgh9ijkl0123mnop f",
    ];
    let mut haystack: Vec<u8> = Vec::new();
    let mut region_starts: Vec<u32> = Vec::new();
    let split_after = 3usize; // shard boundary after region 3's start
    let mut split_off = 0usize;
    for (idx, f) in files.iter().enumerate() {
        region_starts.push(haystack.len() as u32);
        if idx == split_after {
            split_off = haystack.len();
        }
        haystack.extend_from_slice(f.as_bytes());
        haystack.extend_from_slice(&[0u8; 8]);
    }
    let region_count = region_starts.len();

    // Single whole-buffer dispatch (base 0).
    let single = matcher
        .scan_presence_by_region(backend.as_ref(), &haystack, &region_starts)
        .expect("single dispatch");

    // Two shards split at a region boundary, each with its global region_base,
    // both against the FULL region table; OR the per-shard bitmaps.
    let mut scratch = vyre_libs::scan::dispatch_io::ScanDispatchScratch::default();
    let shard0 = matcher
        .scan_presence_by_region_with_scratch(
            backend.as_ref(),
            &haystack[..split_off],
            &region_starts,
            0,
            &mut scratch,
        )
        .expect("shard 0");
    let shard1 = matcher
        .scan_presence_by_region_with_scratch(
            backend.as_ref(),
            &haystack[split_off..],
            &region_starts,
            split_off as u32,
            &mut scratch,
        )
        .expect("shard 1");
    let mut sharded = vec![0u32; region_count * words];
    for (acc, (a, b)) in sharded.iter_mut().zip(shard0.iter().zip(shard1.iter())) {
        *acc = *a | *b;
    }

    assert_eq!(
        sharded, single,
        "sharded region_base dispatch != single dispatch — multi-shard attribution is broken",
    );
    // Sanity: shard 0 must only touch regions < split_after, shard 1 only >=.
    for r in 0..region_count {
        let in_shard0 = (0..words).any(|w| shard0[r * words + w] != 0);
        let in_shard1 = (0..words).any(|w| shard1[r * words + w] != 0);
        if in_shard0 {
            assert!(r < split_after, "shard 0 wrote region {r} >= split {split_after}");
        }
        if in_shard1 {
            assert!(r >= split_after, "shard 1 wrote region {r} < split {split_after}");
        }
    }
    eprintln!("sharded region_base equivalence OK: {region_count} regions, split after {split_after}");
}

/// Oracle for the dense-output lever: on a match-DENSE coalesced batch the
/// triple-append `scan()` collapses on per-hit atomic-counter serialization + a
/// large triple readback, while `scan_presence_by_region` keeps the idempotent
/// per-region `atomic_or` and a compact bitmap readback — staying near the scan
/// ceiling. This measures both over the same buffer + 16 KiB region layout so the
/// speedup is honest (same kernel front-end, same haystack, only the output path
/// differs).
#[test]
#[ignore = "measurement; run with --features gpu --ignored --nocapture"]
fn region_presence_throughput_vs_scan_triples_dense() {
    use std::time::Instant;
    use vyre_driver_wgpu::WgpuBackend;

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(matcher) = scanner.gpu_matcher() else {
        eprintln!("SKIP: no gpu_matcher");
        return;
    };
    let backend = match WgpuBackend::shared() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no wgpu backend ({e})");
            return;
        }
    };

    // ~8 MB of deterministically secret-dense text (≈1 literal hit per ~30 B), the
    // regime that collapses the triple path. Kept under one wgpu dispatch's reach
    // (65535 workgroups × 128-wide = 8.38 MiB) so the measurement compares the two
    // OUTPUT paths over one dispatch each, without per-shard plumbing differences;
    // the production phase-1 shards larger batches. Lowercased to match the fold.
    let line = "x akiaqylpmn5hfiqr7bbb ghp_xyz1234abcd5678efgh9ijkl0123mnop sk_live_4ec39hqlyjwdarjtt1zdp7dc\n";
    const TARGET: usize = 8_000_000;
    let mut haystack: Vec<u8> = Vec::with_capacity(TARGET + line.len());
    while haystack.len() < TARGET {
        haystack.extend_from_slice(line.as_bytes());
    }
    let mb = haystack.len() as f64 / 1e6;

    // Region layout: one region per 16 KiB (the file-size class keyhog coalesces).
    const REGION: usize = 16 * 1024;
    let region_starts: Vec<u32> = (0..haystack.len()).step_by(REGION).map(|o| o as u32).collect();
    let n_regions = region_starts.len();

    // Warm (shader compile / first-dispatch init).
    let _ = matcher.scan(backend.as_ref(), &haystack[..4096], 4096);
    let _ = matcher.scan_presence_by_region(backend.as_ref(), &haystack[..REGION], &[0]);

    let max_matches: u32 = 4_000_000;
    let t = Instant::now();
    let triples = matcher
        .scan(backend.as_ref(), &haystack, max_matches)
        .expect("scan triples");
    let scan_ms = t.elapsed().as_secs_f64() * 1000.0;
    let scan_mbps = mb / (scan_ms / 1e3);

    let t = Instant::now();
    let presence = matcher
        .scan_presence_by_region(backend.as_ref(), &haystack, &region_starts)
        .expect("scan_presence_by_region");
    let pres_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pres_mbps = mb / (pres_ms / 1e3);

    let fired: usize = presence.iter().filter(|&&w| w != 0).count();
    eprintln!("\n=== dense-output lever on {mb:.1} MiB ({n_regions} × 16 KiB regions) ===");
    eprintln!(
        "  scan() triples            : {scan_ms:>8.1} ms  {scan_mbps:>9.1} MB/s  ({} triples)",
        triples.len()
    );
    eprintln!(
        "  scan_presence_by_region   : {pres_ms:>8.1} ms  {pres_mbps:>9.1} MB/s  ({fired} non-zero presence words)"
    );
    eprintln!(
        "  region-presence speedup   : {:.1}× over the triple-append path",
        pres_mbps / scan_mbps.max(1e-9)
    );
}
