//! Reproducer for task #56 - GPU AC kernel drops the
//! `stackblitz-credentials` finding at offset 1801032 of
//! `big_with_secrets.txt` while CPU SIMD and GPU literal-set both
//! find it. The original observation comes from
//! `.internal/bench/bench_all.sh`, where the scoreboard has long
//! documented this as a known-broken cell pending a real fix.
//!
//! Reproduction strategy: drive a real `CompiledScanner` (loads the
//! full 889-detector set, identical to what the binary uses) over
//! the actual bench-corpus slice that contains the missed secret,
//! then compare SIMD vs GPU AC findings. The slice is read directly
//! from the persisted bench corpus on disk so the bug we reproduce
//! is the same bug the bench surfaces, not a synthetic
//! approximation.
//!
//! Skipped when:
//! - the bench corpus isn't present (CI image without the persisted
//!   corpus volume; the `build_corpora.sh` script provisions it but
//!   it lives outside the repo so a fresh clone won't have it),
//! - no compatible wgpu adapter is detected.
//!
//! When the bug is fixed this test stops being a skip-on-no-corpus
//! repro and becomes a regression gate: the SIMD vs GPU finding
//! sets MUST agree at the stackblitz offset (and globally, on this
//! slice).

use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn bench_corpus_path() -> PathBuf {
    PathBuf::from("/media/mukund-thiru/SanthData/keyhog-bench-corpora/big_with_secrets.txt")
}

/// Offset of the `sb_4bZ39EnIvgTAxogqQ1wam7az` credential in
/// `big_with_secrets.txt`. The corpus is deterministically built by
/// `.internal/bench/build_corpora.sh` and this offset is stable
/// across rebuilds - the planted-secrets section is appended last,
/// after a fixed-size source-tree prefix.
const STACKBLITZ_OFFSET: usize = 1_801_032;
const STACKBLITZ_TOKEN: &str = "sb_4bZ39EnIvgTAxogqQ1wam7az";

/// Read a window from the bench corpus centered on the stackblitz
/// offset. 64 KiB is enough to cover the AC's bounded suffix window
/// many times over while staying small enough that the test runs in
/// seconds, not minutes.
fn read_window() -> Option<Vec<u8>> {
    let path = bench_corpus_path();
    if !path.exists() {
        return None;
    }
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(&path).ok()?;
    let win_start = STACKBLITZ_OFFSET.saturating_sub(8 * 1024);
    f.seek(SeekFrom::Start(win_start as u64)).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn make_chunk(bytes: Vec<u8>) -> Chunk {
    let s = String::from_utf8_lossy(&bytes).into_owned();
    Chunk {
        data: s.into(),
        metadata: ChunkMetadata {
            source_type: "bench".into(),
            path: Some("big_with_secrets.txt".into()),
            ..Default::default()
        },
    }
}

fn finds_stackblitz(matches: &[keyhog_core::RawMatch]) -> bool {
    matches.iter().any(|m| {
        let cred: &str = m.credential.as_ref();
        cred.contains(STACKBLITZ_TOKEN)
    })
}

/// CPU/SIMD baseline: confirms the planted secret is detectable at
/// all by the loaded detector set. If this fails the corpus or the
/// detector set has drifted, not the AC kernel.
#[test]
fn baseline_simd_finds_stackblitz_token() {
    let Some(window) = read_window() else {
        eprintln!(
            "SKIP: bench corpus not present at {:?}",
            bench_corpus_path()
        );
        return;
    };
    // Sanity: the window must actually contain the planted token,
    // otherwise neither backend would be expected to find it.
    let s = String::from_utf8_lossy(&window);
    assert!(
        s.contains(STACKBLITZ_TOKEN),
        "fixture window does not contain {STACKBLITZ_TOKEN}; \
         corpus drift - rebuild via .internal/bench/build_corpora.sh"
    );

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = make_chunk(window);
    let matches = scanner.scan(&chunk);
    assert!(
        finds_stackblitz(&matches),
        "SIMD/CPU baseline must find {STACKBLITZ_TOKEN}; got {} matches: {:?}",
        matches.len(),
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>(),
    );
}

/// Narrow repro: 64 KiB window around the missed offset. This
/// passed on first introduction - the AC kernel handles the
/// secret in isolation; the bug only manifests on the full-corpus
/// dispatch path below.
#[test]
fn gpu_ac_kernel_finds_stackblitz_token_in_narrow_window() {
    let Some(window) = read_window() else {
        eprintln!(
            "SKIP: bench corpus not present at {:?}",
            bench_corpus_path()
        );
        return;
    };
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Skip when no GPU adapter is available - we can't claim AC
    // kernel parity if the kernel can't even run. The skip is loud
    // (eprintln) so a no-GPU machine doesn't fake-pass.
    let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
        eprintln!("SKIP: no wgpu adapter available");
        return;
    };

    let chunks = [make_chunk(window)];
    // Direct call to the AC dispatch path - independent of the
    // env-var routing in scan_chunks_with_backend. If
    // scan_coalesced_gpu_ac falls back internally (e.g. matcher
    // unavailable), we still get a result; finds_stackblitz then
    // reflects the AC outcome OR the fallback outcome, which is
    // what an end user would see at KEYHOG_GPU_KERNEL=ac.
    let ac_results = scanner.scan_coalesced_gpu_ac(&chunks);
    let ac_flat: Vec<_> = ac_results.into_iter().flatten().collect();
    assert!(
        finds_stackblitz(&ac_flat),
        "GPU AC kernel missed {STACKBLITZ_TOKEN} at corpus offset \
         {STACKBLITZ_OFFSET} in narrow window. Found {} matches: {:?}",
        ac_flat.len(),
        ac_flat
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.location.offset))
            .collect::<Vec<_>>(),
    );
}

/// Bisection: feed the AC dispatch progressively larger windows
/// around the FIRST stackblitz occurrence (corpus byte 1_801_050)
/// and report which window size loses the finding. Pinpoints the
/// shard-count / coalesced-buffer-length threshold at which the
/// kernel-or-routing pipeline silently drops the match.
///
/// Sizes intentionally span the WGSL workgroup-count ceiling of
/// 65 535 (≈ 4 194 240 bytes at wg64): 1 MiB, 2 MiB, 4 MiB, 5 MiB,
/// 8 MiB, 16 MiB, 32 MiB. If recall drops between two adjacent sizes,
/// the threshold is in that interval and the fix is whatever
/// pipeline stage's bound is crossed.
#[test]
fn bisect_gpu_ac_recall_by_window_size() {
    let path = bench_corpus_path();
    if !path.exists() {
        eprintln!("SKIP: bench corpus not present at {:?}", path);
        return;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: bench corpus unreadable: {e}");
            return;
        }
    };
    let needle = STACKBLITZ_TOKEN.as_bytes();
    let Some(needle_off) = bytes.windows(needle.len()).position(|w| w == needle) else {
        eprintln!("SKIP: corpus missing planted token");
        return;
    };

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
        eprintln!("SKIP: no wgpu adapter available");
        return;
    };

    const MIB: usize = 1024 * 1024;
    // Sizes around the 1-shard / 2-shard boundary (max single-shard
    // bytes = 65 535 × 64 = 4 194 240). 3 MiB, 4 194 240, 4 194 241,
    // and 5 MiB pinpoint whether the regression is shard-count
    // (single vs split) or content-position (where in the buffer
    // the planted token lands).
    let sizes = [
        1 * MIB,
        2 * MIB,
        3 * MIB,
        4_194_240,      // exactly 1 shard at the WGSL workgroup cap
        4_194_240 + 64, // first byte over → 2 shards
        4 * MIB,
        5 * MIB,
        8 * MIB,
        16 * MIB,
        32 * MIB,
    ];

    let mut report = Vec::new();
    for &size in &sizes {
        // Center the window on the planted offset so the token lives
        // at window-local offset ≈ size/2 - never at a shard boundary
        // unless the window itself crosses one.
        let win_start = needle_off.saturating_sub(size / 2);
        let win_end = (win_start + size).min(bytes.len());
        let window = bytes[win_start..win_end].to_vec();
        let chunk = make_chunk(window.clone());

        // Drive both backends over the SAME bytes. If SIMD finds it
        // and AC misses it, the bug is purely AC-side. If both miss
        // it, the chunk-coalesce + dedup downstream is dropping it.
        let ac_results = scanner.scan_coalesced_gpu_ac(std::slice::from_ref(&chunk));
        let ac_flat: Vec<_> = ac_results.into_iter().flatten().collect();
        let ac_hit = finds_stackblitz(&ac_flat);
        let ac_stackblitz_count = ac_flat
            .iter()
            .filter(|m| m.detector_id.as_ref() == "stackblitz-credentials")
            .count();

        let simd_matches = scanner.scan(&chunk);
        let simd_hit = finds_stackblitz(&simd_matches);
        let simd_stackblitz_count = simd_matches
            .iter()
            .filter(|m| m.detector_id.as_ref() == "stackblitz-credentials")
            .count();

        let expected_shards = (win_end - win_start).div_ceil(65_535 * 64);
        report.push((size, ac_flat.len(), ac_hit, expected_shards));
        eprintln!(
            "bisect {:>10} bytes win_start={:>10} stackblitz_local={:>10} \
             ac={:>5} hit={} ac_sb={} | simd={:>5} hit={} simd_sb={} | shards={}",
            size,
            win_start,
            needle_off - win_start,
            ac_flat.len(),
            ac_hit,
            ac_stackblitz_count,
            simd_matches.len(),
            simd_hit,
            simd_stackblitz_count,
            expected_shards,
        );
    }

    // Find the smallest size where recall breaks. The bisection
    // surfaces a real defect when ANY size > 0 misses the planted
    // token, since the narrow_window test already confirms the
    // kernel can find it in isolation.
    let first_miss = report.iter().find(|(_, _, hit, _)| !hit);
    if let Some((size, n, _, shards)) = first_miss {
        panic!(
            "TASK #56 bisection: recall broke at window size {} bytes \
             ({} matches, {} shards). Narrow 64 KiB window finds the \
             same token via the same dispatch, so the bug lives in \
             whatever pipeline stage's bound is crossed between the \
             narrow-window size and this size.",
            size, n, shards,
        );
    }
}

/// Full-corpus repro: ingests the entire 64 MiB bench corpus as a
/// single `Chunk` (mirrors how `keyhog scan big_with_secrets.txt`
/// chunks it - the default `window_size` is 64 MiB, so a 64-MiB
/// file is a single chunk by design). This is the dispatch shape
/// the bench harness measures, so reproducing it in-process gives
/// a focused unit-of-debug independent of the CLI wrapper.
///
/// Expected current behaviour: this test will FAIL - it's the
/// regression gate for task #56. When the kernel is fixed and the
/// scoreboard's gpu-ac/big_with_secrets cell's expected count
/// moves from 14 to 15, this test starts passing.
#[test]
fn gpu_ac_kernel_must_find_stackblitz_token_on_full_corpus() {
    let path = bench_corpus_path();
    if !path.exists() {
        eprintln!("SKIP: bench corpus not present at {:?}", path);
        return;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: bench corpus unreadable: {e}");
            return;
        }
    };
    // Sanity: the planted token must live at the expected offset.
    let token_bytes = STACKBLITZ_TOKEN.as_bytes();
    if !bytes.windows(token_bytes.len()).any(|w| w == token_bytes) {
        eprintln!(
            "SKIP: bench corpus does not contain planted token \
             {STACKBLITZ_TOKEN}; rebuild via .internal/bench/build_corpora.sh"
        );
        return;
    }

    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
        eprintln!("SKIP: no wgpu adapter available");
        return;
    };

    let chunks = [make_chunk(bytes)];

    // First: direct call to the AC dispatch path. This is the
    // engine surface keyhog's CLI ultimately routes to.
    let direct_results = scanner.scan_coalesced_gpu_ac(&chunks);
    let direct_flat: Vec<_> = direct_results.into_iter().flatten().collect();
    let direct_has_stackblitz = finds_stackblitz(&direct_flat);

    // Second: same input + same scanner, but through the
    // production routing layer: `scan_chunks_with_backend(Gpu)`
    // with `KEYHOG_GPU_KERNEL=ac` set. This is the path the
    // binary takes when invoked as `keyhog scan --backend gpu`
    // with the env var on.
    // SAFETY: single-threaded integration test; process-wide env
    // var write is safe (Rust 2024 marked set_var unsafe to
    // signal the multi-threading hazard, which doesn't apply
    // here - cargo runs each integration test binary in its own
    // process).
    unsafe {
        std::env::set_var("KEYHOG_GPU_KERNEL", "ac");
    }
    let routed_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let routed_flat: Vec<_> = routed_results.into_iter().flatten().collect();
    let routed_has_stackblitz = finds_stackblitz(&routed_flat);

    // Diagnostic emit so the test failure narrows the surface
    // (not just "missed it" - *which* path missed it).
    eprintln!(
        "diagnostic - direct: {} matches, finds_stackblitz={}; \
         routed: {} matches, finds_stackblitz={}",
        direct_flat.len(),
        direct_has_stackblitz,
        routed_flat.len(),
        routed_has_stackblitz,
    );

    assert!(
        direct_has_stackblitz,
        "TASK #56: direct scan_coalesced_gpu_ac dropped {STACKBLITZ_TOKEN} \
         on the full 64-MiB corpus. The AC kernel is broken at the kernel \
         level. Found {} matches.",
        direct_flat.len(),
    );
    assert!(
        routed_has_stackblitz,
        "TASK #56: scan_chunks_with_backend(Gpu) + KEYHOG_GPU_KERNEL=ac \
         dropped {STACKBLITZ_TOKEN} on the full 64-MiB corpus. The kernel \
         finds it via direct dispatch (above), so the bug is in the routing \
         layer between scan_chunks_with_backend and scan_coalesced_gpu_ac \
         (most likely a per-chunk preparation step that shifts byte offsets). \
         Found {} matches.",
        routed_flat.len(),
    );
}
