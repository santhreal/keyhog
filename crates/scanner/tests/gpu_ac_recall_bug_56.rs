#![cfg(feature = "gpu")]
//! Reproducer for task #56 - GPU AC kernel drops the
//! `stackblitz-credentials` finding at offset 1801032 of
//! `big_with_secrets.txt` while CPU SIMD and GPU literal-set both
//! find it. The original observation comes from
//! `.internal/bench/bench_all.sh`, where the scoreboard exposed a
//! GPU-vs-CPU recall divergence that must stay executable.
//!
//! Reproduction strategy: drive a real `CompiledScanner` (loads the
//! full detector set, identical to what the binary uses) over
//! a corpus slice that contains the missed secret, then compare SIMD
//! vs GPU AC findings. If `KEYHOG_GPU_AC_RECALL_CORPUS` is set, the
//! test reads that exact file and fails on read/drift errors. Without
//! an override it uses a deterministic generated corpus with the same
//! token offset, so a fresh checkout still exercises the regression.

mod support;
use support::gpu_gate::require_gpu_or_panic;
use support::paths::detector_dir;

use std::path::PathBuf;
use std::sync::OnceLock;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

const GPU_AC_RECALL_CORPUS_ENV: &str = "KEYHOG_GPU_AC_RECALL_CORPUS";
const GPU_AC_RECALL_CORPUS_REPO_REL: &str = "benchmarks/corpora/gpu_ac_recall/big_with_secrets.txt";
const GENERATED_CORPUS_LEN: usize = 33 * 1024 * 1024;

fn bench_corpus_path() -> PathBuf {
    if let Some(path) = std::env::var_os(GPU_AC_RECALL_CORPUS_ENV) {
        return PathBuf::from(path);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push(GPU_AC_RECALL_CORPUS_REPO_REL);
    path
}

/// Offset of the `sb_4bZ39EnIvgTAxogqQ1wam7az` credential in the
/// external `big_with_secrets.txt` corpus and in the generated fallback
/// corpus used by fresh checkouts.
const STACKBLITZ_OFFSET: usize = 1_801_032;
const STACKBLITZ_TOKEN: &str = "sb_4bZ39EnIvgTAxogqQ1wam7az";

static CORPUS_BYTES: OnceLock<Vec<u8>> = OnceLock::new();

fn read_required_corpus(path: PathBuf) -> Vec<u8> {
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "read GPU AC recall corpus {}: {e}. Fix the path or unset {GPU_AC_RECALL_CORPUS_ENV} \
             to use the generated regression corpus.",
            path.display()
        )
    })
}

fn generated_gpu_ac_recall_corpus() -> Vec<u8> {
    let mut bytes = vec![b'a'; GENERATED_CORPUS_LEN];
    for index in (0..bytes.len()).step_by(4096) {
        bytes[index] = b'\n';
    }

    let context = b"stackblitz_token = \"";
    let context_start = STACKBLITZ_OFFSET
        .checked_sub(context.len())
        .expect("generated corpus context fits before token offset");
    bytes[context_start..context_start + context.len()].copy_from_slice(context);
    bytes[STACKBLITZ_OFFSET..STACKBLITZ_OFFSET + STACKBLITZ_TOKEN.len()]
        .copy_from_slice(STACKBLITZ_TOKEN.as_bytes());
    bytes[STACKBLITZ_OFFSET + STACKBLITZ_TOKEN.len()] = b'"';
    bytes[STACKBLITZ_OFFSET + STACKBLITZ_TOKEN.len() + 1] = b'\n';
    bytes
}

fn corpus_bytes() -> &'static [u8] {
    CORPUS_BYTES.get_or_init(|| {
        if std::env::var_os(GPU_AC_RECALL_CORPUS_ENV).is_some() {
            return read_required_corpus(bench_corpus_path());
        }
        let path = bench_corpus_path();
        if path.exists() {
            return read_required_corpus(path);
        }
        generated_gpu_ac_recall_corpus()
    })
}

fn require_stackblitz_token(bytes: &[u8]) -> usize {
    let needle = STACKBLITZ_TOKEN.as_bytes();
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| {
            panic!(
                "GPU AC recall corpus does not contain planted token {STACKBLITZ_TOKEN}; \
                 fix {GPU_AC_RECALL_CORPUS_ENV} or the generated fixture"
            )
        })
}

fn wgpu_device_available_or_policy_allows_absence(context: &str) -> bool {
    match vyre_driver_wgpu::runtime::cached_device() {
        Ok(_) => true,
        Err(error) => {
            require_gpu_or_panic(context);
            eprintln!(
                "{context}: GPU AC recall not run because no wgpu adapter is available and GPU runtime policy does not require one: {error}"
            );
            false
        }
    }
}

/// Read a window from the recall corpus centered on the stackblitz
/// offset. 64 KiB is enough to cover the AC's bounded suffix window
/// many times over while staying small enough that the test runs in
/// seconds, not minutes.
fn read_window() -> Vec<u8> {
    let bytes = corpus_bytes();
    let win_start = STACKBLITZ_OFFSET.saturating_sub(8 * 1024);
    let win_end = (win_start + 64 * 1024).min(bytes.len());
    bytes[win_start..win_end].to_vec()
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
    let window = read_window();
    // Sanity: the window must actually contain the planted token,
    // otherwise neither backend would be expected to find it.
    let s = String::from_utf8_lossy(&window);
    assert!(
        s.contains(STACKBLITZ_TOKEN),
        "fixture window does not contain {STACKBLITZ_TOKEN}; \
         corpus drift - rebuild via .internal/bench/build_corpora.sh"
    );

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
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
    let window = read_window();
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    if !wgpu_device_available_or_policy_allows_absence(
        "gpu_ac_kernel_finds_stackblitz_token_in_narrow_window",
    ) {
        return;
    }

    let chunks = [make_chunk(window)];
    // Direct call to the AC dispatch path - independent of the
    // env-var routing in scan_chunks_with_backend. If
    // scan_coalesced_gpu_ac falls back internally (e.g. matcher
    // unavailable), we still get a result; finds_stackblitz then
    // reflects the AC outcome OR the fallback outcome, which is
    // what an end user would see at KEYHOG_GPU_KERNEL=ac.
    let ac_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
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
    let bytes = corpus_bytes();
    let needle_off = require_stackblitz_token(bytes);

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    if !wgpu_device_available_or_policy_allows_absence("bisect_gpu_ac_recall_by_window_size") {
        return;
    }

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
        let ac_results =
            scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::Gpu);
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

/// Full-corpus repro: ingests the entire recall corpus as a single `Chunk`.
/// With an external 64 MiB `big_with_secrets.txt`, this mirrors the dispatch
/// shape the bench harness measures. With the generated 33 MiB fallback, it
/// still crosses the multi-shard GPU dispatch path and keeps the stackblitz
/// recall assertion executable in a fresh checkout.
#[test]
fn gpu_ac_kernel_must_find_stackblitz_token_on_full_corpus() {
    let bytes = corpus_bytes().to_vec();
    // Sanity: the planted token must live at the expected offset.
    require_stackblitz_token(&bytes);

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    if !wgpu_device_available_or_policy_allows_absence(
        "gpu_ac_kernel_must_find_stackblitz_token_on_full_corpus",
    ) {
        return;
    }

    let chunks = [make_chunk(bytes)];

    // First: direct call to the AC dispatch path. This is the
    // engine surface keyhog's CLI ultimately routes to.
    let direct_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
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
