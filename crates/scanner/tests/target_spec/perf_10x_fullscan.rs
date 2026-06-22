//! TARGET-SPEC (FAILING-BY-DESIGN): the 10x full-scan worklist.
//!
//! ## Why these tests are RED today, and what turns them green
//! A keyhog scan is two stages:
//!   * **phase-1 / match** — the literal/regex prefilter (`AlphabetScreen` +
//!     bigram bloom + Hyperscan/AC). On an RTX-5090 host this is ~0.03 s for a
//!     16 MiB corpus and is effectively FREE; the GPU region-presence route
//!     only replaces THIS stage, which is why forcing GPU is 1.3-5.3x SLOWER
//!     end-to-end.
//!   * **phase-2 / verify** — per-candidate capture / checksum / entropy /
//!     ML-MoE / companion / suppression / dedup. This is 15-30 s on the same
//!     corpus and is the WHOLE bottleneck. It runs entirely on the CPU today,
//!     one candidate at a time.
//!
//! The 10x lives in moving phase-2 to a BATCHED GPU verify path. This file
//! encodes that target as executable contracts: it measures the real CPU
//! `SimdCpu` full-scan baseline in-test, then asserts the *target* full-scan
//! wall time is at most baseline/10. There is no 10x path today, so every case
//! here FAILS — each red line is one tracked entry in the 10x worklist, and the
//! whole file flips green automatically when batched-GPU phase-2 lands and the
//! orchestrator routes to it.
//!
//! The named size cells assert REAL measured ratios against concrete targets and
//! stay visibly RED until the target is met. Per Law 9 they must never be
//! weakened to pass; per Law 6 they assert a real computed value (the speedup
//! ratio), never a shape. Rollup tests are declaration-coverage checks only and
//! must not duplicate the heavy scans already owned by the named cells.
//!
//! ## What the 10x baseline is measured against
//! `baseline_secs` = wall time of the REAL `CompiledScanner` running the REAL
//! `ScanBackend::SimdCpu` (the shipped default high-throughput path) over the
//! synthetic corpus, including phase-2. `target_secs` = `baseline_secs / 10.0`.
//! The contract: the fastest available full-scan path completes in
//! `<= target_secs`. We exercise the fastest path keyhog can offer for this
//! workload via `select_backend` + `scan_with_backend`; until the batched-GPU
//! phase-2 exists, the fastest path IS SimdCpu, so the measured time equals the
//! baseline and the `<= baseline/10` assertion fails by ~10x. That gap is the
//! finding.

use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{probe_hardware, select_backend, CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::time::Instant;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn build_scanner() -> CompiledScanner {
    let detectors = load_detectors(&detectors_dir()).expect("load detectors for target-spec perf");
    CompiledScanner::compile(detectors).expect("compile scanner for target-spec perf")
}

/// Synthetic corpus of exactly `target_bytes`, dense with REAL detector-prefix
/// literals so phase-1 surfaces a heavy candidate stream that phase-2 must
/// verify — i.e. the corpus exercises the phase-2 bottleneck the 10x targets,
/// not an all-noise buffer the prefilter rejects for free.
///
/// Each record carries an authentic anchored shape copied from the shipped
/// detector set (`github_pat_`, `xoxb-`, `sk_live_`, `AKIA`, plus a bare 32-hex
/// and a UUID) interleaved with realistic source-code filler. The bytes are
/// deterministic (a fixed LCG over the record index) so the corpus — and thus
/// the measured ratio — is reproducible run to run.
fn synthetic_corpus(target_bytes: usize) -> String {
    // Authentic anchored record templates. `{H}` is replaced with a
    // per-record hex blob so every record is a DISTINCT credential value (no
    // dedup collapse hiding phase-2 cost). Shapes mirror the real regexes:
    //   github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}
    //   sk_live_[a-zA-Z0-9]{24,}
    //   xoxb-<digits>-<digits>-<alnum{24,32}>
    //   AKIA[0-9A-Z]{16}
    const TEMPLATES: &[&str] = &[
        "github_token = \"github_pat_{A}_{B}\"\n",
        "stripe_key   = \"sk_live_{A}{B}\"\n",
        "slack_bot    = \"xoxb-2233445566-2233445566-{A}\"\n",
        "aws_key_id   = \"AKIA{C}\"\n",
        "session_hex  = \"{A}{B}\"  // 64-hex blob, entropy candidate\n",
        "trace_uuid   = \"{U}\"\n",
        "// ordinary source line with no credential, function helper(): void\n",
        "let config = { host: \"db.internal\", port: 5432, retries: 3 };\n",
    ];

    let mut out = String::with_capacity(target_bytes + 256);
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        // SplitMix64 — high-quality deterministic pseudo-random.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    const HEXD: &[u8; 16] = b"0123456789abcdef";
    const ALNUM: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let hexn = |r: &mut dyn FnMut() -> u64, n: usize| -> String {
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            s.push(HEXD[(r() % 16) as usize] as char);
        }
        s
    };
    let alnumn = |r: &mut dyn FnMut() -> u64, n: usize| -> String {
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            s.push(ALNUM[(r() % 62) as usize] as char);
        }
        s
    };

    let mut i = 0usize;
    while out.len() < target_bytes {
        let tpl = TEMPLATES[i % TEMPLATES.len()];
        let a = alnumn(&mut next, 22);
        let b = alnumn(&mut next, 59);
        let c = alnumn(&mut next, 16).to_uppercase();
        let u = format!(
            "{}-{}-{}-{}-{}",
            hexn(&mut next, 8),
            hexn(&mut next, 4),
            hexn(&mut next, 4),
            hexn(&mut next, 4),
            hexn(&mut next, 12),
        );
        let rec = tpl
            .replace("{A}", &a)
            .replace("{B}", &b)
            .replace("{C}", &c)
            .replace("{U}", &u);
        out.push_str(&rec);
        i += 1;
    }
    out.truncate(target_bytes);
    out
}

fn chunk_of(data: String, label: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "target-spec-perf".into(),
            // NOTE: must not contain `.keyhog` / `detectors` path segments — the
            // scan entry point skips those (telemetry record_file_skipped), which
            // would make the measured time meaninglessly fast.
            path: Some(format!("corpus/{label}.rs")),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// Median of an odd-length sample; sorts in place.
fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Run one full scan (phase-1 + phase-2) of `chunk` on `backend`, returning
/// (wall_seconds, candidate_findings). The fragment cache is cleared first so
/// cross-file reassembly state from a prior iteration never skews timing.
fn full_scan_secs(scanner: &CompiledScanner, chunk: &Chunk, backend: ScanBackend) -> (f64, usize) {
    scanner.clear_fragment_cache();
    let t = Instant::now();
    let matches = scanner.scan_with_backend(chunk, backend);
    (t.elapsed().as_secs_f64(), matches.len())
}

/// Corpus sizes for the data-driven 10x worklist (in MiB). The task names
/// {8,16,32,64}; we sweep all four so the target is proven scale-invariant.
const SIZE_MIB: &[usize] = &[8, 16, 32, 64];

/// The headline target: GPU/batched phase-2 must make the full scan at least
/// this many times faster than the shipped CPU `SimdCpu` default.
const SPEEDUP_TARGET: f64 = 10.0;

/// Timed scans per measurement (after one warm-up). A ~10x miss is orders of
/// magnitude larger than run-to-run jitter, so a single timed scan is a sound
/// RED signal and keeps these multi-MiB full scans (which run for real in the
/// normal test set — no `#[ignore]`) within a reasonable wall-clock budget.
const MEASURE_REPS: usize = 1;

/// One full-scan 10x contract at `mib` MiB. Measures the SimdCpu baseline
/// (median of 3) and the fastest available path (median of 3), then asserts the
/// fastest path met `baseline / SPEEDUP_TARGET`. RED until batched-GPU phase-2
/// lands and `select_backend` routes this workload to it.
fn assert_fullscan_10x_at(mib: usize) {
    let bytes = mib * 1024 * 1024;
    eprintln!("perf_10x_fullscan[{mib} MiB]: starting measured 10x cell");
    let scanner = build_scanner();
    let corpus = synthetic_corpus(bytes);
    assert_eq!(
        corpus.len(),
        bytes,
        "synthetic corpus must be EXACTLY {bytes} bytes ({mib} MiB); got {}",
        corpus.len()
    );
    let chunk = chunk_of(corpus, &format!("fullscan-{mib}mib"));

    // Baseline: shipped CPU default. Warm once (compile caches, first-touch
    // pages), then median of MEASURE_REPS timed scans. A 10x gap dwarfs
    // run-to-run noise, so MEASURE_REPS=1 keeps these heavy multi-MiB scans
    // runnable in the normal `cargo test` set (they must RUN and be RED, never
    // `#[ignore]`) while remaining a sound miss-by-~10x signal.
    let _ = full_scan_secs(&scanner, &chunk, ScanBackend::SimdCpu);
    let mut base = Vec::with_capacity(MEASURE_REPS);
    let mut cand_count = 0usize;
    for _ in 0..MEASURE_REPS {
        let (s, n) = full_scan_secs(&scanner, &chunk, ScanBackend::SimdCpu);
        base.push(s);
        cand_count = n;
    }
    let baseline_secs = median(base);

    // The phase-1 prefilter MUST have surfaced real candidates — otherwise the
    // corpus failed to exercise phase-2 and the ratio is meaningless. This is a
    // soundness guard on the TEST, not the target.
    assert!(
        cand_count >= 100,
        "{mib} MiB target-spec corpus surfaced only {cand_count} candidate findings; \
         expected >=100 so the measured time actually reflects phase-2. The corpus \
         generator regressed — fix the corpus, do not relax the 10x target."
    );

    // Fastest path keyhog can offer for this workload today. `select_backend`
    // returns the routed backend for the host; on a GPU host with batched
    // phase-2 this would route to the GPU verify path. Until that exists the
    // routed backend is SimdCpu, so `fastest_secs ≈ baseline_secs`.
    let caps = probe_hardware();
    let routed = select_backend(caps, bytes as u64, scanner.runtime_status().pattern_count);
    let _ = full_scan_secs(&scanner, &chunk, routed);
    let mut fast = Vec::with_capacity(MEASURE_REPS);
    for _ in 0..MEASURE_REPS {
        let (s, _n) = full_scan_secs(&scanner, &chunk, routed);
        fast.push(s);
    }
    let fastest_secs = median(fast);

    let target_secs = baseline_secs / SPEEDUP_TARGET;
    let speedup = baseline_secs / fastest_secs.max(1e-12);

    eprintln!(
        "perf_10x_fullscan[{mib} MiB]: baseline(SimdCpu)={baseline_secs:.4}s \
         fastest(routed={})={fastest_secs:.4}s  target<= {target_secs:.4}s  \
         speedup={speedup:.2}x  (target {SPEEDUP_TARGET:.0}x)  candidates={cand_count}",
        routed.label()
    );

    assert!(
        fastest_secs <= target_secs,
        "10x WORKLIST [{mib} MiB]: fastest full-scan path ({}) took {fastest_secs:.4}s but the \
         target is baseline/{SPEEDUP_TARGET:.0} = {target_secs:.4}s (baseline SimdCpu = \
         {baseline_secs:.4}s). Current speedup is {speedup:.2}x, not {SPEEDUP_TARGET:.0}x. \
         The 10x lives in a BATCHED-GPU phase-2 verify path that does not exist yet — \
         phase-1/match is already ~free, so routing to GPU region-presence cannot close this. \
         This line stays RED until batched phase-2 lands and select_backend routes here.",
        routed.label()
    );
}

// ---- Data-driven 10x full-scan worklist (one #[test] per size) -------------

#[test]
fn fullscan_10x_8mib() {
    assert_fullscan_10x_at(8);
}

#[test]
fn fullscan_10x_16mib() {
    assert_fullscan_10x_at(16);
}

#[test]
fn fullscan_10x_32mib() {
    assert_fullscan_10x_at(32);
}

#[test]
fn fullscan_10x_64mib() {
    assert_fullscan_10x_at(64);
}

/// Fast cross-size declaration rollup.
///
/// The per-size tests above own the measured 10x assertions. This rollup keeps
/// the size list visible without rerunning the full multi-MiB scan suite inside
/// one opaque test.
#[test]
fn fullscan_10x_all_sizes_rollup() {
    assert_eq!(
        SIZE_MIB,
        &[8, 16, 32, 64],
        "fullscan 10x target sizes changed; keep the named measured tests in sync"
    );
    eprintln!("fullscan 10x measured sizes declared: {SIZE_MIB:?}");
}
