//! TARGET-SPEC (FAILING-BY-DESIGN): the batched-GPU phase-2 verify worklist.
//!
//! ## The bottleneck this file targets
//! keyhog's full scan = phase-1 match (≈free, ~0.03 s / 16 MiB on RTX-5090) +
//! phase-2 verify (per-candidate capture / checksum / entropy / ML-MoE /
//! companion / suppression / dedup). Phase-2 is 15-30 s on the same corpus and
//! is ALL of the wall time. It runs on the CPU, one candidate at a time. The
//! GPU region-presence route only replaces phase-1, so forcing GPU is strictly
//! slower end-to-end — the 10x can only come from BATCHING phase-2 onto the GPU.
//!
//! ## The targets encoded here (concrete, defensible, RED today)
//!   1. **Per-candidate phase-2 cost `< PER_CANDIDATE_TARGET_US`.** A batched
//!      GPU verify amortizes fixed dispatch cost across the whole candidate
//!      stream; the per-candidate marginal cost target is 10 µs (= the
//!      throughput implied by target #2). Measured CPU per-candidate cost today
//!      is far higher, so this fails.
//!   2. **Batch verify of N candidates completes in `< N / 100_000` seconds.**
//!      i.e. ≥100k candidates/second sustained — the batched-GPU verify
//!      throughput target. Today's CPU phase-2 is well under 100k/s, so the
//!      measured wall time exceeds `N/100_000` and this fails.
//!
//! Phase-1 is ≈free relative to phase-2, so the full `scan_with_backend` wall
//! time is a SOUND, slightly-pessimistic proxy for phase-2 time: it can only
//! make the CPU look *slower*, never faster, so an assertion that the path is
//! fast ENOUGH cannot pass spuriously. When the real batched-GPU phase-2 lands,
//! the same `scan_with_backend(routed)` call drops below these targets and the
//! file flips green with no test change (Law 9: never weaken to pass).
//!
//! These RUN in the normal `cargo test` set and assert REAL measured µs/candidate
//! and candidates/second, not shapes (Law 6).

use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{probe_hardware, select_backend, CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::time::Instant;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn build_scanner() -> CompiledScanner {
    let detectors =
        load_detectors(&detectors_dir()).expect("load detectors for phase-2 target-spec");
    CompiledScanner::compile(detectors).expect("compile scanner for phase-2 target-spec")
}

/// Candidate-DENSE corpus: every line is an authentic anchored credential shape
/// so phase-1 surfaces a candidate for nearly every line and phase-2 has a
/// heavy, realistic stream to verify. Distinct values per line (no dedup
/// collapse). `target_lines` lines are emitted; the byte size follows.
fn candidate_dense_corpus(target_lines: usize) -> String {
    const TEMPLATES: &[&str] = &[
        "k = \"github_pat_{A22}_{A59}\"",
        "s = \"sk_live_{A24}{A16}\"",
        "b = \"xoxb-2233445566-2233445566-{A28}\"",
        "a = \"AKIA{U16}\"",
        "h = \"{H64}\"",
        "u = \"{UUID}\"",
    ];
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    const HEXD: &[u8; 16] = b"0123456789abcdef";
    const ALNUM: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let hexn = |r: &mut dyn FnMut() -> u64, n: usize| {
        (0..n)
            .map(|_| HEXD[(r() % 16) as usize] as char)
            .collect::<String>()
    };
    let alnumn = |r: &mut dyn FnMut() -> u64, n: usize| {
        (0..n)
            .map(|_| ALNUM[(r() % 62) as usize] as char)
            .collect::<String>()
    };

    let mut out = String::with_capacity(target_lines * 96);
    for i in 0..target_lines {
        let tpl = TEMPLATES[i % TEMPLATES.len()];
        let a22 = alnumn(&mut next, 22);
        let a59 = alnumn(&mut next, 59);
        let a24 = alnumn(&mut next, 24);
        let a16 = alnumn(&mut next, 16);
        let a28 = alnumn(&mut next, 28);
        let u16s = alnumn(&mut next, 16).to_uppercase();
        let h64 = hexn(&mut next, 64);
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            hexn(&mut next, 8),
            hexn(&mut next, 4),
            hexn(&mut next, 4),
            hexn(&mut next, 4),
            hexn(&mut next, 12)
        );
        let line = tpl
            .replace("{A22}", &a22)
            .replace("{A59}", &a59)
            .replace("{A24}", &a24)
            .replace("{A16}", &a16)
            .replace("{A28}", &a28)
            .replace("{U16}", &u16s)
            .replace("{H64}", &h64)
            .replace("{UUID}", &uuid);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn chunk_of(data: String, label: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "phase2-target-spec".into(),
            path: Some(format!("corpus/{label}.rs")),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Median full-scan wall seconds over `chunk`, and the candidate-finding count.
/// Full-scan time is a sound upper bound on phase-2 time (phase-1 ≈ free).
fn scan_secs_and_candidates(
    scanner: &CompiledScanner,
    chunk: &Chunk,
    backend: ScanBackend,
) -> (f64, usize) {
    scanner.clear_fragment_cache();
    let _ = scanner.scan_with_backend(chunk, backend); // warm
    let mut times = Vec::with_capacity(MEASURE_REPS);
    let mut n = 0usize;
    for _ in 0..MEASURE_REPS {
        scanner.clear_fragment_cache();
        let t = Instant::now();
        let m = scanner.scan_with_backend(chunk, backend);
        times.push(t.elapsed().as_secs_f64());
        n = m.len();
    }
    (median(times), n)
}

/// Candidate-stream sizes (lines ≈ candidates). Data-driven so the worklist
/// scales; each is one batched-phase-2 contract.
const CANDIDATE_LINES: &[usize] = &[10_000, 25_000, 50_000, 100_000];

/// Target #2: batched-GPU phase-2 must sustain >= this many candidates/second.
/// `N candidates < N / 100_000 s`  <=>  throughput >= 100_000 cand/s.
const TARGET_CANDS_PER_SEC: f64 = 100_000.0;

/// Target #1: per-candidate marginal phase-2 cost, in microseconds. 1/100_000 s
/// = 10 µs — the per-candidate budget implied by the 100k/s batch throughput.
const PER_CANDIDATE_TARGET_US: f64 = 10.0;

/// Timed scans per measurement after one warm-up. The current CPU phase-2 misses
/// the 100k cand/s target by a large factor — far beyond jitter — so one timed
/// scan is a sound RED signal and keeps the suite runnable (no `#[ignore]`).
const MEASURE_REPS: usize = 1;

/// `N candidates < N / 100_000 s` contract at a given candidate-stream size.
/// RED until batched-GPU phase-2 sustains 100k candidates/s.
fn assert_batch_phase2_throughput_at(lines: usize) {
    let scanner = build_scanner();
    let corpus = candidate_dense_corpus(lines);
    let chunk = chunk_of(corpus, &format!("phase2-{lines}"));

    let caps = probe_hardware();
    let routed = select_backend(
        caps,
        chunk.data.len() as u64,
        scanner.runtime_status().pattern_count,
    );
    let (secs, n) = scan_secs_and_candidates(&scanner, &chunk, routed);

    assert!(
        n >= lines / 4,
        "candidate-dense corpus of {lines} lines surfaced only {n} candidates (expected \
         >= {}); the corpus failed to drive phase-2. Fix the corpus generator, do not \
         relax the throughput target.",
        lines / 4
    );

    let budget_secs = n as f64 / TARGET_CANDS_PER_SEC; // N / 100_000
    let cands_per_sec = n as f64 / secs.max(1e-12);

    eprintln!(
        "perf_10x_phase2[{lines} lines]: routed={} verified {n} candidates in {secs:.4}s \
         ({cands_per_sec:.0} cand/s)  budget(N/100000)={budget_secs:.4}s  \
         (target >= {TARGET_CANDS_PER_SEC:.0} cand/s)",
        routed.label()
    );

    assert!(
        secs <= budget_secs,
        "BATCH PHASE-2 WORKLIST [{lines} lines]: verifying {n} candidates took {secs:.4}s but \
         the batched-GPU target is N/100000 = {budget_secs:.4}s ({TARGET_CANDS_PER_SEC:.0} \
         cand/s). Measured throughput is {cands_per_sec:.0} cand/s on the routed path ({}). \
         Phase-2 runs one-candidate-at-a-time on the CPU today; this stays RED until the \
         batched-GPU verify lands. Phase-1 is ≈free, so routing to GPU region-presence does \
         NOT help — the work to move is phase-2.",
        routed.label()
    );
}

/// Per-candidate marginal cost contract at a given candidate-stream size.
/// RED until per-candidate phase-2 cost drops below `PER_CANDIDATE_TARGET_US`.
fn assert_per_candidate_cost_at(lines: usize) {
    let scanner = build_scanner();
    let corpus = candidate_dense_corpus(lines);
    let chunk = chunk_of(corpus, &format!("percand-{lines}"));

    let caps = probe_hardware();
    let routed = select_backend(
        caps,
        chunk.data.len() as u64,
        scanner.runtime_status().pattern_count,
    );
    let (secs, n) = scan_secs_and_candidates(&scanner, &chunk, routed);

    assert!(
        n >= lines / 4,
        "per-candidate corpus of {lines} lines surfaced only {n} candidates (expected \
         >= {}); fix the corpus, do not relax the per-candidate target.",
        lines / 4
    );

    let per_candidate_us = secs * 1e6 / n as f64;

    eprintln!(
        "perf_10x_phase2[{lines} lines]: per-candidate cost = {per_candidate_us:.2} µs on \
         routed={} (target < {PER_CANDIDATE_TARGET_US:.1} µs)",
        routed.label()
    );

    assert!(
        per_candidate_us < PER_CANDIDATE_TARGET_US,
        "PER-CANDIDATE PHASE-2 WORKLIST [{lines} lines]: marginal phase-2 cost is \
         {per_candidate_us:.2} µs/candidate on the routed path ({}), but the batched-GPU \
         target is < {PER_CANDIDATE_TARGET_US:.1} µs/candidate (= the 100k cand/s budget). \
         Per-candidate CPU verify (capture/checksum/entropy/ML/companion/suppression/dedup) \
         is the cost; batching it onto the GPU is what closes this. RED until that lands.",
        routed.label()
    );
}

// ---- Data-driven batched-phase-2 throughput worklist -----------------------

#[test]
fn batch_phase2_throughput_10k() {
    assert_batch_phase2_throughput_at(10_000);
}

#[test]
fn batch_phase2_throughput_25k() {
    assert_batch_phase2_throughput_at(25_000);
}

#[test]
fn batch_phase2_throughput_50k() {
    assert_batch_phase2_throughput_at(50_000);
}

#[test]
fn batch_phase2_throughput_100k() {
    assert_batch_phase2_throughput_at(100_000);
}

// ---- Data-driven per-candidate-cost worklist -------------------------------

#[test]
fn per_candidate_cost_10k() {
    assert_per_candidate_cost_at(10_000);
}

#[test]
fn per_candidate_cost_25k() {
    assert_per_candidate_cost_at(25_000);
}

#[test]
fn per_candidate_cost_50k() {
    assert_per_candidate_cost_at(50_000);
}

#[test]
fn per_candidate_cost_100k() {
    assert_per_candidate_cost_at(100_000);
}

/// Rollup over every candidate-stream size: asserts BOTH the throughput and the
/// per-candidate targets at every size in one body, naming all unmet sizes at
/// once. Scales the worklist with `CANDIDATE_LINES`.
#[test]
fn batch_phase2_all_sizes_rollup() {
    let scanner = build_scanner();
    let caps = probe_hardware();
    let mut unmet: Vec<(usize, f64, f64)> = Vec::new(); // (lines, cand/s, µs/cand)
    for &lines in CANDIDATE_LINES {
        let corpus = candidate_dense_corpus(lines);
        let chunk = chunk_of(corpus, &format!("rollup-{lines}"));
        let routed = select_backend(
            caps,
            chunk.data.len() as u64,
            scanner.runtime_status().pattern_count,
        );
        let (secs, n) = scan_secs_and_candidates(&scanner, &chunk, routed);
        let cps = n as f64 / secs.max(1e-12);
        let us = secs * 1e6 / n.max(1) as f64;
        eprintln!(
            "rollup[{lines} lines]: {cps:.0} cand/s, {us:.2} µs/cand \
             (targets >= {TARGET_CANDS_PER_SEC:.0} cand/s, < {PER_CANDIDATE_TARGET_US:.1} µs)"
        );
        if cps < TARGET_CANDS_PER_SEC || us >= PER_CANDIDATE_TARGET_US {
            unmet.push((lines, cps, us));
        }
    }
    assert!(
        unmet.is_empty(),
        "BATCH PHASE-2 ROLLUP: {} of {} candidate-stream sizes miss the batched-GPU phase-2 \
         targets (>= {TARGET_CANDS_PER_SEC:.0} cand/s AND < {PER_CANDIDATE_TARGET_US:.1} \
         µs/cand): {:?} (lines, cand/s, µs/cand). All sizes must meet both once batched \
         phase-2 lands.",
        unmet.len(),
        CANDIDATE_LINES.len(),
        unmet
    );
}
