#![cfg(feature = "gpu")]
//! Throughput measurement for the GPU fallback offload (`docs/EXECUTION_PLAN.md`):
//! GPU megakernel dispatch of the always-active fallback DFA catalog over a
//! 16 KB-file batch vs the equivalent SINGLE-THREAD CPU `RegexSet` work, at the
//! low- and high-density size class. This is the honest answer to "how many ×
//! faster than one CPU thread is the GPU at 16 KB scanning" — measured, release.
//!
//! "Always-active" mirrors `engine/compile.rs`: a fallback pattern whose detector
//! has NO keyword >= 4 chars runs its regex over the WHOLE chunk on every scan
//! (the `Phase2AlwaysActivePrefilter` RegexSet path), which profiling put at
//! 58-74% of phase-2. That is the set this offload targets.
//!
//! Run: cargo test -p keyhog-scanner --release --features gpu \
//!        --test phase2_gpu_throughput -- --ignored --nocapture

#[path = "support/mod.rs"]
mod support;
use support::paths::detector_dir;

use std::time::{Duration, Instant};

use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_runtime::megakernel::BatchRuleProgram;

const FILE_LEN: usize = 16 * 1024;
const N_FILES: usize = 1024;
const PER_RULE_MAX_DFA_STATES: usize = 1024;
const MAX_MATCHES: u32 = 100_000;
const HIT_CAPACITY: u32 = 1 << 20;
const WARMUP: usize = 2;
const ITERS: usize = 8;

/// Collect the always-active fallback regexes: detector has no >= 4-char keyword.
fn always_active_regexes() -> Option<Vec<String>> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).ok()?;
    let mut out = Vec::new();
    for d in &detectors {
        let has_strong_keyword = d.keywords.iter().any(|k| k.len() >= 4);
        if has_strong_keyword {
            continue; // keyword-triggered: cheap on CPU, not part of this offload
        }
        for p in &d.patterns {
            out.push(p.regex.clone());
        }
    }
    Some(out)
}

/// Build a synthetic 16 KB file. `density` tokens of a realistic secret-ish shape
/// are sprinkled into otherwise benign code-like filler.
fn synth_file(idx: usize, density: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FILE_LEN);
    let filler = b"    let value = compute_something(config, index);  // ordinary code line\n";
    while buf.len() < FILE_LEN {
        buf.extend_from_slice(filler);
    }
    buf.truncate(FILE_LEN);
    for d in 0..density {
        // Spread tokens across the file; vary by file/idx so the DFA actually
        // transitions (not all-identical bytes).
        let off = ((idx * 131 + d * 877) % (FILE_LEN - 64)).max(8);
        let tok = format!("ghp_{:0>36}", (idx * 7 + d) % 1_000_000);
        buf[off..off + tok.len()].copy_from_slice(tok.as_bytes());
    }
    buf
}

fn build_catalog(regexes: &[String]) -> (Vec<BatchRuleProgram>, usize) {
    use rayon::prelude::*;
    let built: Vec<Option<BatchRuleProgram>> = regexes
        .par_iter()
        .enumerate()
        .map(|(idx, re)| {
            vyre_libs::scan::build_regex_dfa_unanchored(
                std::slice::from_ref(&re.as_str()),
                MAX_MATCHES,
                PER_RULE_MAX_DFA_STATES,
            )
            .ok()
            .and_then(|pipe| {
                BatchRuleProgram::new(
                    idx as u32,
                    pipe.dfa.transitions,
                    pipe.dfa.accept,
                    pipe.dfa.state_count,
                )
                .ok()
            })
        })
        .collect();
    let host_path = built.iter().filter(|b| b.is_none()).count();
    let rules: Vec<BatchRuleProgram> = built.into_iter().flatten().collect();
    (rules, host_path)
}

/// Single-thread CPU baseline: the `Phase2AlwaysActivePrefilter` shape — batched
/// case-insensitive `RegexSet`s, run over every file on ONE thread.
fn cpu_regexset_baseline(regexes: &[String], files: &[Vec<u8>]) -> (Duration, usize) {
    const BATCH: usize = 512;
    let sets: Vec<regex::bytes::RegexSet> = regexes
        .chunks(BATCH)
        .filter_map(|chunk| {
            regex::bytes::RegexSetBuilder::new(chunk)
                .size_limit(64 << 20)
                .dfa_size_limit(64 << 20)
                .build()
                .ok()
        })
        .collect();
    let start = Instant::now();
    let mut total_match_pats = 0usize;
    for f in files {
        for set in &sets {
            total_match_pats += set.matches(f).iter().count();
        }
    }
    (start.elapsed(), total_match_pats)
}

#[test]
#[ignore = "throughput measurement; run with --release --ignored --nocapture"]
fn phase2_gpu_vs_single_thread_cpu_16k() {
    let Some(regexes) = always_active_regexes() else {
        eprintln!("SKIP: detectors unavailable");
        return;
    };
    let backend = WgpuBackend::new().expect("Fix: live GPU required for the throughput gate");

    eprintln!("always-active fallback patterns: {}", regexes.len());
    let (rules, host_path) = build_catalog(&regexes);
    eprintln!(
        "megakernel catalog: {} GPU rules packed, {} host-path (state-cap/un-lowerable)",
        rules.len(),
        host_path
    );
    assert!(
        !rules.is_empty(),
        "no always-active pattern lowered to a DFA rule"
    );

    let total_bytes = (N_FILES * FILE_LEN) as f64;

    for (label, density) in [("low-density", 0usize), ("high-density", 8usize)] {
        let raw: Vec<Vec<u8>> = (0..N_FILES).map(|i| synth_file(i, density)).collect();

        // ---- GPU: build the batch once, dispatch warm, time steady state. ----
        let files: Vec<BatchFile> = raw
            .iter()
            .enumerate()
            .map(|(i, b)| BatchFile::new(i as u64, 0, b.clone()))
            .collect();
        let batch = FileBatch::upload(
            backend.device_queue(),
            &files,
            rules.len() as u32,
            HIT_CAPACITY,
        )
        .expect("FileBatch upload");
        let config = BatchDispatchConfig {
            workgroup_size_x: 64,
            worker_groups: 1024,
            hit_capacity: HIT_CAPACITY,
            timeout: Duration::from_secs(120),
            ..Default::default()
        };
        let mut dispatcher = BatchDispatcher::new(backend.clone(), config).expect("dispatcher");
        let mut hits: Vec<HitRecord> = Vec::with_capacity(1 << 16);

        for _ in 0..WARMUP {
            dispatcher
                .dispatch_into(&batch, &rules, &mut hits)
                .expect("warmup dispatch");
        }
        let mut best = Duration::MAX;
        let mut last_hits = 0usize;
        for _ in 0..ITERS {
            let t = Instant::now();
            dispatcher
                .dispatch_into(&batch, &rules, &mut hits)
                .expect("dispatch");
            best = best.min(t.elapsed());
            last_hits = hits.len();
        }
        let gpu_mbps = total_bytes / best.as_secs_f64() / (1024.0 * 1024.0);

        // ---- CPU single thread baseline over the same set. ----
        let (cpu_dur, cpu_hits) = cpu_regexset_baseline(&regexes, &raw);
        let cpu_mbps = total_bytes / cpu_dur.as_secs_f64() / (1024.0 * 1024.0);

        eprintln!(
            "\n[{label}] {N_FILES} x {FILE_LEN}B = {:.1} MB | rules={}\n  \
             GPU  : {:>8.2} ms/dispatch  {:>10.1} MB/s  ({last_hits} raw hits)\n  \
             CPU1 : {:>8.2} ms           {:>10.1} MB/s  ({cpu_hits} pattern-matches)\n  \
             GPU/CPU1 speedup: {:.1}x",
            total_bytes / (1024.0 * 1024.0),
            rules.len(),
            best.as_secs_f64() * 1e3,
            gpu_mbps,
            cpu_dur.as_secs_f64() * 1e3,
            cpu_mbps,
            gpu_mbps / cpu_mbps,
        );
    }
}
