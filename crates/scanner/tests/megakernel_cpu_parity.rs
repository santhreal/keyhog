#![cfg(feature = "gpu")]
//! Megakernel phase-2 port — slice 4: end-to-end GPU≡CPU parity on real files.
//!
//! Scans real mirror-corpus files with BOTH (a) the megakernel batched DFA rule
//! catalog on the GPU and (b) the CPU `regex` crate, then asserts the set of
//! `(file, detector)` firings is IDENTICAL. This is the parity gate the live
//! `scan_phase2_patterns` replacement must pass: the GPU path may not drop or
//! invent a detector firing relative to the CPU reference (Law 10 — no silent
//! recall change). (`docs/EXECUTION_PLAN.md` step 5 gate.)
//!
//! Run: cargo test -p keyhog-scanner --features gpu --test megakernel_cpu_parity -- --ignored --nocapture

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

#[path = "support/mod.rs"]
mod support;
use support::paths::corpus_dir;

use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::BatchRuleProgram;

const WORKER_GROUPS: u32 = 256;
const HIT_CAPACITY: u32 = 65_536;
const MAX_MATCHES: u32 = 200_000;
const MAX_DFA_STATES: usize = 16_384;

/// Detector regexes for the parity gate. These are **overlap-free** (the prefix
/// char before the body — `_` / `-` — is NOT in the body charclass), so the
/// unanchored DFA stays small. Patterns whose prefix chars ARE in the body class
/// (AWS `AKIA[A-Z0-9]{16}`, `AIza[A-Za-z0-9_-]{35}`, `sk_live_…`) blow up the
/// unanchored DFA (overlap ambiguity under the `.*` self-loop) and MUST use the
/// GpuLiteralSet literal-core prefilter path instead — the hybrid the live port
/// needs (task #4). This gate covers the unanchored-DFA portion.
const PATTERNS: &[&str] = &[
    "ghp_[A-Za-z0-9]{36}",
    "gho_[A-Za-z0-9]{36}",
    "ghs_[A-Za-z0-9]{36}",
    "ghu_[A-Za-z0-9]{36}",
    "xox[baprs]-[A-Za-z0-9-]{10,48}",
];

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
#[ignore = "live GPU; run with --ignored --nocapture"]
fn megakernel_matches_cpu_regex_on_real_files() {
    let backend = WgpuBackend::new().expect("Fix: live GPU required for the parity gate");
    let Some(root) = corpus_dir() else {
        eprintln!("SKIP: mirror corpus absent");
        return;
    };
    let raw = collect_files(&root, 1500);
    assert!(!raw.is_empty(), "mirror corpus must have files");

    // --- CPU reference: (file_idx, pattern_idx) firings via the BYTE regex
    // engine on RAW bytes — apples-to-apples with the GPU byte-DFA (find-anywhere
    // = unanchored is_match). Using `regex::bytes` (not `regex::Regex` on lossy
    // text) is load-bearing: `from_utf8_lossy` rewrites non-UTF-8 bytes and would
    // make the reference disagree with the byte DFA. ---
    let cpu_res: Vec<regex::bytes::Regex> = PATTERNS
        .iter()
        .map(|p| regex::bytes::Regex::new(p).expect("reference regex compiles"))
        .collect();
    let mut cpu: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (fi, bytes) in raw.iter().enumerate() {
        for (pi, re) in cpu_res.iter().enumerate() {
            if re.is_match(bytes) {
                cpu.insert((fi, pi));
            }
        }
    }

    // --- GPU: one unanchored DFA rule per pattern, dispatched over all files. ---
    let rules: Vec<BatchRuleProgram> = PATTERNS
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let pipe = build_regex_dfa_unanchored(&[p], MAX_MATCHES, MAX_DFA_STATES)
                .unwrap_or_else(|e| panic!("pattern {idx} {p:?} must compile unanchored: {e:?}"));
            BatchRuleProgram::new(
                idx as u32,
                pipe.dfa.transitions,
                pipe.dfa.accept,
                pipe.dfa.state_count,
            )
            .expect("rule valid")
        })
        .collect();

    let files: Vec<BatchFile> = raw
        .iter()
        .enumerate()
        .map(|(i, b)| BatchFile::new(i as u64, 0, b.clone()))
        .collect();
    // rule_count = NUMBER OF RULES (not worker_groups!) — it sizes the work queue
    // (files × rule_count) and the kernel's file_idx=claim/rule_count mapping.
    let batch = FileBatch::upload(
        backend.device_queue(),
        &files,
        rules.len() as u32,
        HIT_CAPACITY,
    )
    .expect("FileBatch upload");
    let config = BatchDispatchConfig {
        workgroup_size_x: 64,
        worker_groups: WORKER_GROUPS,
        hit_capacity: HIT_CAPACITY,
        timeout: Duration::from_secs(30),
        ..Default::default()
    };
    // Uses the DEFAULT `BatchDispatcher::new` writer. That default is the
    // divergence-safe scalar writer: the batch kernel's per-file DFA loop scans
    // files of different lengths, so subgroup lanes diverge as shorter files
    // finish; the hierarchical-subgroup writer (which requires uniform control
    // flow) strands its leader's reserved ring slot once that lane exits and
    // silently drops hits found afterward. This gate first ran RED with the old
    // `Auto`→hierarchical default — 6 of 46 detector firings dropped, every miss
    // a match found past its subgroup leader's shorter file — which is exactly
    // the recall loss the scalar default fixes.
    let mut dispatcher = BatchDispatcher::new(backend.clone(), config).expect("dispatcher");
    let mut hits: Vec<HitRecord> = Vec::with_capacity(4096);
    let report = dispatcher
        .dispatch_into(&batch, &rules, &mut hits)
        .expect("dispatch");

    // Dedup the many-hits-per-match `HitRecord`s to the firing set.
    let gpu: BTreeSet<(usize, usize)> = hits
        .iter()
        .map(|h| (h.file_idx as usize, h.rule_idx as usize))
        .collect();

    eprintln!(
        "parity: {} files, {} raw GPU hits, items_processed={} | GPU firings={} CPU firings={}",
        raw.len(),
        hits.len(),
        report.items_processed,
        gpu.len(),
        cpu.len()
    );
    eprintln!("dispatch report: {report:?}");

    // The recall gate: GPU and CPU must fire the SAME (file, detector) pairs.
    let only_gpu: Vec<_> = gpu.difference(&cpu).take(10).collect();
    let only_cpu: Vec<(usize, usize)> = cpu.difference(&gpu).copied().collect();

    // Root-cause diagnostic for GPU misses: file size + the byte offset where the
    // CPU match actually is. If misses cluster past a byte threshold, it's a
    // per-file scan-length / worker-geometry cap in the dispatcher.
    if !only_cpu.is_empty() {
        let max_file = raw.iter().map(Vec::len).max().unwrap_or(0);
        eprintln!(
            "GPU MISSES ({}) — file_size / cpu_match_offset:",
            only_cpu.len()
        );
        for &(fi, pi) in only_cpu.iter().take(20) {
            if let Some(m) = cpu_res[pi].find(&raw[fi]) {
                let ctx_lo = m.start().saturating_sub(6);
                let ctx_hi = (m.end() + 6).min(raw[fi].len());
                eprintln!(
                    "  file {fi} (len {}) pattern {pi}: match [{}..{}] = {:?} | context {:?}",
                    raw[fi].len(),
                    m.start(),
                    m.end(),
                    String::from_utf8_lossy(&raw[fi][m.start()..m.end()]),
                    String::from_utf8_lossy(&raw[fi][ctx_lo..ctx_hi]),
                );
            }
        }
        let max_match_off = only_cpu
            .iter()
            .filter_map(|&(fi, pi)| cpu_res[pi].find(&raw[fi]).map(|m| m.start()))
            .max()
            .unwrap_or(0);
        eprintln!(
            "  largest file in corpus = {max_file} bytes; largest missed-match offset = {max_match_off}"
        );
    }

    assert!(
        gpu == cpu,
        "GPU≡CPU parity broken.\n  only-in-GPU (false positives): {only_gpu:?}\n  \
         only-in-CPU (GPU misses — RECALL LOSS): {:?}",
        only_cpu.iter().take(10).collect::<Vec<_>>()
    );
    eprintln!(
        "PARITY OK: GPU firing set == CPU firing set ({} firings)",
        gpu.len()
    );
}
