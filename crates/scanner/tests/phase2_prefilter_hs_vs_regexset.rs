//! DECISION GATE: can Hyperscan replace the `regex::RegexSet` always-active
//! phase-2 prefilter, the measured #1 scan cost (`phase2:prefilter` ≈ 44% of scan
//! in the small-file regime, ~35µs/call), at a real speedup AND without
//! changing the matched-pattern set (soundness)?
//!
//! `build_simd_scanner` compiles ONLY the keyword-triggered `ac_map` into
//! Hyperscan; every always-active phase-2 pattern runs through `regex::RegexSet`
//! instead. Hyperscan is built
//! for thousands of patterns at multi-GB/s, and `SINGLEMATCH` (fire each pattern
//! at most once) is exactly "does pattern P match at all", the prefilter's
//! question, with no broad-pattern callback storm.
//!
//! This A/Bs both engines over the real detector regexes on the real mirror
//! corpus: throughput each, speedup, and per-file matched-set PARITY over the
//! patterns that compile in BOTH engines (the soundness oracle the production
//! swap must satisfy; HS-dropped / regex-failed patterns keep a loud host path).
//!
//! Run: cargo test -p keyhog-scanner --features simd \
//!        --test phase2_prefilter_hs_vs_regexset -- --ignored --nocapture
#![cfg(feature = "simd")]

use std::collections::BTreeSet;
use std::time::Instant;

use hyperscan::{
    Block as BlockMode, BlockDatabase, Builder, Matching, Pattern, PatternFlags, Patterns,
};

#[path = "support/mod.rs"]
mod support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

/// Patterns per `regex::RegexSet` batch (mirrors the production prefilter, which
/// batches rather than building one giant set that blows the compiled-size cap).
const REGEX_BATCH: usize = 256;

/// Build a Hyperscan block DB over `(id, regex)`, dropping patterns HS rejects
/// (PCRE features / "pattern too large") the same way the production
/// `compile_hs_db` does. Returns the DB and the set of dropped ids.
fn build_hs(patterns: &[(usize, String)]) -> (BlockDatabase, BTreeSet<usize>) {
    // SINGLEMATCH only: fire each pattern at most once (prefilter semantics) and
    // let each pattern's INLINE flags (`(?i)` etc.) govern case, exactly as the
    // `regex::Regex::new(raw)` reference does, so a flag asymmetry can't masquerade
    // as an HS soundness gap.
    let flags = PatternFlags::SINGLEMATCH;
    // First drop ids HS can't even parse individually, so the batch build only
    // contends with the size cap.
    let mut attempts: Vec<Pattern> = Vec::new();
    let mut dropped: BTreeSet<usize> = BTreeSet::new();
    for (id, re) in patterns {
        match Pattern::with_flags(re, flags) {
            Ok(mut p) => {
                p.id = Some(*id);
                attempts.push(p);
            }
            Err(_) => {
                dropped.insert(*id);
            }
        }
    }
    let db: BlockDatabase = loop {
        let obj = Patterns(std::mem::take(&mut attempts));
        match Builder::build::<BlockMode>(&obj) {
            Ok(db) => break db,
            Err(_) if obj.0.len() > 50 => {
                attempts = obj.0;
                attempts.sort_by_key(|p| std::cmp::Reverse(p.expression.len()));
                let remove = (attempts.len() / 10).max(1);
                for _ in 0..remove {
                    if let Some(r) = attempts.pop() {
                        dropped.insert(r.id.unwrap_or(usize::MAX));
                    }
                }
                attempts.sort_by_key(|p| p.id.unwrap_or(0));
            }
            Err(e) => panic!("HS batch build failed irrecoverably: {e}"),
        }
    };
    (db, dropped)
}

#[test]
#[ignore = "live measurement over the real corpus; run with --ignored --nocapture"]
fn hs_vs_regexset_throughput_and_parity() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let Some(root) = corpus_dir() else {
        eprintln!("SKIP: mirror corpus absent");
        return;
    };

    // (global_id, regex) for every detector pattern.
    let patterns: Vec<(usize, String)> = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| p.regex.clone()))
        .enumerate()
        .collect();
    eprintln!("patterns: {}", patterns.len());

    // ---- regex::RegexSet side (batched), tracking which ids compiled. ----
    let mut regex_batches: Vec<(regex::RegexSet, Vec<usize>)> = Vec::new();
    let mut regex_ok: BTreeSet<usize> = BTreeSet::new();
    for chunk in patterns.chunks(REGEX_BATCH) {
        // Compile members individually so one bad pattern doesn't sink a batch.
        let mut srcs = Vec::new();
        let mut ids = Vec::new();
        for (id, re) in chunk {
            if regex::Regex::new(re).is_ok() {
                srcs.push(re.clone());
                ids.push(*id);
            }
        }
        if let Ok(set) = regex::RegexSetBuilder::new(&srcs)
            .size_limit(64 << 20)
            .build()
        {
            for &id in &ids {
                regex_ok.insert(id);
            }
            regex_batches.push((set, ids));
        }
    }

    // ---- Hyperscan side. ----
    let (hs_db, hs_dropped) = build_hs(&patterns);
    let hs_scratch = hs_db.alloc_scratch().expect("HS scratch");
    let hs_ok: BTreeSet<usize> = patterns
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !hs_dropped.contains(id))
        .collect();
    eprintln!(
        "compiled: regex {} / HS {} (HS dropped {})",
        regex_ok.len(),
        hs_ok.len(),
        hs_dropped.len()
    );

    let files = corpus_files(&root, 4000);
    let total_bytes: usize = files.iter().map(Vec::len).sum();
    eprintln!(
        "corpus: {} files, {:.2} MiB",
        files.len(),
        total_bytes as f64 / 1048576.0
    );

    let regex_match = |bytes: &[u8]| -> BTreeSet<usize> {
        let text = String::from_utf8_lossy(bytes);
        let mut out = BTreeSet::new();
        for (set, ids) in &regex_batches {
            for local in set.matches(&text).iter() {
                out.insert(ids[local]);
            }
        }
        out
    };
    let hs_match = |bytes: &[u8]| -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        let _ = hs_db.scan(bytes, &hs_scratch, |id, _from, _to, _flags| {
            out.insert(id as usize);
            Matching::Continue
        });
        out
    };

    // Warm both caches.
    for f in files.iter().take(64) {
        let _ = regex_match(f);
        let _ = hs_match(f);
    }

    // ---- Time regex::RegexSet. ----
    let t = Instant::now();
    let mut regex_sink = 0usize;
    for f in &files {
        regex_sink += regex_match(f).len();
    }
    let regex_ms = t.elapsed().as_secs_f64() * 1e3;

    // ---- Time Hyperscan. ----
    let t = Instant::now();
    let mut hs_sink = 0usize;
    for f in &files {
        hs_sink += hs_match(f).len();
    }
    let hs_ms = t.elapsed().as_secs_f64() * 1e3;

    let mb = total_bytes as f64 / 1048576.0;
    eprintln!(
        "\nregex::RegexSet : {regex_ms:8.1} ms  {:7.1} MiB/s  (marks/file sink={regex_sink})",
        mb / (regex_ms / 1e3)
    );
    eprintln!(
        "Hyperscan       : {hs_ms:8.1} ms  {:7.1} MiB/s  (marks/file sink={hs_sink})",
        mb / (hs_ms / 1e3)
    );
    eprintln!("speedup         : {:.1}x\n", regex_ms / hs_ms.max(1e-9));

    // ---- Parity over the patterns compiled in BOTH engines. ----
    let both: BTreeSet<usize> = regex_ok.intersection(&hs_ok).copied().collect();
    let mut mismatched_files = 0usize;
    let mut shown = 0usize;
    for (fi, f) in files.iter().enumerate() {
        let r: BTreeSet<usize> = regex_match(f).intersection(&both).copied().collect();
        let h: BTreeSet<usize> = hs_match(f).intersection(&both).copied().collect();
        if r != h {
            mismatched_files += 1;
            if shown < 8 {
                let only_r: Vec<_> = r.difference(&h).copied().collect();
                let only_h: Vec<_> = h.difference(&r).copied().collect();
                eprintln!(
                    "  PARITY MISMATCH file {fi} (len {}): regex-only={:?} hs-only={:?}",
                    f.len(),
                    only_r,
                    only_h
                );
                shown += 1;
            }
        }
    }
    eprintln!(
        "parity: {} / {} files identical over {} shared patterns ({} mismatched)",
        files.len() - mismatched_files,
        files.len(),
        both.len(),
        mismatched_files
    );
}
