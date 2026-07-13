//! Entropy-edge runner, on-demand diagnostic pinning the detector entropy
//! floor. NOT a `cargo test` gate.
//!
//! Most detectors couple a regex to an entropy floor (≈4.5 bits/byte default).
//! This probe swaps each contract positive's credential for a same-length
//! synthetic body at successive target entropies (4.0–5.0 in 0.25-bit rungs)
//! and reports the hit-rate decay, so an operator can see exactly where the
//! boundary lives: a sharp 100%→0% step between two rungs pins the floor.
//!
//! Why `#[ignore]` and not a gate (T-01)
//! -------------------------------------
//! Swapping the credential for a synthetic body MEASURES the entropy gate
//! that is a recall RATE over a corpus, and detection-accuracy rates are owned
//! by the differential bench (`benchmarks/bench`), never asserted in
//! `cargo test` (see the internal design notes T-01). It is also not a sound
//! behavior contract: the synthetic body drops the detector's distinctive
//! prefix/shape, so a prefixed detector legitimately stops matching regardless
//! of entropy. Per-rule entropy-floor BEHAVIOR is covered by the `entropy_*`
//! unit tests on known inputs; this file stays a report-only probe, run
//! explicitly with `--ignored --nocapture`.

mod support;
use support::contracts::{load_contracts, make_chunk, scanner, surfaces};

use std::collections::BTreeMap;

const SOURCE_TYPE: &str = "entropy-edge";

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let n = s.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// Rungs the credential entropy is tested at; 0.25-bit steps so a single-rung
/// gap pins the boundary.
const ENTROPY_RUNGS: &[f64] = &[3.5, 4.0, 4.25, 4.5, 4.75, 5.0];

/// A `len`-byte string whose Shannon entropy is near `target`: a string drawn
/// from `2^target` distinct symbols has entropy `log2(N)`. Deterministic;
/// rounds within ~0.15 bits of target.
fn synth_at_entropy(target: f64, len: usize) -> String {
    let n_symbols = (2.0f64.powf(target).round() as usize).clamp(2, 64);
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(len);
    for i in 0..len {
        out.push(ALPHABET[i % n_symbols] as char);
    }
    out
}

#[test]
#[ignore = "measurement: pins the entropy floor over the contract corpus; rates are owned by the bench (T-01). Run with --ignored --nocapture"]
fn entropy_floor_sweep() {
    let scanner = scanner();
    let contracts = load_contracts();

    let mut per_rung: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut total_runs = 0usize;
    let mut total_hits = 0usize;
    let mut original_runs = 0usize;
    let mut original_hits = 0usize;

    for c in &contracts {
        for p in &c.positive {
            // Control: the original credential at whatever entropy it has.
            let chunk = make_chunk(&p.text, SOURCE_TYPE, "entropy.txt");
            original_runs += 1;
            if surfaces(&scanner, &chunk, &p.credential) {
                original_hits += 1;
            }

            let len = p.credential.len();
            if len < 8 {
                continue;
            }
            for &target in ENTROPY_RUNGS {
                let synthetic = synth_at_entropy(target, len);
                if synthetic.len() != len {
                    continue;
                }
                let actual = shannon_entropy(&synthetic);
                let text = p.text.replace(&p.credential, &synthetic);
                let chunk = make_chunk(&text, SOURCE_TYPE, "entropy.txt");
                let hit = surfaces(&scanner, &chunk, &synthetic);
                let bucket = per_rung
                    .entry(format!("{target:.2}->{actual:.2}"))
                    .or_insert((0, 0));
                bucket.0 += 1;
                total_runs += 1;
                if hit {
                    bucket.1 += 1;
                    total_hits += 1;
                }
            }
        }
    }

    let orig_pct = (original_hits as f64 / original_runs.max(1) as f64) * 100.0;
    let mut summary = format!(
        "entropy-edge sweep (diagnostic, not a gate):\n  original-credential control: \
         {original_hits}/{original_runs} ({orig_pct:.1}%)\n  synthetic-credential per \
         target-entropy rung:\n"
    );
    for (rung, (runs, hits)) in &per_rung {
        let pct = (*hits as f64 / (*runs).max(1) as f64) * 100.0;
        summary.push_str(&format!(
            "    {rung:<14} {hits:>4}/{runs:<4} ({pct:5.1}%)\n"
        ));
    }
    let overall = (total_hits as f64 / total_runs.max(1) as f64) * 100.0;
    summary.push_str(&format!(
        "    TOTAL {total_hits}/{total_runs} ({overall:.1}%), a sharp boundary between rungs \
         pins the entropy floor\n"
    ));
    eprintln!("{summary}");
}
