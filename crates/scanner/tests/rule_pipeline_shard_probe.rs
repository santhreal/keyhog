//! Probe: how does keyhog's full regex set bin into shards under
//! vyre's `STATE_CAP = 1024` (LANES * 32) cap?
//!
//! Background: the GPU literal-set kernel walks every detector pattern
//! per input byte (O(N × L) per byte where N=3164, L≈10). The
//! `RulePipeline` byte-NFA does O(state-count) per byte regardless of
//! pattern count, but cannot fit all 3164 patterns into one NFA — vyre
//! caps a single compiled set at 1024 states. The fix is to bin
//! patterns into shards that EACH fit the cap and dispatch them in
//! parallel. This probe measures bin packing so we know how many
//! shards to expect (≈ work per dispatch and total scheduling cost).
//!
//! Strategy: O(N) — compile each pattern in isolation via the
//! cap-tracking `compile_regex_set` to learn its per-pattern state
//! contribution, then greedy bin-pack against the 1024-state cap.
//! No disk-cache writes; no quadratic blow-up.
//!
//! Run with `cargo test --release --test rule_pipeline_shard_probe -- --nocapture`.

use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;
use vyre_libs::matching::{compile_regex_set, RegexCompileError};

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn shard_distribution_under_state_cap() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let pats = scanner.pattern_regex_strs();
    eprintln!("Total regex patterns: {}", pats.len());

    // Step 1: per-pattern state cost. Each compile attempt is one
    // pattern in isolation; on success we read `plan.num_states`,
    // on failure we record the reason and skip from binning.
    const SHARD_CAP_STATES: usize = 1024;
    let mut per_pattern: Vec<(usize, usize)> = Vec::with_capacity(pats.len());
    let mut singletons_over_cap: Vec<(usize, usize)> = Vec::new();
    let mut singletons_unparseable: Vec<(usize, String)> = Vec::new();
    for (i, p) in pats.iter().enumerate() {
        match compile_regex_set(&[*p]) {
            Ok(set) => {
                let n = set.plan.num_states as usize;
                if n > SHARD_CAP_STATES {
                    singletons_over_cap.push((i, n));
                } else {
                    per_pattern.push((i, n));
                }
            }
            Err(RegexCompileError::TooManyStates { states, .. }) => {
                singletons_over_cap.push((i, states));
            }
            Err(e) => {
                singletons_unparseable.push((i, format!("{e:?}")));
            }
        }
    }

    let total_states: usize = per_pattern.iter().map(|(_, n)| n).sum();
    eprintln!(
        "  fits-singly: {} / {} (sum of states: {}, mean: {:.1})",
        per_pattern.len(),
        pats.len(),
        total_states,
        total_states as f64 / per_pattern.len().max(1) as f64
    );
    eprintln!(
        "  oversized-singletons: {} (will need their own per-shard dispatch via vyre's `plan_shards` or skip-with-warn)",
        singletons_over_cap.len()
    );
    eprintln!(
        "  unparseable (regex syntax vyre rejects): {}",
        singletons_unparseable.len()
    );
    if !singletons_over_cap.is_empty() {
        eprintln!("  first 5 oversized: ");
        for (pid, n) in singletons_over_cap.iter().take(5) {
            eprintln!("    pid={} states={} regex={:?}", pid, n, pats[*pid]);
        }
    }
    if !singletons_unparseable.is_empty() {
        // Bucket by short reason prefix so we know WHAT vyre rejects.
        use std::collections::BTreeMap;
        let mut buckets: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (pid, why) in &singletons_unparseable {
            let bucket = bucket_reason(why);
            buckets.entry(bucket).or_default().push(*pid);
        }
        eprintln!("  unparseable breakdown by reason:");
        for (reason, pids) in &buckets {
            eprintln!("    {}: {}", reason, pids.len());
        }
        for (reason, pids) in &buckets {
            eprintln!("  samples from bucket {:?} (first 3):", reason);
            for pid in pids.iter().take(3) {
                let s = pats[*pid];
                let short: String = s.chars().take(180).collect();
                let truncated = if s.len() > 180 { "..." } else { "" };
                eprintln!("    pid={} regex={}{}", pid, short, truncated);
            }
        }
    }

    // Step 2: greedy first-fit on the patterns that fit singly.
    // Each shard accumulates patterns until the next one would
    // overflow `SHARD_CAP_STATES`. Real cross-pattern compile cost
    // may differ from sum-of-singletons because `compile_regex_set`
    // shares an entry state across all patterns (saves one per
    // pattern); we verify the actual compile of the shard at the
    // end.
    let mut shards: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    let mut cur_states: usize = 1; // shared entry
    for (pid, n) in &per_pattern {
        if cur_states + n > SHARD_CAP_STATES && !cur.is_empty() {
            shards.push(std::mem::take(&mut cur));
            cur_states = 1;
        }
        cur.push(*pid);
        cur_states += n;
    }
    if !cur.is_empty() {
        shards.push(cur);
    }

    let sizes: Vec<usize> = shards.iter().map(|s| s.len()).collect();
    let total_assigned: usize = sizes.iter().sum();
    eprintln!("Shards (greedy first-fit at 1024-state cap):");
    eprintln!(
        "  count: {}, patterns assigned: {} / {}",
        shards.len(),
        total_assigned,
        pats.len()
    );
    eprintln!(
        "  shard sizes: min={} max={} avg={:.1}",
        sizes.iter().min().copied().unwrap_or(0),
        sizes.iter().max().copied().unwrap_or(0),
        total_assigned as f64 / shards.len().max(1) as f64
    );

    // Step 3: verify the first shard actually compiles (catches
    // any cross-pattern epsilon-state inflation that the singleton
    // estimate missed).
    if let Some(first) = shards.first() {
        let pats0: Vec<&str> = first.iter().map(|&j| pats[j]).collect();
        match compile_regex_set(&pats0) {
            Ok(set) => eprintln!(
                "  first-shard verify: ok ({} patterns → {} states)",
                first.len(),
                set.plan.num_states
            ),
            Err(e) => {
                eprintln!("  first-shard verify FAILED: {e:?}");
                eprintln!("  binning was too aggressive — singleton sum underestimates real cost");
            }
        }
    }

    assert!(!shards.is_empty(), "every pattern was rejected by vyre");
}

fn bucket_reason(err: &str) -> String {
    if err.contains("lookahead") || err.contains("Lookahead") || err.contains("lookbehind") {
        "lookaround"
    } else if err.contains("backref") || err.contains("Backref") {
        "backreference"
    } else if err.contains("Unicode") || err.contains("unicode") {
        "unicode"
    } else if err.contains("byte > 0x7F") || err.contains("0x7F") {
        "high-byte / non-ASCII class"
    } else if err.contains("TooManyStates") {
        "state-cap exceeded (alone)"
    } else if err.contains("UnsupportedHir") || err.contains("Unsupported") {
        "unsupported HIR node"
    } else if err.contains("Parse") || err.contains("syntax") {
        "regex-syntax parse error"
    } else {
        // Take the first 40 chars as a fallback bucket so we still
        // get a useful breakdown for unknown error shapes.
        let trimmed = err.split_once("{").map(|(s, _)| s).unwrap_or(err);
        let s: String = trimmed.chars().take(40).collect();
        return format!("other: {s}");
    }
    .to_string()
}
