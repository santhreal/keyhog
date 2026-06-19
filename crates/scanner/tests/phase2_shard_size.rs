//! Feasibility measurement for the GPU phase-2 port (`docs/EXECUTION_PLAN.md`
//! step 1): how many real detector regexes pack into one `RulePipeline` NFA
//! before the subgroup state cap (LANES_PER_SUBGROUP×32 = 1024), and therefore
//! how many shards the ~2,700 always-active phase-2 patterns need. Also counts
//! patterns the byte-NFA frontend cannot lower (lookaround/backref/unicode) —
//! those need a loud host path, never a silent drop (Law 10).
//!
//! Run: cargo test -p keyhog-scanner --features gpu --test phase2_shard_size -- --ignored --nocapture

#[path = "support/mod.rs"]
mod support;
use support::paths::detector_dir;

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn measure_nfa_shard_size() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let regexes: Vec<String> = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| p.regex.clone()))
        .collect();

    const INPUT_LEN: u32 = 4096;
    let refs: Vec<&str> = regexes.iter().map(String::as_str).collect();

    // Greedily pack into shards: add each pattern to the current shard; if the
    // combined NFA exceeds the state cap, close the shard and start a new one.
    let mut shards = 0usize;
    let mut packed = 0usize;
    let mut unsupported = 0usize;
    let mut cur: Vec<&str> = Vec::new();

    for &r in &refs {
        let mut trial = cur.clone();
        trial.push(r);
        if vyre_libs::scan::build_rule_pipeline_from_regex(&trial, "input", "hits", INPUT_LEN)
            .is_ok()
        {
            cur = trial;
            packed += 1;
            continue;
        }
        // r didn't fit with the current shard. Close the current shard.
        if !cur.is_empty() {
            shards += 1;
        }
        // Does r compile on its own?
        if vyre_libs::scan::build_rule_pipeline_from_regex(&[r], "input", "hits", INPUT_LEN).is_ok()
        {
            cur = vec![r];
            packed += 1;
        } else {
            unsupported += 1;
            cur = Vec::new();
        }
    }
    if !cur.is_empty() {
        shards += 1;
    }

    let per_shard = if shards > 0 {
        packed as f64 / shards as f64
    } else {
        0.0
    };
    eprintln!(
        "NFA shard sizing: {} patterns | {packed} lowerable, {unsupported} NOT lowerable \
         (need loud host path) | {shards} shards (~{per_shard:.1} patterns/shard, cap=1024 states)",
        refs.len()
    );
    eprintln!(
        "  → GPU phase-2 port: {shards} resident RulePipeline dispatches per coalesced batch \
         (+ {unsupported} host-path patterns)."
    );
}
