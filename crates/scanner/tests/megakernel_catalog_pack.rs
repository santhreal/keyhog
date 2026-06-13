#![cfg(feature = "gpu")]
//! Megakernel fallback port — slice 1: host-side catalog construction.
//!
//! Proves keyhog's real detector regexes compile into the vyre megakernel's
//! batched DFA rule catalog (`docs/GPU_DETECTION_REWRITE.md` step 5):
//!   regex → `build_regex_dfa_pipeline` (compile_regex_set → nfa_to_dfa, a FULL
//!   dense `state*256` DFA) → `CompiledDfa` → `BatchRuleProgram` (direct field
//!   map) → `pack_rule_catalog`.
//!
//! Reports how many patterns fit the DFA state budget (one rule each) vs how
//! many exceed it / can't lower — those take a LOUD host path in the real port,
//! never a silent drop (Law 10). This is the empirical answer to "does the
//! existing engine carry keyhog's fallback set", not a guess.
//!
//! Run: cargo test -p keyhog-scanner --features gpu --test megakernel_catalog_pack -- --ignored --nocapture

#[path = "support/mod.rs"]
mod support;
use support::paths::detector_dir;

use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::rule_catalog::pack_rule_catalog;
use vyre_runtime::megakernel::BatchRuleProgram;

/// Hit-capacity for the per-pattern DFA pipeline build. Not load-bearing for the
/// host-side catalog pack; the real dispatch sizes this from the batch.
const MAX_MATCHES: u32 = 100_000;

/// Per-rule DFA state budget. Unanchored DFAs are ~3x the anchored size; a
/// pattern that exceeds this is routed to the loud host path (never silently
/// dropped). 1024 keeps construction tractable at the 1668-pattern scale while
/// covering the vast majority (anchored mean ~96 states/rule → unanchored ~290).
const PER_RULE_MAX_DFA_STATES: usize = 1024;

#[test]
#[ignore = "measurement/feasibility; run with --ignored --nocapture"]
fn fallback_patterns_pack_into_megakernel_rule_catalog() {
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

    // UNANCHORED (find-anywhere) catalog — the production fallback contract.
    // `build_regex_dfa_unanchored` adds the implicit `.*` via an NFA-table
    // start-self-loop (O(256)/pattern), so this builds at the full 1668-pattern
    // scale WITHOUT the OOM that the `(?s).*?`-in-regex approach hit. Built in
    // PARALLEL (rayon) — in production the catalog is built once at scanner init
    // and cached to disk, so this models that one-time cost amortized over cores.
    use rayon::prelude::*;
    let built: Vec<Option<BatchRuleProgram>> = regexes
        .par_iter()
        .enumerate()
        .map(|(idx, re)| {
            build_regex_dfa_unanchored(
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
    let host_path = built.iter().filter(|b| b.is_none()).count(); // LOUD host path in the port
    let rules: Vec<BatchRuleProgram> = built.into_iter().flatten().collect();
    let total_states: u64 = rules.iter().map(|r| u64::from(r.state_count)).sum();

    let packed = pack_rule_catalog(&rules).expect("pack the fallback DFA rule catalog");
    eprintln!(
        "megakernel catalog: {} patterns | {} rules packed | {} host-path (budget/un-lowerable) | \
         {} total DFA states | catalog: {} transition words, {} accept words, {} rejected",
        regexes.len(),
        rules.len(),
        host_path,
        total_states,
        packed.transitions.len(),
        packed.accept.len(),
        packed.rejected_rules.len(),
    );

    // The engine must carry a real majority of the set on the GPU path; the rest
    // take the LOUD host path (never silently dropped).
    assert!(
        !rules.is_empty(),
        "no fallback pattern compiled into a megakernel DFA rule — engine/compile path is broken"
    );
}
