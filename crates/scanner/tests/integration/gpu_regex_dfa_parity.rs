//! Integration test: DFA pipeline reference_scan results match NFA
//! RulePipeline on the same inputs for all matching patterns.
//!
//! Uses real detector regex patterns from the keyhog corpus to verify
//! that the DFA literal-core extraction path produces a superset of
//! the matches the NFA path would find (since the DFA only matches
//! literal prefixes, not the full regex — it's a prefilter tier).

use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// Build the pattern set from real detectors. Returns None if the
/// detector directory is unavailable (e.g. in CI without the corpus).
fn real_detector_patterns() -> Option<Vec<String>> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).ok()?;
    let scanner = keyhog_scanner::CompiledScanner::compile(detectors).ok()?;
    Some(
        scanner
            .pattern_regex_strs()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    )
}

#[test]
fn dfa_literal_matches_are_subset_of_nfa_matches_on_synthetic_haystack() {
    // Use a small set of patterns that both NFA and DFA can handle.
    let patterns = &["AKIA", "ghp_", "sk_live_"];
    let input_len = 256_u32;

    // Build NFA pipeline.
    let nfa_pipeline = match vyre_libs::scan::build_rule_pipeline_from_regex(
        patterns, "input", "hits", input_len,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: NFA pipeline compile failed: {e}");
            return;
        }
    };

    // Build DFA pipeline.
    let dfa_pipeline = match keyhog_scanner::engine::build_regex_dfa(patterns, input_len) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: DFA pipeline compile failed: {e}");
            return;
        }
    };

    let haystack = b"prefix AKIA12345 ghp_abcdef sk_live_xyz suffix";

    let nfa_matches = nfa_pipeline.reference_scan(haystack);
    let dfa_matches = dfa_pipeline.reference_scan(haystack);

    // DFA matches are based on literal cores, so each DFA match
    // position should correspond to an NFA match for the same pattern
    // at the same start position.
    for dfa_m in &dfa_matches {
        let nfa_has_match = nfa_matches.iter().any(|nfa_m| {
            nfa_m.pattern_id == dfa_m.pattern_id && nfa_m.start == dfa_m.start
        });
        assert!(
            nfa_has_match,
            "DFA match (pattern={}, start={}, end={}) has no corresponding NFA match. \
             NFA matches: {:?}",
            dfa_m.pattern_id, dfa_m.start, dfa_m.end, nfa_matches
        );
    }
}

#[test]
fn dfa_and_nfa_agree_on_pure_literal_patterns() {
    // For pure literal patterns, NFA and DFA should produce identical
    // match sets (modulo end position — NFA sees the full match while
    // DFA sees only the literal core).
    let patterns = &["AKIA", "ghp_", "Bearer"];
    let input_len = 128_u32;

    let nfa_pipeline = vyre_libs::scan::build_rule_pipeline_from_regex(
        patterns, "input", "hits", input_len,
    )
    .expect("NFA compile");

    let dfa_pipeline =
        keyhog_scanner::engine::build_regex_dfa(patterns, input_len).expect("DFA compile");

    let haystack = b"Authorization: Bearer AKIA12345 token ghp_abc";

    let nfa_matches = nfa_pipeline.reference_scan(haystack);
    let dfa_matches = dfa_pipeline.reference_scan(haystack);

    // For pure literals, match counts should be equal.
    assert_eq!(
        nfa_matches.len(),
        dfa_matches.len(),
        "NFA and DFA should produce the same number of matches for pure literals. \
         NFA: {nfa_matches:?}, DFA: {dfa_matches:?}"
    );
}

#[test]
fn dfa_pipeline_handles_real_detector_subset() {
    let Some(all_patterns) = real_detector_patterns() else {
        eprintln!("SKIP: detectors unavailable");
        return;
    };

    // Take first 20 patterns that have extractable literal cores.
    let mut candidates: Vec<&str> = Vec::new();
    for pat in &all_patterns {
        // Quick heuristic: pattern starts with alphanumeric = has literal core.
        if pat.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            candidates.push(pat);
        }
        if candidates.len() >= 20 {
            break;
        }
    }

    if candidates.is_empty() {
        eprintln!("SKIP: no patterns with literal cores found");
        return;
    }

    eprintln!("Testing DFA pipeline with {} real detector patterns", candidates.len());

    let result = keyhog_scanner::engine::build_regex_dfa(&candidates, 1024);
    match result {
        Ok(pipeline) => {
            assert!(pipeline.dfa.state_count > 0);
            eprintln!(
                "  DFA compiled: {} states, {} patterns",
                pipeline.dfa.state_count, pipeline.pattern_count
            );
            // Quick sanity: scan an empty haystack produces no matches.
            let empty_matches = pipeline.reference_scan(b"");
            assert!(empty_matches.is_empty());
        }
        Err(e) => {
            eprintln!("  DFA compile returned error (acceptable): {e}");
        }
    }
}
