//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec};
use regex::Regex;

use super::compiler_prefix::extract_literal_prefixes;

pub fn build_ac_pattern_set(literals: &[String]) -> Result<Option<AhoCorasick>> {
    if literals.is_empty() {
        return Ok(None);
    }
    // ASCII case-insensitive to match Hyperscan's PatternFlags::CASELESS
    // (see simd.rs). Without this, the CpuFallback backend misses literal
    // hits on case-varied text (e.g. random base containing `akia` or
    // `AKia`) that the SimdCpu backend finds, producing per-backend
    // finding divergence visible in proptest gpu_proptest_invariants
    // P1b. Detector keywords also rely on caseless matching for env-var
    // shapes like `AWS_KEY_ID` vs `aws_key_id` — the existing
    // fallback_keyword_ac at build_fallback_keyword_ac (this file)
    // already uses ascii_case_insensitive(true) for the same reason.
    Ok(Some(
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(literals)?,
    ))
}

/// Keep GPU literal inputs in Keyhog order so Vyre match pattern IDs map back
/// to `ac_map` without an adapter table.
pub fn build_gpu_literals(ac_literals: &[String]) -> Option<std::sync::Arc<Vec<Vec<u8>>>> {
    if ac_literals.iter().any(String::is_empty) {
        tracing::warn!("GPU literal set contains an empty literal; disabling GPU literal scan");
        return None;
    }
    let literals: Vec<Vec<u8>> = ac_literals
        .iter()
        .map(|literal| literal.as_bytes().to_vec())
        .collect();
    if literals.is_empty() {
        None
    } else {
        tracing::info!(
            patterns = literals.len(),
            "GPU literal set prepared for Vyre"
        );
        Some(std::sync::Arc::new(literals))
    }
}

pub fn build_same_prefix_patterns(literals: &[String]) -> Vec<Vec<usize>> {
    let mut groups: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for (i, lit) in literals.iter().enumerate() {
        groups.entry(lit.as_str()).or_default().push(i);
    }
    let mut map = vec![Vec::new(); literals.len()];
    for indices in groups.values() {
        if indices.len() > 1 {
            for &i in indices {
                map[i] = indices.iter().copied().filter(|&j| j != i).collect();
            }
        }
    }
    map
}

pub fn build_prefix_propagation(literals: &[String]) -> Vec<Vec<usize>> {
    let mut map = vec![Vec::new(); literals.len()];
    // Sort indices by literal length (shortest first) for efficient prefix matching.
    let mut sorted: Vec<(usize, &str)> = literals
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.as_str()))
        .collect();
    sorted.sort_by_key(|(_, s)| s.len());
    // For each longer string, check if any shorter string is its prefix.
    for a in 0..sorted.len() {
        for b in (a + 1)..sorted.len() {
            let (j, short) = sorted[a];
            let (i, long) = sorted[b];
            if short != long && long.starts_with(short) {
                map[j].push(i);
            }
        }
    }
    map
}

pub fn build_fallback_keyword_ac(
    fallback: &[(CompiledPattern, Vec<String>)],
) -> (Option<AhoCorasick>, Vec<Vec<usize>>) {
    let mut all_keywords = Vec::new();
    let mut keyword_to_patterns = Vec::new();
    let mut keyword_map: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (pattern_idx, (_, keywords)) in fallback.iter().enumerate() {
        for kw in keywords {
            // Floor stays at 4: lowering it to 3 to admit
            // mailchimp's `-us`/`-eu`/`-uk` and openai/anthropic's
            // `sk-`/`sk-ant-`/`pk-` measured a NET F1 regression
            // (-67 TP, +28 FP) on SecretBench-medium 15k seed-0
            // because (a) too-broad fallback detectors like
            // helicone-api-key `sk-[a-zA-Z0-9]{20,}` fired
            // wrongly on neighboring lines and (b) the recall
            // gain on mailchimp was small. The right fix for
            // those detectors is per-detector keyword tightening,
            // not a global threshold change.
            if kw.len() < 4 {
                continue;
            }
            let idx = *keyword_map.entry(kw.clone()).or_insert_with(|| {
                all_keywords.push(kw.clone());
                keyword_to_patterns.push(Vec::new());
                all_keywords.len() - 1
            });
            keyword_to_patterns[idx].push(pattern_idx);
        }
    }

    if all_keywords.is_empty() {
        return (None, Vec::new());
    }

    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(all_keywords)
        .ok();

    (ac, keyword_to_patterns)
}

pub fn log_quality_warnings(warnings: &[String]) {
    for warning in warnings {
        tracing::warn!(target: "keyhog::scanner::quality", "{}", warning);
    }
}

pub fn compile_detector_companions(detector: &DetectorSpec) -> Result<Vec<CompiledCompanion>> {
    detector
        .companions
        .iter()
        .map(|companion| compile_companion(companion, &detector.id))
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn compile_detector_pattern(
    detector_index: usize,
    detector: &DetectorSpec,
    pattern_index: usize,
    pattern: &PatternSpec,
    ac_literals: &mut Vec<String>,
    ac_map: &mut Vec<CompiledPattern>,
    fallback: &mut Vec<(CompiledPattern, Vec<String>)>,
    quality_warnings: &mut Vec<String>,
) -> Result<()> {
    let detector_id = &detector.id;
    let compiled = compile_pattern(detector_index, pattern_index, pattern, detector_id)?;

    // Prefix extraction for Aho-Corasick prefiltering
    let prefixes = extract_literal_prefixes(&pattern.regex);

    // Proactive Homoglyph Expansion:
    // kimi-decode audit: the previous flow here built a fallback regex
    // shaped `^<expanded_prefix>` with NO body constraint, which would
    // match any string starting with the homoglyph variant of the
    // prefix — the exact same flutterwave-FP bug the production path
    // (`compile_pattern`, earlier in this file) was already fixed for
    // via `rewrite_alternation_prefix`. Since this `compile_detector_pattern`
    // entry point has zero internal call sites and is only retained as
    // a `pub` surface for hypothetical external consumers, the safe
    // move is to skip the prefix-only homoglyph fallback here entirely.
    // Callers needing homoglyph defense should route through the live
    // CompiledScanner::compile pipeline which applies the validated
    // rewrite + full-body anchoring.

    if !prefixes.is_empty() {
        tracing::debug!(
            detector_id,
            ?prefixes,
            mode = "AC",
            "compiled detector pattern"
        );
        for prefix in prefixes {
            ac_literals.push(prefix);
            ac_map.push(compiled.clone());
        }
    } else {
        // No literal prefix. With Hyperscan, these will be compiled directly
        // into the HS database alongside the AC-prefix patterns. Without
        // Hyperscan, they go to the keyword-gated regex fallback.
        if detector.keywords.is_empty() {
            quality_warnings.push(format!(
                "Detector {detector_id} pattern {pattern_index} has no literal prefix and no keywords."
            ));
        }
        fallback.push((compiled, detector.keywords.clone()));
    }
    Ok(())
}

pub fn compile_pattern(
    detector_index: usize,
    pattern_index: usize,
    spec: &PatternSpec,
    detector_id: &str,
) -> Result<CompiledPattern> {
    Ok(CompiledPattern {
        detector_index,
        regex: shared_regex(&spec.regex).map_err(|e| ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: pattern_index,
            source: e,
        })?,
        group: spec.group,
        client_safe: spec.client_safe,
    })
}

static REGEX_CACHE: std::sync::OnceLock<
    parking_lot::RwLock<std::collections::HashMap<String, std::sync::Arc<Regex>>>,
> = std::sync::OnceLock::new();

pub fn shared_regex_compile(
    pattern: &str,
) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    let regex = regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .crlf(true)
        .build()?;
    Ok(std::sync::Arc::new(regex))
}

pub fn warm_shared_regex_cache(
    compiled: Vec<(
        String,
        std::result::Result<std::sync::Arc<Regex>, regex::Error>,
    )>,
) {
    let cache =
        REGEX_CACHE.get_or_init(|| parking_lot::RwLock::new(std::collections::HashMap::new()));
    let mut w = cache.write();
    for (pattern, res) in compiled {
        if let Ok(arc) = res {
            w.insert(pattern, arc);
        }
    }
}

/// Compile a regex once per unique source string and share the compiled
/// `Arc<Regex>` across every detector that uses it. The 889-detector corpus
/// has ~6-15% duplicate regexes (Google, JWT, Slack shapes); this collapses
/// each duplicate set into a single compiled instance, cutting startup
/// compile time and resident memory proportionally — see audits/legendary-
/// 2026-04-26 sources_verifier_detectors_legendary.md.
///
/// The cache is process-wide via a `parking_lot::RwLock<HashMap<...>>`.
/// Lookup is lock-free and extremely high-performance during the main parallel compile.
fn shared_regex(pattern: &str) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    let cache =
        REGEX_CACHE.get_or_init(|| parking_lot::RwLock::new(std::collections::HashMap::new()));
    if let Some(hit) = cache.read().get(pattern) {
        return Ok(std::sync::Arc::clone(hit));
    }
    let arc = shared_regex_compile(pattern)?;
    cache
        .write()
        .insert(pattern.to_string(), std::sync::Arc::clone(&arc));
    Ok(arc)
}

pub fn compile_companion(spec: &CompanionSpec, detector_id: &str) -> Result<CompiledCompanion> {
    let regex = regex::RegexBuilder::new(&spec.regex)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .crlf(true)
        .build()
        .map_err(|e| ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: FIRST_CAPTURE_GROUP_INDEX,
            source: e,
        })?;
    let capture_group = (regex.captures_len() > 1).then_some(FIRST_CAPTURE_GROUP_INDEX);
    Ok(CompiledCompanion {
        name: spec.name.clone(),
        regex,
        capture_group,
        within_lines: spec.within_lines,
        required: spec.required,
    })
}
