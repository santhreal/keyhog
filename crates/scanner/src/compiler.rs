//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec};
use regex::Regex;

#[path = "compiler_prefix.rs"]
mod compiler_prefix;
pub use compiler_prefix::{extract_literal_prefix, extract_literal_prefixes, is_escaped_literal};

pub struct CompileState {
    pub ac_literals: Vec<String>,
    pub ac_map: Vec<CompiledPattern>,
    pub fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub companions: Vec<Vec<CompiledCompanion>>,
    pub quality_warnings: Vec<String>,
}

pub fn build_compile_state(detectors: &[DetectorSpec]) -> Result<CompileState> {
    use rayon::prelude::*;
    use std::collections::HashMap;

    // De-duplicate identical regex strings BEFORE compilation. The 888-
    // detector corpus has ~6-15% duplicate patterns (e.g. multiple
    // google-* detectors share the `AIza` regex shape). Compiling each
    // once cuts startup-compile time and RAM proportionally — see
    // audits/legendary-2026-04-26.
    let unique_patterns: HashMap<String, ()> = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| (p.regex.clone(), ())))
        .collect();
    tracing::debug!(
        unique = unique_patterns.len(),
        "compiler dedup: unique pattern regexes"
    );

    // Phase 1: Pre-compile all regexes in parallel (the expensive part).
    let compiled_results: Vec<Result<(Vec<CompiledPattern>, Vec<CompiledCompanion>)>> = detectors
        .par_iter()
        .enumerate()
        .map(|(detector_index, detector)| {
            let companions = compile_detector_companions(detector)?;
            let mut patterns = Vec::new();
            for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
                patterns.push(compile_pattern(
                    detector_index,
                    pattern_index,
                    pattern,
                    &detector.id,
                )?);
            }
            Ok((patterns, companions))
        })
        .collect();

    // Phase 2: Assemble results sequentially (fast, no regex compilation).
    let mut ac_literals = Vec::new();
    let mut ac_map = Vec::new();
    let mut fallback = Vec::new();
    let mut companions = Vec::with_capacity(detectors.len());
    let mut quality_warnings = Vec::new();

    for (detector_index, (result, detector)) in compiled_results
        .into_iter()
        .zip(detectors.iter())
        .enumerate()
    {
        let (compiled_patterns, detector_companions) = result?;
        companions.push(detector_companions);

        for (pattern_index, (compiled, pattern)) in compiled_patterns
            .into_iter()
            .zip(detector.patterns.iter())
            .enumerate()
        {
            let prefixes = extract_literal_prefixes(&pattern.regex);

            // Homoglyph expansion for high-confidence patterns
            for prefix in &prefixes {
                if prefix.len() >= 3 {
                    let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
                    if expanded_prefix != *prefix {
                        if let Ok(re) = Regex::new(&format!("^{}", expanded_prefix)) {
                            let expanded_pattern = CompiledPattern {
                                detector_index,
                                regex: std::sync::Arc::new(re),
                                group: pattern.group,
                            };
                            fallback.push((expanded_pattern, detector.keywords.clone()));
                        }
                    }
                }
            }

            if !prefixes.is_empty() {
                for prefix in prefixes {
                    ac_literals.push(prefix);
                    ac_map.push(compiled.clone());
                }
            } else {
                if detector.keywords.is_empty() {
                    quality_warnings.push(format!(
                        "Detector {} pattern {pattern_index} has no literal prefix and no keywords.",
                        detector.id
                    ));
                }
                fallback.push((compiled, detector.keywords.clone()));
            }
        }
    }

    Ok(CompileState {
        ac_literals,
        ac_map,
        fallback,
        companions,
        quality_warnings,
    })
}

pub fn build_ac_pattern_set(literals: &[String]) -> Result<Option<AhoCorasick>> {
    if literals.is_empty() {
        return Ok(None);
    }
    Ok(Some(AhoCorasick::new(literals)?))
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

pub fn build_detector_to_patterns(
    ac_map: &[CompiledPattern],
    detector_count: usize,
) -> Vec<Vec<usize>> {
    let mut map = vec![Vec::new(); detector_count];
    for (pat_idx, entry) in ac_map.iter().enumerate() {
        map[entry.detector_index].push(pat_idx);
    }
    map
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
    // For high-confidence patterns (with literal prefixes), add an expanded
    // version that handles common Unicode lookalike characters.
    for prefix in &prefixes {
        if prefix.len() >= 3 {
            let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
            if expanded_prefix != *prefix {
                if let Ok(re) = Regex::new(&format!("^{}", expanded_prefix)) {
                    let expanded_pattern = CompiledPattern {
                        detector_index,
                        regex: std::sync::Arc::new(re),
                        group: pattern.group,
                    };
                    // Always put homoglyph variants in fallback (they are regexes)
                    fallback.push((expanded_pattern, detector.keywords.clone()));
                }
            }
        }
    }

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
    })
}

/// Compile a regex once per unique source string and share the compiled
/// `Arc<Regex>` across every detector that uses it. The 888-detector corpus
/// has ~6-15% duplicate regexes (Google, JWT, Slack shapes); this collapses
/// each duplicate set into a single compiled instance, cutting startup
/// compile time and resident memory proportionally — see audits/legendary-
/// 2026-04-26 sources_verifier_detectors_legendary.md.
///
/// The cache is process-wide via a `parking_lot::Mutex<HashMap<...>>`.
/// Lookup is rare (only at scanner construction) so the contention cost is
/// negligible compared to the compile saving.
fn shared_regex(pattern: &str) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().get(pattern) {
        return Ok(Arc::clone(hit));
    }
    let regex = regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .crlf(true)
        .build()?;
    let arc = Arc::new(regex);
    cache.lock().insert(pattern.to_string(), Arc::clone(&arc));
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
