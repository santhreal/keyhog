//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec};
use regex::Regex;

#[path = "compiler_prefix.rs"]
mod compiler_prefix;
pub use compiler_prefix::{
    extract_inner_literals, extract_literal_prefix, extract_literal_prefixes, is_escaped_literal,
};

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

            // Homoglyph expansion for high-confidence patterns: catches
            // tokens where the literal prefix has been visually spoofed
            // with Cyrillic/Greek/full-width lookalikes. Earlier code
            // dropped just the expanded PREFIX into fallback as
            // `Regex::new("^[hh][ff]_")` — anchored to start, but with
            // NO body constraint, so any string beginning with the
            // prefix would match. Combined with the task #69 fallback
            // wire fix that finally runs these patterns, that turned
            // every prefix-anchored detector into "fires on `<prefix>*`."
            // Fix: substitute the expanded prefix into the FULL regex so
            // the homoglyph variant still requires the rest of the
            // pattern to match.
            for prefix in &prefixes {
                if prefix.len() < 3 {
                    continue;
                }
                let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
                if expanded_prefix == *prefix {
                    continue;
                }
                let full_homoglyph_regex = if let Some(suffix) =
                    pattern.regex.strip_prefix(prefix.as_str())
                {
                    // Simple case: prefix is the literal head of the regex.
                    format!("{expanded_prefix}{suffix}")
                } else if let Some(rewritten) =
                    rewrite_alternation_prefix(&pattern.regex, &expanded_prefix)
                {
                    // Alternation case: regex is `(?:p1|p2|...)body`. Replace
                    // the leading `(?:...)` with the expanded prefix so the
                    // homoglyph variant still requires the rest of the pattern
                    // to match. Without this, every alternation-prefix detector
                    // silently skipped its homoglyph fallback — leaving
                    // Cyrillic/full-width spoofed credentials of the form
                    // `[ɡ̅р][hн]p_<body>` invisible to the scanner.
                    rewritten
                } else {
                    // Prefix appears in the parse tree but isn't a leading
                    // literal slice and isn't a trivially-rewritable alternation
                    // (e.g. it sits inside a nested group). Skip — there's no
                    // safe text rewrite we can do here.
                    continue;
                };
                if let Ok(re) = Regex::new(&full_homoglyph_regex) {
                    fallback.push((
                        CompiledPattern {
                            detector_index,
                            regex: std::sync::Arc::new(re),
                            group: pattern.group,
                        },
                        detector.keywords.clone(),
                    ));
                }
            }

            if !prefixes.is_empty() {
                for prefix in prefixes {
                    ac_literals.push(prefix);
                    ac_map.push(compiled.clone());
                }
            } else {
                // Prefix extraction failed — try the AST-walking inner-literal
                // extractor before falling back. Patterns like
                // `[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}` have no leading literal
                // but contain `_AKIA` mid-pattern; pulling that into the AC
                // moves the detector out of the O(m × n) fallback loop and
                // into the O(n) prefilter path.
                let inner = extract_inner_literals(&pattern.regex);
                if !inner.is_empty() {
                    for lit in inner {
                        ac_literals.push(lit);
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
    }

    Ok(CompileState {
        ac_literals,
        ac_map,
        fallback,
        companions,
        quality_warnings,
    })
}

/// If `regex` is `(?:p1|p2|...)body` (with optional inline flags / `?:`
/// variants), replace the leading alternation group with `expanded_prefix`.
/// Returns the rewritten regex source; returns `None` if the regex doesn't
/// start with a non-capturing alternation group we know how to rewrite.
///
/// This is the homoglyph counterpart of `extract_literal_prefixes`'s
/// alternation handling — when the prefix extractor returned a literal
/// from inside `(?:ghp_|github_pat_)`, the homoglyph compiler needs the
/// matching surgical rewrite to splice the expanded prefix into the
/// regex without losing the trailing body constraint.
fn rewrite_alternation_prefix(regex: &str, expanded_prefix: &str) -> Option<String> {
    // Strip a leading inline flag group like `(?i)`.
    let (flag_prefix, body) = split_leading_inline_flag(regex);
    // Only consider non-capturing groups — `(?:p1|p2|...)`. A bare
    // `(...)` is a capturing group around the whole credential, NOT an
    // alternation of prefixes; rewriting it as "{expanded_prefix}{suffix}"
    // would drop the credential body and leave a regex that matches just
    // the prefix. That was the flutterwave false-positive on negative:
    // `(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)` got rewritten to
    // `FLW[SСＳ][EЕΕＥ]C[KКΚＫ]_` which then matched bare `FLWSECK_`
    // anywhere in the text.
    let group_open_end = if let Some(rest) = body.strip_prefix("(?:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?i:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?m:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?s:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?im:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?is:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?ms:") {
        body.len() - rest.len()
    } else {
        // Bare `(` or no leading group — refuse to rewrite. The simple
        // strip_prefix path in the caller handles literal-head regexes;
        // this function is strictly for `(?:...)` alternation prefixes.
        return None;
    };
    // Find the matching closing `)` for the leading group.
    let bytes = body.as_bytes();
    let mut depth: i32 = 0;
    let mut close_at: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close_at = Some(i);
                    break;
                }
            }
            // Don't track escapes — we only need to find the *top-level*
            // closing paren, and within a regex source a literal `(` or
            // `)` inside a character class is rare in real detectors.
            _ => {}
        }
    }
    let close = close_at?;
    // The leading group must actually contain a `|` — without one this
    // is just `(?:singleton)pattern`, not an alternation, and rewriting
    // would silently drop the singleton body.
    let inside = &body[group_open_end..close];
    if !inside.contains('|') {
        return None;
    }
    // Trailing body after the alternation group.
    let suffix = &body[close + 1..];
    Some(format!("{flag_prefix}{expanded_prefix}{suffix}"))
}

fn split_leading_inline_flag(s: &str) -> (&str, &str) {
    if !s.starts_with("(?") {
        return ("", s);
    }
    let bytes = s.as_bytes();
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        (&s[..=i], &s[i + 1..])
    } else {
        ("", s)
    }
}

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
    })
}

/// Compile a regex once per unique source string and share the compiled
/// `Arc<Regex>` across every detector that uses it. The 889-detector corpus
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternation_rewrite_basic() {
        let out = rewrite_alternation_prefix("(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}", "[gɡ]hp_");
        assert_eq!(out.unwrap(), "[gɡ]hp_[a-zA-Z0-9_]{36}");
    }

    #[test]
    fn alternation_rewrite_with_inline_flag() {
        let out = rewrite_alternation_prefix(
            "(?i)(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}",
            "[gɡ]hp_",
        );
        assert_eq!(out.unwrap(), "(?i)[gɡ]hp_[a-zA-Z0-9_]{36}");
    }

    #[test]
    fn alternation_rewrite_with_alternative_flag_prefix() {
        let out = rewrite_alternation_prefix("(?i:abc|def)\\w+", "[a]bc");
        assert_eq!(out.unwrap(), "[a]bc\\w+");
    }

    #[test]
    fn alternation_rewrite_handles_nested_groups() {
        // Inner `(\d+)` should not confuse the depth tracker.
        let out = rewrite_alternation_prefix(
            "(?:abc(?:\\d{2})|def)body",
            "[a]bc",
        );
        assert_eq!(out.unwrap(), "[a]bcbody");
    }

    #[test]
    fn alternation_rewrite_returns_none_for_literal_head() {
        // No leading group → caller should fall through to strip_prefix.
        let out = rewrite_alternation_prefix("AKIA[A-Z0-9]{16}", "[a]kia");
        assert!(out.is_none());
    }

    #[test]
    fn alternation_rewrite_returns_none_for_capturing_full_pattern() {
        // `(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)` is a CAPTURING group
        // around the full credential, not an alternation of prefixes.
        // Rewriting it would silently drop the credential body and leave
        // just the expanded prefix matching anywhere in the chunk — the
        // exact bug that caused flutterwave-api-key to fire on prose
        // `FLWSECK_TEST-short-X`. Refuse to rewrite capturing groups.
        let out = rewrite_alternation_prefix(
            "(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)",
            "FLW[SСＳ]ECK_TEST-",
        );
        assert!(
            out.is_none(),
            "must not rewrite a capturing-group-around-full-credential; \
             a non-None result here matches the prefix anywhere"
        );
    }

    #[test]
    fn alternation_rewrite_returns_none_for_singleton_group() {
        // `(?:foobody)` has no `|` so it's not an alternation; rewriting
        // would silently drop the `body` part. Refuse.
        let out = rewrite_alternation_prefix("(?:foobody)tail", "[fF]oo");
        assert!(out.is_none());
    }

    #[test]
    fn split_leading_inline_flag_parses_common_shapes() {
        assert_eq!(split_leading_inline_flag("(?i)body"), ("(?i)", "body"));
        assert_eq!(split_leading_inline_flag("(?im)body"), ("(?im)", "body"));
        assert_eq!(split_leading_inline_flag("(?ims)body"), ("(?ims)", "body"));
        assert_eq!(split_leading_inline_flag("body"), ("", "body"));
        assert_eq!(
            split_leading_inline_flag("(?:abc|def)body"),
            ("", "(?:abc|def)body")
        );
    }
}
