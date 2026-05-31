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
    // shapes like `AWS_KEY_ID` vs `aws_key_id` - the existing
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
    // ASCII-lowercase every literal for the GPU automaton. The SIMD path
    // compiles Hyperscan with `PatternFlags::CASELESS` unconditionally
    // (simd.rs), so detection is case-INSENSITIVE for every pattern. The GPU
    // AC / literal-set DFA matches bytes exactly, so a lowercase literal prefix
    // (e.g. `csb_`) never fires on an uppercase occurrence (`CSB_...`) and the
    // GPU path silently drops matches SIMD finds - the PERF-07 gpu_parity
    // violation, proven on drivers/gpu/drm/amd/include/soc21_enum.h (SIMD 4
    // findings, GPU 0). The GPU phase-1 paths lowercase the coalesced haystack
    // to the same fold before matching; lowercasing the literal set here is the
    // other half of that case-insensitive contract. ASCII fold is position-
    // preserving (1 byte -> 1 byte, only A-Z affected), so match offsets map
    // back unchanged and phase 2 re-confirms on the original mixed-case bytes
    // with the caseless regex.
    let literals: Vec<Vec<u8>> = ac_literals
        .iter()
        .map(|literal| literal.to_ascii_lowercase().into_bytes())
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
    crate::prefix_trie::build_propagation_table(literals)
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
    // prefix - the exact same flutterwave-FP bug the production path
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
    // Eagerly validate regex SYNTAX so a malformed detector pattern (e.g.
    // `(unclosed`) is rejected at compile time rather than silently degrading
    // to a never-matching rule on first use - a silently-accepted bad regex
    // is a dead detector. The cheap `regex_syntax` parse runs for every
    // pattern but builds NO NFA/DFA, so the lazy-compile win below is
    // preserved; `regex_syntax` is the same front end the `regex` crate uses,
    // so a parse error here is a build error there.
    if regex_syntax::Parser::new().parse(&spec.regex).is_err() {
        // Re-run through the `regex` crate only on the rare invalid pattern to
        // obtain the canonical `regex::Error` for the structured error; the
        // matcher-build cost here is irrelevant since we're erroring out.
        let source = regex::Regex::new(&spec.regex)
            .err()
            .unwrap_or_else(|| regex::Error::Syntax(spec.regex.clone()));
        return Err(ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: pattern_index,
            source,
        });
    }
    // The matcher is NOT built here - it is deferred to first use via
    // `LazyRegex` (see types.rs). Building the whole corpus up front cost
    // ~450ms-2.3s per invocation; deferral lets a scan compile only the
    // patterns the Aho-Corasick prefilter actually selects.
    Ok(CompiledPattern {
        detector_index,
        regex: LazyRegex::detector(spec.regex.as_str()),
        group: spec.group,
        client_safe: spec.client_safe,
    })
}

/// Number of independently-locked shards in the process-wide regex cache.
/// Mirrors `multiline::fragment_cache::SHARD_COUNT` so the regex cache and the
/// fragment cache share the same contention profile under rayon.
const REGEX_CACHE_SHARDS: usize = 64;

/// Total compiled-regex entries retained across all shards before LRU eviction
/// kicks in. The embedded corpus is ~889 detectors with ~6-15% duplicate
/// regexes, so the unique compiled set is well under 1k; 8192 leaves ample
/// headroom for the corpus plus any user `--detectors` overlay while still
/// bounding a long-lived daemon/watch process that recompiles distinct
/// detector sets per job. Without this cap the former `dashmap::DashMap` grew
/// without eviction, retaining every unique pattern source string plus its
/// compiled `Arc<Regex>` (each holding a ~1 MiB lazy-DFA cache) for the life
/// of the process - a slow unbounded-allocation on daemon/watch paths that
/// load many different detector sets.
const REGEX_CACHE_CAPACITY: usize = 8192;

type RegexCacheShard = parking_lot::Mutex<lru::LruCache<String, std::sync::Arc<Regex>>>;

static REGEX_CACHE: std::sync::OnceLock<Box<[RegexCacheShard]>> = std::sync::OnceLock::new();

fn regex_cache() -> &'static [RegexCacheShard] {
    REGEX_CACHE.get_or_init(|| {
        let per_shard = (REGEX_CACHE_CAPACITY / REGEX_CACHE_SHARDS).max(1);
        let nz = std::num::NonZeroUsize::new(per_shard).unwrap_or(std::num::NonZeroUsize::MIN);
        (0..REGEX_CACHE_SHARDS)
            .map(|_| parking_lot::Mutex::new(lru::LruCache::new(nz)))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    })
}

/// Pick the shard for a pattern from a hash of its source bytes, so the same
/// pattern always lands in the same shard (consistent dedup) and the load
/// spreads evenly across shards under parallel compile.
fn regex_cache_shard(pattern: &str) -> &'static RegexCacheShard {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pattern.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % REGEX_CACHE_SHARDS;
    &regex_cache()[idx]
}

pub fn shared_regex_compile(
    pattern: &str,
) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    let regex = regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(regex_dfa_limit())
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
    for (pattern, res) in compiled {
        if let Ok(arc) = res {
            regex_cache_shard(&pattern).lock().put(pattern, arc);
        }
    }
}

/// Compile a regex once per unique source string and share the compiled
/// `Arc<Regex>` across every detector that uses it. The 889-detector corpus
/// has ~6-15% duplicate regexes (Google, JWT, Slack shapes); this collapses
/// each duplicate set into a single compiled instance, cutting startup
/// compile time and resident memory proportionally - see audits/legendary-
/// 2026-04-26 sources_verifier_detectors_legendary.md.
///
/// The cache is process-wide and bounded: a sharded `parking_lot::Mutex<
/// lru::LruCache<...>>` (mirroring `multiline::fragment_cache`) caps total
/// retained entries at `REGEX_CACHE_CAPACITY` and evicts least-recently-used
/// patterns. This keeps the dedup win for the fixed corpus while bounding the
/// daemon/watch paths, which recompile a fresh scanner per job and would
/// otherwise accumulate every distinct `--detectors` pattern (plus its
/// ~1 MiB lazy-DFA cache) forever in the old unbounded `DashMap`.
pub(crate) fn shared_regex(
    pattern: &str,
) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    let shard = regex_cache_shard(pattern);
    // Cache-hit fast path: `&str` lookup, no owned-key allocation. `get`
    // bumps LRU recency, so hot corpus patterns are never evicted under load.
    if let Some(hit) = shard.lock().get(pattern) {
        return Ok(std::sync::Arc::clone(hit));
    }
    // Compile outside the lock so a slow NFA/DFA build never blocks other
    // patterns hashing to the same shard.
    let arc = shared_regex_compile(pattern)?;
    let mut lock = shard.lock();
    // Another thread may have inserted the same pattern while we compiled;
    // prefer the already-cached instance to keep the dedup invariant.
    if let Some(hit) = lock.get(pattern) {
        return Ok(std::sync::Arc::clone(hit));
    }
    lock.put(pattern.to_string(), std::sync::Arc::clone(&arc));
    Ok(arc)
}

pub fn compile_companion(spec: &CompanionSpec, detector_id: &str) -> Result<CompiledCompanion> {
    let regex = regex::RegexBuilder::new(&spec.regex)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(regex_dfa_limit())
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
