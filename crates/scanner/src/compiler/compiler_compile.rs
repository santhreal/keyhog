//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec};
use regex::Regex;

pub(crate) fn build_ac_pattern_set(literals: &[String]) -> Result<Option<AhoCorasick>> {
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
    // phase2_keyword_ac at build_phase2_keyword_ac (this file)
    // already uses ascii_case_insensitive(true) for the same reason.
    Ok(Some(
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(literals)?,
    ))
}

/// Keep GPU literal inputs in Keyhog order so Vyre match pattern IDs map back
/// to `ac_map` without an adapter table.
#[cfg(feature = "gpu")]
pub(crate) fn build_gpu_literals(
    ac_literals: &[String],
    phase2_keywords: &[String],
) -> Option<std::sync::Arc<Vec<Vec<u8>>>> {
    if ac_literals
        .iter()
        .chain(phase2_keywords)
        .any(String::is_empty)
    {
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
        .chain(phase2_keywords)
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

pub(crate) fn build_same_prefix_patterns(literals: &[String]) -> Vec<Vec<usize>> {
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

pub(crate) fn build_prefix_propagation(literals: &[String]) -> Vec<Vec<usize>> {
    crate::prefix_trie::build_propagation_table(literals)
}

pub(crate) fn build_phase2_keyword_ac(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
) -> (Option<AhoCorasick>, Vec<Vec<usize>>, Vec<String>) {
    let mut all_keywords = Vec::new();
    let mut keyword_to_patterns = Vec::new();
    let mut keyword_map: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (pattern_idx, (_, keywords)) in phase2_patterns.iter().enumerate() {
        for kw in keywords {
            // Floor stays at 4: lowering it to 3 to admit
            // mailchimp's `-us`/`-eu`/`-uk` and openai/anthropic's
            // `sk-`/`sk-ant-`/`pk-` measured a NET F1 regression
            // (-67 TP, +28 FP) on SecretBench-medium 15k seed-0
            // because (a) too-broad phase-2 detectors like
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
        return (None, Vec::new(), Vec::new());
    }

    let keyword_count = all_keywords.len();
    let ac = match AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(&all_keywords)
    {
        Ok(ac) => Some(ac),
        Err(error) => {
            tracing::warn!(
                keywords = keyword_count,
                %error,
                "phase-2 keyword Aho-Corasick build failed; keyword-gate optimization disabled (recall preserved)"
            );
            None
        }
    };

    (ac, keyword_to_patterns, all_keywords)
}

pub(crate) fn log_quality_warnings(warnings: &[String]) {
    for warning in warnings {
        tracing::warn!(target: "keyhog::scanner::quality", "{}", warning);
    }
}

pub(crate) fn compile_detector_companions(
    detector: &DetectorSpec,
) -> Result<Vec<CompiledCompanion>> {
    detector
        .companions
        .iter()
        .map(|companion| compile_companion(companion, &detector.id))
        .collect()
}

/// Process-wide set of regex source strings already proven syntactically
/// valid by `regex_syntax::Parser`. A one-shot `keyhog scan` rebuilds the whole
/// engine every invocation, and `compile_pattern` used to re-run the
/// `regex_syntax` syntax parse over EVERY one of the ~1846 embedded pattern
/// sources on each rebuild (~17 ms serial, measured) — pure repeated work, since
/// the embedded corpus never changes within a process and the regex strings are
/// dedup-stable. Memoize the validation verdict per source so the second and
/// later engine builds in the same process (daemon recompiles, watch-mode
/// rebuilds, the per-invocation compile a test/bench harness repeats, the K-fold
/// cold loop in perf_startup_latency) skip re-parsing an already-validated
/// source. Mirrors the existing process-wide `REGEX_CACHE` (compiled matchers)
/// and the on-disk Hyperscan DB cache: validate once, reuse forever.
/// (PERF-startup_latency-1.) Bounded by the universe of distinct pattern
/// sources, which is < 2k for the corpus plus any `--detectors` overlay.
static VALIDATED_REGEX_SOURCES: std::sync::OnceLock<
    parking_lot::Mutex<std::collections::HashSet<std::sync::Arc<str>>>,
> = std::sync::OnceLock::new();

fn validated_regex_sources(
) -> &'static parking_lot::Mutex<std::collections::HashSet<std::sync::Arc<str>>> {
    VALIDATED_REGEX_SOURCES
        .get_or_init(|| parking_lot::Mutex::new(std::collections::HashSet::new()))
}

pub(crate) fn compile_pattern(
    detector_index: usize,
    pattern_index: usize,
    spec: &PatternSpec,
    detector_id: &str,
    detector_keywords: &[String],
) -> Result<CompiledPattern> {
    // Eagerly validate regex SYNTAX so a malformed detector pattern (e.g.
    // `(unclosed`) is rejected at compile time rather than silently degrading
    // to a never-matching rule on first use - a silently-accepted bad regex
    // is a dead detector. The cheap `regex_syntax` parse builds NO NFA/DFA, so
    // the lazy-compile win below is preserved; `regex_syntax` is the same front
    // end the `regex` crate uses, so a parse error here is a build error there.
    //
    // The verdict is memoized process-wide (`VALIDATED_REGEX_SOURCES`): a source
    // already proven valid in this process is NOT re-parsed, so repeated engine
    // rebuilds (one-shot CLI runs sharing a process, daemon/watch recompiles,
    // the cold loop in perf_startup_latency) pay the ~17 ms full-corpus syntax
    // parse only once instead of every build. Correctness is unchanged: a source
    // only enters the set AFTER a successful parse, and an invalid source never
    // enters it, so it is re-validated (and re-rejected) on every build.
    let already_validated = validated_regex_sources()
        .lock()
        .contains(spec.regex.as_str());
    if !already_validated {
        if regex_syntax::Parser::new().parse(&spec.regex).is_err() {
            // Re-run through the `regex` crate only on the rare invalid pattern to
            // obtain the canonical `regex::Error` for the structured error; the
            // matcher-build cost here is irrelevant since we're erroring out.
            let source = regex::Regex::new(&spec.regex)
                .err()
                .unwrap_or_else(|| regex::Error::Syntax(spec.regex.clone())); // LAW10: constructs the fallback Error value for reporting; not a swallow
            return Err(ScanError::RegexCompile {
                detector_id: detector_id.to_string(),
                index: pattern_index,
                source,
            });
        }
        validated_regex_sources()
            .lock()
            .insert(std::sync::Arc::from(spec.regex.as_str()));
    }
    // The matcher is NOT built here - it is built on first use via
    // `LazyRegex` (see types.rs). Building the whole corpus up front cost
    // ~450ms-2.3s per invocation; lazy build lets a scan compile only the
    // patterns the Aho-Corasick prefilter actually selects.
    Ok(CompiledPattern {
        detector_index,
        regex: LazyRegex::detector(spec.regex.as_str()),
        group: spec.group,
        client_safe: spec.client_safe,
        match_proves_keyword_nearby: match_proves_keyword_nearby(
            spec.regex.as_str(),
            detector_keywords,
        ),
        homoglyph_variant: false,
    })
}

pub(crate) fn match_proves_keyword_nearby(regex: &str, detector_keywords: &[String]) -> bool {
    let prefixes = super::compiler_prefix::extract_literal_prefixes(regex);
    !prefixes.is_empty()
        && prefixes.iter().all(|prefix| {
            detector_keywords.iter().any(|keyword| {
                !keyword.is_empty()
                    && prefix
                        .as_bytes()
                        .get(..keyword.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(keyword.as_bytes()))
            })
        })
}

/// Number of independently-locked shards in the process-wide regex cache.
/// Mirrors `fragment_cache::SHARD_COUNT` so the regex cache and the
/// fragment cache share the same contention profile under rayon.
const REGEX_CACHE_SHARDS: usize = 64;

/// Total compiled-regex entries retained across all shards before LRU eviction
/// kicks in. The embedded corpus is ~900 detectors with ~6-15% duplicate
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
        let nz = std::num::NonZeroUsize::new(per_shard).unwrap_or(std::num::NonZeroUsize::MIN); // LAW10: zero => NonZeroUsize::MIN floor; shard/size knob, perf-only
        (0..REGEX_CACHE_SHARDS)
            .map(|_| parking_lot::Mutex::new(lru::LruCache::new(nz)))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    })
}

/// Pick the shard for a pattern from a hash of its source bytes, so the same
/// pattern always lands in the same shard (consistent dedup) and the load
/// spreads evenly across shards under parallel compile. Uses the scanner's
/// shared cache-key hash owner instead of a second standard-library hash path.
fn regex_cache_shard(pattern: &str) -> &'static RegexCacheShard {
    let idx = (crate::util_hash::hash_fast(pattern.as_bytes()) as usize) % REGEX_CACHE_SHARDS;
    &regex_cache()[idx]
}

pub(crate) fn shared_regex_compile(
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

/// Compile a regex once per unique source string and share the compiled
/// `Arc<Regex>` across every detector that uses it. The embedded corpus
/// has ~6-15% duplicate regexes (Google, JWT, Slack shapes); this collapses
/// each duplicate set into a single compiled instance, cutting startup
/// compile time and resident memory proportionally - see docs/EXECUTION_PLAN.md.
///
/// The cache is process-wide and bounded: a sharded `parking_lot::Mutex<
/// lru::LruCache<...>>` (mirroring `fragment_cache`) caps total
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

pub(crate) fn compile_companion(
    spec: &CompanionSpec,
    detector_id: &str,
) -> Result<CompiledCompanion> {
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
