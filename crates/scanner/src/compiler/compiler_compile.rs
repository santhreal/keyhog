//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec};
use regex::Regex;
use std::borrow::Cow;
static BUILD_GPU_LITERALS_INVOCATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn build_gpu_literals_invocations() -> usize {
    BUILD_GPU_LITERALS_INVOCATIONS.load(std::sync::atomic::Ordering::Relaxed)
}

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
    // shapes like `AWS_KEY_ID` vs `aws_key_id`; the phase-two keyword index
    // applies identical ASCII-insensitive comparison.
    Ok(Some(
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(literals)?,
    ))
}

/// Keep GPU literal inputs in KeyHog order so VYRE match pattern IDs map back
/// to `ac_map` without an adapter table.
pub(crate) fn build_gpu_literals<'a>(
    ac_literals: impl IntoIterator<Item = &'a [u8]>,
    phase2_keywords: impl IntoIterator<Item = &'a [u8]>,
    phase2_always_anchor_literals: impl IntoIterator<Item = &'a [u8]>,
    confirmed_anchor_literals: impl IntoIterator<Item = &'a [u8]>,
    generic_keyword_literals: impl IntoIterator<Item = &'a [u8]>,
) -> Option<std::sync::Arc<Vec<Vec<u8>>>> {
    BUILD_GPU_LITERALS_INVOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    build_gpu_literal_rows(
        ac_literals
            .into_iter()
            .chain(phase2_keywords)
            .chain(phase2_always_anchor_literals)
            .chain(confirmed_anchor_literals)
            .chain(generic_keyword_literals),
        "GPU fused literal set",
    )
}

/// One-shot guard so the empty-literal GPU-disable notice is printed to stderr at
/// most once per process (the `tracing::warn!` still fires every time for logs).
static GPU_LITERAL_EMPTY_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn build_gpu_literal_rows<'a>(
    literals: impl Iterator<Item = &'a [u8]>,
    label: &'static str,
) -> Option<std::sync::Arc<Vec<Vec<u8>>>> {
    // VYRE compiles this set case-insensitively, matching Hyperscan's CASELESS
    // detector and keyword semantics without rewriting source bytes. Preserve
    // canonical literal bytes here so serialized artifacts and positioned
    // evidence describe the actual compiled detector plan.
    let mut rows = Vec::new();
    for literal in literals {
        if literal.is_empty() {
            // Law 10: an empty AC literal disables the ENTIRE GPU literal scan for
            // this build (every scan then routes to CPU/SIMD). A `tracing::warn!`
            // alone is silent to an operator running an exact GPU backend at the default
            // log level (surface it loudly, once, like report_gpu_matcher_unavailable).
            tracing::warn!("{label} contains an empty literal; disabling GPU literal scan");
            if GPU_LITERAL_EMPTY_WARNED.set(()).is_ok() {
                eprintln!(
                    "keyhog: a detector produced an empty literal in the {label}, so the GPU \
literal matcher was discarded and every scan will route through CPU/SIMD instead of the GPU \
literal path. Check your detector definitions for an empty AC literal (an empty `keywords`/\
prefix entry). Use --require-gpu when GPU acceleration is mandatory."
                );
            }
            return None;
        }
        rows.push(literal.to_vec());
    }
    if rows.is_empty() {
        None
    } else {
        tracing::info!(patterns = rows.len(), "{} prepared for VYRE", label);
        Some(std::sync::Arc::new(rows))
    }
}

pub(crate) fn build_same_prefix_patterns(literals: &[String]) -> crate::engine::CsrU32 {
    let mut groups: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for (index, literal) in literals.iter().enumerate() {
        groups.entry(literal.as_str()).or_default().push(index);
    }
    let mut pairs = Vec::new();
    for indices in groups.values().filter(|indices| indices.len() > 1) {
        for &row in indices {
            pairs.extend(
                indices
                    .iter()
                    .copied()
                    .filter(|&other| other != row)
                    .map(|other| (row, other)),
            );
        }
    }
    crate::engine::CsrU32::from_pairs(literals.len(), pairs)
}

pub(crate) fn build_prefix_propagation(literals: &[String]) -> crate::engine::CsrU32 {
    crate::engine::CsrU32::from_pairs(
        literals.len(),
        crate::prefix_trie::build_propagation_pairs(literals),
    )
}

const PHASE2_KEYWORD_BUCKET_COUNT: usize = 1 << 16;

#[inline]
fn phase2_keyword_prefix(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0].to_ascii_lowercase(), bytes[1].to_ascii_lowercase()])
}

/// Compact exact ASCII-insensitive keyword index.
///
/// Every phase-two keyword has at least two bytes. A direct 16-bit prefix table
/// rejects almost every haystack position with one bounded lookup; only rows
/// sharing that prefix perform full byte comparison. This avoids rebuilding a
/// multi-megabyte Aho-Corasick automaton during every installed process start.
pub(crate) struct Phase2KeywordIndex {
    bucket_offsets: Box<[u32]>,
    bucket_keyword_ids: Box<[u32]>,
    keywords: Box<[Box<[u8]>]>,
}

pub(crate) struct Phase2KeywordMatches<'a> {
    index: &'a Phase2KeywordIndex,
    haystack: &'a [u8],
    next_position: usize,
}

impl Phase2KeywordIndex {
    pub(crate) fn build(keywords: &[Cow<'_, str>]) -> Option<Self> {
        if keywords.iter().any(|keyword| keyword.len() < 2) {
            tracing::warn!(
                "phase-2 keyword index received a sub-bigram literal; keyword-gate optimization disabled (recall preserved)"
            );
            return None;
        }
        let mut rows = Vec::with_capacity(keywords.len());
        for (keyword_id, keyword) in keywords.iter().enumerate() {
            let Ok(keyword_id) = u32::try_from(keyword_id) else {
                tracing::warn!(
                    keywords = keywords.len(),
                    "phase-2 keyword index exceeds u32 rows; keyword-gate optimization disabled (recall preserved)"
                );
                return None;
            };
            rows.push((phase2_keyword_prefix(keyword.as_bytes()), keyword_id));
        }
        rows.sort_unstable();

        let mut bucket_offsets = vec![0u32; PHASE2_KEYWORD_BUCKET_COUNT + 1];
        let mut cursor = 0usize;
        for (bucket, offset) in bucket_offsets
            .iter_mut()
            .take(PHASE2_KEYWORD_BUCKET_COUNT)
            .enumerate()
        {
            *offset = u32::try_from(cursor).expect("keyword rows were bounded to u32");
            while rows
                .get(cursor)
                .is_some_and(|(prefix, _)| usize::from(*prefix) == bucket)
            {
                cursor += 1;
            }
        }
        bucket_offsets[PHASE2_KEYWORD_BUCKET_COUNT] =
            u32::try_from(cursor).expect("keyword rows were bounded to u32");

        Some(Self {
            bucket_offsets: bucket_offsets.into_boxed_slice(),
            bucket_keyword_ids: rows.into_iter().map(|(_, keyword_id)| keyword_id).collect(),
            keywords: keywords
                .iter()
                .map(|keyword| Box::<[u8]>::from(keyword.as_bytes()))
                .collect(),
        })
    }

    #[inline]
    pub(crate) fn find_iter<'a>(&'a self, haystack: &'a str) -> Phase2KeywordMatches<'a> {
        Phase2KeywordMatches {
            index: self,
            haystack: haystack.as_bytes(),
            next_position: 0,
        }
    }
}

impl Iterator for Phase2KeywordMatches<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let mut best: Option<(usize, usize)> = None;
        let mut position = self.next_position;
        while position + 1 < self.haystack.len() && best.is_none_or(|(end, _)| position + 2 <= end)
        {
            let prefix = usize::from(phase2_keyword_prefix(&self.haystack[position..]));
            let candidate_start = self.index.bucket_offsets[prefix] as usize;
            let candidate_end = self.index.bucket_offsets[prefix + 1] as usize;
            for &keyword_id in &self.index.bucket_keyword_ids[candidate_start..candidate_end] {
                let keyword_id = keyword_id as usize;
                let keyword = &self.index.keywords[keyword_id];
                let remaining = &self.haystack[position..];
                if remaining.len() >= keyword.len()
                    && remaining[..keyword.len()].eq_ignore_ascii_case(keyword)
                {
                    let candidate = (position + keyword.len(), keyword_id);
                    if best.is_none_or(|current| candidate < current) {
                        best = Some(candidate);
                    }
                }
            }
            position += 1;
        }

        match best {
            Some((end, keyword_id)) => {
                self.next_position = end;
                Some(keyword_id)
            }
            None => {
                self.next_position = self.haystack.len();
                None
            }
        }
    }
}

pub(crate) fn build_phase2_keyword_index<'a>(
    phase2_patterns: &'a [(CompiledPattern, Vec<String>)],
) -> (
    Option<Phase2KeywordIndex>,
    crate::engine::CsrU32,
    Vec<Cow<'a, str>>,
) {
    let mut all_keywords = Vec::new();
    let mut keyword_pattern_pairs = Vec::new();
    let mut keyword_map: std::collections::HashMap<Cow<'a, str>, usize, ahash::RandomState> =
        std::collections::HashMap::with_hasher(ahash::RandomState::new());

    let mut add_candidate = |candidate: Cow<'a, str>, pattern_idx: usize| {
        use std::collections::hash_map::Entry;

        let idx = match keyword_map.entry(candidate) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let idx = all_keywords.len();
                all_keywords.push(entry.key().clone());
                entry.insert(idx);
                idx
            }
        };
        keyword_pattern_pairs.push((idx, pattern_idx));
    };

    for (pattern_idx, (pattern, keywords)) in phase2_patterns.iter().enumerate() {
        let allows_repeated_separator = pattern.allows_repeated_keyword_separator;
        for keyword in keywords {
            // Raw detector keywords retain the measured four-byte floor.
            if keyword.len() >= 4 {
                add_candidate(Cow::Borrowed(keyword.as_str()), pattern_idx);
            }
            // Repeated-separator regexes also admit their detector-scoped stem.
            if allows_repeated_separator {
                if let Some(stem) = longest_compound_keyword_segment(keyword) {
                    if stem.len() >= 2 && stem != *keyword {
                        add_candidate(Cow::Owned(stem), pattern_idx);
                    }
                }
            }
        }
    }

    if all_keywords.is_empty() {
        return (
            None,
            crate::engine::CsrU32::from_pairs(0, std::iter::empty()),
            Vec::new(),
        );
    }

    let index = Phase2KeywordIndex::build(&all_keywords);
    (
        index,
        crate::engine::CsrU32::from_pairs(all_keywords.len(), keyword_pattern_pairs),
        all_keywords,
    )
}

fn longest_compound_keyword_segment(keyword: &str) -> Option<String> {
    keyword
        .split(['_', '-', '.'])
        .filter(|segment| {
            segment.len() >= 2 && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .max_by_key(|segment| segment.len())
        .map(str::to_ascii_lowercase)
}

fn regex_allows_repeated_compound_keyword_separator(regex: &str) -> bool {
    let Ok(hir) = regex_syntax::Parser::new().parse(regex) else {
        return false;
    };
    hir_contains_repeated_separator(&hir)
}

fn hir_contains_repeated_separator(hir: &regex_syntax::hir::Hir) -> bool {
    use regex_syntax::hir::HirKind;

    match hir.kind() {
        HirKind::Repetition(repetition) => {
            let repeats = repetition.max.is_none_or(|maximum| maximum > 1);
            (repeats && hir_is_compound_keyword_separator(&repetition.sub))
                || hir_contains_repeated_separator(&repetition.sub)
        }
        HirKind::Capture(capture) => hir_contains_repeated_separator(&capture.sub),
        HirKind::Concat(parts) | HirKind::Alternation(parts) => {
            parts.iter().any(hir_contains_repeated_separator)
        }
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => false,
    }
}

fn hir_is_compound_keyword_separator(hir: &regex_syntax::hir::Hir) -> bool {
    use regex_syntax::hir::{Class, HirKind};

    match hir.kind() {
        HirKind::Class(Class::Unicode(class)) => {
            let mut has_join_punctuation = false;
            for range in class.iter() {
                let start = u32::from(range.start());
                let end = u32::from(range.end());
                // Unicode whitespace ranges are short. Reject a broad user
                // class before walking it so routing analysis stays bounded.
                if end - start > 32 {
                    return false;
                }
                for codepoint in start..=end {
                    let Some(character) = char::from_u32(codepoint) else {
                        return false;
                    };
                    if matches!(character, '_' | '-' | '.') {
                        has_join_punctuation = true;
                    } else if !character.is_whitespace() {
                        return false;
                    }
                }
            }
            has_join_punctuation
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut has_join_punctuation = false;
            for range in class.iter() {
                for byte in range.start()..=range.end() {
                    if matches!(byte, b'_' | b'-' | b'.') {
                        has_join_punctuation = true;
                    } else if !byte.is_ascii_whitespace() {
                        return false;
                    }
                }
            }
            has_join_punctuation
        }
        _ => false,
    }
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

pub(crate) fn compile_pattern(
    detector_index: usize,
    pattern_index: usize,
    spec: &PatternSpec,
    detector_id: &str,
    detector_keywords: &[String],
) -> Result<CompiledPattern> {
    spec.validate_required_literals()
        .map_err(|reason| ScanError::DetectorPatternPolicy {
            detector_id: detector_id.to_string(),
            index: pattern_index,
            reason,
        })?;
    // Validate the source by building it exactly as the scan path will
    // (`shared_regex_compile` = the same case-insensitive / CRLF / size-limit
    // builder `LazyRegex::get` uses), so a malformed or oversized pattern from
    // the embedded corpus or a user `--detectors` overlay is still rejected
    // loudly here, before a scan can start.
    //
    // The build is deliberately NOT retained. Seeding every corpus pattern's
    // compiled `Regex` held one NFA / one-pass-DFA / Teddy-prefilter state
    // machine per declared pattern, companion and generated homoglyph variant
    // resident for the whole process (~450 MB measured over the embedded
    // corpus's 1,709 patterns and 178 companions) even when the scan touched
    // eleven bytes. Phase-1 literal gating means a real scan reaches a small
    // fraction of the corpus, and `LazyRegex` rebuilds exactly those, once
    // each, through the shared process-wide regex cache. `shared_regex_compile`
    // (not `shared_regex`) keeps this throwaway validation build out of that
    // cache so the cache holds only patterns a scan actually used.
    let validated =
        shared_regex_compile(spec.regex.as_str()).map_err(|source| ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: pattern_index,
            source,
        })?;
    // Validate the declared capture group is a real index in THIS regex.
    // `captures_len()` counts the implicit whole-match group 0 plus every
    // explicit group, so a valid `group` satisfies `group < captures_len`. An
    // out-of-range group is not a regex error (the pattern compiles); it only
    // bites at scan time, where `extract_grouped_matches` resolves the target
    // with `locs.get(group).unwrap_or((full_start, full_end))` and SILENTLY
    // falls back to the whole match, capturing keyword + separator + value
    // instead of the secret, which pollutes the credential and usually fails the
    // checksum, dropping a real secret. Fail closed here (Law 10: no silent
    // fallback) so a malformed detector from ANY source, the embedded corpus or
    // a user `--detectors` overlay, is rejected loudly at compile rather than
    // mis-scanned. (The embedded corpus is held clean by
    // detector_capture_group_integrity.rs; this also covers user overlays.)
    if let Some(group) = spec.group {
        let captures_len = validated.captures_len();
        if group >= captures_len {
            return Err(ScanError::CaptureGroupOutOfRange {
                detector_id: detector_id.to_string(),
                index: pattern_index,
                group,
                captures_len,
            });
        }
    }
    drop(validated);
    let pattern_index = u32::try_from(pattern_index)
        .ok()
        .filter(|index| *index != u32::MAX)
        .ok_or_else(|| ScanError::DetectorPatternPolicy {
            detector_id: detector_id.to_string(),
            index: pattern_index,
            reason: "pattern index exceeds the provenance ordinal contract".to_string(),
        })?;
    Ok(CompiledPattern {
        detector_index,
        pattern_index,
        regex: LazyRegex::detector(spec.regex.as_str()),
        group: spec.group,
        client_safe: spec.client_safe,
        weak_anchor: spec.weak_anchor,
        structural_password_slot: spec.structural_password_slot,
        match_proves_keyword_nearby: match_proves_keyword_nearby(
            spec.regex.as_str(),
            detector_keywords,
        ),
        allows_repeated_keyword_separator: regex_allows_repeated_compound_keyword_separator(
            spec.regex.as_str(),
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

/// Total source keys retained across all shards before LRU eviction. Values are
/// weak references: compiled regex programs stay resident only while a live
/// scanner workload owns them. The bounded keys allow concurrent live scanners
/// to deduplicate compilation without turning completed daemon/watch jobs into
/// a process-lifetime compiled-regex heap.
const REGEX_CACHE_CAPACITY: usize = 8192;

type RegexCacheShard = parking_lot::Mutex<lru::LruCache<String, std::sync::Weak<Regex>>>;

static REGEX_CACHE: std::sync::LazyLock<Box<[RegexCacheShard]>> = std::sync::LazyLock::new(|| {
    (0..REGEX_CACHE_SHARDS)
        .map(|_| parking_lot::Mutex::new(lru::LruCache::new(std::num::NonZeroUsize::MIN)))
        .collect::<Vec<_>>()
        .into_boxed_slice()
});

fn regex_cache() -> &'static [RegexCacheShard] {
    &REGEX_CACHE
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

/// Compile a regex once per unique source string shared by concurrently live
/// scanners. The cache holds weak references, so a completed workload releases
/// its compiled programs when its `LazyRegex` owners drop. Source keys remain
/// bounded by `REGEX_CACHE_CAPACITY` for daemon/watch processes that load many
/// custom detector sets.
pub(crate) fn shared_regex(
    pattern: &str,
) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    let shard = regex_cache_shard(pattern);
    // Cache-hit fast path: `&str` lookup, no owned-key allocation. `get`
    // bumps LRU recency, so hot corpus patterns are never evicted under load.
    if let Some(hit) = shard.lock().get(pattern).and_then(std::sync::Weak::upgrade) {
        return Ok(hit);
    }
    // Compile outside the lock so a slow NFA/DFA build never blocks other
    // patterns hashing to the same shard.
    let arc = shared_regex_compile(pattern)?;
    let mut lock = shard.lock();
    // Another thread may have inserted the same pattern while we compiled;
    // prefer the already-cached instance to keep the dedup invariant.
    if let Some(hit) = lock.get(pattern).and_then(std::sync::Weak::upgrade) {
        return Ok(hit);
    }
    let per_shard = (REGEX_CACHE_CAPACITY / REGEX_CACHE_SHARDS).max(1);
    crate::fragment_cache::grow_lru_for_workload(&mut lock, per_shard);
    lock.put(pattern.to_string(), std::sync::Arc::downgrade(&arc));
    Ok(arc)
}

pub(crate) fn shared_regex_cache_workload_probe(pattern: &str) -> (usize, usize) {
    for shard in regex_cache() {
        shard.lock().clear();
    }

    let first = shared_regex(pattern).expect("probe regex compiles");
    let first_weak = std::sync::Arc::downgrade(&first);
    let second = shared_regex(pattern).expect("live probe regex reuses cache");
    let live_compiles = if std::sync::Arc::ptr_eq(&first, &second) {
        1
    } else {
        2
    };
    drop((first, second));

    let expired = first_weak.upgrade().is_none();
    let completed_workload = shared_regex(pattern).expect("expired probe regex recompiles");
    let completed_workload_compiles = live_compiles + usize::from(expired);
    drop(completed_workload);
    (live_compiles, completed_workload_compiles)
}

pub(crate) fn companion_regex(
    pattern: &str,
) -> std::result::Result<std::sync::Arc<Regex>, regex::Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(regex_dfa_limit())
        .crlf(true)
        .build()
        .map(std::sync::Arc::new)
}

pub(crate) fn compile_companion(
    spec: &CompanionSpec,
    detector_id: &str,
) -> Result<CompiledCompanion> {
    let regex = companion_regex(&spec.regex).map_err(|e| ScanError::RegexCompile {
        detector_id: detector_id.to_string(),
        index: FIRST_CAPTURE_GROUP_INDEX,
        source: e,
    })?;
    let capture_group = match spec.capture_group {
        Some(group) if group < regex.captures_len() => Some(group),
        Some(group) => {
            return Err(ScanError::Config(format!(
                "detector {detector_id:?} companion {:?} selects capture group {group}, \
                 but its regex exposes groups 0..{}",
                spec.name,
                regex.captures_len().saturating_sub(1)
            )));
        }
        None => (regex.captures_len() > 1).then_some(FIRST_CAPTURE_GROUP_INDEX),
    };
    Ok(CompiledCompanion {
        name: std::sync::Arc::from(spec.name.as_str()),
        regex: LazyRegex::companion(spec.regex.as_str()),
        capture_group,
        within_lines: spec.within_lines,
        within_bytes: spec.within_bytes,
        direction: spec.direction,
        scope: spec.scope,
        requirement: spec.effective_requirement(),
        value_relation: spec.value_relation,
    })
}
