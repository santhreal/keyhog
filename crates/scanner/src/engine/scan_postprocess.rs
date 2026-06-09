use super::CompiledScanner;
use crate::types::*;
use keyhog_core::{Chunk, RawMatch};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};

/// Per-pattern confirmed-pass profiler (env-gated; measurement only). Set
/// `KEYHOG_PROFILE_CONFIRMED=1` to accumulate, per (ac_map ∪ fallback) index,
/// the wall time its whole-chunk extract costs and how many chunks it ran on —
/// isolating WHICH triggered detectors dominate `extract_confirmed_patterns`
/// and whether localization (anchored verify at the trigger position) would
/// help. Zero-cost when unset.
fn confirmed_prof_enabled() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_CONFIRMED").as_deref() == Ok("1"))
}
static CONFIRMED_PAT_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static CONFIRMED_PAT_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();

fn confirmed_prof_vecs(len: usize) -> (&'static [AtomicU64], &'static [AtomicU64]) {
    let ns = CONFIRMED_PAT_NS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    let runs = CONFIRMED_PAT_RUNS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    (ns.as_slice(), runs.as_slice())
}

/// ML batch-size histogram (env-gated by `KEYHOG_PROFILE_MLBATCH=1`). Buckets the
/// `ml_pending.len()` seen at each [`CompiledScanner::apply_ml_batch_scores`]
/// call so we can measure how far per-(sub)chunk ML batches sit from the GPU MoE
/// 64-candidate dispatch threshold — the data that decides whether cross-(sub)chunk
/// batch unification is worth the recall-exactness cost. Zero-cost when unset.
fn ml_batch_prof_enabled() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_MLBATCH").as_deref() == Ok("1"))
}
static ML_BATCH_BUCKETS: [AtomicU64; 10] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static ML_BATCH_CALLS: AtomicU64 = AtomicU64::new(0);
static ML_BATCH_CANDIDATES: AtomicU64 = AtomicU64::new(0);
static ML_BATCH_CALLS_GE64: AtomicU64 = AtomicU64::new(0);
static ML_BATCH_CANDIDATES_GE64: AtomicU64 = AtomicU64::new(0);

fn ml_batch_bucket(n: usize) -> usize {
    match n {
        0 => 0,
        1 => 1,
        2..=7 => 2,
        8..=15 => 3,
        16..=31 => 4,
        32..=63 => 5,
        64..=127 => 6,
        128..=255 => 7,
        256..=1023 => 8,
        _ => 9,
    }
}

/// Record one `apply_ml_batch_scores` call's pending-candidate count.
pub(crate) fn ml_batch_record(n: usize) {
    ML_BATCH_BUCKETS[ml_batch_bucket(n)].fetch_add(1, Relaxed);
    ML_BATCH_CALLS.fetch_add(1, Relaxed);
    ML_BATCH_CANDIDATES.fetch_add(n as u64, Relaxed);
    if n >= 64 {
        ML_BATCH_CALLS_GE64.fetch_add(1, Relaxed);
        ML_BATCH_CANDIDATES_GE64.fetch_add(n as u64, Relaxed);
    }
}

/// Print + reset the ML batch-size histogram. Called from `phase2_profile_dump`.
pub fn ml_batch_profile_dump() {
    let calls = ML_BATCH_CALLS.swap(0, Relaxed);
    let cands = ML_BATCH_CANDIDATES.swap(0, Relaxed);
    let calls_ge64 = ML_BATCH_CALLS_GE64.swap(0, Relaxed);
    let cands_ge64 = ML_BATCH_CANDIDATES_GE64.swap(0, Relaxed);
    let buckets: [u64; 10] = std::array::from_fn(|i| ML_BATCH_BUCKETS[i].swap(0, Relaxed));
    if calls == 0 {
        return;
    }
    let names = [
        "0", "1", "2-7", "8-15", "16-31", "32-63", "64-127", "128-255", "256-1023", "1024+",
    ];
    eprintln!(
        "=== ML batch-size histogram: calls={calls} candidates={cands} (avg {:.1}/call) | \
GPU-eligible (>=64): {calls_ge64} calls ({:.1}%), {cands_ge64} candidates ({:.1}% of all ML work) ===",
        cands as f64 / calls as f64,
        100.0 * calls_ge64 as f64 / calls as f64,
        100.0 * cands_ge64 as f64 / cands.max(1) as f64,
    );
    for i in 0..10 {
        eprintln!("  {:>9}: {}", names[i], buckets[i]);
    }
}

/// Decode-recursion profiler (env-gated; measurement only). Set
/// `KEYHOG_PROFILE_DECODE=1` to accumulate, across a full scan, how many parent
/// chunks entered decode-through, how many decoded sub-chunks were produced and
/// rescanned, their total byte volume, the wall time spent generating them
/// (`decode_chunk`) and the wall time spent rescanning them (`scan_inner` /
/// `scan_windowed`). This is the lever behind the ~0.4 MB/s end-to-end ceiling:
/// the per-sub-chunk fixed phase-2 cost (fallback prefilter) is paid once per
/// decoded sub-chunk, so the sub-chunk COUNT is what dominates. Zero-cost when
/// unset. Dump+reset with [`decode_profile_dump`].
fn decode_prof_enabled() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_DECODE").as_deref() == Ok("1"))
}
static DECODE_PARENTS: AtomicU64 = AtomicU64::new(0);
static DECODE_SUBCHUNKS: AtomicU64 = AtomicU64::new(0);
static DECODE_SUBCHUNK_BYTES: AtomicU64 = AtomicU64::new(0);
static DECODE_GEN_NS: AtomicU64 = AtomicU64::new(0);
static DECODE_SCAN_NS: AtomicU64 = AtomicU64::new(0);

/// Print and reset the accumulated decode-recursion counters. Call after a
/// `KEYHOG_PROFILE_DECODE=1` run. Returns `(parents, subchunks, bytes, gen_ms,
/// scan_ms)` so a measurement test can assert on it.
pub fn decode_profile_dump() -> (u64, u64, u64, f64, f64) {
    let parents = DECODE_PARENTS.swap(0, Relaxed);
    let subchunks = DECODE_SUBCHUNKS.swap(0, Relaxed);
    let bytes = DECODE_SUBCHUNK_BYTES.swap(0, Relaxed);
    let gen_ms = DECODE_GEN_NS.swap(0, Relaxed) as f64 / 1e6;
    let scan_ms = DECODE_SCAN_NS.swap(0, Relaxed) as f64 / 1e6;
    eprintln!(
        "decode-recursion: parents={parents} subchunks={subchunks} \
         ({:.1} sub/parent) bytes={bytes} gen={gen_ms:.1}ms scan={scan_ms:.1}ms \
         ({:.2} MB/s rescan)",
        if parents > 0 {
            subchunks as f64 / parents as f64
        } else {
            0.0
        },
        if scan_ms > 0.0 {
            (bytes as f64 / 1e6) / (scan_ms / 1e3)
        } else {
            0.0
        },
    );
    (parents, subchunks, bytes, gen_ms, scan_ms)
}

static CONFIRMED_GATE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Override the confirmed-pass suffix gate (test/diagnostic). `Some(true)`
/// forces it on, `Some(false)` off, `None` = env default (on). Recall is
/// identical either way — the gate only skips patterns whose required suffix
/// literal is absent (so they cannot match), so it is safe to flip.
pub fn set_confirmed_suffix_gate(mode: Option<bool>) {
    CONFIRMED_GATE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

fn confirmed_suffix_gate_enabled() -> bool {
    match CONFIRMED_GATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_CONFIRMED_GATE").as_deref() != Ok("0"))
}

/// Extract a pattern's required SUFFIX literals: every match ENDS with one of
/// these, so if NONE appears in the chunk the pattern cannot match and its
/// whole-chunk regex run can be skipped. Used to skip the O(chunk) `.*<sitename>`
/// scans of site-specific key detectors that trigger on the common prefix
/// ("key") but require a rare trailing literal the regex prefilter never uses.
///
/// Case-SENSITIVE parse (the runtime regex's case-insensitivity is matched by
/// the ASCII-case-insensitive gate AC) so the suffix doesn't case-explode.
/// `None`/empty unless the suffix is a finite set of <=4 literals each >= 6
/// bytes (selective enough to be worth gating); lowercased for the caseless AC.
fn suffix_gate_literals(src: &str) -> Vec<String> {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    const MIN_LEN: usize = 6;
    const MAX_LITS: usize = 4;
    let Ok(hir) = regex_syntax::ParserBuilder::new().build().parse(src) else {
        return Vec::new();
    };
    let mut ex = Extractor::new();
    ex.kind(ExtractKind::Suffix);
    let seq = ex.extract(&hir);
    if !seq.is_finite() {
        return Vec::new();
    }
    let Some(lits) = seq.literals() else {
        return Vec::new();
    };
    if lits.is_empty() || lits.len() > MAX_LITS {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(lits.len());
    for l in lits {
        if l.len() < MIN_LEN {
            return Vec::new();
        }
        let Ok(s) = std::str::from_utf8(l.as_bytes()) else {
            return Vec::new();
        };
        out.push(s.to_ascii_lowercase());
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Build the confirmed-pass suffix gate: one ASCII-case-insensitive AC over
/// every ac_map pattern's required suffix literals, plus per-pattern literal
/// ids. Returns `(ac, per_pattern_literal_ids)`; the AC is `None` when no
/// pattern has a gateable suffix.
pub(crate) fn build_confirmed_suffix_gate(
    ac_map: &[CompiledPattern],
) -> (Option<aho_corasick::AhoCorasick>, Vec<Vec<u32>>) {
    use std::collections::HashMap;
    let mut literals: Vec<String> = Vec::new();
    let mut literal_id: HashMap<String, usize> = HashMap::new();
    let mut per_pattern: Vec<Vec<u32>> = vec![Vec::new(); ac_map.len()];
    // The embedded corpus has ~6-15% duplicate regex sources; cache the suffix
    // extraction per source so we parse each unique pattern at most once.
    let mut src_cache: HashMap<&str, Vec<String>> = HashMap::new();
    for (i, p) in ac_map.iter().enumerate() {
        let src = p.regex.as_str();
        let lits = src_cache
            .entry(src)
            .or_insert_with(|| suffix_gate_literals(src));
        for lit in lits.clone() {
            let id = *literal_id.entry(lit.clone()).or_insert_with(|| {
                literals.push(lit.clone());
                literals.len() - 1
            });
            per_pattern[i].push(id as u32);
        }
    }
    if literals.is_empty() {
        return (None, per_pattern);
    }
    let ac = aho_corasick::AhoCorasickBuilder::new()
        .match_kind(aho_corasick::MatchKind::Standard)
        .ascii_case_insensitive(true)
        .build(&literals)
        .ok();
    (ac, per_pattern)
}

impl CompiledScanner {
    pub(crate) fn post_process_matches(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        self.post_process_matches_inner(chunk, matches, deadline);
    }

    pub(crate) fn post_process_matches_inner(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        let pp_start = std::time::Instant::now();
        self.scan_cross_chunk_fragments(chunk, matches, deadline);

        #[cfg(feature = "decode")]
        if chunk.data.len() <= self.config.max_decode_bytes {
            let prof_decode = decode_prof_enabled();
            // Dedup keys reuse the existing `Arc<str>` from `RawMatch` instead
            // of cloning to `String`. For 50+ pre-existing matches per chunk
            // this saves ~10-30 µs of allocator pressure per call.
            let mut seen: HashSet<(Arc<str>, Arc<str>)> = matches
                .iter()
                .map(|m| (Arc::clone(&m.detector_id), Arc::clone(&m.credential)))
                .collect();
            let gen_start = prof_decode.then(std::time::Instant::now);
            let decoded_chunks = {
                let _g = super::profile::span(super::profile::P::Decode);
                crate::decode::decode_chunk(
                    chunk,
                    self.config.max_decode_depth,
                    self.config.validate_decode,
                    deadline,
                    self.alphabet_screen.as_ref(),
                )
            };
            if let Some(t) = gen_start {
                DECODE_GEN_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
                if !decoded_chunks.is_empty() {
                    DECODE_PARENTS.fetch_add(1, Relaxed);
                    DECODE_SUBCHUNKS.fetch_add(decoded_chunks.len() as u64, Relaxed);
                }
            }
            for decoded_chunk in decoded_chunks {
                // kimi-wave1 finding 5.LOW: a single decoded chunk that
                // exceeds `max_decode_bytes` slips past the outer guard
                // (which only checked the *input* chunk size). Skip
                // anything that grew past the configured ceiling - the
                // input was already a decode bomb if we got here.
                if decoded_chunk.data.len() > self.config.max_decode_bytes {
                    tracing::debug!(
                        path = ?chunk.metadata.path,
                        decoded_len = decoded_chunk.data.len(),
                        ceiling = self.config.max_decode_bytes,
                        "decoded chunk exceeds max_decode_bytes; skipping"
                    );
                    continue;
                }
                if prof_decode {
                    DECODE_SUBCHUNK_BYTES.fetch_add(decoded_chunk.data.len() as u64, Relaxed);
                }
                let scan_start = prof_decode.then(std::time::Instant::now);
                // Mark the rescan so the phase-2 profiler can separate sub-chunk
                // per-pass cost from parent-chunk cost (cheap thread-local swap).
                let restore_rescan = super::profile::set_in_decode(true);
                let decoded_matches = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                    self.scan_windowed(&decoded_chunk, deadline)
                } else {
                    // Decoded sub-chunks are post-process recursion;
                    // they're typically tiny (base64/hex/url payloads
                    // sliced out of the outer chunk). NEVER route them
                    // to the GPU literal-set: per-dispatch overhead
                    // (driver init + queue submit + sync) is 10-100 ms,
                    // and `KEYHOG_BACKEND=gpu` would otherwise force
                    // every decoded chunk through that path. On a
                    // 64 MiB chunk that decodes into 1 000 sub-chunks
                    // that's a 50-second tax - exactly the wall-clock
                    // delta keyhog used to show vs SIMD on messy
                    // corpora. Force a CPU backend here regardless of
                    // env override.
                    let decoded_backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
                    self.scan_inner(&decoded_chunk, decoded_backend, deadline)
                };
                super::profile::set_in_decode(restore_rescan);
                if let Some(t) = scan_start {
                    DECODE_SCAN_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
                }
                for m in decoded_matches {
                    if crate::context::is_known_example_credential(&m.credential)
                        && chunk.data.as_str().contains(m.credential.as_ref())
                    {
                        continue;
                    }
                    // Reverse-decoder example guard: a credential surfaced from a
                    // `/reverse` chunk whose REVERSED form carries a documentation
                    // marker (`…ELPMAXE…` is `EXAMPLE` reversed) is a reversed
                    // placeholder, not a hidden real secret. The forward checks
                    // miss it because the marker bytes are themselves reversed,
                    // and `is_known_example_credential` only matches a *trailing*
                    // EXAMPLE - reversal moves the marker mid-string. Without this,
                    // reversing a negative fixture that embeds EXAMPLE/PLACEHOLDER
                    // surfaces a false positive (smartsheet contract negative).
                    if decoded_chunk.metadata.source_type.contains("/reverse") {
                        let rev = crate::decode::reverse::reverse_str(&m.credential).to_uppercase();
                        if rev.contains("EXAMPLE")
                            || rev.contains("PLACEHOLDER")
                            || rev.contains("SAMPLE")
                            || rev.contains("YOUR_")
                        {
                            continue;
                        }
                    }
                    let key = (Arc::clone(&m.detector_id), Arc::clone(&m.credential));
                    if seen.insert(key) {
                        matches.push(m);
                    }
                }
            }
        }
        tracing::debug!(
            target: "keyhog::routing",
            chunk_bytes = chunk.data.len(),
            matches = matches.len(),
            elapsed_ms = pp_start.elapsed().as_millis() as u64,
            "post_process_matches_inner done",
        );
    }

    fn scan_cross_chunk_fragments(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        if !Self::has_fragment_assignment_syntax(chunk.data.as_bytes()) {
            return;
        }

        let Some(assign_re) = crate::shared_regexes::ASSIGN_RE.as_ref() else {
            return;
        };

        for (line_idx, line) in chunk.data.lines().enumerate() {
            if let Some(caps) = assign_re.captures(line) {
                let Some(var_name_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };

                let fragment_line = line_idx + 1;
                // Compute the trigger value's byte offset within chunk.data.
                // `line` borrows from chunk.data so pointer arithmetic gives
                // the line's offset; value_match.start() is offset within
                // `line`. Used below to give reassembled findings a REAL
                // source-file position instead of the synthetic
                // dummy_chunk offset (which used to read ~19 - the length
                // of the `reassembled_key = "` prefix). Synthetic offsets
                // broke the chunk-boundary recall invariant (proptest
                // gpu_proptest_invariants P3): identical credentials got
                // different offsets depending on whether the source was
                // scanned as one chunk or two, making the test see false
                // "drops". Real-source-offset removes that asymmetry.
                let fragment_value_offset = {
                    let line_offset =
                        line.as_ptr() as usize - chunk.data.as_ref().as_ptr() as usize;
                    line_offset + value_match.start()
                };
                // The contributing fragment's path. Reassembly is same-path
                // only (see `FragmentCache::record_and_reassemble`), so this
                // is the authoritative attribution for every candidate the
                // trigger fragment produces. Captured before the move below
                // so the reassembled finding's `file_path` can be stamped
                // from it instead of inherited from `chunk.metadata.clone()`.
                let fragment_path: Option<std::sync::Arc<str>> = chunk
                    .metadata
                    .path
                    .as_ref()
                    .map(|p| std::sync::Arc::from(p.as_str()));
                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: crate::multiline::extract_prefix(var_name_match.as_str()),
                    var_name: var_name_match.as_str().to_string(),
                    value: zeroize::Zeroizing::new(value_match.as_str().to_string()),
                    line: fragment_line,
                    path: fragment_path.clone(),
                };

                let candidates = self.fragment_cache.record_and_reassemble(fragment);
                for candidate in candidates {
                    // `candidate` is `Zeroizing<String>` (kimi-wave1 fix).
                    let entropy = crate::pipeline::match_entropy(candidate.as_str().as_bytes());
                    if entropy < 3.0 || candidate.len() < 16 {
                        continue;
                    }

                    let mut dummy_data = String::with_capacity(candidate.len() + 24);
                    dummy_data.push_str("reassembled_key = \"");
                    dummy_data.push_str(candidate.as_str());
                    dummy_data.push('"');
                    let dummy_chunk = Chunk {
                        data: dummy_data.into(),
                        metadata: chunk.metadata.clone(),
                    };

                    // Tiny synthesized chunk - NEVER dispatch through
                    // GPU even if `KEYHOG_BACKEND=gpu` is set; the
                    // per-dispatch overhead (~10-100 ms) is orders of
                    // magnitude larger than scanning ~50 bytes on the
                    // CPU. The previous flow leaked the env override
                    // into `select_backend_for_file` and turned a
                    // 64 MiB messy-corpus scan into ~60 s of dummy
                    // GPU launches.
                    let backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
                    let mut reassembled_matches = self.scan_inner(&dummy_chunk, backend, deadline);
                    for m in &mut reassembled_matches {
                        m.detector_id = format!("{}:reassembled", m.detector_id).into();
                        // Stamp the finding's path from the CONTRIBUTING
                        // fragment, not the synthetic `dummy_chunk` (which
                        // cloned the outer chunk's metadata). A candidate can
                        // be glued from a fragment recorded by an earlier
                        // chunk plus this trigger fragment; inheriting the
                        // dummy chunk's path mis-attributed the reassembled
                        // finding to whatever chunk happened to be scanning
                        // when reassembly fired - the cross-file attribution
                        // mangling that produced `:reassembled` FPs. Reassembly
                        // is same-path only, so `fragment_path` is the correct
                        // source for every candidate this fragment yields.
                        m.location.file_path = fragment_path.clone();
                        // Point the finding to the trigger fragment's
                        // line AND byte offset in the source chunk.
                        // Previously offset was the synthetic position
                        // inside `"reassembled_key = \"…\""` (~19 bytes
                        // from dummy_chunk start), which broke the
                        // chunk-boundary recall invariant since the
                        // same credential got different synthetic
                        // offsets depending on chunk topology.
                        // fragment_line is window-local to `chunk`; add the
                        // chunk's base line so the reassembled finding reports
                        // the absolute file line, matching the `+ base_offset`
                        // on `m.location.offset` below. 0 on non-windowed.
                        m.location.line = Some(fragment_line + chunk.metadata.base_line);
                        // kimi-engine audit: chunk metadata can carry
                        // `base_offset` near usize::MAX (custom sources
                        // synthesizing chunks). Unchecked addition would
                        // panic in debug / wrap in release; saturating
                        // pins to MAX which is a benign garbage offset
                        // (no legitimate file is 18 EB long) but does
                        // not panic mid-scan.
                        m.location.offset =
                            fragment_value_offset.saturating_add(chunk.metadata.base_offset);
                    }
                    matches.append(&mut reassembled_matches);
                    // Zeroized automatically on drop (SensitiveString)
                }
            }
        }
    }

    fn has_fragment_assignment_syntax(data: &[u8]) -> bool {
        let has_assignment =
            memchr::memchr(b'=', data).is_some() || memchr::memchr(b':', data).is_some();
        let has_quote = memchr::memchr(b'"', data).is_some()
            || memchr::memchr(b'\'', data).is_some()
            || memchr::memchr(b'`', data).is_some();
        has_assignment && has_quote
    }

    pub(crate) fn expand_triggered_patterns(&self, triggered_patterns: &[u64]) -> Vec<u64> {
        // Propagate ONLY via `same_prefix_patterns`: when AC matches a
        // literal prefix shared by patterns X and Y, both X and Y need
        // to be evaluated since they're different regexes that happen
        // to share the same fixed prefix.
        //
        // The previous flow ALSO propagated via `detector_to_patterns`,
        // expanding to every other pattern of the same detector. That
        // was wasted work: each pattern is in `ac_map` *because* it has
        // a literal AC prefix, and if Y's prefix was not matched in
        // this chunk, Y's regex (which starts with that prefix) can't
        // match either. The expansion forced full-text regex passes on
        // patterns that were guaranteed to return no matches - the
        // dominant cost of the per-detector regex pass on chunks that
        // trigger multiple AC patterns of multi-pattern detectors.
        // No-trigger fast path: if no AC pattern fired, every word is
        // zero, so same-prefix expansion has nothing to propagate. Bail
        // BEFORE the `to_vec()` clone and the O(words) bit-scan loop -
        // the caller's `expanded.iter().any(|&w| w != 0)` would be false
        // anyway, so an empty vec is an equivalent (and cheaper) "no
        // patterns" signal. On the dominant no-hit chunk this drops the
        // expansion clone + scan to a single all-zero pass.
        if !triggered_patterns.iter().any(|&w| w != 0) {
            return Vec::new();
        }
        let mut expanded = triggered_patterns.to_vec();
        for (word_idx, &word) in triggered_patterns.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let pat_idx = word_idx * 64 + bit;
                if pat_idx >= self.ac_map.len() {
                    break;
                }
                // kimi-engine audit: defensive bounds check. ac_map and
                // same_prefix_patterns SHOULD be the same length after
                // compilation, but if a future deserialization path
                // restores compiled state from disk with a mismatched
                // shape (or a bug in the compiler tears the invariant)
                // we'd panic on the indexed access. .get() turns that
                // into a benign skip - we lose the same-prefix expansion
                // for this pattern rather than crashing the scan.
                if let Some(siblings) = self.same_prefix_patterns.get(pat_idx) {
                    for &other_idx in siblings {
                        let other_idx = other_idx as usize;
                        // Same defensive bound on the expanded write -
                        // a stale sibling index past the bitmask end
                        // would otherwise panic via bounds-checked
                        // slice index. We compute the bucket up front
                        // and silently skip out-of-range writes.
                        let bucket = other_idx / 64;
                        if let Some(slot) = expanded.get_mut(bucket) {
                            *slot |= 1u64 << (other_idx % 64);
                        }
                    }
                }
                bits &= bits - 1; // clear lowest set bit
            }
        }
        expanded
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extract_confirmed_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        let prof = confirmed_prof_enabled();
        let total = self.ac_map.len() + self.fallback.len();
        // Suffix gate: one AC pass marks which required-suffix literals are
        // present in the chunk; a triggered pattern whose suffix literals are
        // ALL absent cannot match (every match ends with one of them), so its
        // whole-chunk regex run is skipped. `None` when the gate is disabled or
        // no pattern is gateable.
        let suffix_present: Option<std::collections::HashSet<usize>> = match &self.suffix_gate_ac {
            Some(ac) if confirmed_suffix_gate_enabled() => Some(
                ac.find_overlapping_iter(&*preprocessed.text)
                    .map(|m| m.pattern().as_usize())
                    .collect(),
            ),
            _ => None,
        };
        for &pat_idx in confirmed_patterns {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            // Skip a gated ac_map pattern whose required suffix literal is absent.
            if let Some(present) = &suffix_present {
                if let Some(gate) = self.ac_suffix_gate.get(pat_idx) {
                    if !gate.is_empty() && !gate.iter().any(|id| present.contains(&(*id as usize)))
                    {
                        continue;
                    }
                }
            }
            let entry = if pat_idx < self.ac_map.len() {
                &self.ac_map[pat_idx]
            } else {
                let fallback_idx = pat_idx - self.ac_map.len();
                if fallback_idx >= self.fallback.len() {
                    continue;
                }
                &self.fallback[fallback_idx].0
            };
            let t0 = if prof {
                Some(std::time::Instant::now())
            } else {
                None
            };
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
                deadline,
            );
            if let Some(t0) = t0 {
                let (ns, runs) = confirmed_prof_vecs(total);
                if let (Some(n), Some(r)) = (ns.get(pat_idx), runs.get(pat_idx)) {
                    n.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
                    r.fetch_add(1, Relaxed);
                }
            }
        }
    }

    /// Print and reset the per-pattern confirmed-pass profile (top 30 by time).
    pub fn confirmed_profile_dump(&self, label: &str) {
        let total = self.ac_map.len() + self.fallback.len();
        let (ns, runs) = confirmed_prof_vecs(total);
        let mut rows: Vec<(usize, u64, u64)> = (0..total)
            .map(|i| (i, ns[i].swap(0, Relaxed), runs[i].swap(0, Relaxed)))
            .filter(|&(_, n, _)| n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        let grand: u64 = rows.iter().map(|r| r.1).sum();
        eprintln!(
            "=== CONFIRMED per-pattern [{label}] total={:.1} ms over {} triggered patterns ===",
            grand as f64 / 1e6,
            rows.len()
        );
        for (i, n, r) in rows.iter().take(30) {
            let src = if *i < self.ac_map.len() {
                self.ac_map[*i].regex.as_str()
            } else {
                self.fallback[*i - self.ac_map.len()].0.regex.as_str()
            };
            let per = if *r > 0 { *n / *r } else { 0 };
            let s: String = src.chars().take(60).collect();
            eprintln!(
                "  {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run  {}",
                *n as f64 / 1e6,
                100.0 * *n as f64 / grand.max(1) as f64,
                r,
                per,
                s
            );
        }
    }

    #[cfg(feature = "ml")]
    pub(crate) fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if ml_batch_prof_enabled() {
            ml_batch_record(scan_state.ml_pending.len());
        }
        if scan_state.ml_pending.is_empty() {
            return;
        }

        if !self.config.ml_enabled {
            let pending = scan_state.ml_pending.drain(..).collect::<Vec<_>>();
            for p in pending {
                let mut raw_match = p.raw_match;
                raw_match.confidence = Some(p.heuristic_conf);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
            return;
        }

        // Borrow rather than clone - `ml_pending` is alive for the duration
        // of the call, so `&str` references stay valid through ML scoring.
        // On a wide scan with hundreds of pending matches this drops 2N
        // owned-string allocations per batch.
        let candidates: Vec<(&str, &str)> = scan_state
            .ml_pending
            .iter()
            .map(|pending| (pending.credential.as_str(), pending.ml_context.as_str()))
            .collect();

        let scores = crate::gpu::batch_ml_inference(&candidates, &self.config);
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores) {
            // Honour the runtime `--ml-weight` / `ml_weight` knob instead
            // of the compile-time ML_WEIGHT/HEURISTIC_WEIGHT consts: the
            // blend is `w·ml + (1-w)·heuristic` with `w` already clamped to
            // [0,1] by `ScannerConfig::sanitise`. A hardcoded 0.6/0.4 made
            // the tuned knob a no-op (the tuned!=shipped trap) - now the
            // value the user / benchmark sets is the value the blend uses.
            let ml_weight = self.config.ml_weight;
            let mut final_score = if pending.model_authoritative {
                // Entropy-fallback candidate: the MoE is the unified scorer. The
                // "heuristic" here is bare entropy magnitude, which is precisely
                // what mislabels high-entropy non-secrets (FQDNs, git SHAs,
                // base64 blobs) - so it must NOT floor the model. Taking the
                // model score directly lets the MoE suppress those FPs (probe:
                // structured non-secrets score ~0.01, real secrets ~0.98) while
                // the downstream penalty/checksum/floor pipeline below still
                // applies uniformly. The shape gates in scan_entropy_fallback
                // already removed the cheap non-secrets before this point.
                ml_conf
            } else {
                // Detector/generic match: the regex is positive evidence, so the
                // heuristic is a confidence FLOOR and the model can only raise.
                let blended = (ml_weight * ml_conf) + ((1.0 - ml_weight) * pending.heuristic_conf);
                blended.max(pending.heuristic_conf).max(ml_conf)
            };

            // `--scan-comments` opts the Comment context out of the
            // ML-blended confidence multiplier so a real credential in
            // a `// TODO: rotate this …` comment surfaces with the
            // same weight as one on a bare assignment line. Test/docs contexts
            // stay penalized unless `--no-suppress-test-fixtures` is active.
            let context_penalty_applies = match pending.code_context {
                crate::context::CodeContext::Comment => !self.config.scan_comments,
                crate::context::CodeContext::TestCode
                | crate::context::CodeContext::Documentation => self.config.penalize_test_paths,
                _ => false,
            };
            if context_penalty_applies && final_score < 0.95 {
                final_score *= pending.code_context.confidence_multiplier();
            }

            let final_score = crate::confidence::apply_post_ml_penalties(
                final_score,
                &pending.credential,
                crate::confidence::is_service_anchored_detector(&pending.raw_match.detector_id),
            );
            let final_score = crate::confidence::apply_path_confidence_penalties(
                final_score,
                pending.raw_match.location.file_path.as_deref(),
                self.config.penalize_test_paths,
            );
            let final_score = if let Some(floor) =
                crate::confidence::known_prefix_confidence_floor(&pending.credential)
            {
                final_score.max(floor)
            } else {
                final_score
            };

            // Bayesian calibration multiplier (Tier-B #4). No-op when no
            // calibration cache exists or the detector has zero recorded
            // observations beyond the Beta(1,1) prior. Detectors with a
            // long clean track get amplified; chronic FP-emitters muted.
            let final_score = crate::confidence::apply_calibration_multiplier(
                final_score,
                &pending.raw_match.detector_id,
            );

            // Embedded-checksum adjudication - the FINAL confidence step so a
            // cryptographically-confirmed token (GitHub/npm/Slack/Stripe/GitLab/
            // PyPI) clears the `--precision` 0.85 bar regardless of how ML or
            // calibration scored its shape, and a checksum-failing one is
            // dropped. `process_match` already rejects `Invalid` before a match
            // reaches `ml_pending`, but the Pending branch never applied the
            // `Valid` floor that the non-ML `Final` branch did - so a confirmed
            // GitHub PAT was scored only on its 0.8 prefix floor and silently
            // suppressed under precision. Routing through the one shared policy
            // closes that gap and keeps the ML path self-consistent.
            let Some(final_score) =
                crate::checksum::checksum_adjusted_confidence(final_score, &pending.credential)
            else {
                continue;
            };

            // The fixture opt-out disables test/docs hard suppression too; low
            // confidence comments still follow `--scan-comments`.
            let hard_suppressed = pending.code_context.should_hard_suppress(final_score)
                && (self.config.penalize_test_paths
                    || matches!(pending.code_context, crate::context::CodeContext::Comment));
            if !hard_suppressed {
                let mut raw_match = pending.raw_match;
                raw_match.confidence = Some(final_score);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
        }
    }
}
