#[cfg(feature = "simd")]
use super::phase2_hs::Phase2HsEngine;
use crate::types::LazyRegex;
use aho_corasick::AhoCorasick;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;

// The per-scanner performance tuning lives at crate root but remains an
// engine-internal route selector, not scanner public API.
pub(crate) use crate::tuning::*;

/// Per-pattern phase-2 profiler (measurement only). Enabled by the unified
/// scanner profiler (`keyhog scan --profile`) so profiling has one runtime owner.
/// Accumulates wall time per phase-2 pattern to identify the detectors that
/// dominate `scan_phase2_patterns`. Zero-cost when unset.
pub(crate) fn phase2_pattern_prof_enabled() -> bool {
    super::profile::enabled()
}

static PHASE2_PATTERN_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static PHASE2_PATTERN_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();

/// Sub-split of `populate_active_phase2`: time spent in the always-active
/// RegexSet prefilter vs the keyword Aho-Corasick. Confirms which half of the
/// active-set computation dominates. Env-gated like the per-pattern profiler.
pub(crate) static POPULATE_PREFILTER_NS: AtomicU64 = AtomicU64::new(0);
pub(crate) static POPULATE_KEYWORD_NS: AtomicU64 = AtomicU64::new(0);

/// Prefix-gate diagnostics (enabled by `keyhog scan --profile`). Counts how
/// many gateable batches were SKIPPED (their required prefix literals absent)
/// vs RUN, and how many `mark_matches` calls the gate saw — so we can tell
/// whether the gate actually skips on a given corpus or whether spliced context
/// keeps it firing.
pub(crate) static GATE_BATCH_SKIPS: AtomicU64 = AtomicU64::new(0);
pub(crate) static GATE_BATCH_RUNS: AtomicU64 = AtomicU64::new(0);
pub(crate) static GATE_CALLS: AtomicU64 = AtomicU64::new(0);

/// SWE-101 no-candidate fast-path counters. ALWAYS live (no env gate): a
/// regression test reads them to PROVE the always-active prefilter does **no
/// per-pattern work** on a chunk that cannot activate any always-active pattern.
///
///   * `MARK_CALLS`          — every `mark_matches` call.
///   * `MARK_GATE_SKIPS`     — calls that the combined no-candidate gate proved
///     inert (no always-active pattern can fire), so the expensive per-pattern
///     body (HS `scan_each` enumeration + the HS-incompatible whole-chunk regex
///     loop, or the `regex::RegexSet` batch loop) was skipped entirely.
///   * `MARK_PERPATTERN_WORK` — calls that DID enter the expensive per-pattern
///     marking body. On a no-candidate corpus this MUST stay at zero; any
///     increment is the flagship "a phase-2 pass ate runtime on a chunk with no
///     candidate" regression (SWE-101).
///
/// These are relaxed atomics bumped once per call on a path that is already doing
/// (or deliberately skipping) a chunk scan, so the counter cost is in the noise;
/// they are not behind the profiler flag because the regression gate must observe
/// them in an ordinary (unprofiled) run.
pub(crate) static MARK_CALLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static MARK_GATE_SKIPS: AtomicU64 = AtomicU64::new(0);
pub(crate) static MARK_PERPATTERN_WORK: AtomicU64 = AtomicU64::new(0);

/// Snapshot `(calls, gate_skips, perpattern_work)` of the no-candidate fast-path
/// counters WITHOUT resetting them. The SWE-101 regression test reads a delta
/// across a scan to assert that a no-candidate chunk did zero per-pattern work.
#[cfg(test)]
pub(crate) fn phase2_mark_stats() -> (u64, u64, u64) {
    (
        MARK_CALLS.load(Relaxed),
        MARK_GATE_SKIPS.load(Relaxed),
        MARK_PERPATTERN_WORK.load(Relaxed),
    )
}

/// Reset the no-candidate fast-path counters to zero (test isolation between
/// scans).
#[cfg(test)]
pub(crate) fn phase2_mark_stats_reset() {
    MARK_CALLS.store(0, Relaxed);
    MARK_GATE_SKIPS.store(0, Relaxed);
    MARK_PERPATTERN_WORK.store(0, Relaxed);
}

/// Print and reset the prefix-gate skip counters. Returns `(calls, skips, runs)`.
#[cfg(test)]
pub(crate) fn phase2_gate_stats_dump() -> (u64, u64, u64) {
    let calls = GATE_CALLS.swap(0, Relaxed);
    let skips = GATE_BATCH_SKIPS.swap(0, Relaxed);
    let runs = GATE_BATCH_RUNS.swap(0, Relaxed);
    eprintln!(
        "prefix-gate: calls={calls} gateable_batch_skips={skips} gateable_batch_runs={runs} \
         ({:.1}% skipped)",
        if skips + runs > 0 {
            100.0 * skips as f64 / (skips + runs) as f64
        } else {
            0.0
        }
    );
    (calls, skips, runs)
}

pub(crate) fn phase2_pattern_prof_vecs(len: usize) -> (&'static [AtomicU64], &'static [AtomicU64]) {
    let ns = PHASE2_PATTERN_NS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    let runs = PHASE2_PATTERN_RUNS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    (ns.as_slice(), runs.as_slice())
}

#[inline]
pub(crate) fn phase2_pattern_prof_record(len: usize, index: usize, nanos: u64) {
    let (ns, runs) = phase2_pattern_prof_vecs(len);
    if let (Some(n), Some(r)) = (ns.get(index), runs.get(index)) {
        n.fetch_add(nanos, Relaxed);
        r.fetch_add(1, Relaxed);
    }
}

/// Per-thread scratch for computing the active phase-2 set of a chunk.
///
/// Previously this was a dense `Vec<bool>` of `phase2_patterns.len()` (~1000) that
/// was zero-filled, `copy_from_slice`-seeded, and then fully iterated by the
/// caller every chunk - O(F) per chunk even when only a handful of patterns
/// fire. We now carry a SPARSE list of active phase-2 indices instead, so
/// callers visit only the active patterns. Two pieces:
///   * `active`: the sparse index list, refilled (not reallocated) per chunk.
///   * `stamp` + `generation`: a versioned "seen" set used to dedup a pattern
///     that is both always-active and keyword-triggered, without the O(F)
///     per-chunk clear a dense bitmap would need. The generation counter just
///     increments; `stamp` is grown once and reused.
pub(crate) struct ActivePatternsScratch {
    pub(crate) active: Vec<usize>,
    stamp: Vec<u32>,
    generation: u32,
}

impl ActivePatternsScratch {
    pub(crate) const fn new() -> Self {
        Self {
            active: Vec::new(),
            stamp: Vec::new(),
            generation: 0,
        }
    }

    /// Begin a fresh chunk: bump the generation so all previous stamps are
    /// stale, ensure the stamp vector covers `len` patterns, and clear the
    /// sparse list (retaining its capacity). On generation wraparound the
    /// stamp vector is reset so a stale `u32::MAX` stamp can't alias.
    pub(crate) fn begin(&mut self, len: usize) {
        if self.stamp.len() < len {
            self.stamp.resize(len, 0);
        }
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            // Wrapped: every stamp must be treated as stale.
            self.stamp.iter_mut().for_each(|s| *s = 0);
            self.generation = 1;
        }
        self.active.clear();
    }

    /// Record `index` as active if it has not already been recorded this
    /// generation. Returns nothing; dedup is silent. `pub(crate)` so the
    /// extracted [`super::phase2_hs::Phase2HsEngine::mark`] can mark into it.
    #[inline]
    pub(crate) fn mark(&mut self, index: usize) {
        if let Some(slot) = self.stamp.get_mut(index) {
            if *slot != self.generation {
                *slot = self.generation;
                self.active.push(index);
            }
        }
    }

    /// O(1) membership test against the current generation. Used by the
    /// shared-anchor path to gate candidate positions to the active set
    /// without a second pass over `active`.
    #[inline]
    pub(crate) fn is_active(&self, index: usize) -> bool {
        self.stamp.get(index) == Some(&self.generation)
    }
}

thread_local! {
    /// Per-thread scratch for shared-anchor candidate `(pattern_idx, pos)`
    /// pairs. Grown once and reused (cleared, not freed) per chunk.
    pub(crate) static ANCHOR_CANDIDATES: RefCell<Vec<(u32, u32)>> = const { RefCell::new(Vec::new()) };
}

/// Combined-RegexSet prefilter for the always-active phase-2 patterns.
///
/// Always-active phase-2 patterns (patterns with no >=4-char keyword for the AC
/// prefilter) otherwise run their individual capture regex over the FULL chunk
/// on every scan. Measured on the RTX 5090, that made `scan_phase2_patterns`
/// ~97% of per-chunk scan time (~127 ms of a 1 MiB no-hit chunk; ~7 MiB/s).
/// This runs ONE linear `RegexSet` pass and marks only the patterns that can
/// match somewhere; the rest are skipped (they would extract zero matches).
///
/// SOUNDNESS: each set entry is built with the EXACT flags of the pattern's
/// own regex — `shared_regex` (case-insensitive + CRLF + size/DFA limits) for
/// `detector` patterns, `Regex::new` defaults for `plain` homoglyph variants —
/// so the set reports a pattern iff that pattern's regex matches. No real match
/// is ever skipped (recall-preserving); only dead work is removed. It MUST run
/// over the same text the extraction uses (`preprocessed.text`).
/// One compiled RegexSet batch plus the phase-2 indices its set entries map
/// back to (`phase2_indices[set_pattern_id] == phase-2 pattern index`).
pub(crate) struct PrefilterBatch {
    pub(crate) set: regex::RegexSet,
    /// For PLAIN (homoglyph-variant) batches: an ASCII-folded RegexSet (the
    /// homoglyph regex with non-ASCII stripped: `[sѕｓ]`→`[s]`, `[lіІιΙｌΟοоOo]`→
    /// `[lOo]`), in the SAME entry order as `set`. On a pure-ASCII chunk the
    /// fold is match-equivalent to the unicode form, so `matches()` returns the
    /// IDENTICAL set of entry ids — identical marking, identical active-set
    /// order — but evaluates faster. `None` for case-insensitive batches and on
    /// fold-compile failure (the unicode `set` is then used everywhere).
    pub(crate) ascii_set: Option<regex::RegexSet>,
    /// Truncated-at-first-unbounded-repetition variant of `set` (each entry
    /// passed through `truncate_for_prefilter`, SAME entry order), kept on the
    /// fast lazy-DFA. A sound SUPERSET marking gate — see `truncate_for_prefilter`.
    /// Used instead of `set` when `prefilter_truncate_enabled()`.
    pub(crate) set_trunc: regex::RegexSet,
    /// Truncated variant of `ascii_set` (the folded form, then truncated). Same
    /// `None` conditions as `ascii_set`.
    pub(crate) ascii_set_trunc: Option<regex::RegexSet>,
    pub(crate) phase2_indices: Vec<usize>,
    /// True iff EVERY pattern in this batch is prefix-anchorable (a finite,
    /// non-empty, pure-ASCII required-prefix literal set, each member >= 3
    /// bytes). When true, the combined prefix-literal Aho-Corasick gate
    /// (`ci_gate`/`plain_gate`) is a SOUND skip oracle: if NONE of those
    /// patterns' prefix literals appears in the chunk, none can match, so this
    /// batch's whole-chunk RegexSet pass is dead work and is skipped. False ->
    /// the batch always runs (a pattern with no required literal could match
    /// without any gate literal, so skipping would drop recall).
    pub(crate) gateable: bool,
    /// True iff EVERY pattern in this batch is a compiler-generated homoglyph
    /// fallback variant (`CompiledPattern::homoglyph_variant`). Such a batch is
    /// skipped ENTIRELY on a pure-ASCII chunk when `homoglyph_ascii_skip` is on:
    /// each variant's base ASCII prefix is in the AC/confirmed path, so on a
    /// no-homoglyph chunk the variant adds nothing. This is the precise skip the
    /// case-sensitivity heuristic got wrong (generic plain fallbacks share the
    /// case flag but have no base AC pattern; they land in non-skippable batches).
    pub(crate) homoglyph_skippable: bool,
}

/// SWE-101 combined no-candidate gate for the always-active phase-2 prefilter.
///
/// The always-active patterns split into ANCHORABLE (every match begins with one
/// of a finite, >=3-byte ASCII required-prefix literal — their union is the
/// `anchor_ac`) and NON-ANCHORABLE (can match with no required literal). On a
/// PURE-ASCII chunk where `anchor_ac` finds no literal, no anchorable pattern can
/// fire, so the expensive HS / RegexSet body is skipped; the few non-anchorable
/// patterns are checked PRECISELY with their OWN compiled regexes (`non_anchorable`)
/// and only the ones that actually match are marked. Findings stay byte-identical
/// to the full body (validated by `phase2_prefilter_hs_findings_parity` and
/// `phase2_no_candidate_zero_work`), but the per-chunk cost drops from a
/// ~2,700-pattern scan to one AC `is_match` plus a handful of per-pattern checks.
pub(crate) struct CombinedNoCandidateGate {
    /// `ascii_case_insensitive` Aho-Corasick over the anchorable always-active
    /// patterns' required-prefix literals (ASCII-lowercased + deduped). A no-hit on
    /// a pure-ASCII chunk proves none of those patterns can match.
    pub(crate) anchor_ac: AhoCorasick,
    /// The non-anchorable always-active patterns (those with NO required prefix
    /// literal), as `(phase2_index, regex)`. Empty when every always-active
    /// pattern is anchorable (the ideal — the gate then does a pure AC `is_match`
    /// and nothing else on the skip path). Each regex is the pattern's OWN compiled
    /// `LazyRegex` (cloned `Arc`, shared compile cache), so checking it on the skip
    /// path is byte-for-byte match-equivalent to the full body — no over-marking,
    /// no under-marking, recall-identical by construction.
    pub(crate) non_anchorable: Vec<(usize, LazyRegex)>,
    /// Fast first-bigram prescreen for the no-candidate path.
    ///
    /// A 65536-bit direct lookup table (8 KB, fits in L1d) indexed by
    /// `(byte_a as u16) << 8 | byte_b as u16`. Each set bit means "at least
    /// one anchor literal starts with this 2-byte sequence (after ASCII
    /// case-folding)". ALL four case combinations are inserted for alphabetic
    /// pairs, mirroring the `ascii_case_insensitive` AC.
    ///
    /// `anchor_present` checks this before running the full AC: if NO adjacent
    /// byte pair in the text has its bit set, the AC scan is guaranteed to
    /// return false (no literal can start in the text). This is O(N/4) with a
    /// 4-wide unrolled loop (~1 cycle/byte on Zen 4 / Apple M-series vs.
    /// ~5-15 ns/byte for AC state-machine transitions) — roughly 10-30x
    /// cheaper than the AC on typical 200-4096 byte no-candidate chunks.
    ///
    /// Soundness: every anchor literal starts with its first 2 bytes; if those
    /// 2 bytes (case-folded) never appear adjacent in the text, the literal
    /// cannot start there. No real candidate is ever skipped (sound subset of
    /// the AC's own non-hit criterion), and no extra false positives are
    /// introduced (the AC still confirms every bloom hit). Law 10 is fully
    /// satisfied: the bloom only accelerates the skip path, never widens it.
    pub(crate) anchor_first_bigram_bloom: Box<[u64; 1024]>,
}

impl CombinedNoCandidateGate {
    /// Build the first-bigram bloom from deduplicated, ASCII-lowercased
    /// anchor literals. Inserts all four ASCII case variants for each
    /// alphabetic byte pair to mirror the `ascii_case_insensitive` AC.
    /// Called once at scanner-build time; zero cost on the hot path.
    pub(crate) fn build_first_bigram_bloom(lits: &[Vec<u8>]) -> Box<[u64; 1024]> {
        let mut bits = Box::new([0u64; 1024]);
        for lit in lits {
            if lit.len() < 2 {
                // Law 10: a <2-byte literal has no first-bigram to gate on, so the
                // prescreen cannot prove its absence — silently skipping it would
                // make `anchor_present` miss that literal. `gate_prefix_literals`
                // enforces ≥3-byte ASCII prefixes upstream (else the pattern runs
                // unconditionally), so this is unreachable; but if that invariant
                // ever weakens, fail OPEN — every bigram present ⇒ `anchor_present`
                // always falls through to the exact AC, never a silent skip.
                return Box::new([u64::MAX; 1024]);
            }
            let a = lit[0]; // lowercased; guaranteed ASCII by gate_prefix_literals
            let b = lit[1];
            // Insert all case variants: for alphabetic bytes the AC matches
            // both cases (ascii_case_insensitive), so we mirror that here.
            let a_variants: &[u8] = if a.is_ascii_alphabetic() {
                &[a, a ^ 0x20] // lowercase + uppercase toggle via XOR 0x20
            } else {
                std::slice::from_ref(&a)
            };
            let b_variants: &[u8] = if b.is_ascii_alphabetic() {
                &[b, b ^ 0x20]
            } else {
                std::slice::from_ref(&b)
            };
            for &ca in a_variants {
                for &cb in b_variants {
                    let idx = (ca as usize) << 8 | cb as usize;
                    bits[idx >> 6] |= 1u64 << (idx & 63);
                }
            }
        }
        bits
    }

    /// True iff an anchorable pattern's required prefix MAY occur in
    /// `match_text` (pure-ASCII precondition checked by the caller).
    ///
    /// Fast path: the first-bigram bloom checks whether any adjacent byte pair
    /// in the text has its bit set. No set bit → the AC scan is guaranteed to
    /// return false and is skipped entirely (sub-100 ns on warm 8 KB L1d table).
    /// A bloom hit → AC runs for a precise answer (recall-identical to before).
    ///
    /// Soundness: every anchor literal starts with the 2-byte sequence that is
    /// in the bloom; if the bloom finds no such sequence, the AC finds nothing.
    #[inline]
    pub(crate) fn anchor_present(&self, match_text: &str) -> bool {
        // --- Bigram prescreen (O(N/4), ~1 cycle/byte) ---
        // Four independent probes per iteration avoid serial-dependency stalls.
        let bytes = match_text.as_bytes();
        let bits = self.anchor_first_bigram_bloom.as_ref();
        let len = bytes.len();
        if len < 2 {
            // No bigram exists — AC cannot match either (shortest literal ≥ 3 bytes).
            return false;
        }
        let last_start = len - 2; // last valid pair index
                                  // Inline bigram probe helper: look up (bytes[i], bytes[i+1]) in the bloom.
                                  // The optimizer inlines this at each of the four unrolled call sites.
        #[inline(always)]
        fn probe(bits: &[u64; 1024], bytes: &[u8], i: usize) -> bool {
            let idx = (bytes[i] as usize) << 8 | bytes[i + 1] as usize;
            bits[idx >> 6] & (1u64 << (idx & 63)) != 0
        }
        let mut i = 0usize;
        // 4-wide unrolled: independent loads, one branch per group of four.
        while i + 4 <= last_start + 1 {
            if probe(bits, bytes, i)
                | probe(bits, bytes, i + 1)
                | probe(bits, bytes, i + 2)
                | probe(bits, bytes, i + 3)
            {
                // At least one bigram hit: run the AC for precision.
                return self.anchor_ac.is_match(match_text);
            }
            i += 4;
        }
        // Tail: fewer than 4 remaining pairs.
        while i <= last_start {
            if probe(bits, bytes, i) {
                return self.anchor_ac.is_match(match_text);
            }
            i += 1;
        }
        // Bloom found no first-bigram match: the AC is guaranteed to find nothing.
        false
    }

    /// Mark the non-anchorable always-active patterns that actually match
    /// `match_text` into `scratch`, for the skip path (no anchorable pattern can
    /// match here). Each pattern is checked with its OWN compiled regex, so the
    /// marked set is exactly what the full body would mark for these patterns.
    #[inline]
    pub(crate) fn mark_non_anchorable(
        &self,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
    ) {
        for (idx, re) in &self.non_anchorable {
            if re.get().is_match(match_text) {
                scratch.mark(*idx);
            }
        }
    }

    /// True iff some non-anchorable pattern can fire on `match_text` — the boolean
    /// companion to [`mark_non_anchorable`](Self::mark_non_anchorable) for the
    /// admission gate. Checks each pattern's own regex, early-exiting at the first
    /// match, so the admission decision is exact (never over- or under-admits).
    #[inline]
    #[cfg(any(feature = "simd", feature = "gpu"))]
    pub(crate) fn any_non_anchorable_match(&self, match_text: &str) -> bool {
        self.non_anchorable
            .iter()
            .any(|(_, re)| re.get().is_match(match_text))
    }
}

pub(crate) struct Phase2AlwaysActivePrefilter {
    /// RegexSet batches; running each and unioning the reported patterns is
    /// equivalent to running every entry's regex individually, but in a handful
    /// of linear passes instead of thousands.
    pub(crate) batches: Vec<PrefilterBatch>,
    /// Patterns whose batch failed to compile (e.g. exceeded the size limit):
    /// run unconditionally so a compile failure costs performance, never recall.
    pub(crate) ungated_indices: Vec<usize>,
    /// Combined Aho-Corasick over the required-prefix literals of every
    /// CASE-INSENSITIVE gateable batch's patterns (built `ascii_case_insensitive`
    /// to mirror the detector regexes' case folding). A no-hit proves NO gateable
    /// ci pattern can match, so all `gateable` ci batches are skipped. `None`
    /// when no ci pattern is gate-eligible. SOUND on every chunk (ci batches run
    /// the same `set` on all chunks).
    pub(crate) ci_gate: Option<AhoCorasick>,
    /// Combined Aho-Corasick over the required-prefix literals of every PLAIN
    /// (homoglyph-variant) gateable batch's ASCII-FOLDED form (case-sensitive,
    /// matching the `ascii_set` matcher). A no-hit on a pure-ASCII chunk proves
    /// no gateable plain pattern's folded form can match, so all `gateable` plain
    /// batches are skipped. Applied ONLY on the ASCII path (`use_ascii`); on a
    /// non-ASCII chunk the unicode `set` runs unconditionally (the folded literals
    /// don't describe its required prefixes). `None` when none are gate-eligible.
    pub(crate) plain_gate: Option<AhoCorasick>,
    /// SWE-101 combined no-candidate gate — the ONE fast combined prefilter that
    /// gates the expensive per-pattern marking. See [`CombinedNoCandidateGate`].
    /// `Some` whenever the gate can be built (an `ascii_case_insensitive`
    /// Aho-Corasick over the anchorable always-active patterns' required-prefix
    /// literals, plus the small non-anchorable always-mark list, and no ungated
    /// pattern); `None` only on a degraded build, where `mark_matches` runs the
    /// full body unconditionally (recall-safe, never a silent skip — Law 10).
    pub(crate) combined_gate: Option<CombinedNoCandidateGate>,
    /// Hyperscan-backed engine over the SAME always-active patterns. When present
    /// and enabled (`phase2_hs_enabled`), `mark_matches` uses it instead of the
    /// `regex::RegexSet` batches above: one SIMD multi-pattern scan with
    /// `SINGLEMATCH` (fire-once = "does P match") replaces the ~2,679-pattern
    /// whole-chunk RegexSet pass — the measured #1 scan cost (`phase2:prefilter`),
    /// ~1000x faster (`phase2_prefilter_hs_vs_regexset`) and findings-identical
    /// (`phase2_prefilter_hs_findings_parity`). `None` when the `simd` feature
    /// is off or HS failed to compile (then the RegexSet batches are the path).
    #[cfg(feature = "simd")]
    pub(crate) hs: Option<Phase2HsEngine>,
}

/// Bytes of already-scanned parent context kept on each side of the decoded span
/// when focus-restricting the phase-2 pass. Covers any self-contained phase-2
/// match that begins in context and extends into the decoded text (the credential
/// prefix). Generous relative to credential prefix lengths; the differential
/// `decode_focus_parity` gate validates it is sufficient.
pub(crate) const DECODE_FOCUS_MARGIN: usize = 64;

// NOTE: there is intentionally NO confirmed-pass equivalent of this focus. A
// decode sub-chunk splices the decoded text in place of the encoded blob, which
// (a) changes the byte adjacencies at the junction and (b) creates new token
// boundaries inside what was a contiguous base64/hex run. A confirmed /
// companion-anchored detector can therefore fire on spliced context arbitrarily
// far from the decoded span where the parent — which saw the still-encoded bytes
// — did not, so the "outside the decoded span is a parent duplicate" theorem that
// makes the phase-2 focus sound does NOT hold for confirmed detectors. A
// symmetric `[ds-M, de+M]` window with M=256 still dropped real cloudflare-api-token
// and mysql-connection-string findings on the mirror corpus; the only provably
// safe M equals the full splice context (zero savings). Do not re-add it.

/// Extract a pattern's required-prefix literals IF it is gate-eligible: the
/// prefix `Seq` must be finite, non-empty, every member >= 3 bytes AND pure
/// ASCII (so an `ascii_case_insensitive` Aho-Corasick over them is a sound
/// presence oracle). Returns the literal byte strings, or `None` when the
/// pattern can match without any specific prefix literal (then it must never be
/// gated). Mirrors the soundness contract of `regex_prefix_anchorable`.
pub(crate) fn gate_prefix_literals(src: &str) -> Option<Vec<Vec<u8>>> {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    // recall-safe (fail-OPEN) — if the prefix-source regex cannot be parsed here,
    // we return `None`, which makes the caller run the pattern UNCONDITIONALLY (no
    // prefix gate). The gate only ever SKIPS a pattern when it has positively
    // proven the required prefix is absent; a parse failure can therefore never
    // cause a missed match, only a missed optimization.
    let hir = regex_syntax::ParserBuilder::new().build().parse(src).ok()?; // LAW10: fail-open, see above
    let mut ex = Extractor::new();
    ex.kind(ExtractKind::Prefix);
    let seq = ex.extract(&hir);
    if !seq.is_finite() {
        return None;
    }
    let literals = seq.literals()?;
    if literals.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(literals.len());
    for lit in literals {
        let bytes = lit.as_bytes();
        // Every member must be a real >=3-byte ASCII required prefix. A short or
        // non-ASCII member would make the AC gate either over-match (unsound case
        // folding) or too weak; bail so the pattern runs unconditionally.
        if bytes.len() < 3 || !bytes.is_ascii() {
            return None;
        }
        out.push(bytes.to_vec());
    }
    Some(out)
}

thread_local! {
    /// Per-thread pool for the active phase-2 scratch. Pool one per worker;
    /// it is grown once and reused thereafter (no per-chunk allocation).
    pub(crate) static ACTIVE_PATTERNS_POOL: RefCell<ActivePatternsScratch> =
        const { RefCell::new(ActivePatternsScratch::new()) };
}
