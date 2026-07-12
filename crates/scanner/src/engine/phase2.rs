pub(crate) use super::phase2_first_bigram::FirstBigramSet;
#[cfg(feature = "simd")]
use super::phase2_hs::Phase2HsEngine;
use crate::types::LazyRegex;
use aho_corasick::AhoCorasick;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;

mod mark_stats;
#[cfg(feature = "simd")]
pub(crate) use mark_stats::record_mark_hs_served;
pub(crate) use mark_stats::{
    format_mark_decomposition, phase2_mark_stats, phase2_mark_stats_reset, record_mark_call,
    record_mark_gate_skip, record_mark_perpattern_work, record_mark_regexset_served, MarkSnapshot,
};

mod hs_mark_timing;
pub(crate) use hs_mark_timing::{
    format_hs_mark_split, hs_mark_timing_reset, hs_mark_timing_snapshot, HsMarkSplit,
};
#[cfg(feature = "simd")]
pub(crate) use hs_mark_timing::{record_hs_mark_dropped_ns, record_hs_mark_scan_ns};

// The per-scanner performance tuning lives at crate root but remains an
// engine-internal route selector, not scanner public API.
pub(crate) use crate::tuning::*;

pub(crate) const MIN_PREFIX_BYTES: usize = 3;

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

pub(crate) fn phase2_pattern_prof_reset(len: usize) {
    let (ns, runs) = phase2_pattern_prof_vecs(len);
    for n in ns {
        n.store(0, Relaxed);
    }
    for r in runs {
        r.store(0, Relaxed);
    }
    POPULATE_PREFILTER_NS.store(0, Relaxed);
    POPULATE_KEYWORD_NS.store(0, Relaxed);
    GATE_BATCH_SKIPS.store(0, Relaxed);
    GATE_BATCH_RUNS.store(0, Relaxed);
    GATE_CALLS.store(0, Relaxed);
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
    /// homoglyph regex with non-ASCII stripped: `[sѕｓ]`→`[s]`, `[lіІιΙｌΟοо]`→
    /// `[l]`), in the SAME entry order as `set`. On a pure-ASCII chunk the
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

/// Lazily built portable RegexSet prefilter state. Hyperscan and the
/// no-candidate gate can answer many chunks without ever touching these
/// heavyweight RegexSet batches, so scanner construction keeps this behind a
/// per-scanner OnceLock.
pub(crate) struct PortablePrefilter {
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
    /// introduced (the AC still confirms every first-bigram hit). Law 10 is
    /// fully satisfied: the set only accelerates the skip path, never widens it.
    pub(crate) anchor_first_bigram: FirstBigramSet,
}

impl CombinedNoCandidateGate {
    /// True iff an anchorable pattern's required prefix MAY occur in
    /// `match_text` (pure-ASCII precondition checked by the caller).
    ///
    /// Fast path: the first-bigram set checks whether any adjacent byte pair
    /// in the text can begin a literal. No set bit means the AC scan is
    /// guaranteed false and is skipped entirely. A hit runs the exact AC.
    #[inline]
    pub(crate) fn anchor_present(&self, match_text: &str) -> bool {
        self.anchor_first_bigram.may_have_match(match_text) && self.anchor_ac.is_match(match_text)
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
    #[cfg(any(feature = "simd", feature = "gpu", test))]
    pub(crate) fn any_non_anchorable_match(&self, match_text: &str) -> bool {
        self.non_anchorable
            .iter()
            .any(|(_, re)| re.get().is_match(match_text))
    }
}

pub(crate) struct Phase2AlwaysActivePrefilter {
    /// Valid always-active phase-2 indices. Invalid indices are counted and
    /// warned during construction; portable RegexSet construction consumes this
    /// clean list lazily on the first RegexSet fallback use.
    pub(crate) valid_always_active_indices: Vec<usize>,
    /// Heavy portable RegexSet batches/gates. Lazily initialized so the HS path
    /// and no-candidate skip path do not pay RegexSet construction for scans
    /// that never need it.
    pub(crate) portable: OnceLock<PortablePrefilter>,
    /// SWE-101 combined no-candidate gate — the ONE fast combined prefilter that
    /// gates the expensive per-pattern marking. See [`CombinedNoCandidateGate`].
    /// Lazily initialized so scanner construction stores only validated routing
    /// indices; a scan that disables the gate or never reaches phase-2 does not
    /// compile its Aho-Corasick state.
    pub(crate) combined_gate: OnceLock<Option<CombinedNoCandidateGate>>,
    /// Hyperscan-backed engine over the SAME always-active patterns. Lazily
    /// initialized so scanner construction and no-candidate chunks do not compile
    /// the one-shard ~2k-pattern HS database. When present and enabled
    /// (`phase2_hs_enabled`), `mark_matches` uses it instead of the
    /// `regex::RegexSet` batches above: one SIMD multi-pattern scan with
    /// `SINGLEMATCH` (fire-once = "does P match") replaces the ~2,679-pattern
    /// whole-chunk RegexSet pass — the measured #1 scan cost (`phase2:prefilter`),
    /// ~1000x faster (`phase2_prefilter_hs_vs_regexset`) and findings-identical
    /// (`phase2_prefilter_hs_findings_parity`). `None` when the `simd` feature
    /// is off or HS failed to compile (then the RegexSet batches are the path).
    ///
    /// The engine holds TWO sub-databases (`Phase2HsEngine::{full, ascii_lean}`):
    /// on a pure-ASCII chunk with `homoglyph_ascii_skip` on, `mark_matches` passes
    /// `skip_homoglyph_ascii=true` and marking routes through the lean sub-DB that
    /// EXCLUDES the ~2.8k inert homoglyph variants — the same skip the RegexSet
    /// path already applies, extended to HS (measured 100-215× cheaper on ASCII,
    /// recall-neutral: `hs_homoglyph_ascii_skip_drops_only_homoglyph_variants`).
    #[cfg(feature = "simd")]
    pub(crate) hs: OnceLock<Option<Phase2HsEngine>>,
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
/// prefix `Seq` must be finite, non-empty, every member at least
/// `MIN_PREFIX_BYTES` AND pure ASCII (so an `ascii_case_insensitive`
/// Aho-Corasick over them is a sound
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
        if bytes.len() < MIN_PREFIX_BYTES || !bytes.is_ascii() {
            return None;
        }
        out.push(bytes.to_vec());
    }
    Some(out)
}

/// ASCII-fold a regex source: drop every non-ASCII codepoint, order preserved.
///
/// This is the EXACT folded form the plain (homoglyph) phase-2 matchers compile
/// and run on pure-ASCII chunks. The prefilter's gate literals
/// (`pattern_gate_literals`), the RegexSet alternate (`build_ascii_alternate` /
/// `ascii_folded_sources`), and the shared-anchor localizer
/// (`phase2_anchor::build`) MUST all fold identically — that is the soundness
/// contract that the folded gate/literals describe the matcher that actually
/// runs. Centralized here so the fold is one definition instead of three
/// hand-kept copies that could silently drift apart.
pub(crate) fn ascii_fold_regex_src(src: &str) -> String {
    src.chars().filter(char::is_ascii).collect()
}

thread_local! {
    /// Per-thread pool for the active phase-2 scratch. Pool one per worker;
    /// it is grown once and reused thereafter (no per-chunk allocation).
    pub(crate) static ACTIVE_PATTERNS_POOL: RefCell<ActivePatternsScratch> =
        const { RefCell::new(ActivePatternsScratch::new()) };
}
