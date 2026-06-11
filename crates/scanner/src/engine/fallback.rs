#[cfg(feature = "simd")]
use super::fallback_hs::HsFallbackEngine;
use aho_corasick::AhoCorasick;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::OnceLock;

// The fallback/prefilter runtime toggles live in `fallback_toggles.rs`;
// re-export them here so the existing `fallback::set_*` / `fallback::*_enabled`
// paths (mod.rs, lib.rs, backend_triggered.rs, the satellite impls) are
// unchanged after the split.
pub use super::fallback_toggles::*;


/// Per-pattern fallback profiler (env-gated; measurement only). Set
/// `KEYHOG_PROFILE_FALLBACK=1` to accumulate, per fallback pattern index, the
/// wall time its capture-regex walk costs and how many chunks it ran on. This
/// isolates WHICH fallback detectors dominate `scan_fallback_patterns` (77-85%
/// of phase-2 per the breakdown) so anchor-localization targets the real hot
/// set, not the homoglyph variants that never fire. Zero-cost when unset.
pub(crate) fn fallback_pat_prof_enabled() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_FALLBACK").as_deref() == Ok("1"))
}

static FALLBACK_PAT_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static FALLBACK_PAT_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();

/// Sub-split of `populate_active_fallback`: time spent in the always-active
/// RegexSet prefilter vs the keyword Aho-Corasick. Confirms which half of the
/// active-set computation dominates. Env-gated like the per-pattern profiler.
pub(crate) static POPULATE_PREFILTER_NS: AtomicU64 = AtomicU64::new(0);
pub(crate) static POPULATE_KEYWORD_NS: AtomicU64 = AtomicU64::new(0);

/// Prefix-gate diagnostics (env-gated by `KEYHOG_PROFILE_FALLBACK`). Counts how
/// many gateable batches were SKIPPED (their required prefix literals absent)
/// vs RUN, and how many `mark_matches` calls the gate saw — so we can tell
/// whether the gate actually skips on a given corpus or whether spliced context
/// keeps it firing.
pub(crate) static GATE_BATCH_SKIPS: AtomicU64 = AtomicU64::new(0);
pub(crate) static GATE_BATCH_RUNS: AtomicU64 = AtomicU64::new(0);
pub(crate) static GATE_CALLS: AtomicU64 = AtomicU64::new(0);

/// Print and reset the prefix-gate skip counters. Returns `(calls, skips, runs)`.
pub fn fallback_gate_stats_dump() -> (u64, u64, u64) {
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

pub(crate) fn fallback_prof_vecs(len: usize) -> (&'static [AtomicU64], &'static [AtomicU64]) {
    let ns = FALLBACK_PAT_NS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    let runs = FALLBACK_PAT_RUNS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    (ns.as_slice(), runs.as_slice())
}

#[inline]
pub(crate) fn fallback_prof_record(len: usize, index: usize, nanos: u64) {
    let (ns, runs) = fallback_prof_vecs(len);
    if let (Some(n), Some(r)) = (ns.get(index), runs.get(index)) {
        n.fetch_add(nanos, Relaxed);
        r.fetch_add(1, Relaxed);
    }
}

/// Per-thread scratch for computing the active-fallback set of a chunk.
///
/// Previously this was a dense `Vec<bool>` of `fallback.len()` (~1000) that
/// was zero-filled, `copy_from_slice`-seeded, and then fully iterated by the
/// caller every chunk - O(F) per chunk even when only a handful of patterns
/// fire. We now carry a SPARSE list of active fallback indices instead, so
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
    const fn new() -> Self {
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
    /// extracted [`super::fallback_hs::HsFallbackEngine::mark`] can mark into it.
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

/// Combined-RegexSet prefilter for the always-active fallback patterns.
///
/// Always-active fallbacks (patterns with no >=4-char keyword for the AC
/// prefilter) otherwise run their individual capture regex over the FULL chunk
/// on every scan. Measured on the RTX 5090, that made `scan_fallback_patterns`
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
/// One compiled RegexSet batch plus the fallback indices its set entries map
/// back to (`fallback_indices[set_pattern_id] == fallback index`).
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
    pub(crate) fallback_indices: Vec<usize>,
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

pub(crate) struct AlwaysActiveFallbackPrefilter {
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
    /// Hyperscan-backed engine over the SAME always-active patterns. When present
    /// and enabled (`fallback_hs_enabled`), `mark_matches` uses it instead of the
    /// `regex::RegexSet` batches above: one SIMD multi-pattern scan with
    /// `SINGLEMATCH` (fire-once = "does P match") replaces the ~2,679-pattern
    /// whole-chunk RegexSet pass — the measured #1 scan cost (`fb:prefilter`),
    /// ~1000x faster (`fallback_prefilter_hs_vs_regexset`) and findings-identical
    /// (`fallback_prefilter_hs_findings_parity`). `None` when the `simd` feature
    /// is off or HS failed to compile (then the RegexSet batches are the path).
    #[cfg(feature = "simd")]
    pub(crate) hs: Option<HsFallbackEngine>,
}



/// Bytes of already-scanned parent context kept on each side of the decoded span
/// when focus-restricting the fallback pass. Covers any self-contained fallback
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
// makes the fallback focus sound does NOT hold for confirmed detectors. A
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
    let hir = regex_syntax::ParserBuilder::new().build().parse(src).ok()?;
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
    /// Per-thread pool for the active-fallback scratch. Pool one per worker;
    /// it is grown once and reused thereafter (no per-chunk allocation).
    pub(crate) static ACTIVE_PATTERNS_POOL: RefCell<ActivePatternsScratch> =
        const { RefCell::new(ActivePatternsScratch::new()) };
}
