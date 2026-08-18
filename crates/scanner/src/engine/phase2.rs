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
#[cfg(test)]
pub(crate) use mark_stats::take_mark_stats;
pub(crate) use mark_stats::{
    format_mark_decomposition, mark_snapshot_from_typed, record_mark_call, record_mark_gate_skip,
    record_mark_perpattern_work, record_mark_regexset_served, MarkSnapshot,
};

mod hs_mark_timing;
pub(crate) use hs_mark_timing::{format_hs_mark_split, hs_mark_split_from_typed, HsMarkSplit};
#[cfg(feature = "simd")]
pub(crate) use hs_mark_timing::{hs_mark_dropped_span, hs_mark_scan_span};

// The per-scanner performance tuning lives at crate root but remains an
// engine-internal route selector, not scanner public API.
pub(crate) use crate::tuning::*;

pub(crate) const MIN_PREFIX_BYTES: usize = 3;

/// Exact evidence for the two disjoint always-active phase-2 families. GPU
/// region receipts populate positive and negative state; CPU autoroute may
/// persist only a complete negative proof for byte-identical representatives.
/// An outer `Option` means no complete evidence is available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Phase2AlwaysActiveGpuEvidence<'a> {
    pub(crate) prefixless_admitted: bool,
    pub(crate) prefixless_complete: bool,
    pub(crate) prefixless_candidate_bits: Option<&'a [u32]>,
    pub(crate) prefixless_candidate_map: Option<&'a [u32]>,
    pub(crate) anchor_present: bool,
    /// Complete raw-byte `(literal_id, offset)` rows for the always-active
    /// anchor segment. `None` means positions were not produced, so presence
    /// alone may admit work but cannot replace the host anchor walk.
    pub(crate) anchor_literal_matches: Option<&'a [(u32, u32)]>,
}

impl<'a> Phase2AlwaysActiveGpuEvidence<'a> {
    #[inline]
    pub(crate) const fn exact_absence() -> Phase2AlwaysActiveGpuEvidence<'static> {
        Phase2AlwaysActiveGpuEvidence {
            prefixless_admitted: false,
            prefixless_complete: true,
            prefixless_candidate_bits: Some(&[]),
            prefixless_candidate_map: Some(&[]),
            anchor_present: false,
            anchor_literal_matches: Some(&[]),
        }
    }

    #[inline]
    pub(crate) fn prefixless_candidates(self) -> Option<(&'a [u32], &'a [u32])> {
        let bits = self.prefixless_candidate_bits?;
        let map = self.prefixless_candidate_map?;
        bits.len()
            .checked_mul(u32::BITS as usize)
            .filter(|&expected| expected == map.len())
            .map(|_| (bits, map))
    }
}

/// Per-pattern phase-2 profiler (measurement only). Enabled by the unified
/// scanner profiler (`keyhog scan --profile`) so profiling has one runtime owner.
/// Accumulates wall time per phase-2 pattern to identify the detectors that
/// dominate `scan_phase2_patterns`. Zero-cost when unset.
pub(crate) fn phase2_pattern_prof_enabled() -> bool {
    super::profile::enabled()
}

static PHASE2_PATTERN_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static PHASE2_PATTERN_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();

/// Prefix-gate diagnostics (enabled by `keyhog scan --perf-trace`), mapped to
/// [`keyhog_profile::CounterId::Phase2PrefilterGateSkips`] and [`keyhog_profile::CounterId::Phase2PrefilterMarkCalls`].
/// Counts how many gateable batches were SKIPPED (their required prefix literals absent)
/// vs RUN, and how many `mark_matches` calls the gate saw, so we can tell
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
    pub(crate) fn begin(&mut self, len: usize) -> Result<(), crate::error::ScanError> {
        self.active.clear();
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            // Wrapped: every stamp must be treated as stale.
            self.stamp.iter_mut().for_each(|s| *s = 0);
            self.generation = 1;
        }
        let requested_bytes = len.saturating_mul(
            std::mem::size_of::<u32>().saturating_add(std::mem::size_of::<usize>()),
        );
        crate::enforce_cpu_scratch_ceiling(requested_bytes)?;
        if self.stamp.len() < len {
            self.stamp.resize(len, 0);
        }
        Ok(())
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
    pub(crate) fn remove_indices(&mut self, indices: &[u32]) {
        for &index in indices {
            if index == u32::MAX {
                continue;
            }
            if let Some(slot) = self.stamp.get_mut(index as usize) {
                if *slot == self.generation {
                    *slot = 0;
                }
            }
        }
        let generation = self.generation;
        let stamp = &self.stamp;
        self.active
            .retain(|&index| stamp.get(index) == Some(&generation));
    }

    /// O(1) membership test against the current generation. Used by the
    /// shared-anchor path to gate candidate positions to the active set
    /// without a second pass over `active`.
    #[inline]
    pub(crate) fn is_active(&self, index: usize) -> bool {
        self.stamp.get(index) == Some(&self.generation)
    }
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
/// own regex: `shared_regex` (case-insensitive + CRLF + size/DFA limits) for
/// `detector` patterns, `Regex::new` defaults for `plain` homoglyph variants
/// so the set reports a pattern iff that pattern's regex matches. No real match
/// is ever skipped (recall-preserving); only dead work is removed. It MUST run
/// over the same text the extraction uses (`preprocessed.text`).
/// One compiled RegexSet batch plus the phase-2 indices its set entries map
/// back to (`phase2_indices[set_pattern_id] == phase-2 pattern index`).
pub(crate) struct PrefilterBatch {
    /// Phase-2 pattern indices owned by this batch, in set-entry order
    /// (`phase2_indices[set_pattern_id]`). They are also the compile input:
    /// every matcher variant is derived from these patterns on demand.
    pub(crate) phase2_indices: Vec<usize>,
    /// The case partition this batch was built for. Case-sensitive batches are
    /// the PLAIN (homoglyph-variant) ones and own an ASCII-folded alternate;
    /// case-insensitive batches have none.
    pub(crate) case_insensitive: bool,
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
    /// The unicode form: reports a pattern iff that pattern's regex matches.
    /// `None` after a failed compile, which makes the caller mark every index
    /// in the batch (a recall-safe superset).
    ///
    /// Every variant below is compiled on FIRST USE, not at prefilter
    /// construction. A whole scope is routinely built and then skipped for an
    /// entire scan: the residual scope exists for non-ASCII chunks, and on a
    /// decoded sub-chunk every one of its batches is homoglyph-skippable. Eager
    /// compilation charged 1.4 s (24 RegexSets over 2,739 patterns) to the first
    /// decoded sub-chunk of any scan, then ran none of them, and every other
    /// scan worker blocked on that one initialization.
    ///
    /// `OnceLock` rather than `LazyLock`: the initializer needs the runtime
    /// `phase2_patterns` slice, which is not available where the cell is
    /// declared. This matches the enclosing per-scope caches.
    pub(crate) set: std::sync::OnceLock<Option<regex::RegexSet>>,
    /// For PLAIN (homoglyph-variant) batches: an ASCII-folded RegexSet (the
    /// homoglyph regex with non-ASCII stripped: `[sѕｓ]`→`[s]`, `[lіІιΙｌΟοо]`→
    /// `[l]`), in the SAME entry order as `set`. On a pure-ASCII chunk the
    /// fold is match-equivalent to the unicode form, so `matches()` returns the
    /// IDENTICAL set of entry ids, identical marking, identical active-set
    /// order, but evaluates faster. `None` for case-insensitive batches and on
    /// fold-compile failure (the unicode `set` is then used, ungated).
    pub(crate) ascii_set: std::sync::OnceLock<Option<regex::RegexSet>>,
    /// Truncated-at-first-unbounded-repetition variant of `set` (each entry
    /// passed through `truncate_for_prefilter`, SAME entry order), kept on the
    /// fast lazy-DFA. A sound SUPERSET marking gate (see `truncate_for_prefilter`).
    /// Used instead of `set` when `prefilter_truncate_enabled()`.
    pub(crate) set_trunc: std::sync::OnceLock<Option<regex::RegexSet>>,
    /// Truncated variant of `ascii_set` (the folded form, then truncated). Same
    /// `None` conditions as `ascii_set`.
    pub(crate) ascii_set_trunc: std::sync::OnceLock<Option<regex::RegexSet>>,
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
    // A batch whose matcher cannot compile is discovered at match time and its
    // patterns are marked unconditionally there, so there is no eager list of
    // compile casualties to carry.
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
/// of a finite, >=3-byte ASCII required-prefix literal, their union is the
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
    /// The non-anchorable always-active patterns (those with no required
    /// boundary literal), as `(phase2_index, regex, homoglyph_variant)`.
    /// Homoglyph variants are omitted when the dispatch plan activates the
    /// proven ASCII skip; otherwise each pattern is checked with its own
    /// compiled regex.
    pub(crate) non_anchorable: Vec<(usize, LazyRegex, bool)>,
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
    /// ~5-15 ns/byte for AC state-machine transitions), roughly 10-30x
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
        allowed_indices: &[usize],
        skip_homoglyph: bool,
    ) {
        for (idx, re, homoglyph_variant) in &self.non_anchorable {
            if !(skip_homoglyph && *homoglyph_variant)
                && allowed_indices.binary_search(idx).is_ok()
                && re.get().is_match(match_text)
            {
                scratch.mark(*idx);
            }
        }
    }

    /// True iff some non-anchorable pattern can fire on `match_text`: the boolean
    /// companion to [`mark_non_anchorable`](Self::mark_non_anchorable) for the
    /// admission gate.
    #[inline]
    pub(crate) fn any_non_anchorable_match(&self, match_text: &str, skip_homoglyph: bool) -> bool {
        self.non_anchorable
            .iter()
            .any(|(_, re, homoglyph_variant)| {
                !(skip_homoglyph && *homoglyph_variant) && re.get().is_match(match_text)
            })
    }
}

pub(crate) struct Phase2AlwaysActivePrefilter {
    /// Every valid always-active phase-2 index. Used by the legacy whole-chunk
    /// path and the admission proof, where no anchor localizer owns extraction.
    pub(crate) valid_always_active_indices: Vec<usize>,
    /// Always-active indices not owned by the main required-prefix localizer.
    /// This is the only prefilter scope needed by the anchored extraction path
    /// when the optional plain-pattern localizer is disabled.
    pub(crate) anchor_residual_indices: Vec<usize>,
    /// Anchor residual further restricted to case-insensitive patterns. On an
    /// ASCII chunk with the plain-pattern localizer enabled, every remaining
    /// case-sensitive pattern is extracted by that localizer, so only this set
    /// may be marked by the prefilter.
    pub(crate) localized_residual_indices: Vec<usize>,
    /// Heavy portable RegexSet batches/gates for the full legacy scope.
    pub(crate) portable: OnceLock<PortablePrefilter>,
    /// Portable batches for the anchor-owned residual scope.
    pub(crate) portable_anchor_residual: OnceLock<PortablePrefilter>,
    /// Portable batches for the anchor plus plain-localizer residual scope.
    pub(crate) portable_localized_residual: OnceLock<PortablePrefilter>,
    /// SWE-101 combined no-candidate gates for the full, anchor-residual, and
    /// localized-residual scopes. Each is lazy because many scans need only one
    /// scope; compiling the full-corpus automaton for a small residual scope
    /// added tens of milliseconds to every cold scan.
    pub(crate) combined_gate: OnceLock<Option<CombinedNoCandidateGate>>,
    pub(crate) combined_gate_anchor_residual: OnceLock<Option<CombinedNoCandidateGate>>,
    pub(crate) combined_gate_localized_residual: OnceLock<Option<CombinedNoCandidateGate>>,
    /// Lazy Hyperscan engine for the full legacy/admission scope.
    #[cfg(feature = "simd")]
    pub(crate) hs: OnceLock<Option<Phase2HsEngine>>,
    /// Authenticated packed program retained until the full scope is first used.
    #[cfg(feature = "simd")]
    pub(crate) packed_hs:
        std::sync::Mutex<Option<crate::execution_pack::simd_program::HyperscanPhase2ScopeProgram>>,
    /// Hyperscan engine over only patterns not owned by the main anchor path.
    #[cfg(feature = "simd")]
    pub(crate) hs_anchor_residual: OnceLock<Option<Phase2HsEngine>>,
    /// Authenticated packed program retained until the anchor residual is first used.
    #[cfg(feature = "simd")]
    pub(crate) packed_hs_anchor_residual:
        std::sync::Mutex<Option<crate::execution_pack::simd_program::HyperscanPhase2ScopeProgram>>,
    /// Hyperscan engine over only patterns not owned by either ASCII localizer.
    #[cfg(feature = "simd")]
    pub(crate) hs_localized_residual: OnceLock<Option<Phase2HsEngine>>,
    /// Authenticated packed program retained until the localized residual is first used.
    #[cfg(feature = "simd")]
    pub(crate) packed_hs_localized_residual:
        std::sync::Mutex<Option<crate::execution_pack::simd_program::HyperscanPhase2ScopeProgram>>,
}

/// Bytes of already-scanned parent context kept on each side of the decoded span
/// when focus-restricting the phase-2 pass. Covers any self-contained phase-2
/// match that begins in context and extends into the decoded text (the credential
/// prefix). Generous relative to credential prefix lengths; the differential
/// `decode_focus_parity` gate validates it is sufficient.
pub(crate) const DECODE_FOCUS_MARGIN: usize = 64;

/// Whether homoglyph variants are inert for this chunk.
///
/// A homoglyph variant only adds reach over its base pattern when the text
/// actually contains a confusable glyph; every variant's base ASCII prefix is
/// already owned by the anchor and confirmed paths. So the exact condition is
/// "no confusable glyph is present", which
/// [`crate::homoglyph::may_contain_confusable`] proves with a byte prefilter and
/// exact character membership on the narrow candidate path.
///
/// This used to test `chunk_is_ascii`, a much cruder proxy for the same fact.
/// Any non-ASCII byte at all forced the full residual pattern set, even though
/// most non-ASCII source text (accented names, box drawing, arrows, emoji,
/// CJK) contains no confusable. On this repository's own sources that was 858
/// of 945 non-ASCII files paying for nothing, and those chunks were where
/// `phase2:prefilter` spent its time.
///
/// Decoded sub-chunks keep their existing blanket skip: decoded non-ASCII
/// bytes are payload, not credential homoglyphs.
#[inline]
pub(crate) fn homoglyph_skip_applies(text: &str, enabled: bool) -> bool {
    enabled && (super::profile::in_decode() || !crate::homoglyph::may_contain_confusable(text))
}

// NOTE: there is intentionally NO confirmed-pass equivalent of this focus. A
// decode sub-chunk splices the decoded text in place of the encoded blob, which
// (a) changes the byte adjacencies at the junction and (b) creates new token
// boundaries inside what was a contiguous base64/hex run. A confirmed /
// companion-anchored detector can therefore fire on spliced context arbitrarily
// far from the decoded span where the parent, which saw the still-encoded bytes
// did not, so the "outside the decoded span is a parent duplicate" theorem that
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
    // recall-safe (fail-OPEN), if the prefix-source regex cannot be parsed here,
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
/// (`phase2_anchor::build`) MUST all fold identically, that is the soundness
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
