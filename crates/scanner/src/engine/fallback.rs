use super::*;
use crate::context;
#[cfg(feature = "simd")]
use crate::simd::backend::{HsCompileOpts, HsScanner};
use aho_corasick::AhoCorasick;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::Instant;

/// Per-pattern fallback profiler (env-gated; measurement only). Set
/// `KEYHOG_PROFILE_FALLBACK=1` to accumulate, per fallback pattern index, the
/// wall time its capture-regex walk costs and how many chunks it ran on. This
/// isolates WHICH fallback detectors dominate `scan_fallback_patterns` (77-85%
/// of phase-2 per the breakdown) so anchor-localization targets the real hot
/// set, not the homoglyph variants that never fire. Zero-cost when unset.
fn fallback_pat_prof_enabled() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_FALLBACK").as_deref() == Ok("1"))
}

static FALLBACK_PAT_NS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static FALLBACK_PAT_RUNS: OnceLock<Vec<AtomicU64>> = OnceLock::new();

/// Sub-split of `populate_active_fallback`: time spent in the always-active
/// RegexSet prefilter vs the keyword Aho-Corasick. Confirms which half of the
/// active-set computation dominates. Env-gated like the per-pattern profiler.
static POPULATE_PREFILTER_NS: AtomicU64 = AtomicU64::new(0);
static POPULATE_KEYWORD_NS: AtomicU64 = AtomicU64::new(0);

/// Prefix-gate diagnostics (env-gated by `KEYHOG_PROFILE_FALLBACK`). Counts how
/// many gateable batches were SKIPPED (their required prefix literals absent)
/// vs RUN, and how many `mark_matches` calls the gate saw — so we can tell
/// whether the gate actually skips on a given corpus or whether spliced context
/// keeps it firing.
static GATE_BATCH_SKIPS: AtomicU64 = AtomicU64::new(0);
static GATE_BATCH_RUNS: AtomicU64 = AtomicU64::new(0);
static GATE_CALLS: AtomicU64 = AtomicU64::new(0);

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

fn fallback_prof_vecs(len: usize) -> (&'static [AtomicU64], &'static [AtomicU64]) {
    let ns = FALLBACK_PAT_NS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    let runs = FALLBACK_PAT_RUNS.get_or_init(|| (0..len).map(|_| AtomicU64::new(0)).collect());
    (ns.as_slice(), runs.as_slice())
}

#[inline]
fn fallback_prof_record(len: usize, index: usize, nanos: u64) {
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
struct ActivePatternsScratch {
    active: Vec<usize>,
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
    fn begin(&mut self, len: usize) {
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
    /// generation. Returns nothing; dedup is silent.
    #[inline]
    fn mark(&mut self, index: usize) {
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
    fn is_active(&self, index: usize) -> bool {
        self.stamp.get(index) == Some(&self.generation)
    }
}

/// Runtime override for the anchor enable flag: 0 = follow env, 1 = force on,
/// 2 = force off. Lets a differential test scan one input down BOTH the
/// anchored and whole-chunk fallback paths in a single process (the env read is
/// cached, so it alone can't be toggled mid-run).
static FALLBACK_ANCHOR_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Override shared-anchor fallback localization (test/diagnostic). `Some(true)`
/// forces it on, `Some(false)` forces the legacy whole-chunk path, `None`
/// restores the env-driven default. Recall is identical either way — this only
/// selects the performance route, so it is safe to flip at runtime.
pub fn set_fallback_anchor_mode(mode: Option<bool>) {
    let v = match mode {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    FALLBACK_ANCHOR_OVERRIDE.store(v, Relaxed);
}

/// Runtime override for the homoglyph ASCII-gate (0=env, 1=on, 2=off). Lets a
/// validation test scan one input with the gate on and off to prove the
/// confirmed path covers every homoglyph variant's pure-ASCII matches.
static HOMOGLYPH_GATE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Override the homoglyph ASCII-gate (test/diagnostic). `Some(true)` forces it
/// on (skip homoglyph variants on pure-ASCII chunks), `Some(false)` forces
/// every homoglyph variant to run, `None` restores the default (on).
pub fn set_fallback_homoglyph_gate(mode: Option<bool>) {
    let v = match mode {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    HOMOGLYPH_GATE_OVERRIDE.store(v, Relaxed);
}

/// Whether the homoglyph ASCII-gate is enabled (default on). Set
/// `KEYHOG_HOMOGLYPH_GATE=0` (or `set_fallback_homoglyph_gate(Some(false))`) to
/// run every homoglyph variant on every chunk (the unoptimized path).
fn homoglyph_gate_enabled() -> bool {
    match HOMOGLYPH_GATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_HOMOGLYPH_GATE").as_deref() != Ok("0"))
}

/// Runtime override for the homoglyph ASCII-SKIP (0=env, 1=on, 2=off).
static HOMOGLYPH_ASCII_SKIP_OVERRIDE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);

/// Override the homoglyph ASCII-skip (test/diagnostic). `Some(true)` forces it
/// on, `Some(false)` off, `None` = env default. The differential gate
/// `homoglyph_ascii_skip_parity` flips this in-process to prove that skipping
/// every homoglyph variant on a pure-ASCII chunk drops no finding (the base
/// literal-prefix pattern is in the AC/confirmed path — see `compiler_build.rs`,
/// which pushes BOTH the homoglyph fallback variant AND the base prefix to
/// `ac_literals`/`ac_map`).
pub fn set_homoglyph_ascii_skip(mode: Option<bool>) {
    HOMOGLYPH_ASCII_SKIP_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

/// Whether to SKIP the always-active homoglyph fallback variants on a pure-ASCII
/// chunk. Tempting because `fb:prefilter` (the ~2,730-pattern pass over every
/// chunk) is the #1 scan cost and the variants only ADD reach on non-ASCII bytes.
///
/// **MEASURED NEGATIVE — default OFF.** RE-CONFIRMED 2026-06-09 by a full-finding
/// diff over the mirror corpus (skip vs no-skip via a top-level is_ascii gate):
/// the skip DROPS ~30 real findings (e.g. `jwt-token`) and the drops cascade into
/// spurious adds via overlap suppression. The base prefix IS in the phase-1 AC,
/// but the confirmed-extraction path that the trigger feeds has DIFFERENT
/// downstream gating (companion / keyword-proximity / confidence) than the
/// fallback path, so the always-active variant fires where confirmed does not —
/// the variant is load-bearing on ASCII, not redundant. The real fix is to close
/// that gap (make confirmed extraction catch those findings) BEFORE any ASCII
/// skip — not the skip itself. Gated behind `KEYHOG_HOMOGLYPH_ASCII_SKIP=1`
/// (measurement only). NOTE: earlier "recall-neutral" measurements were vacuous —
/// HS was the default prefilter and early-returned before this per-batch skip ran.
fn homoglyph_ascii_skip_enabled() -> bool {
    match HOMOGLYPH_ASCII_SKIP_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_HOMOGLYPH_ASCII_SKIP").as_deref() == Ok("1"))
}

static FALLBACK_REVERSE_OVERRIDE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Diagnostic: override the fallback extraction-order reversal (test hook).
pub fn set_fallback_reverse(mode: Option<bool>) {
    FALLBACK_REVERSE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

/// Diagnostic: reverse the fallback active-pattern extraction order. Used to
/// prove whether the final finding set is INDEPENDENT of fallback extraction
/// order — if it is, an O(text) literal prefilter (which marks in a different
/// order than the RegexSet) is safe to adopt.
fn fallback_reverse_enabled() -> bool {
    match FALLBACK_REVERSE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_REVERSE").as_deref() == Ok("1"))
}

/// Whether shared-anchor fallback localization is enabled. On by default; set
/// `KEYHOG_FALLBACK_ANCHOR=0` (or `set_fallback_anchor_mode(Some(false))`) to
/// force the legacy whole-chunk path. Recall is identical either way — this is
/// a pure performance route.
fn fallback_anchor_enabled() -> bool {
    match FALLBACK_ANCHOR_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_ANCHOR").as_deref() != Ok("0"))
}

thread_local! {
    /// Per-thread scratch for shared-anchor candidate `(pattern_idx, pos)`
    /// pairs. Grown once and reused (cleared, not freed) per chunk.
    static ANCHOR_CANDIDATES: RefCell<Vec<(u32, u32)>> = const { RefCell::new(Vec::new()) };
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
struct PrefilterBatch {
    set: regex::RegexSet,
    /// For PLAIN (homoglyph-variant) batches: an ASCII-folded RegexSet (the
    /// homoglyph regex with non-ASCII stripped: `[sѕｓ]`→`[s]`, `[lіІιΙｌΟοоOo]`→
    /// `[lOo]`), in the SAME entry order as `set`. On a pure-ASCII chunk the
    /// fold is match-equivalent to the unicode form, so `matches()` returns the
    /// IDENTICAL set of entry ids — identical marking, identical active-set
    /// order — but evaluates faster. `None` for case-insensitive batches and on
    /// fold-compile failure (the unicode `set` is then used everywhere).
    ascii_set: Option<regex::RegexSet>,
    /// Truncated-at-first-unbounded-repetition variant of `set` (each entry
    /// passed through `truncate_for_prefilter`, SAME entry order), kept on the
    /// fast lazy-DFA. A sound SUPERSET marking gate — see `truncate_for_prefilter`.
    /// Used instead of `set` when `prefilter_truncate_enabled()`.
    set_trunc: regex::RegexSet,
    /// Truncated variant of `ascii_set` (the folded form, then truncated). Same
    /// `None` conditions as `ascii_set`.
    ascii_set_trunc: Option<regex::RegexSet>,
    fallback_indices: Vec<usize>,
    /// True iff EVERY pattern in this batch is prefix-anchorable (a finite,
    /// non-empty, pure-ASCII required-prefix literal set, each member >= 3
    /// bytes). When true, the combined prefix-literal Aho-Corasick gate
    /// (`ci_gate`/`plain_gate`) is a SOUND skip oracle: if NONE of those
    /// patterns' prefix literals appears in the chunk, none can match, so this
    /// batch's whole-chunk RegexSet pass is dead work and is skipped. False ->
    /// the batch always runs (a pattern with no required literal could match
    /// without any gate literal, so skipping would drop recall).
    gateable: bool,
    /// True iff EVERY pattern in this batch is a compiler-generated homoglyph
    /// fallback variant (`CompiledPattern::homoglyph_variant`). Such a batch is
    /// skipped ENTIRELY on a pure-ASCII chunk when `homoglyph_ascii_skip` is on:
    /// each variant's base ASCII prefix is in the AC/confirmed path, so on a
    /// no-homoglyph chunk the variant adds nothing. This is the precise skip the
    /// case-sensitivity heuristic got wrong (generic plain fallbacks share the
    /// case flag but have no base AC pattern; they land in non-skippable batches).
    homoglyph_skippable: bool,
}

pub(crate) struct AlwaysActiveFallbackPrefilter {
    /// RegexSet batches; running each and unioning the reported patterns is
    /// equivalent to running every entry's regex individually, but in a handful
    /// of linear passes instead of thousands.
    batches: Vec<PrefilterBatch>,
    /// Patterns whose batch failed to compile (e.g. exceeded the size limit):
    /// run unconditionally so a compile failure costs performance, never recall.
    ungated_indices: Vec<usize>,
    /// Combined Aho-Corasick over the required-prefix literals of every
    /// CASE-INSENSITIVE gateable batch's patterns (built `ascii_case_insensitive`
    /// to mirror the detector regexes' case folding). A no-hit proves NO gateable
    /// ci pattern can match, so all `gateable` ci batches are skipped. `None`
    /// when no ci pattern is gate-eligible. SOUND on every chunk (ci batches run
    /// the same `set` on all chunks).
    ci_gate: Option<AhoCorasick>,
    /// Combined Aho-Corasick over the required-prefix literals of every PLAIN
    /// (homoglyph-variant) gateable batch's ASCII-FOLDED form (case-sensitive,
    /// matching the `ascii_set` matcher). A no-hit on a pure-ASCII chunk proves
    /// no gateable plain pattern's folded form can match, so all `gateable` plain
    /// batches are skipped. Applied ONLY on the ASCII path (`use_ascii`); on a
    /// non-ASCII chunk the unicode `set` runs unconditionally (the folded literals
    /// don't describe its required prefixes). `None` when none are gate-eligible.
    plain_gate: Option<AhoCorasick>,
    /// Hyperscan-backed engine over the SAME always-active patterns. When present
    /// and enabled (`fallback_hs_enabled`), `mark_matches` uses it instead of the
    /// `regex::RegexSet` batches above: one SIMD multi-pattern scan with
    /// `SINGLEMATCH` (fire-once = "does P match") replaces the ~2,679-pattern
    /// whole-chunk RegexSet pass — the measured #1 scan cost (`fb:prefilter`),
    /// ~1000x faster (`fallback_prefilter_hs_vs_regexset`) and findings-identical
    /// (`fallback_prefilter_hs_findings_parity`). `None` when the `simd` feature
    /// is off or HS failed to compile (then the RegexSet batches are the path).
    #[cfg(feature = "simd")]
    hs: Option<HsFallbackEngine>,
}

/// Hyperscan-backed always-active prefilter engine. See the `hs` field on
/// [`AlwaysActiveFallbackPrefilter`].
#[cfg(feature = "simd")]
struct HsFallbackEngine {
    scanner: HsScanner,
    /// HS pattern id -> always-active fallback index (the `det_idx` slot we set
    /// on each surviving pattern at build).
    hs_to_fallback: Vec<usize>,
    /// Patterns HS could not compile (PCRE feature / over-long): a LOUD host
    /// path (Law 10). Each keeps its own compiled regex and is marked per chunk
    /// via `is_match`, so its recall is preserved, never silently dropped.
    dropped: Vec<(usize, LazyRegex)>,
}

#[cfg(feature = "simd")]
impl HsFallbackEngine {
    /// Compile an HS database over the always-active patterns. Each pattern
    /// carries its OWN case flag (`is_case_insensitive`) so the marked set is
    /// identical to the per-pattern `regex` reference, plus `SINGLEMATCH` so a
    /// broad always-active pattern fires once instead of storming the callback.
    /// Returns `None` (caller keeps the RegexSet path) if no pattern survives.
    fn build(
        fallback: &[(CompiledPattern, Vec<String>)],
        always_active: &[usize],
    ) -> Option<Self> {
        let mut refs: Vec<(usize, usize, &str, bool)> = Vec::with_capacity(always_active.len());
        let mut caseless: Vec<bool> = Vec::with_capacity(always_active.len());
        for &idx in always_active {
            let Some((pat, _)) = fallback.get(idx) else {
                continue;
            };
            // det_idx slot carries the fallback index back through `pattern_info`.
            refs.push((idx, 0, pat.regex.as_str(), false));
            caseless.push(pat.regex.is_case_insensitive());
        }
        if refs.is_empty() {
            return None;
        }
        let opts = HsCompileOpts {
            singlematch: true,
            caseless: Some(&caseless),
            // ONE database: the prefilter scans every chunk against all patterns,
            // so a sharded scan would pay the per-shard overhead N times per
            // chunk and lose to the RegexSet on tiny files. A single DB + the
            // no-alloc `scan_each` is the fast path.
            shard_target: Some(usize::MAX),
            // Byte mode (UTF8 off): both the pattern source and the haystack are
            // UTF-8 bytes, so byte matching is correct for the unicode homoglyph
            // classes, and HS_FLAG_UTF8 actually REJECTS many of these patterns
            // at compile (→ silent fallback to RegexSet). Byte mode keeps them on
            // the fast path; findings parity holds (`..._findings_parity`).
            utf8: false,
        };
        let (scanner, unsupported) = match HsScanner::compile_with_opts(&refs, opts) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::fallback",
                    %error,
                    "HS always-active prefilter compile failed — using the regex::RegexSet path",
                );
                return None;
            }
        };
        let mut hs_to_fallback = vec![0usize; scanner.pattern_count()];
        for hs_id in 0..scanner.pattern_count() {
            if let Some((fb, _, _)) = scanner.pattern_info(hs_id) {
                hs_to_fallback[hs_id] = fb;
            }
        }
        // `unsupported` indexes `refs`; map back to fallback indices and keep
        // each on its own compiled regex (the LOUD host path, Law 10).
        let dropped: Vec<(usize, LazyRegex)> = unsupported
            .iter()
            .filter_map(|&i| refs.get(i).map(|r| r.0))
            .map(|fb_idx| (fb_idx, fallback[fb_idx].0.regex.clone()))
            .collect();
        if !dropped.is_empty() {
            tracing::warn!(
                target: "keyhog::fallback",
                count = dropped.len(),
                "HS prefilter: {} always-active pattern(s) on the loud regex host path (HS-incompatible)",
                dropped.len(),
            );
        }
        Some(Self {
            scanner,
            hs_to_fallback,
            dropped,
        })
    }

    /// Mark every always-active pattern that can match `match_text`. One SIMD
    /// scan marks the HS-covered patterns; the loud host path marks the few
    /// HS-incompatible ones. The marked set is a sound superset of the matching
    /// patterns (extraction filters), identical to the RegexSet path.
    #[inline]
    fn mark(&self, match_text: &str, scratch: &mut ActivePatternsScratch) {
        let hs_to_fallback = &self.hs_to_fallback;
        self.scanner.scan_each(match_text.as_bytes(), |hs_id| {
            if let Some(&fb) = hs_to_fallback.get(hs_id) {
                scratch.mark(fb);
            }
        });
        for (idx, re) in &self.dropped {
            if re.get().is_match(match_text) {
                scratch.mark(*idx);
            }
        }
    }
}

/// Override for the fallback prefix-literal skip gate (test/diagnostic).
/// `Some(true)` forces it on, `Some(false)` off, `None` = env default (on).
/// Recall is identical either way — the gate only skips batches whose patterns
/// ALL provably require a prefix literal that is absent from the chunk.
static PREFIX_GATE_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Override for the prefilter `{N,}`→`{N}` truncation (the lazy-DFA lever).
/// `Some(true)` forces it on, `Some(false)` off, `None` = env default.
/// Recall-identical either way (the truncated set is a sound SUPERSET marking
/// gate; extraction with the full pattern filters) — proven by
/// `prefilter_truncate_parity`; it only trades prefilter speed for a little
/// extra extraction.
static PREFILTER_TRUNCATE_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Override for the Hyperscan always-active prefilter. `Some(true)` forces the
/// HS engine, `Some(false)` forces the legacy `regex::RegexSet` batches, `None`
/// = env default (on when an HS engine compiled). The two engines mark the SAME
/// active set on every chunk (`fallback_prefilter_hs_parity`) and produce
/// IDENTICAL findings end-to-end (`fallback_prefilter_hs_findings_parity`), so
/// recall is unchanged either way — this only selects the SIMD-fast path vs the
/// ~1000x-slower RegexSet reference. Lets the parity gates A/B both in one run.
static FALLBACK_HS_OVERRIDE: AtomicU8 = AtomicU8::new(0);

/// Select the always-active prefilter engine (test/diagnostic). Recall is
/// identical; this only trades the SIMD fast path for the RegexSet reference.
pub fn set_fallback_hs(mode: Option<bool>) {
    FALLBACK_HS_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

/// Whether the HS always-active prefilter is enabled. Default ON: the HS engine
/// is ~1000x the `regex::RegexSet` throughput on the always-active set
/// (`fallback_prefilter_hs_vs_regexset`) and is the measured #1 scan cost.
/// `KEYHOG_FALLBACK_HS=0` forces the legacy reference path.
#[cfg(feature = "simd")]
fn fallback_hs_enabled() -> bool {
    match FALLBACK_HS_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_HS").as_deref() != Ok("0"))
}

/// Max chunk length (bytes) for which the HS prefilter is used; larger chunks
/// fall through to the `regex::RegexSet` batches. HS's per-scan cost is roughly
/// constant in chunk size (dominated by the unicode-homoglyph automaton), so it
/// beats the RegexSet's per-call setup on SMALL chunks but loses once the
/// per-byte automaton work over a large chunk dominates. Tunable via
/// `KEYHOG_FALLBACK_HS_MAX_LEN`; default chosen so the small-file regime (the
/// common case) takes HS and 16 KiB chunks take the RegexSet.
#[cfg(feature = "simd")]
fn hs_prefilter_max_len() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("KEYHOG_FALLBACK_HS_MAX_LEN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4096)
    })
}

pub fn set_prefilter_truncate(mode: Option<bool>) {
    PREFILTER_TRUNCATE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

fn prefilter_truncate_enabled() -> bool {
    match PREFILTER_TRUNCATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    // Default ON: −16.8% end-to-end on the mirror corpus (interleaved median of
    // 9), recall-identical (`prefilter_truncate_parity` 200k + contracts +
    // encoding-explosion + no-hit-recall). The `{N,}` bodies forced the folded
    // prefilter RegexSet onto the slow PikeVM path; bounding them keeps it on the
    // lazy-DFA. Helps BOTH the 16 KiB parent scan and every decode sub-chunk.
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PREFILTER_TRUNCATE").as_deref() != Ok("0"))
}

pub fn set_fallback_prefix_gate(mode: Option<bool>) {
    PREFIX_GATE_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

fn fallback_prefix_gate_enabled() -> bool {
    match PREFIX_GATE_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    // Default OFF: on the mirror corpus the gate skipped only ~17% of gateable
    // batches (the folded-prefix literal union is too broad — one credential
    // prefix anywhere in a chunk or spliced sub-chunk makes every batch run) and
    // the per-chunk AC `is_match` cost cancelled the saving end-to-end. Kept
    // behind the toggle as a sound, parity-validated lever for corpora with
    // genuinely literal-sparse chunks. The decode-recursion win is the focus
    // restriction (`KEYHOG_DECODE_FOCUS`), not this gate.
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_PREFIX_GATE").as_deref() == Ok("1"))
}

/// Override for the decode-recursion FOCUS restriction (the real lever).
/// `Some(true)` forces it on, `Some(false)` off, `None` = env default (on).
/// When on, the fallback pass on a decode sub-chunk scans only a window around
/// the freshly decoded text (`ChunkMetadata::decoded_span`) instead of the whole
/// spliced parent context — the context was already scanned (and any finding
/// deduped) by the parent chunk. Signals (`keyword_nearby`), line offsets and
/// the keyword AC still run over the FULL splice, so confidence/report decisions
/// are unchanged; only the expensive prefilter RegexSet + regex extraction are
/// windowed. Recall-validated by `decode_focus_parity`.
static DECODE_FOCUS_OVERRIDE: AtomicU8 = AtomicU8::new(0);

pub fn set_decode_focus(mode: Option<bool>) {
    DECODE_FOCUS_OVERRIDE.store(
        match mode {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        },
        Relaxed,
    );
}

pub(crate) fn decode_focus_enabled() -> bool {
    match DECODE_FOCUS_OVERRIDE.load(Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_DECODE_FOCUS").as_deref() != Ok("0"))
}

/// Bytes of already-scanned parent context kept on each side of the decoded span
/// when focus-restricting the fallback pass. Covers any self-contained fallback
/// match that begins in context and extends into the decoded text (the credential
/// prefix). Generous relative to credential prefix lengths; the differential
/// `decode_focus_parity` gate validates it is sufficient.
const DECODE_FOCUS_MARGIN: usize = 64;

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
fn gate_prefix_literals(src: &str) -> Option<Vec<Vec<u8>>> {
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

impl AlwaysActiveFallbackPrefilter {
    /// Patterns per RegexSet batch. A single set over all ~2.7k always-active
    /// patterns blows the compiled-program size limit; batching keeps each
    /// set's NFA bounded while still collapsing thousands of full-chunk regex
    /// walks into a handful of linear set passes.
    const BATCH_SIZE: usize = 512;
    /// Generous per-batch compiled-program + lazy-DFA budget. Larger than the
    /// per-pattern `REGEX_SIZE_LIMIT_BYTES` because a batch holds many patterns;
    /// size/DFA limits only affect compile success and cache size, never which
    /// matches are reported, so a larger limit here stays match-equivalent.
    const BATCH_SIZE_LIMIT_BYTES: usize = 64 << 20;

    /// Build from the always-active fallback indices. Always returns `Some` for
    /// a non-empty input: patterns in batches that fail to compile fall into
    /// `ungated_indices` and run unconditionally, so the result is always
    /// recall-equivalent to running every always-active pattern.
    pub(crate) fn build(
        fallback: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
    ) -> Option<Self> {
        if always_active_indices.is_empty() {
            return None;
        }
        // The HS engine is the fast path for SMALL chunks; the `regex::RegexSet`
        // batches below stay as the LARGE-chunk path (HS's unicode-homoglyph
        // automaton over many bytes loses to the folded/truncated RegexSet) and
        // the no-`simd` fallback. `mark_matches` dispatches by chunk length, so
        // BOTH are load-bearing — the batches are not dead weight.
        #[cfg(feature = "simd")]
        let hs = HsFallbackEngine::build(fallback, always_active_indices);
        // Partition by regex flags so each batch is built match-equivalent to
        // its patterns' own compilation (case-insensitive detector regexes vs
        // plain homoglyph variants).
        // Partition by (a) regex case flags and (b) homoglyph-variant status, so
        // each batch is homogeneous: case-insensitive detector regexes; plain
        // homoglyph VARIANTS (skippable on ASCII — base AC covers them); and other
        // plain (generic/case-sensitive) fallbacks that have NO base AC pattern
        // and must run on every chunk.
        let mut ci: Vec<usize> = Vec::new();
        let mut plain_homoglyph: Vec<usize> = Vec::new();
        let mut plain_other: Vec<usize> = Vec::new();
        for &index in always_active_indices {
            match fallback.get(index) {
                Some((pattern, _)) if pattern.regex.is_case_insensitive() => ci.push(index),
                Some((pattern, _)) if pattern.homoglyph_variant => plain_homoglyph.push(index),
                Some(_) => plain_other.push(index),
                // Out-of-range index (shouldn't happen): run it unconditionally.
                None => {}
            }
        }
        let mut batches = Vec::new();
        let mut ungated_indices = Vec::new();
        let mut ci_gate_lits: Vec<Vec<u8>> = Vec::new();
        let mut plain_gate_lits: Vec<Vec<u8>> = Vec::new();
        Self::build_partition(
            fallback,
            &ci,
            true,
            false,
            &mut batches,
            &mut ungated_indices,
            &mut ci_gate_lits,
        );
        Self::build_partition(
            fallback,
            &plain_other,
            false,
            false,
            &mut batches,
            &mut ungated_indices,
            &mut plain_gate_lits,
        );
        Self::build_partition(
            fallback,
            &plain_homoglyph,
            false,
            true,
            &mut batches,
            &mut ungated_indices,
            &mut plain_gate_lits,
        );
        Some(Self {
            batches,
            ungated_indices,
            ci_gate: Self::build_gate_ac(&ci_gate_lits, true),
            plain_gate: Self::build_gate_ac(&plain_gate_lits, false),
            // Reuse the `hs` built above; both engines are always present so
            // `mark_matches` can size-dispatch between them.
            #[cfg(feature = "simd")]
            hs,
        })
    }

    /// Compute a pattern's gate-eligible required-prefix literals for the given
    /// case partition. Plain (homoglyph) patterns are matched on the ASCII path
    /// via their ASCII-FOLDED form, so their prefix literals must be extracted
    /// from that folded source — extracting from the unicode form would yield
    /// non-ASCII members that never appear in folded matching. `None` => the
    /// pattern is NOT gate-eligible and must run unconditionally.
    fn pattern_gate_literals(
        fallback: &[(CompiledPattern, Vec<String>)],
        index: usize,
        case_insensitive: bool,
    ) -> Option<Vec<Vec<u8>>> {
        let (pattern, _) = fallback.get(index)?;
        if case_insensitive {
            gate_prefix_literals(pattern.regex.as_str())
        } else {
            // Plain batch: gate on the ASCII-folded form (the matcher used on
            // ASCII chunks). `ascii_fold_src` must equal what `build_ascii_
            // alternate` compiles so the gate describes the running matcher.
            let folded: String = pattern
                .regex
                .as_str()
                .chars()
                .filter(char::is_ascii)
                .collect();
            gate_prefix_literals(&folded)
        }
    }

    fn build_partition(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        case_insensitive: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
        ungated_indices: &mut Vec<usize>,
        gate_lits: &mut Vec<Vec<u8>>,
    ) {
        // Split the partition into gate-eligible vs not so each compiled batch is
        // homogeneous: a `gateable` batch contains ONLY patterns that provably
        // require one of their prefix literals, making the combined-AC no-hit a
        // sound skip oracle for the whole batch.
        let mut eligible: Vec<usize> = Vec::new();
        let mut other: Vec<usize> = Vec::new();
        for &i in indices {
            if Self::pattern_gate_literals(fallback, i, case_insensitive).is_some() {
                eligible.push(i);
            } else {
                other.push(i);
            }
        }
        // Ungateable patterns: always-run batches (gateable = false).
        Self::build_batches(
            fallback,
            &other,
            case_insensitive,
            false,
            homoglyph,
            batches,
            ungated_indices,
        );
        // Eligible patterns: gateable batches. Only contribute their literals to
        // the combined gate when the batch was actually built as `gateable` (a
        // plain batch missing its `ascii_set`, or a compile failure, downgrades
        // to always-run, and then its literals must NOT gate anything).
        let first_new = batches.len();
        Self::build_batches(
            fallback,
            &eligible,
            case_insensitive,
            true,
            homoglyph,
            batches,
            ungated_indices,
        );
        // Re-derive contributed literals from the batches that ended up gateable,
        // so a downgraded batch (ascii_set None / compile failure) is excluded.
        for batch in &batches[first_new..] {
            if !batch.gateable {
                continue;
            }
            for &idx in &batch.fallback_indices {
                if let Some(lits) = Self::pattern_gate_literals(fallback, idx, case_insensitive) {
                    gate_lits.extend(lits);
                }
            }
        }
    }

    /// Compile `indices` into RegexSet batches with the given `gateable` intent.
    /// A plain batch is only marked gateable when its `ascii_set` compiles (the
    /// folded matcher the gate describes); otherwise it downgrades to always-run.
    fn build_batches(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
        case_insensitive: bool,
        gateable: bool,
        homoglyph: bool,
        batches: &mut Vec<PrefilterBatch>,
        ungated_indices: &mut Vec<usize>,
    ) {
        for chunk in indices.chunks(Self::BATCH_SIZE) {
            let srcs: Vec<&str> = chunk
                .iter()
                .filter_map(|&i| fallback.get(i).map(|(p, _)| p.regex.as_str()))
                .collect();
            let built = Self::compile_set(&srcs, case_insensitive);
            match built {
                Ok(set) => {
                    let ascii_set = if case_insensitive {
                        None
                    } else {
                        Self::build_ascii_alternate(fallback, chunk)
                    };
                    // Truncated SUPERSET variants (lazy-DFA-friendly): each entry
                    // through `truncate_for_prefilter` (fallback to verbatim), SAME
                    // order. If the truncated set fails to compile, reuse the full
                    // set (truncation is a perf opt, never a correctness need).
                    let trunc_srcs: Vec<String> = srcs
                        .iter()
                        .map(|s| truncate_for_prefilter(s).unwrap_or_else(|| s.to_string()))
                        .collect();
                    let set_trunc = match Self::compile_set_owned(&trunc_srcs, case_insensitive) {
                        Some(trunc) => trunc,
                        // Truncated form failed to compile: reuse the full set as
                        // the (sound-superset) trunc gate by recompiling it — it
                        // already compiled above as `set`. If even that anomalously
                        // fails, never unwrap in production: degrade this batch to
                        // always-run (ungated) so a compile anomaly costs perf, not
                        // recall.
                        None => match Self::compile_set(&srcs, case_insensitive) {
                            Ok(full) => full,
                            Err(_) => {
                                ungated_indices.extend_from_slice(chunk);
                                continue;
                            }
                        },
                    };
                    let ascii_set_trunc = ascii_set
                        .as_ref()
                        .and_then(|_| Self::build_ascii_alternate_trunc(fallback, chunk))
                        .or_else(|| ascii_set.clone());
                    // A plain gateable batch needs its folded matcher present for
                    // the (ASCII-path) gate to describe what actually runs. If the
                    // fold failed to compile, the unicode `set` runs on ASCII text
                    // and the folded-literal gate would be unsound -> downgrade.
                    let batch_gateable = gateable && (case_insensitive || ascii_set.is_some());
                    batches.push(PrefilterBatch {
                        set,
                        ascii_set,
                        set_trunc,
                        ascii_set_trunc,
                        fallback_indices: chunk.to_vec(),
                        gateable: batch_gateable,
                        homoglyph_skippable: homoglyph,
                    });
                }
                Err(_) => ungated_indices.extend_from_slice(chunk),
            }
        }
    }

    fn compile_set(
        srcs: &[&str],
        case_insensitive: bool,
    ) -> std::result::Result<regex::RegexSet, regex::Error> {
        regex::RegexSetBuilder::new(srcs)
            .case_insensitive(case_insensitive)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .crlf(case_insensitive)
            .build()
    }

    fn compile_set_owned(srcs: &[String], case_insensitive: bool) -> Option<regex::RegexSet> {
        regex::RegexSetBuilder::new(srcs)
            .case_insensitive(case_insensitive)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .crlf(case_insensitive)
            .build()
            .ok()
    }

    /// Build the combined skip-gate Aho-Corasick over `literals`. `ci` selects
    /// ASCII case-insensitive matching (for the detector-regex partition).
    /// `None` when there are no literals to gate on.
    fn build_gate_ac(literals: &[Vec<u8>], ci: bool) -> Option<AhoCorasick> {
        if literals.is_empty() {
            return None;
        }
        AhoCorasick::builder()
            .ascii_case_insensitive(ci)
            .build(literals)
            .ok()
    }

    /// Build the ASCII-folded alternate RegexSet for a plain (homoglyph) batch:
    /// each homoglyph regex with every non-ASCII codepoint removed, in the SAME
    /// entry order. Match-equivalent to the unicode form on pure-ASCII text.
    /// `None` if any fold fails to compile (the unicode set is used instead).
    fn build_ascii_alternate(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<regex::RegexSet> {
        let folded: Vec<String> = indices
            .iter()
            .filter_map(|&i| fallback.get(i))
            .map(|(p, _)| p.regex.as_str().chars().filter(char::is_ascii).collect())
            .collect();
        if folded.len() != indices.len() {
            return None;
        }
        regex::RegexSetBuilder::new(&folded)
            .case_insensitive(false)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .build()
            .ok()
    }

    /// As `build_ascii_alternate`, but each folded source is additionally passed
    /// through `truncate_for_prefilter` (truncate the FOLDED form so the matcher
    /// that runs on ASCII text stays on the lazy-DFA). SAME entry order; `None`
    /// if any fold or the truncated set fails to compile.
    fn build_ascii_alternate_trunc(
        fallback: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<regex::RegexSet> {
        let folded: Vec<String> = indices
            .iter()
            .filter_map(|&i| fallback.get(i))
            .map(|(p, _)| {
                let f: String = p.regex.as_str().chars().filter(char::is_ascii).collect();
                truncate_for_prefilter(&f).unwrap_or(f)
            })
            .collect();
        if folded.len() != indices.len() {
            return None;
        }
        regex::RegexSetBuilder::new(&folded)
            .case_insensitive(false)
            .size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .dfa_size_limit(Self::BATCH_SIZE_LIMIT_BYTES)
            .build()
            .ok()
    }

    /// Mark every always-active fallback whose regex can match `match_text`.
    /// `match_text` MUST be the text the per-pattern extraction runs on
    /// (`preprocessed.text`) for the prefilter to stay sound under unicode
    /// normalization.
    /// `localize_plain`: the caller (the shared-anchor path) handles the plain
    /// (homoglyph) patterns on pure-ASCII chunks via the localized AC, so they
    /// are SKIPPED here (no whole-chunk RegexSet pass). When false, plain
    /// batches run their ASCII-folded alternate (the order-preserving fold) —
    /// the safety-net path that is always recall-correct.
    fn mark_matches(
        &self,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        localize_plain: bool,
    ) {
        // SIMD fast path: one Hyperscan scan replaces the whole-chunk RegexSet
        // batch loop below (the measured #1 scan cost). `localize_plain` is a
        // RegexSet-batch optimization (skip plain batches the shared-anchor AC
        // covers); the HS path marks the full matching set instead — a sound
        // SUPERSET (eligible patterns still route through the AC+verify path,
        // non-eligible through whole-chunk extraction), proven findings-identical.
        #[cfg(feature = "simd")]
        if let Some(hs) = &self.hs {
            // Size-dispatch: HS wins on SMALL chunks (its near-constant per-scan
            // cost beats the RegexSet's per-call lazy-DFA setup), but its unicode
            // automaton over MANY bytes loses to the folded/truncated RegexSet on
            // large chunks. Above the threshold, fall through to the batches.
            if fallback_hs_enabled() && match_text.len() <= hs_prefilter_max_len() {
                let _ = localize_plain;
                hs.mark(match_text, scratch);
                return;
            }
        }
        let use_ascii = homoglyph_gate_enabled() && match_text.is_ascii();

        // Prefix-literal skip gate (KH decode-recursion lever). A `gateable`
        // batch's patterns ALL provably require one of their prefix literals; if
        // the combined Aho-Corasick over those literals finds NONE in the chunk,
        // the batch cannot produce a single match and its whole-chunk RegexSet
        // pass is skipped. `is_match` early-exits at the first literal, so the
        // full O(text) scan only happens on chunks that have none — exactly the
        // skip case (the dominant decode-recursion sub-chunk shape, and most
        // low-density source). `present == true` means "run gateable batches as
        // before" — recall is identical, only dead work is removed.
        let gate_on = fallback_prefix_gate_enabled();
        // ci batches run `set` on every chunk -> the ci gate applies always.
        let ci_present = !gate_on
            || self
                .ci_gate
                .as_ref()
                .is_none_or(|ac| ac.is_match(match_text));
        // plain batches are gated only on the ASCII path (the folded-literal gate
        // describes the folded matcher); on a non-ASCII chunk the unicode `set`
        // runs unconditionally, so `plain_present` is forced true there.
        let plain_present = !gate_on
            || !use_ascii
            || self
                .plain_gate
                .as_ref()
                .is_none_or(|ac| ac.is_match(match_text));

        let prof = fallback_pat_prof_enabled();
        if prof {
            GATE_CALLS.fetch_add(1, Relaxed);
        }
        // Truncated (lazy-DFA) marking sets: a sound SUPERSET — over-marks at
        // most, extraction with the full pattern filters. The win is keeping the
        // RegexSet off PikeVM on `{N,}` bodies.
        let truncate = prefilter_truncate_enabled();
        let ascii = match_text.is_ascii();
        for batch in &self.batches {
            let is_plain = batch.ascii_set.is_some();
            // A HOMOGLYPH-variant batch on a pure-ASCII chunk: skip entirely. Each
            // variant's base ASCII prefix is in the AC/confirmed path
            // (compiler_build.rs pushes both), and a chunk with no non-ASCII bytes
            // has no homoglyph for the variant to catch — so it adds nothing the
            // base AC doesn't. This removes the dominant `fb:prefilter` cost on
            // all-ASCII source. Proven recall-neutral by `homoglyph_ascii_skip_parity`.
            // Generic/case-sensitive plain fallbacks (no base AC) are in
            // non-skippable batches and are unaffected.
            if batch.homoglyph_skippable && ascii && homoglyph_ascii_skip_enabled() {
                continue;
            }
            // Or: the caller's localizer covers this plain batch.
            if is_plain && localize_plain && use_ascii {
                continue;
            }
            // Skip a gateable batch whose required prefix literals are all absent.
            if batch.gateable {
                let present = if is_plain { plain_present } else { ci_present };
                if !present {
                    if prof {
                        GATE_BATCH_SKIPS.fetch_add(1, Relaxed);
                    }
                    continue;
                }
                if prof {
                    GATE_BATCH_RUNS.fetch_add(1, Relaxed);
                }
            }
            let set = match (
                truncate,
                use_ascii,
                &batch.ascii_set,
                &batch.ascii_set_trunc,
            ) {
                (true, true, Some(_), Some(ascii_trunc)) => ascii_trunc,
                (false, true, Some(ascii), _) => ascii,
                (true, _, _, _) => &batch.set_trunc,
                (false, _, _, _) => &batch.set,
            };
            for set_idx in set.matches(match_text).iter() {
                scratch.mark(batch.fallback_indices[set_idx]);
            }
        }
        for &index in &self.ungated_indices {
            scratch.mark(index);
        }
    }
}

/// True iff `src` has a finite, enumerable required-prefix literal set every
/// member of which is >= 3 bytes — the soundness precondition for driving the
/// pattern from prefix-anchor positions instead of a whole-chunk walk.
fn regex_prefix_anchorable(src: &str) -> bool {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    let Ok(hir) = regex_syntax::ParserBuilder::new().build().parse(src) else {
        return false;
    };
    let mut ex = Extractor::new();
    ex.kind(ExtractKind::Prefix);
    let seq = ex.extract(&hir);
    matches!(
        (seq.is_finite(), seq.len(), seq.min_literal_len()),
        (true, Some(n), Some(min)) if n > 0 && min >= 3
    )
}

/// For the PREFILTER (presence/marking) ONLY: truncate a pattern at its FIRST
/// top-level unbounded repetition and bound that repetition to its minimum, so
/// the always-active prefilter RegexSet stays on the fast lazy-DFA instead of
/// falling to PikeVM on `{N,}`/`+`/`*` bodies (the measured ~793 ms dominant
/// cost on BOTH parent and decode sub-chunk scans).
///
/// SOUNDNESS: any match of the FULL pattern `A B{n,} <rest>` contains the prefix
/// `A B{n}` at its start, so if the truncated form does NOT match, the full
/// pattern cannot match anywhere — i.e. the truncated set is a SOUND SUPERSET
/// presence gate. It may over-mark (a pattern whose `A B{n}` is present but whose
/// `<rest>` is absent), but extraction runs the FULL pattern and filters those,
/// so the finding set is unchanged. For the common credential shape `prefix
/// charclass{n,}` (no trailing `<rest>`) the truncation is EXACT, not merely a
/// superset.
///
/// Returns `None` when there is no top-level unbounded repetition (already
/// bounded → use the source verbatim) or the structure is not a simple top-level
/// concat/repetition (kept full — sound, just stays on the slow path). The
/// returned string is validated to compile.
pub fn truncate_for_prefilter(src: &str) -> Option<String> {
    use regex_syntax::ast::{Ast, RepetitionKind, RepetitionRange};
    let ast = regex_syntax::ast::parse::Parser::new().parse(src).ok()?;
    let single;
    let nodes: &[Ast] = match &ast {
        Ast::Concat(c) => &c.asts,
        // A bare top-level repetition (e.g. `[a-z]{20,}`): a one-node concat.
        Ast::Repetition(_) => {
            single = [ast.clone()];
            &single
        }
        _ => return None,
    };
    for node in nodes {
        let Ast::Repetition(rep) = node else { continue };
        let b_start = rep.span.start.offset; // start of the repeated sub-expr B
        let op_start = rep.op.span.start.offset; // start of the `{n,}`/`+`/`*` op
        let truncated = match &rep.op.kind {
            // B* → drop B entirely; the gate is the prefix before it.
            RepetitionKind::ZeroOrMore => src.get(..b_start)?.to_string(),
            // B+ → B{1} == one B; keep through the repeated expr, drop the `+`.
            RepetitionKind::OneOrMore => src.get(..op_start)?.to_string(),
            // B{n,} → B{n}; keep through the repeated expr, bound to the minimum.
            RepetitionKind::Range(RepetitionRange::AtLeast(n)) => {
                format!("{}{{{}}}", src.get(..op_start)?, n)
            }
            // ZeroOrOne / Exactly / Bounded are already finite — not a blow-up
            // source; keep scanning for a later unbounded repetition.
            _ => continue,
        };
        // Defensive: never ship a prefilter pattern that fails to compile.
        return regex::Regex::new(&truncated).ok().map(|_| truncated);
    }
    None
}

/// Round `idx` down to the nearest UTF-8 char boundary (stable-Rust stand-in
/// for the unstable `str::floor_char_boundary`). Used to snap the decode-focus
/// window so a slice never splits a multi-byte codepoint.
fn focus_floor_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn focus_ceil_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn truncate_src(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut i = n.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    format!("{}…", &s[..i])
}

thread_local! {
    /// Per-thread pool for the active-fallback scratch. Pool one per worker;
    /// it is grown once and reused thereafter (no per-chunk allocation).
    static ACTIVE_PATTERNS_POOL: RefCell<ActivePatternsScratch> =
        const { RefCell::new(ActivePatternsScratch::new()) };
}

impl CompiledScanner {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn scan_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                return;
            }
        }

        // Shared-anchor fast path: one Aho-Corasick pass over all eligible
        // patterns' required-prefix literals yields candidate positions, each
        // verified by an anchored regex - replacing each pattern's own
        // whole-chunk walk. Recall-identical (see `fallback_anchor`); handles
        // any chunk size, so it supersedes the small/large split below. Active
        // patterns with no required-literal anchor keep the whole-chunk path
        // inside `scan_fallback_with_anchors`.
        if !self.fallback.is_empty() && fallback_anchor_enabled() {
            if let Some(anchor_idx) = &self.fallback_anchor_index {
                self.scan_fallback_with_anchors(
                    anchor_idx,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    deadline,
                    None,
                );
                return;
            }
        }

        if preprocessed.text.len() > LARGE_FALLBACK_SCAN_THRESHOLD && !self.fallback.is_empty() {
            self.scan_large_fallback_patterns(
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                deadline,
            );
            return;
        }
        let prof = fallback_pat_prof_enabled();
        self.with_active_fallback_patterns(
            &chunk.data,
            &preprocessed.text,
            |this, active_patterns| {
                // `active_patterns` is the SPARSE list of active fallback indices,
                // so we touch only the patterns that can fire on this chunk rather
                // than the full `fallback.len()` vector.
                for (tested, &index) in active_patterns.iter().enumerate() {
                    if let Some(deadline) = deadline {
                        if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    let (entry, _keywords) = &this.fallback[index];
                    let t0 = if prof { Some(Instant::now()) } else { None };
                    this.extract_matches(
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
                        fallback_prof_record(
                            this.fallback.len(),
                            index,
                            t0.elapsed().as_nanos() as u64,
                        );
                    }
                }
            },
        );
    }

    /// Decode-recursion FOCUS variant of `scan_fallback_patterns`. A decode
    /// sub-chunk is a small window of already-scanned parent context with the
    /// freshly decoded text spliced in at `focus = (start, end)`. Everything
    /// outside `[start,end)` was scanned (and any finding deduped against
    /// `seen`) when the parent chunk was scanned, so the only NEW fallback
    /// matches are those that touch the decoded text.
    ///
    /// This windows the two expensive parts of the fallback pass — the
    /// always-active prefilter RegexSet and the per-pattern regex extraction —
    /// to `[start-margin, end+margin)`, while keeping the FULL splice for every
    /// signal that decides whether/how a match is reported:
    ///   - `keyword_nearby` (`compute_pattern_signals` reads the full `chunk`),
    ///   - the keyword Aho-Corasick prefilter (`data = &chunk.data`, so a
    ///     keyword in far context still activates its pattern),
    ///   - `line_offsets` / `documentation_lines` / `base_offset` / `base_line`.
    /// So for any match that STARTS inside the focus window the produced
    /// `(detector, credential, location, confidence)` is byte-identical to the
    /// whole-splice scan. Matches outside the window are either pure-context
    /// (already found by the parent → deduped) or unreachable, so the reported
    /// set is unchanged (validated by `decode_focus_parity`).
    ///
    /// PRECONDITION: `preprocessed.text` must be byte-aligned with `chunk.data`
    /// (the homoglyph-normalisation no-op passthrough), so `focus` — computed in
    /// `chunk.data` coordinates — indexes `preprocessed.text` correctly. The
    /// caller checks this; a non-passthrough chunk takes the full-scan path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_fallback_patterns_focused(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        focus: (usize, usize),
    ) {
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                return;
            }
        }
        if self.fallback.is_empty() {
            return;
        }
        let text: &str = &preprocessed.text;
        // Expand the decoded span by the margin and snap to char boundaries.
        let fs = focus_floor_boundary(text, focus.0.saturating_sub(DECODE_FOCUS_MARGIN));
        let fe = focus_ceil_boundary(
            text,
            focus.1.saturating_add(DECODE_FOCUS_MARGIN).min(text.len()),
        );
        if fs >= fe {
            return;
        }
        // If the focus window already covers (almost) the whole chunk, the
        // restriction buys nothing — run the normal path so we don't pay the
        // extra slice setup for no gain.
        if fe - fs >= text.len() {
            self.scan_fallback_patterns(
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                deadline,
            );
            return;
        }
        let focus = Some((fs, fe));

        // Prefer the optimized shared-anchor path (the default), now focus-aware:
        // its AC candidate scan + always-active prefilter run over the window
        // while signals/lines stay full. This is what makes the restriction a net
        // win — the non-anchor whole-chunk prefilter, even windowed, barely beats
        // the anchor path on full text.
        if fallback_anchor_enabled() {
            if let Some(anchor_idx) = &self.fallback_anchor_index {
                self.scan_fallback_with_anchors(
                    anchor_idx,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    deadline,
                    focus,
                );
                return;
            }
        }

        // Anchor index unavailable: windowed non-anchor path (prefilter over the
        // focus slice, keyword AC over full `chunk.data`, extraction cursor-bound
        // to the window).
        let match_text = &text[fs..fe];
        let cursor = focus;
        let prof = fallback_pat_prof_enabled();
        self.with_active_fallback_patterns(&chunk.data, match_text, |this, active_patterns| {
            for (tested, &index) in active_patterns.iter().enumerate() {
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                let (entry, _keywords) = &this.fallback[index];
                let t0 = if prof { Some(Instant::now()) } else { None };
                this.extract_matches_inner(
                    entry,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    0,
                    0,
                    cursor,
                    deadline,
                );
                if let Some(t0) = t0 {
                    fallback_prof_record(
                        this.fallback.len(),
                        index,
                        t0.elapsed().as_nanos() as u64,
                    );
                }
            }
        });
    }

    /// Compute the active-fallback set into the thread-local pool, run the
    /// caller's closure with a borrow of the SPARSE active-index list, and
    /// return whatever the closure returns. The scratch is reset (not freed)
    /// on entry, so the next chunk the same worker handles reuses the
    /// allocation. The closure receives `&[usize]` - the fallback indices
    /// that are active for this chunk, so it visits only those patterns
    /// rather than the full `fallback.len()` vector.
    /// `data` seeds the keyword-AC prefilter (raw chunk bytes, as before).
    /// `match_text` is the text the always-active RegexSet prefilter runs on and
    /// MUST be the same text per-pattern extraction uses (`preprocessed.text`)
    /// so the prefilter is sound under unicode normalization.
    fn with_active_fallback_patterns<R>(
        &self,
        data: &str,
        match_text: &str,
        f: impl FnOnce(&Self, &[usize]) -> R,
    ) -> R {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.fallback.len());
            // anchor_mode = false: the legacy whole-chunk path has no AC gating,
            // so every always-active pattern must be marked for recall.
            self.populate_active_fallback(data, match_text, &mut scratch, false);
            if fallback_reverse_enabled() {
                scratch.active.reverse();
            }
            f(self, &scratch.active)
        })
    }

    /// As `with_active_fallback_patterns`, but hands the closure the full
    /// `ActivePatternsScratch` (not just the sparse list) so it can also test
    /// `is_active(idx)` in O(1) - the shared-anchor path needs that to gate
    /// candidate positions to the active set.
    fn with_active_fallback_scratch<R>(
        &self,
        data: &str,
        match_text: &str,
        f: impl FnOnce(&Self, &ActivePatternsScratch) -> R,
    ) -> R {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.fallback.len());
            // anchor_mode = true: this method only runs on the shared-anchor
            // path, where eligible always-active patterns are gated by the AC.
            self.populate_active_fallback(data, match_text, &mut scratch, true);
            if fallback_reverse_enabled() {
                scratch.active.reverse();
            }
            f(self, &scratch)
        })
    }

    /// Shared-anchor fallback scan. Computes the active set once, then:
    ///   1. runs ONE Aho-Corasick pass over the chunk for every eligible
    ///      pattern's required-prefix literals, collecting `(pattern, pos)`
    ///      candidates for the patterns that are active;
    ///   2. verifies each active eligible pattern anchored at its candidate
    ///      positions (O(match length) each, no per-pattern chunk scan);
    ///   3. runs the remaining active NON-eligible patterns on the legacy
    ///      whole-chunk path.
    /// The union of (2) and (3) is exactly the active set the legacy loop would
    /// have scanned, producing an identical match set (asserted by
    /// `fallback_anchor_parity`).
    #[allow(clippy::too_many_arguments)]
    fn scan_fallback_with_anchors(
        &self,
        anchor_idx: &fallback_anchor::FallbackAnchorIndex,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        // Decode-recursion FOCUS window `[fs, fe)` (in `preprocessed.text` ==
        // `chunk.data` coordinates). When `Some`, the AC candidate scan, the
        // always-active prefilter and every whole-chunk extraction are restricted
        // to this window — the rest of the splice is already-scanned parent
        // context. Signals (`keyword_nearby` via `&chunk.data`), line numbers and
        // anchored verification still use the FULL text, so results for matches
        // starting inside the window are byte-identical. `None` = whole chunk.
        focus: Option<(usize, usize)>,
    ) {
        let prof = fallback_pat_prof_enabled();
        // Text the AC candidate scan and the always-active prefilter run on.
        let scan_text: &str = match focus {
            Some((fs, fe)) => &preprocessed.text[fs..fe],
            None => &preprocessed.text,
        };
        let shift = focus.map_or(0u32, |(fs, _)| fs as u32);
        // `cursor_range` for the whole-chunk extraction fallbacks: restrict match
        // STARTS to the focus window (matches still extend right freely).
        let cursor = focus;
        // Keyword AC still seeds from the FULL chunk bytes so a keyword in far
        // context activates its pattern; only the prefilter text is windowed.
        self.with_active_fallback_scratch(&chunk.data, scan_text, |this, scratch| {
            ANCHOR_CANDIDATES.with(|cell| {
                let mut cands = cell.borrow_mut();
                {
                    let _g = super::profile::span(super::profile::P::FbSharedAc);
                    anchor_idx.collect_candidates(
                        scan_text,
                        |pat| scratch.is_active(pat),
                        &mut cands,
                    );
                }
                // Candidate positions are relative to `scan_text`; lift them back
                // into full-text coordinates so anchored verification indexes the
                // real (full) `preprocessed.text`.
                if shift != 0 {
                    for c in cands.iter_mut() {
                        c.1 += shift;
                    }
                }
                // Candidates are sorted by (pattern, pos); verify each
                // pattern's contiguous run together so its per-pattern
                // signal cache is built at most once.
                let _verify_g = super::profile::span(super::profile::P::FbAnchoredVerify);
                let mut i = 0usize;
                while i < cands.len() {
                    if let Some(deadline) = deadline {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    let pat = cands[i].0 as usize;
                    let mut j = i + 1;
                    while j < cands.len() && cands[j].0 as usize == pat {
                        j += 1;
                    }
                    let group = &cands[i..j];
                    let (entry, _) = &this.fallback[pat];
                    let t0 = if prof { Some(Instant::now()) } else { None };
                    match anchor_idx.anchored_regex(pat) {
                        Some(re) => this.extract_anchored(
                            entry,
                            re,
                            group,
                            preprocessed,
                            line_offsets,
                            code_lines,
                            documentation_lines,
                            chunk,
                            scan_state,
                            deadline,
                        ),
                        // Anchored regex failed to compile (logged once in
                        // `AnchoredRegex::get`): fall back LOUDLY to the
                        // whole-chunk walk so recall is preserved.
                        None => this.extract_matches_inner(
                            entry,
                            preprocessed,
                            line_offsets,
                            code_lines,
                            documentation_lines,
                            chunk,
                            scan_state,
                            0,
                            0,
                            cursor,
                            deadline,
                        ),
                    }
                    if let Some(t0) = t0 {
                        fallback_prof_record(
                            this.fallback.len(),
                            pat,
                            t0.elapsed().as_nanos() as u64,
                        );
                    }
                    i = j;
                }
            });

            // Localized homoglyph path (ASCII chunks): the prefilter skipped
            // the plain (homoglyph) patterns, so verify them here from the
            // folded-literal AC candidate positions via `extract_anchored`
            // (O(match) each — dense over-marking from a short literal is a
            // cheap quick-fail, not a whole-chunk scan). Plain patterns with
            // no folded literal run whole-chunk (they are few).
            if homoglyph_gate_enabled() && scan_text.is_ascii() && anchor_idx.has_plain_localizer()
            {
                ANCHOR_CANDIDATES.with(|cell| {
                    let mut cands = cell.borrow_mut();
                    anchor_idx.collect_plain_candidates(scan_text, &mut cands);
                    if shift != 0 {
                        for c in cands.iter_mut() {
                            c.1 += shift;
                        }
                    }
                    let mut i = 0usize;
                    while i < cands.len() {
                        if let Some(deadline) = deadline {
                            if std::time::Instant::now() >= deadline {
                                break;
                            }
                        }
                        let pat = cands[i].0 as usize;
                        let mut j = i + 1;
                        while j < cands.len() && cands[j].0 as usize == pat {
                            j += 1;
                        }
                        let group = &cands[i..j];
                        let (entry, _) = &this.fallback[pat];
                        let t0 = if prof { Some(Instant::now()) } else { None };
                        match anchor_idx.anchored_regex(pat) {
                            Some(re) => this.extract_anchored(
                                entry,
                                re,
                                group,
                                preprocessed,
                                line_offsets,
                                code_lines,
                                documentation_lines,
                                chunk,
                                scan_state,
                                deadline,
                            ),
                            None => this.extract_matches_inner(
                                entry,
                                preprocessed,
                                line_offsets,
                                code_lines,
                                documentation_lines,
                                chunk,
                                scan_state,
                                0,
                                0,
                                cursor,
                                deadline,
                            ),
                        }
                        if let Some(t0) = t0 {
                            fallback_prof_record(
                                this.fallback.len(),
                                pat,
                                t0.elapsed().as_nanos() as u64,
                            );
                        }
                        i = j;
                    }
                });
                for &idx in anchor_idx.plain_always_mark() {
                    if let Some(deadline) = deadline {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                    }
                    let pat = idx as usize;
                    let (entry, _) = &this.fallback[pat];
                    let t0 = if prof { Some(Instant::now()) } else { None };
                    this.extract_matches_inner(
                        entry,
                        preprocessed,
                        line_offsets,
                        code_lines,
                        documentation_lines,
                        chunk,
                        scan_state,
                        0,
                        0,
                        cursor,
                        deadline,
                    );
                    if let Some(t0) = t0 {
                        fallback_prof_record(
                            this.fallback.len(),
                            pat,
                            t0.elapsed().as_nanos() as u64,
                        );
                    }
                }
            }

            // Active patterns with no required-literal anchor: whole-chunk
            // (windowed to the focus cursor when focus-restricting).
            let _wholechunk_g = super::profile::span(super::profile::P::FbWholeChunk);
            for (tested, &index) in scratch.active.iter().enumerate() {
                if anchor_idx.is_eligible(index) {
                    continue;
                }
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                let (entry, _) = &this.fallback[index];
                let t0 = if prof { Some(Instant::now()) } else { None };
                this.extract_matches_inner(
                    entry,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    0,
                    0,
                    cursor,
                    deadline,
                );
                if let Some(t0) = t0 {
                    fallback_prof_record(
                        this.fallback.len(),
                        index,
                        t0.elapsed().as_nanos() as u64,
                    );
                }
            }
        });
    }

    pub(crate) fn has_active_fallback_patterns_for_chunk(&self, data: &str) -> bool {
        if self.fallback.is_empty() {
            return false;
        }
        if !self.fallback_always_active_indices.is_empty() || self.fallback_keyword_ac.is_none() {
            return true;
        }
        // No always-active patterns here (the check above returned early if any
        // exist), so the RegexSet prefilter is irrelevant; pass `data` for both.
        self.with_active_fallback_patterns(data, data, |_, active_patterns| {
            !active_patterns.is_empty()
        })
    }

    /// True iff `idx` is an eligible always-active pattern handled by the shared
    /// anchor AC (and therefore excluded from the RegexSet prefilter).
    #[inline]
    fn anchor_always_active_eligible(&self, idx: usize) -> bool {
        self.fallback_anchor_index
            .as_ref()
            .is_some_and(|a| a.is_always_active_eligible(idx))
    }

    /// Compute the active fallback set. `anchor_mode` selects how always-active
    /// patterns are gated:
    ///   * `true` (shared-anchor path): the RegexSet prefilter covers only the
    ///     NON-eligible always-active patterns; eligible ones are gated later by
    ///     the shared AC (see `scan_fallback_with_anchors`), so they are NOT
    ///     marked here. This is the ~10x-smaller prefilter that is the win.
    ///   * `false` (legacy whole-chunk path): every always-active pattern is
    ///     marked (the reduced prefilter doesn't cover the eligible ones, and
    ///     there is no AC gating on this path), so recall is preserved.
    fn populate_active_fallback(
        &self,
        data: &str,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        anchor_mode: bool,
    ) {
        if let Some(keyword_ac) = &self.fallback_keyword_ac {
            let prof = fallback_pat_prof_enabled();
            // Always-active patterns (no >=4-char keyword) would each run their
            // capture regex over the whole chunk. Gate them through a combined
            // RegexSet so only patterns that can actually match are activated;
            // the rest extract nothing and are dead work. The set is built with
            // each pattern's own flags, so this drops cost, never recall. When
            // the set could not be compiled, fall back to marking all of them.
            // The always-active prefilter marks the patterns that can fire. Its
            // plain (homoglyph) batches use a fast ASCII-folded alternate on
            // pure-ASCII chunks (identical marking, far faster) — the perf win.
            // When anchor localization is on, the prefilter covers only the
            // non-eligible always-active set (eligible ones are handled by the
            // shared AC); on the legacy path every always-active pattern must be
            // marked, so a `None` prefilter falls back to marking them all.
            // On the shared-anchor path, plain (homoglyph) patterns are handled
            // by the localized AC on ASCII chunks, so the prefilter skips them.
            let localize_plain = anchor_mode
                && self
                    .fallback_anchor_index
                    .as_ref()
                    .is_some_and(|a| a.has_plain_localizer());
            let t0 = if prof { Some(Instant::now()) } else { None };
            {
                // The anchorless always-active RegexSet — the detectors that run
                // on EVERY chunk. This span is the cost the "fallback" name hides.
                let _g = super::profile::span(super::profile::P::FbPrefilter);
                match &self.fallback_always_active_prefilter {
                    Some(prefilter) => prefilter.mark_matches(match_text, scratch, localize_plain),
                    None => {
                        for &index in &self.fallback_always_active_indices {
                            if anchor_mode && self.anchor_always_active_eligible(index) {
                                continue;
                            }
                            scratch.mark(index);
                        }
                    }
                }
            }
            if let Some(t0) = t0 {
                POPULATE_PREFILTER_NS.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
            }
            let t1 = if prof { Some(Instant::now()) } else { None };
            {
                let _g = super::profile::span(super::profile::P::FbKeywordAc);
                for mat in keyword_ac.find_iter(data) {
                    let keyword_idx = mat.pattern().as_usize();
                    if let Some(pattern_indices) =
                        self.fallback_keyword_to_patterns.get(keyword_idx)
                    {
                        for &pattern_idx in pattern_indices {
                            scratch.mark(pattern_idx as usize);
                        }
                    }
                }
            }
            if let Some(t1) = t1 {
                POPULATE_KEYWORD_NS.fetch_add(t1.elapsed().as_nanos() as u64, Relaxed);
            }
        } else {
            // No keyword prefilter compiled - every fallback pattern is
            // considered active.
            for index in 0..self.fallback.len() {
                scratch.mark(index);
            }
        }
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    fn scan_large_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        let prof = fallback_pat_prof_enabled();
        self.with_active_fallback_patterns(&chunk.data, &preprocessed.text, |this, active_set| {
            // `active_set` is the sparse list of active fallback indices, so
            // we iterate only the patterns that can fire - no second
            // `Vec<&CompiledPattern>` collect and no scan over the inactive
            // entries of the full fallback vector.
            for (tested, &index) in active_set.iter().enumerate() {
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                let (entry, _) = &this.fallback[index];
                let t0 = if prof { Some(Instant::now()) } else { None };
                this.extract_matches(
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
                    fallback_prof_record(
                        this.fallback.len(),
                        index,
                        t0.elapsed().as_nanos() as u64,
                    );
                }
            }
        });
    }

    /// Print and reset the per-pattern fallback profile (top 30 by time). Call
    /// after a profiled run (`KEYHOG_PROFILE_FALLBACK=1`). Each line is the
    /// fallback detector's regex, total ms, run count, and ns/run, plus whether
    /// it carries a regex-required prefix anchor (the localization candidate).
    pub fn fallback_profile_dump(&self, label: &str) {
        let len = self.fallback.len();
        let (ns, runs) = fallback_prof_vecs(len);
        let mut rows: Vec<(usize, u64, u64)> = (0..len)
            .map(|i| (i, ns[i].swap(0, Relaxed), runs[i].swap(0, Relaxed)))
            .filter(|&(_, n, _)| n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        let grand: u64 = rows.iter().map(|r| r.1).sum();
        let prefilter_ms = POPULATE_PREFILTER_NS.swap(0, Relaxed) as f64 / 1e6;
        let keyword_ms = POPULATE_KEYWORD_NS.swap(0, Relaxed) as f64 / 1e6;
        eprintln!(
            "=== FALLBACK per-pattern profile [{label}] ===\n  populate: always-active RegexSet prefilter={prefilter_ms:.1} ms, keyword-AC={keyword_ms:.1} ms\n  extract: {:.1} ms over {} active patterns",
            grand as f64 / 1e6,
            rows.len()
        );
        for (i, n, r) in rows.iter().take(30) {
            let src = self.fallback[*i].0.regex.as_str();
            let anchored = regex_prefix_anchorable(src);
            let per_run = if *r > 0 { *n / *r } else { 0 };
            eprintln!(
                "  {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run  [{}] {}",
                *n as f64 / 1e6,
                100.0 * *n as f64 / grand.max(1) as f64,
                r,
                per_run,
                if anchored { "ANCHOR" } else { "  --  " },
                truncate_src(src, 64),
            );
        }
    }

    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText<'_>,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        // Most detectors declare no companions. Return the empty map without
        // sizing a bucket array (`HashMap::new()` is allocation-free until the
        // first insert) and without entering the search loop. Only detectors
        // that actually have companions pay for the map.
        let Some(detector_companions) = self.companions.get(entry.detector_index) else {
            return Some(HashMap::new());
        };
        if detector_companions.is_empty() {
            return Some(HashMap::new());
        }
        let mut results = HashMap::with_capacity(detector_companions.len());
        for companion in detector_companions {
            if let Some(val) = find_companion(preprocessed, line, companion) {
                results.insert(companion.name.clone(), val);
            } else if companion.required {
                return None;
            }
        }
        Some(results)
    }

    pub(crate) fn match_confidence<'a>(
        &self,
        entry: &CompiledPattern,
        chunk: &Chunk,
        credential: &'a str,
        data: &'a str,
        line: usize,
        entropy: f64,
        has_companion: bool,
        // The context is computed once in `process_match` (where the
        // suppression checks already need it) and threaded through -
        // halves the per-match context-inference work.
        context: context::CodeContext,
        // `keyword_nearby` and `sensitive_file` are constant across
        // every match of a single (chunk, pattern) pair: keyword_nearby
        // depends only on the detector + chunk text, sensitive_file
        // only on the chunk's path. Hoisted to `extract_matches`'s
        // pre-loop preamble so the inner per-match path doesn't keep
        // re-running an O(K) substring scan over the whole chunk +
        // an Aho-Corasick scan over the path.
        keyword_nearby: bool,
        sensitive_file: bool,
        // True when the firing detector is service-anchored (not generic-* /
        // entropy-* / private-key). Such a detector's regex is itself the
        // positive evidence, so the generic probabilistic-promise gate must
        // not bury it - see the rationale in `process_match`.
        is_named_detector: bool,
        scan_state: &mut ScanState,
    ) -> Option<MlScoreResult<'a>> {
        let raw_conf =
            crate::confidence::compute_confidence(&crate::confidence::ConfidenceSignals {
                has_literal_prefix: extract_literal_prefix(entry.regex.as_str()).is_some(),
                has_context_anchor: entry.group.is_some(),
                entropy,
                keyword_nearby,
                sensitive_file,
                match_length: credential.len(),
                has_companion,
            });

        // Checksum validation is handled in process_match (early reject for Invalid,
        // confidence floor for Valid). No need to re-validate here.
        // The fixture opt-out must also bypass this pre-ML context multiplier;
        // otherwise the lower score is baked into `heuristic_conf`.
        let context_multiplier = match context {
            crate::context::CodeContext::TestCode | crate::context::CodeContext::Documentation
                if !self.config.penalize_test_paths =>
            {
                1.0
            }
            _ => context.confidence_multiplier(),
        };
        let heuristic_conf = raw_conf * context_multiplier;
        let score_result = self.calculate_final_score(
            heuristic_conf,
            context,
            credential,
            data,
            line,
            chunk,
            is_named_detector,
            scan_state,
        )?;

        match score_result {
            MlScoreResult::Final(confidence) => {
                let final_score = if let Some(floor) =
                    crate::confidence::known_prefix_confidence_floor(credential)
                {
                    confidence.max(floor)
                } else {
                    confidence
                };

                // Keep comment hard-suppression separate from the fixture
                // opt-out; comments stay controlled by `--scan-comments`.
                let hard_suppressed = context.should_hard_suppress(final_score)
                    && (self.config.penalize_test_paths
                        || matches!(context, crate::context::CodeContext::Comment));
                if hard_suppressed {
                    None
                } else {
                    Some(MlScoreResult::Final(final_score))
                }
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending { .. } => Some(score_result),
            #[cfg(not(feature = "ml"))]
            MlScoreResult::_Lifetime(_) => {
                unreachable!("_Lifetime is a never-constructed placeholder variant")
            }
        }
    }

    fn calculate_final_score<'a>(
        &self,
        heuristic_conf: f64,
        context: context::CodeContext,
        credential: &'a str,
        data: &'a str,
        line: usize,
        chunk: &Chunk,
        is_named_detector: bool,
        _scan_state: &mut ScanState,
    ) -> Option<MlScoreResult<'a>> {
        #[cfg(not(feature = "ml"))]
        {
            let _ = (context, credential, data, line, chunk, is_named_detector);
            Some(MlScoreResult::Final(heuristic_conf))
        }

        #[cfg(feature = "ml")]
        {
            if !self.config.ml_enabled {
                return Some(MlScoreResult::Final(heuristic_conf));
            }

            // The probabilistic-promise gate fast-rejects low-diversity /
            // UUID / structured strings to 0.1 (below the 0.3 report floor).
            // That is correct for generic-* / entropy-* detectors - their
            // only evidence is shape - but a NAMED service-anchored detector
            // proved via its own regex that these bytes are the credential
            // (Heroku / Braze / Codecov / Consul / Linode UUID & hex keys).
            // generic-no-prefix-not-promising matches were already dropped
            // upstream in `process_match`, so the only hits reaching here with
            // `!looks_promising` are named detectors or known-prefix generics.
            if !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
                // A named detector bypasses the 0.1 slam ONLY for genuinely
                // structured secrets (UUID / hex / random tokens). A weak-prefix
                // detector (e.g. stackblitz `sb_[A-Za-z0-9_-]{20,}`) can still
                // match a CODE IDENTIFIER like `sb_get_string_descriptor` or
                // `SB_ENDPOINT_ADDRESS_MASK` - those are never secrets, so they
                // stay slammed even for named detectors. A UUID/hex credential
                // is never identifier-shaped (digit-only segments, no `_`/`-`
                // word structure), so the recall win for the 90+ real
                // structured-key detectors is preserved.
                let identifier_shaped =
                    crate::pipeline::looks_like_word_separated_identifier(credential)
                        || crate::pipeline::looks_like_pure_identifier(credential);
                if !is_named_detector || identifier_shaped {
                    return Some(MlScoreResult::Final(0.1));
                }
            }

            let text_context = local_context_window(data, line, ML_CONTEXT_RADIUS_LINES);
            let ml_context = match chunk.metadata.path.as_deref() {
                Some(path) => format!("file:{path}\n{text_context}"),
                // `local_context_window` returns `&str`; the Some arm is an
                // owned `String`, and `ml_context` feeds `Cow::Owned` below,
                // so both arms must be `String`.
                None => text_context.to_string(),
            };

            Some(MlScoreResult::Pending {
                heuristic_conf,
                code_context: context,
                credential: std::borrow::Cow::Borrowed(credential),
                ml_context: std::borrow::Cow::Owned(ml_context),
            })
        }
    }
}
