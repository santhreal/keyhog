//! Per-instance scanner performance tuning ([`ScannerTuning`]), extracted from
//! `fallback.rs`. Each toggle is a process-global env-var DEFAULT plus a
//! PER-SCANNER override (`AtomicU8`: 0 = follow env, 1 = force on, 2 = force off,
//! or `AtomicUsize` with `usize::MAX` = follow env). A differential parity test
//! drives one input down both code paths by flipping the override ON ITS OWN
//! scanner (`scanner.tuning().set_*`), so two scanners — or two tests running in
//! parallel — never see each other's overrides. The env read is a module-level
//! `OnceLock` because the environment genuinely IS process-global; only the
//! override is per-instance, which is the parallelism/test-leak hazard the old
//! process-global statics carried. Recall is identical either way for every
//! toggle (each selects a performance route or a measurement path, not a
//! detection set) — see the per-method docs. The toggles span the fallback
//! prefilter, the decode-recursion focus, and the confirmed-pass suffix gate, so
//! this carries every recall-identical per-scan route lever in one place.
//! Re-exported through `fallback` (`pub use super::tuning::*`).
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::Relaxed};
use std::sync::OnceLock;

/// Encode an `Option<bool>` override into the `AtomicU8` convention
/// (`None` = follow env, `Some(true)` = force on, `Some(false)` = force off).
#[inline]
fn encode_override(mode: Option<bool>) -> u8 {
    match mode {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    }
}

/// Per-scanner performance tuning. Carried on [`CompiledScanner`] and passed to
/// the always-active prefilter's `mark_matches`/`any_active_match`; the
/// scanner's own scan methods read it through `self.tuning`. Construct with
/// [`ScannerTuning::from_env`] (every override starts at "follow env"); the
/// `set_*` methods exist for differential parity tests to force a route on a
/// single scanner without touching any global state.
#[derive(Debug)]
pub struct ScannerTuning {
    /// Override for the Hyperscan always-active prefilter engine.
    fallback_hs: AtomicU8,
    /// Override for the HS-prefilter size gate (`usize::MAX` = follow env).
    hs_max_len: AtomicUsize,
    /// Override for shared-anchor fallback localization.
    fallback_anchor: AtomicU8,
    /// Override for the homoglyph ASCII gate.
    homoglyph_gate: AtomicU8,
    /// Override for the homoglyph ASCII-skip (measurement only, default off).
    homoglyph_ascii_skip: AtomicU8,
    /// Override for the diagnostic fallback extraction-order reversal.
    fallback_reverse: AtomicU8,
    /// Override for the prefilter `{N,}`→`{N}` truncation.
    prefilter_truncate: AtomicU8,
    /// Override for the fallback prefix-literal skip gate.
    fallback_prefix_gate: AtomicU8,
    /// Override for the decode-recursion focus restriction.
    decode_focus: AtomicU8,
    /// Override for the confirmed-pass suffix gate.
    confirmed_suffix_gate: AtomicU8,
}

impl Default for ScannerTuning {
    fn default() -> Self {
        Self::from_env()
    }
}

impl ScannerTuning {
    /// A tuning with every override at "follow env" — the production state.
    /// The env DEFAULT for each toggle is resolved (and cached) lazily on first
    /// read, so constructing one is allocation-free and never touches the env.
    pub(crate) const fn from_env() -> Self {
        Self {
            fallback_hs: AtomicU8::new(0),
            hs_max_len: AtomicUsize::new(usize::MAX),
            fallback_anchor: AtomicU8::new(0),
            homoglyph_gate: AtomicU8::new(0),
            homoglyph_ascii_skip: AtomicU8::new(0),
            fallback_reverse: AtomicU8::new(0),
            prefilter_truncate: AtomicU8::new(0),
            fallback_prefix_gate: AtomicU8::new(0),
            decode_focus: AtomicU8::new(0),
            confirmed_suffix_gate: AtomicU8::new(0),
        }
    }

    // ── Hyperscan always-active prefilter engine ───────────────────────────

    /// Select the always-active prefilter engine (test/diagnostic). Recall is
    /// identical; this only trades the SIMD fast path for the RegexSet reference.
    /// `Some(true)` forces HS, `Some(false)` forces `regex::RegexSet`, `None` =
    /// env default (on when an HS engine compiled).
    pub fn set_fallback_hs(&self, mode: Option<bool>) {
        self.fallback_hs.store(encode_override(mode), Relaxed);
    }

    /// Whether the HS always-active prefilter is enabled. Default ON: the HS
    /// engine is ~1000x the `regex::RegexSet` throughput on the always-active set
    /// and is the measured #1 scan cost. `KEYHOG_FALLBACK_HS=0` forces the legacy
    /// reference path.
    #[cfg(feature = "simd")]
    pub(crate) fn fallback_hs_enabled(&self) -> bool {
        match self.fallback_hs.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_fallback_hs(),
        }
    }

    /// Force the HS-prefilter size gate (test/diagnostic). `Some(4096)` pins the
    /// historical gate so a chunk >4 KiB takes the RegexSet reference path;
    /// `Some(usize::MAX)` / `None` restores the lifted default (HS at every size).
    /// Recall is identical either way (`fallback_prefilter_hs_large_parity`); this
    /// only selects the SIMD-fast HS path vs the RegexSet reference.
    pub fn set_hs_prefilter_max_len(&self, threshold: Option<usize>) {
        self.hs_max_len.store(threshold.unwrap_or(usize::MAX), Relaxed);
    }

    /// Max chunk length (bytes) for which the HS prefilter is used; larger chunks
    /// fall through to the `regex::RegexSet` batches. The lifted default is
    /// `usize::MAX` (HS at every size — byte-identical to the RegexSet path once
    /// match/dedup ordering became total). `KEYHOG_FALLBACK_HS_MAX_LEN` is a
    /// rollback / A-B escape hatch.
    #[cfg(feature = "simd")]
    pub(crate) fn hs_prefilter_max_len(&self) -> usize {
        let override_val = self.hs_max_len.load(Relaxed);
        if override_val != usize::MAX {
            return override_val;
        }
        env_hs_prefilter_max_len()
    }

    // ── Shared-anchor fallback localization ────────────────────────────────

    /// Override shared-anchor fallback localization (test/diagnostic).
    /// `Some(true)` forces it on, `Some(false)` the legacy whole-chunk path,
    /// `None` the env-driven default. Recall-identical — pure performance route.
    pub fn set_fallback_anchor_mode(&self, mode: Option<bool>) {
        self.fallback_anchor.store(encode_override(mode), Relaxed);
    }

    /// Whether shared-anchor fallback localization is enabled. On by default;
    /// `KEYHOG_FALLBACK_ANCHOR=0` forces the legacy whole-chunk path.
    pub(crate) fn fallback_anchor_enabled(&self) -> bool {
        match self.fallback_anchor.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_fallback_anchor(),
        }
    }

    // ── Homoglyph ASCII gate ───────────────────────────────────────────────

    /// Override the homoglyph ASCII-gate (test/diagnostic). `Some(true)` forces
    /// it on (skip homoglyph variants on pure-ASCII chunks), `Some(false)` forces
    /// every homoglyph variant to run, `None` restores the default (on).
    pub fn set_fallback_homoglyph_gate(&self, mode: Option<bool>) {
        self.homoglyph_gate.store(encode_override(mode), Relaxed);
    }

    /// Whether the homoglyph ASCII-gate is enabled (default on). Set
    /// `KEYHOG_HOMOGLYPH_GATE=0` to run every homoglyph variant on every chunk.
    pub(crate) fn homoglyph_gate_enabled(&self) -> bool {
        match self.homoglyph_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_homoglyph_gate(),
        }
    }

    // ── Homoglyph ASCII-skip (measurement only) ────────────────────────────

    /// Override the homoglyph ASCII-skip (test/diagnostic). `Some(true)` forces
    /// it on, `Some(false)` off, `None` = env default. The differential gate
    /// `homoglyph_ascii_skip_parity` flips this on a single scanner to prove that
    /// skipping every homoglyph variant on a pure-ASCII chunk drops no finding.
    pub fn set_homoglyph_ascii_skip(&self, mode: Option<bool>) {
        self.homoglyph_ascii_skip
            .store(encode_override(mode), Relaxed);
    }

    /// Whether to SKIP the always-active homoglyph fallback variants on a
    /// pure-ASCII chunk. **MEASURED NEGATIVE — default OFF** (skipping drops real
    /// findings, e.g. `generic-password`, via an overlap-suppression cascade; the
    /// always-active variant is load-bearing on ASCII, not redundant). Gated
    /// behind `KEYHOG_HOMOGLYPH_ASCII_SKIP=1` (measurement only) until the
    /// base-AC coverage gap is closed.
    pub(crate) fn homoglyph_ascii_skip_enabled(&self) -> bool {
        match self.homoglyph_ascii_skip.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_homoglyph_ascii_skip(),
        }
    }

    // ── Diagnostic extraction-order reversal ───────────────────────────────

    /// Diagnostic: override the fallback extraction-order reversal (test hook).
    pub fn set_fallback_reverse(&self, mode: Option<bool>) {
        self.fallback_reverse.store(encode_override(mode), Relaxed);
    }

    /// Diagnostic: reverse the fallback active-pattern extraction order, to prove
    /// the final finding set is INDEPENDENT of fallback extraction order.
    pub(crate) fn fallback_reverse_enabled(&self) -> bool {
        match self.fallback_reverse.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_fallback_reverse(),
        }
    }

    // ── Prefilter {N,}→{N} truncation ──────────────────────────────────────

    /// Override the prefilter `{N,}`→`{N}` truncation (the lazy-DFA lever).
    /// `Some(true)` forces it on, `Some(false)` off, `None` = env default.
    /// Recall-identical (the truncated set is a sound SUPERSET marking gate;
    /// extraction with the full pattern filters) — proven by
    /// `prefilter_truncate_parity`.
    pub fn set_prefilter_truncate(&self, mode: Option<bool>) {
        self.prefilter_truncate.store(encode_override(mode), Relaxed);
    }

    /// Whether the prefilter `{N,}`→`{N}` truncation is enabled (default ON:
    /// −16.8% end-to-end on the mirror corpus, recall-identical).
    pub(crate) fn prefilter_truncate_enabled(&self) -> bool {
        match self.prefilter_truncate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_prefilter_truncate(),
        }
    }

    // ── Prefix-literal skip gate ───────────────────────────────────────────

    /// Override the fallback prefix-literal skip gate (test/diagnostic).
    /// Recall-identical — the gate only skips batches whose patterns ALL provably
    /// require a prefix literal absent from the chunk.
    pub fn set_fallback_prefix_gate(&self, mode: Option<bool>) {
        self.fallback_prefix_gate
            .store(encode_override(mode), Relaxed);
    }

    /// Whether the fallback prefix-literal skip gate is enabled (default OFF: the
    /// folded-prefix literal union is too broad to pay off on the mirror corpus;
    /// kept as a sound, parity-validated lever for literal-sparse corpora).
    pub(crate) fn fallback_prefix_gate_enabled(&self) -> bool {
        match self.fallback_prefix_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_fallback_prefix_gate(),
        }
    }

    // ── Decode-recursion focus restriction ─────────────────────────────────

    /// Override the decode-recursion FOCUS restriction (the real lever).
    /// `Some(true)` forces it on, `Some(false)` off, `None` = env default (on).
    /// Recall-validated by `decode_focus_parity`.
    pub fn set_decode_focus(&self, mode: Option<bool>) {
        self.decode_focus.store(encode_override(mode), Relaxed);
    }

    /// Whether the decode-recursion focus restriction is enabled (default on):
    /// the fallback pass on a decode sub-chunk scans only a window around the
    /// freshly decoded text instead of the whole spliced parent context.
    pub(crate) fn decode_focus_enabled(&self) -> bool {
        match self.decode_focus.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_decode_focus(),
        }
    }

    // ── Confirmed-pass suffix gate ─────────────────────────────────────────

    /// Override the confirmed-pass suffix gate (test/diagnostic). `Some(true)`
    /// forces it on, `Some(false)` off, `None` = env default (on). Recall is
    /// identical either way — the gate only skips patterns whose required suffix
    /// literal is absent (so they cannot match), so it is safe to flip.
    pub fn set_confirmed_suffix_gate(&self, mode: Option<bool>) {
        self.confirmed_suffix_gate
            .store(encode_override(mode), Relaxed);
    }

    /// Whether the confirmed-pass suffix gate is enabled (default on): one AC
    /// pass marks which required-suffix literals are present, so a triggered
    /// pattern whose suffix literals are ALL absent skips its whole-chunk regex.
    /// `KEYHOG_CONFIRMED_GATE=0` forces every triggered pattern to run.
    pub(crate) fn confirmed_suffix_gate_enabled(&self) -> bool {
        match self.confirmed_suffix_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => env_confirmed_suffix_gate(),
        }
    }
}

// ── Process-global environment defaults (the environment is process-global, so
//    these are cached once; only the per-scanner OVERRIDE above is instance
//    state). Each mirrors the historical `KEYHOG_*` variable exactly. ─────────

#[cfg(feature = "simd")]
fn env_fallback_hs() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_HS").as_deref() != Ok("0"))
}

#[cfg(feature = "simd")]
fn env_hs_prefilter_max_len() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("KEYHOG_FALLBACK_HS_MAX_LEN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(usize::MAX)
    })
}

fn env_fallback_anchor() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_ANCHOR").as_deref() != Ok("0"))
}

fn env_homoglyph_gate() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_HOMOGLYPH_GATE").as_deref() != Ok("0"))
}

fn env_homoglyph_ascii_skip() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_HOMOGLYPH_ASCII_SKIP").as_deref() == Ok("1"))
}

fn env_fallback_reverse() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_REVERSE").as_deref() == Ok("1"))
}

fn env_prefilter_truncate() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PREFILTER_TRUNCATE").as_deref() != Ok("0"))
}

fn env_fallback_prefix_gate() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_FALLBACK_PREFIX_GATE").as_deref() == Ok("1"))
}

fn env_decode_focus() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_DECODE_FOCUS").as_deref() != Ok("0"))
}

fn env_confirmed_suffix_gate() -> bool {
    static EN: OnceLock<bool> = OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_CONFIRMED_GATE").as_deref() != Ok("0"))
}
