//! Per-instance scanner performance tuning ([`ScannerTuning`]), extracted from
//! `phase2.rs`. Each toggle has a compiled shipped DEFAULT plus a PER-SCANNER
//! override (`AtomicU8`: 0 = compiled default, 1 = force on, 2 = force off;
//! `AtomicUsize` with `usize::MAX` = compiled default; timeout `AtomicU64` with
//! 0 = compiled default). A differential parity test drives one input down both
//! code paths by flipping the override ON ITS OWN scanner (through
//! `keyhog_scanner::testing::set_*` helpers), so two scanners — or two tests
//! running in parallel — never see each other's overrides.
//! `.keyhog.toml` `[tuning]` applies explicit production overrides through the
//! same per-scanner state, so tuning is part of resolved config and autoroute
//! identity instead of ambient process environment. Recall is identical either
//! way for every toggle (each selects a performance route or a measurement path,
//! not a detection set) — see the per-method docs. The toggles span the phase-2
//! prefilter, the decode-recursion focus, and the confirmed-pass suffix gate, so
//! this carries every recall-identical per-scan route lever in one place.
//! Re-exported through `engine::phase2` (`pub use crate::tuning::*`).
use crate::scanner_config::ScannerTuningConfig;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering::Relaxed};
#[cfg(feature = "ml")]
use std::time::Duration;

/// Encode an `Option<bool>` override into the `AtomicU8` convention
/// (`None` = compiled default, `Some(true)` = force on, `Some(false)` = force off).
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
/// [`ScannerTuning::from_defaults`] (every override starts at compiled default); the
/// `set_*` methods exist for differential parity tests to force a route on a
/// single scanner without touching any global state.
#[derive(Debug)]
pub(crate) struct ScannerTuning {
    /// Override for the Hyperscan always-active prefilter engine.
    phase2_hs: AtomicU8,
    /// Override for the HS-prefilter size gate (`usize::MAX` = compiled default).
    hs_max_len: AtomicUsize,
    /// Override for shared-anchor phase-2 localization.
    phase2_anchor: AtomicU8,
    /// Override for the homoglyph ASCII gate.
    homoglyph_gate: AtomicU8,
    /// Override for the homoglyph ASCII-skip (default ON; recall-safe since the
    /// overlapping-AC trigger fix closed the base-literal shadow gap).
    homoglyph_ascii_skip: AtomicU8,
    /// Override for the diagnostic phase-2 extraction-order reversal.
    phase2_reverse: AtomicU8,
    /// Override for the prefilter `{N,}`→`{N}` truncation.
    prefilter_truncate: AtomicU8,
    /// Override for the phase-2 prefix-literal skip gate.
    phase2_prefix_gate: AtomicU8,
    /// Override for the decode-recursion focus restriction.
    decode_focus: AtomicU8,
    /// Override for the confirmed-pass suffix gate.
    confirmed_suffix_gate: AtomicU8,
    /// Override for the SWE-101 combined no-candidate prefilter gate (default ON;
    /// recall-identical — a no-hit is a sound proof nothing can fire). A
    /// differential parity test forces it OFF on one scanner to prove the gate
    /// changes no finding.
    no_candidate_gate: AtomicU8,
    /// Override for phase-2 plain-pattern localization.
    phase2_localizer: AtomicU8,
    /// Override for the GPU megakernel full CPU recall floor.
    gpu_recall_floor: AtomicU8,
    /// Override for GPU MoE readback timeout (`0` = compiled default).
    gpu_moe_timeout_ms: AtomicU64,
}

impl Default for ScannerTuning {
    fn default() -> Self {
        Self::from_defaults()
    }
}

impl ScannerTuning {
    /// A tuning with every override at the compiled shipped default.
    pub(crate) const fn from_defaults() -> Self {
        Self {
            phase2_hs: AtomicU8::new(0),
            hs_max_len: AtomicUsize::new(usize::MAX),
            phase2_anchor: AtomicU8::new(0),
            homoglyph_gate: AtomicU8::new(0),
            homoglyph_ascii_skip: AtomicU8::new(0),
            phase2_reverse: AtomicU8::new(0),
            prefilter_truncate: AtomicU8::new(0),
            phase2_prefix_gate: AtomicU8::new(0),
            decode_focus: AtomicU8::new(0),
            confirmed_suffix_gate: AtomicU8::new(0),
            no_candidate_gate: AtomicU8::new(0),
            phase2_localizer: AtomicU8::new(0),
            gpu_recall_floor: AtomicU8::new(0),
            gpu_moe_timeout_ms: AtomicU64::new(0),
        }
    }

    /// Apply explicit resolved config overrides to this scanner instance.
    pub(crate) fn apply_config(&self, config: &ScannerTuningConfig) {
        self.set_phase2_hs(config.phase2_hs);
        self.set_hs_prefilter_max_len(config.hs_prefilter_max_len);
        self.set_phase2_anchor_mode(config.phase2_anchor);
        self.set_phase2_homoglyph_gate(config.homoglyph_gate);
        self.set_homoglyph_ascii_skip(config.homoglyph_ascii_skip);
        self.set_phase2_reverse(config.fallback_reverse);
        self.set_prefilter_truncate(config.prefilter_truncate);
        self.set_phase2_prefix_gate(config.fallback_prefix_gate);
        self.set_decode_focus(config.decode_focus);
        self.set_confirmed_suffix_gate(config.confirmed_suffix_gate);
        self.set_no_candidate_gate(config.no_candidate_gate);
        self.set_phase2_localizer(config.fallback_localizer);
        self.set_gpu_recall_floor(config.gpu_recall_floor);
        self.set_gpu_moe_timeout_ms(config.gpu_moe_timeout_ms);
    }

    // ── Hyperscan always-active prefilter engine ───────────────────────────

    /// Select the always-active prefilter engine (test/diagnostic). Recall is
    /// identical; this only trades the SIMD fast path for the RegexSet reference.
    /// `Some(true)` forces HS, `Some(false)` forces `regex::RegexSet`, `None` =
    /// compiled default (on when an HS engine compiled).
    pub(crate) fn set_phase2_hs(&self, mode: Option<bool>) {
        self.phase2_hs.store(encode_override(mode), Relaxed);
    }

    /// Whether the HS always-active prefilter is enabled. Default ON: the HS
    /// engine is ~1000x the `regex::RegexSet` throughput on the always-active set
    /// and is the measured #1 scan cost. Explicit config can force the legacy
    /// reference path.
    #[cfg(feature = "simd")]
    pub(crate) fn phase2_hs_enabled(&self) -> bool {
        match self.phase2_hs.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::FALLBACK_HS_DEFAULT,
        }
    }

    /// Force the HS-prefilter size gate (test/diagnostic). `Some(4096)` is the
    /// production default (chunks >4 KiB take the fast localized RegexSet path);
    /// `Some(usize::MAX - 1)` forces HS at every size (the slow full-superset path,
    /// for the A/B parity test). `None` / `Some(usize::MAX)` is the compiled-default
    /// sentinel. Recall is identical
    /// across gates (`fallback_prefilter_hs_large_parity`); this only selects the
    /// HS vs RegexSet route.
    pub(crate) fn set_hs_prefilter_max_len(&self, threshold: Option<usize>) {
        self.hs_max_len
            .store(threshold.unwrap_or(usize::MAX), Relaxed); // LAW10: None is the documented compiled-default sentinel, not an error fallback.
    }

    /// Max chunk length (bytes) for which the HS prefilter is used; larger chunks
    /// fall through to the localized `regex::RegexSet` batches. Default
    /// [`ScannerTuningConfig::HS_PREFILTER_MAX_LEN_DEFAULT`] (4096) — above it the RegexSet path is far
    /// faster because the HS prefilter scans the full always-active superset while
    /// the RegexSet path respects shared-anchor localization (recall-identical,
    /// `fallback_prefilter_hs_large_parity`). Set
    /// `[tuning].hs_prefilter_max_len` to `usize::MAX - 1` to force HS at every
    /// size for an A/B.
    #[cfg(feature = "simd")]
    pub(crate) fn hs_prefilter_max_len(&self) -> usize {
        let override_val = self.hs_max_len.load(Relaxed);
        if override_val != usize::MAX {
            return override_val;
        }
        ScannerTuningConfig::HS_PREFILTER_MAX_LEN_DEFAULT
    }

    // ── Shared-anchor phase-2 localization ────────────────────────────────

    /// Override shared-anchor phase-2 localization (test/diagnostic).
    /// `Some(true)` forces it on, `Some(false)` the legacy whole-chunk path,
    /// `None` the compiled default. Recall-identical — pure performance route.
    pub(crate) fn set_phase2_anchor_mode(&self, mode: Option<bool>) {
        self.phase2_anchor.store(encode_override(mode), Relaxed);
    }

    /// Whether shared-anchor phase-2 localization is enabled. On by default.
    pub(crate) fn phase2_anchor_enabled(&self) -> bool {
        match self.phase2_anchor.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::FALLBACK_ANCHOR_DEFAULT,
        }
    }

    // ── Homoglyph ASCII gate ───────────────────────────────────────────────

    /// Override the homoglyph ASCII-gate (test/diagnostic). `Some(true)` forces
    /// it on (skip homoglyph variants on pure-ASCII chunks), `Some(false)` forces
    /// every homoglyph variant to run, `None` restores the default (on).
    pub(crate) fn set_phase2_homoglyph_gate(&self, mode: Option<bool>) {
        self.homoglyph_gate.store(encode_override(mode), Relaxed);
    }

    /// Whether the homoglyph ASCII-gate is enabled (default on).
    pub(crate) fn homoglyph_gate_enabled(&self) -> bool {
        match self.homoglyph_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::HOMOGLYPH_GATE_DEFAULT,
        }
    }

    // ── Homoglyph ASCII-skip (measurement only) ────────────────────────────

    /// Override the homoglyph ASCII-skip (test/diagnostic). `Some(true)` forces
    /// it on, `Some(false)` off, `None` = compiled default. The differential gate
    /// `homoglyph_ascii_skip_parity` flips this on a single scanner to prove that
    /// skipping every homoglyph variant on a pure-ASCII chunk drops no finding.
    pub(crate) fn set_homoglyph_ascii_skip(&self, mode: Option<bool>) {
        self.homoglyph_ascii_skip
            .store(encode_override(mode), Relaxed);
    }

    /// Whether to SKIP the always-active homoglyph phase-2 variants on a
    /// pure-ASCII chunk. **Default ON** since the base-AC coverage gap was closed:
    /// `collect_triggered_patterns_cpu` now scans the trigger AC with OVERLAPPING
    /// matching, so a detector whose base literal is a substring of a longer
    /// matched literal (e.g. `secret` inside `client_secret`) is no longer
    /// shadowed — its match is reproduced by the AC/confirmed path, making the
    /// always-active homoglyph variant redundant on a chunk with no non-ASCII
    /// bytes. Proven recall-neutral by `homoglyph_ascii_skip_parity_default`
    /// (skip ≡ fold over the mirror corpus + 20k synthetic ASCII inputs). On the
    /// mirror corpus this also corrects an overlap-suppression cascade
    /// (`MAILGUN_API_KEY=key-…` was mislabelled Webhook-Signing-Key when the
    /// variant ran) and is ~13% faster (`phase2:prefilter` is 55% of scan).
    /// Explicit config can force the legacy fold-every-variant path.
    pub(crate) fn homoglyph_ascii_skip_enabled(&self) -> bool {
        match self.homoglyph_ascii_skip.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::HOMOGLYPH_ASCII_SKIP_DEFAULT,
        }
    }

    // ── Diagnostic extraction-order reversal ───────────────────────────────

    /// Diagnostic: override the phase-2 extraction-order reversal (test hook).
    pub(crate) fn set_phase2_reverse(&self, mode: Option<bool>) {
        self.phase2_reverse.store(encode_override(mode), Relaxed);
    }

    /// Diagnostic: reverse the phase-2 active-pattern extraction order, to prove
    /// the final finding set is INDEPENDENT of phase-2 extraction order.
    pub(crate) fn phase2_reverse_enabled(&self) -> bool {
        match self.phase2_reverse.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::FALLBACK_REVERSE_DEFAULT,
        }
    }

    // ── Prefilter {N,}→{N} truncation ──────────────────────────────────────

    /// Override the prefilter `{N,}`→`{N}` truncation (the lazy-DFA lever).
    /// `Some(true)` forces it on, `Some(false)` off, `None` = compiled default.
    /// Recall-identical (the truncated set is a sound SUPERSET marking gate;
    /// extraction with the full pattern filters) — proven by
    /// `prefilter_truncate_parity`.
    pub(crate) fn set_prefilter_truncate(&self, mode: Option<bool>) {
        self.prefilter_truncate
            .store(encode_override(mode), Relaxed);
    }

    /// Whether the prefilter `{N,}`→`{N}` truncation is enabled (default ON:
    /// −16.8% end-to-end on the mirror corpus, recall-identical).
    pub(crate) fn prefilter_truncate_enabled(&self) -> bool {
        match self.prefilter_truncate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::PREFILTER_TRUNCATE_DEFAULT,
        }
    }

    // ── Prefix-literal skip gate ───────────────────────────────────────────

    /// Override the phase-2 prefix-literal skip gate (test/diagnostic).
    /// Recall-identical — the gate only skips batches whose patterns ALL provably
    /// require a prefix literal absent from the chunk.
    pub(crate) fn set_phase2_prefix_gate(&self, mode: Option<bool>) {
        self.phase2_prefix_gate
            .store(encode_override(mode), Relaxed);
    }

    /// Whether the phase-2 prefix-literal skip gate is enabled (default OFF: the
    /// folded-prefix literal union is too broad to pay off on the mirror corpus;
    /// kept as a sound, parity-validated lever for literal-sparse corpora).
    pub(crate) fn phase2_prefix_gate_enabled(&self) -> bool {
        match self.phase2_prefix_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::FALLBACK_PREFIX_GATE_DEFAULT,
        }
    }

    // ── Decode-recursion focus restriction ─────────────────────────────────

    /// Override the decode-recursion FOCUS restriction (the real lever).
    /// `Some(true)` forces it on, `Some(false)` off, `None` = compiled default (on).
    /// Recall-validated by `decode_focus_parity`.
    pub(crate) fn set_decode_focus(&self, mode: Option<bool>) {
        self.decode_focus.store(encode_override(mode), Relaxed);
    }

    /// Whether the decode-recursion focus restriction is enabled (default on):
    /// the phase-2 pass on a decode sub-chunk scans only a window around the
    /// freshly decoded text instead of the whole spliced parent context.
    pub(crate) fn decode_focus_enabled(&self) -> bool {
        match self.decode_focus.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::DECODE_FOCUS_DEFAULT,
        }
    }

    // ── Confirmed-pass suffix gate ─────────────────────────────────────────

    /// Override the confirmed-pass suffix gate (test/diagnostic). `Some(true)`
    /// forces it on, `Some(false)` off, `None` = compiled default (on). Recall is
    /// identical either way — the gate only skips patterns whose required suffix
    /// literal is absent (so they cannot match), so it is safe to flip.
    pub(crate) fn set_confirmed_suffix_gate(&self, mode: Option<bool>) {
        self.confirmed_suffix_gate
            .store(encode_override(mode), Relaxed);
    }

    /// Whether the confirmed-pass suffix gate is enabled (default on): one AC
    /// pass marks which required-suffix literals are present, so a triggered
    /// pattern whose suffix literals are ALL absent skips its whole-chunk regex.
    pub(crate) fn confirmed_suffix_gate_enabled(&self) -> bool {
        match self.confirmed_suffix_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::CONFIRMED_SUFFIX_GATE_DEFAULT,
        }
    }

    // ── SWE-101 combined no-candidate prefilter gate ───────────────────────

    /// Override the SWE-101 combined no-candidate gate (test/diagnostic).
    /// `Some(true)` forces it on, `Some(false)` off (the prefilter runs its full
    /// per-pattern body on every chunk, the pre-fix behavior), `None` = compiled default
    /// (on). Recall-identical: the gate only skips a chunk it has positively proven
    /// cannot fire any always-active pattern. The differential parity test forces
    /// it OFF on one scanner to prove the gate changes no finding.
    pub(crate) fn set_no_candidate_gate(&self, mode: Option<bool>) {
        self.no_candidate_gate.store(encode_override(mode), Relaxed);
    }

    /// Whether the SWE-101 combined no-candidate prefilter gate is enabled
    /// (default ON): one `ascii_case_insensitive` Aho-Corasick over the union of
    /// every always-active pattern's required-prefix literal proves, at ~ns/chunk,
    /// that NO always-active pattern can fire on a pure-ASCII chunk — so the
    /// expensive per-pattern marking body is skipped. Explicit config can force
    /// the legacy run-the-body-on-every-chunk path (recall identical, far slower
    /// — the original SWE-101 cost).
    pub(crate) fn no_candidate_gate_enabled(&self) -> bool {
        match self.no_candidate_gate.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::NO_CANDIDATE_GATE_DEFAULT,
        }
    }

    // ── Phase-2 plain-pattern localizer ───────────────────────────────────

    /// Override phase-2 plain-pattern localization (test/diagnostic).
    pub(crate) fn set_phase2_localizer(&self, mode: Option<bool>) {
        self.phase2_localizer.store(encode_override(mode), Relaxed);
    }

    /// Whether the localized plain-pattern phase-2 path is enabled. Default
    /// OFF: the localizer's per-chunk AC overhead is a net end-to-end loss on
    /// decode-recursion-heavy inputs, while the plain-pattern RegexSet path is
    /// the better shipped default.
    pub(crate) fn phase2_localizer_enabled(&self) -> bool {
        match self.phase2_localizer.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::FALLBACK_LOCALIZER_DEFAULT,
        }
    }

    // ── GPU megakernel CPU recall floor ───────────────────────────────────

    /// Override the full CPU trigger floor for GPU megakernel parity runs.
    /// Default OFF: the production GPU path pays for CPU triggers only when
    /// host-only detectors require them. Enabling this is explicit diagnostic
    /// coverage: it lets the shared CPU trigger net recover any GPU under-fire,
    /// and the megakernel path reports that recovery loudly.
    pub(crate) fn set_gpu_recall_floor(&self, mode: Option<bool>) {
        self.gpu_recall_floor.store(encode_override(mode), Relaxed);
    }

    /// Whether the GPU megakernel should compute the full CPU trigger floor
    /// even when host-only detectors are absent.
    #[cfg(feature = "gpu")]
    pub(crate) fn gpu_recall_floor_enabled(&self) -> bool {
        match self.gpu_recall_floor.load(Relaxed) {
            1 => true,
            2 => false,
            _ => ScannerTuningConfig::GPU_RECALL_FLOOR_DEFAULT,
        }
    }

    // ── GPU MoE readback timeout ──────────────────────────────────────────

    /// Override the GPU MoE readback timeout. This is a bounded-latency tuning
    /// knob, not a detection toggle: timeout still surfaces loudly and the
    /// caller uses CPU MoE for the same candidates.
    pub(crate) fn set_gpu_moe_timeout_ms(&self, timeout_ms: Option<u64>) {
        let value = timeout_ms.unwrap_or(0); // LAW10: documented default sentinel; unset config means shipped scanner tuning, recall-safe.
        self.gpu_moe_timeout_ms.store(value, Relaxed);
    }

    #[cfg(feature = "ml")]
    pub(crate) fn gpu_moe_timeout(&self) -> Duration {
        let configured = self.gpu_moe_timeout_ms.load(Relaxed);
        let ms = if configured == 0 {
            ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT
        } else {
            configured
        };
        Duration::from_millis(ms)
    }
}
