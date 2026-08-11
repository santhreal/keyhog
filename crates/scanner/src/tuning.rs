//! Per-instance scanner performance tuning ([`ScannerTuning`]), extracted from
//! `phase2.rs`. Each toggle has a compiled shipped DEFAULT plus a PER-SCANNER
//! override (`BoolOverride` stored in an `AtomicU8`; `AtomicUsize` with
//! `usize::MAX` = compiled default). A differential parity test drives one input
//! down both code paths by flipping the override on its own scanner (through
//! `keyhog_scanner::testing::set_*` helpers), so two scanners, or two tests
//! running in parallel (never see each other's overrides).
//! `.keyhog.toml` `[tuning]` applies explicit production overrides through the
//! same per-scanner state, so tuning is part of resolved config and autoroute
//! identity instead of ambient process environment. Recall is identical either
//! way for every toggle (each selects a performance route or a measurement path,
//! not a detection set), see the per-method docs. The toggles span the phase-2
//! prefilter, the decode-recursion focus, and the confirmed-pass suffix gate, so
//! this carries every recall-identical per-scan route lever in one place.
//! Re-exported through `engine::phase2` (`pub use crate::tuning::*`).
use crate::scanner_config::{ResolvedScannerTuningConfig, ScannerTuningConfig};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::Relaxed};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum BoolOverride {
    Default = 0,
    ForceOn = 1,
    ForceOff = 2,
}

impl BoolOverride {
    const fn as_byte(self) -> u8 {
        self as u8
    }

    fn from_option(mode: Option<bool>) -> Self {
        match mode {
            None => Self::Default,
            Some(true) => Self::ForceOn,
            Some(false) => Self::ForceOff,
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            x if x == Self::ForceOn.as_byte() => Self::ForceOn,
            x if x == Self::ForceOff.as_byte() => Self::ForceOff,
            _ => Self::Default,
        }
    }

    fn resolve(self, default: bool) -> bool {
        match self {
            Self::Default => default,
            Self::ForceOn => true,
            Self::ForceOff => false,
        }
    }

    fn as_option(self) -> Option<bool> {
        match self {
            Self::Default => None,
            Self::ForceOn => Some(true),
            Self::ForceOff => Some(false),
        }
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
    /// Compile-time Hyperscan shard target retained for canonical snapshots
    /// (0 = compiled default).
    hs_shard_target: AtomicUsize,
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
    /// Override for the confirmed-pass companion mid-literal gate.
    confirmed_companion_gate: AtomicU8,
    /// Override for the SWE-101 combined no-candidate prefilter gate (default ON;
    /// recall-identical, a no-hit is a sound proof nothing can fire). A
    /// differential parity test forces it OFF on one scanner to prove the gate
    /// changes no finding.
    no_candidate_gate: AtomicU8,
    /// Override for phase-2 plain-pattern localization.
    phase2_plain_localizer: AtomicU8,
    /// Override for the GPU region-presence full CPU recall floor.
    gpu_recall_floor: AtomicU8,
    /// Override for chunk lane threshold sweeping (0 = compiled default).
    chunk_lane_threshold: AtomicUsize,
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
            phase2_hs: AtomicU8::new(BoolOverride::Default.as_byte()),
            hs_max_len: AtomicUsize::new(usize::MAX),
            hs_shard_target: AtomicUsize::new(0),
            phase2_anchor: AtomicU8::new(BoolOverride::Default.as_byte()),
            homoglyph_gate: AtomicU8::new(BoolOverride::Default.as_byte()),
            homoglyph_ascii_skip: AtomicU8::new(BoolOverride::Default.as_byte()),
            phase2_reverse: AtomicU8::new(BoolOverride::Default.as_byte()),
            prefilter_truncate: AtomicU8::new(BoolOverride::Default.as_byte()),
            phase2_prefix_gate: AtomicU8::new(BoolOverride::Default.as_byte()),
            decode_focus: AtomicU8::new(BoolOverride::Default.as_byte()),
            confirmed_suffix_gate: AtomicU8::new(BoolOverride::Default.as_byte()),
            confirmed_companion_gate: AtomicU8::new(BoolOverride::Default.as_byte()),
            no_candidate_gate: AtomicU8::new(BoolOverride::Default.as_byte()),
            phase2_plain_localizer: AtomicU8::new(BoolOverride::Default.as_byte()),
            gpu_recall_floor: AtomicU8::new(BoolOverride::Default.as_byte()),
            chunk_lane_threshold: AtomicUsize::new(0),
        }
    }

    /// Apply explicit resolved config overrides to this scanner instance.
    pub(crate) fn apply_config(&self, config: &ScannerTuningConfig) -> Result<(), String> {
        config.validate()?;
        self.set_phase2_hs(config.phase2_hs);
        self.set_hs_prefilter_max_len(config.hs_prefilter_max_len);
        self.hs_shard_target
            .store(config.hs_shard_target.unwrap_or(0), Relaxed);
        self.set_phase2_anchor_mode(config.phase2_anchor);
        self.set_phase2_homoglyph_gate(config.homoglyph_gate);
        self.set_homoglyph_ascii_skip(config.homoglyph_ascii_skip);
        self.set_phase2_reverse(config.fallback_reverse);
        self.set_prefilter_truncate(config.prefilter_truncate);
        self.set_phase2_prefix_gate(config.fallback_prefix_gate);
        self.set_decode_focus(config.decode_focus);
        self.set_confirmed_suffix_gate(config.confirmed_suffix_gate);
        self.set_confirmed_companion_gate(config.confirmed_companion_gate);
        self.set_no_candidate_gate(config.no_candidate_gate);
        self.set_phase2_plain_localizer(config.fallback_localizer);
        self.set_gpu_recall_floor(config.gpu_recall_floor);
        self.set_chunk_lane_threshold(config.chunk_lane_threshold);
        Ok(())
    }

    /// Resolve every per-scanner tuning override once into a plain copyable
    /// record. Scan hot paths pass this snapshot instead of loading atomics and
    /// re-matching compiled defaults inside each phase-2 prefilter/admission
    /// call. Test hooks still mutate `ScannerTuning` before invoking a scan; the
    /// scan observes those mutations when it takes this snapshot.
    pub(crate) fn resolve(&self) -> ResolvedScannerTuningConfig {
        let optional_usize =
            |value: usize, default_sentinel: usize| (value != default_sentinel).then_some(value);
        ScannerTuningConfig {
            phase2_hs: BoolOverride::from_raw(self.phase2_hs.load(Relaxed)).as_option(),
            hs_prefilter_max_len: optional_usize(self.hs_max_len.load(Relaxed), usize::MAX),
            hs_shard_target: optional_usize(self.hs_shard_target.load(Relaxed), 0),
            phase2_anchor: BoolOverride::from_raw(self.phase2_anchor.load(Relaxed)).as_option(),
            homoglyph_gate: BoolOverride::from_raw(self.homoglyph_gate.load(Relaxed)).as_option(),
            homoglyph_ascii_skip: BoolOverride::from_raw(self.homoglyph_ascii_skip.load(Relaxed))
                .as_option(),
            fallback_reverse: BoolOverride::from_raw(self.phase2_reverse.load(Relaxed)).as_option(),
            prefilter_truncate: BoolOverride::from_raw(self.prefilter_truncate.load(Relaxed))
                .as_option(),
            fallback_prefix_gate: BoolOverride::from_raw(self.phase2_prefix_gate.load(Relaxed))
                .as_option(),
            decode_focus: BoolOverride::from_raw(self.decode_focus.load(Relaxed)).as_option(),
            confirmed_suffix_gate: BoolOverride::from_raw(self.confirmed_suffix_gate.load(Relaxed))
                .as_option(),
            confirmed_companion_gate: BoolOverride::from_raw(
                self.confirmed_companion_gate.load(Relaxed),
            )
            .as_option(),
            no_candidate_gate: BoolOverride::from_raw(self.no_candidate_gate.load(Relaxed))
                .as_option(),
            fallback_localizer: BoolOverride::from_raw(self.phase2_plain_localizer.load(Relaxed))
                .as_option(),
            gpu_recall_floor: BoolOverride::from_raw(self.gpu_recall_floor.load(Relaxed))
                .as_option(),
            chunk_lane_threshold: optional_usize(self.chunk_lane_threshold.load(Relaxed), 0),
        }
        .effective()
    }

    // ── Hyperscan always-active prefilter engine ───────────────────────────

    /// Select the always-active prefilter engine (test/diagnostic). Recall is
    /// identical; this only trades the SIMD fast path for the RegexSet reference.
    /// `Some(true)` forces HS, `Some(false)` forces `regex::RegexSet`, `None` =
    /// compiled default (on when an HS engine compiled).
    pub(crate) fn set_phase2_hs(&self, mode: Option<bool>) {
        self.phase2_hs
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
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

    // ── Chunk lane threshold ──────────────────────────────────────────────

    /// Get the current configured chunk lane threshold for small file scanning.
    pub(crate) fn chunk_lane_threshold(&self) -> usize {
        match self.chunk_lane_threshold.load(Relaxed) {
            0 => crate::engine::batch_topology::SMALL_CHUNK_MAX_BYTES,
            val => val,
        }
    }

    /// Force the validated chunk lane threshold for small-file scheduling.
    pub(crate) fn set_chunk_lane_threshold(&self, threshold: Option<usize>) {
        self.chunk_lane_threshold
            .store(threshold.unwrap_or(0), Relaxed);
    }

    // ── Shared-anchor phase-2 localization ────────────────────────────────

    /// Override shared-anchor phase-2 localization (test/diagnostic).
    /// `Some(true)` forces it on, `Some(false)` the legacy whole-chunk path,
    /// `None` the compiled default. Recall-identical (pure performance route).
    pub(crate) fn set_phase2_anchor_mode(&self, mode: Option<bool>) {
        self.phase2_anchor
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether shared-anchor phase-2 localization is enabled. On by default.
    pub(crate) fn phase2_anchor_enabled(&self) -> bool {
        BoolOverride::from_raw(self.phase2_anchor.load(Relaxed))
            .resolve(ScannerTuningConfig::FALLBACK_ANCHOR_DEFAULT)
    }

    // ── Homoglyph ASCII gate ───────────────────────────────────────────────

    /// Override the homoglyph ASCII-gate (test/diagnostic). `Some(true)` forces
    /// it on (skip homoglyph variants on pure-ASCII chunks), `Some(false)` forces
    /// every homoglyph variant to run, `None` restores the default (on).
    pub(crate) fn set_phase2_homoglyph_gate(&self, mode: Option<bool>) {
        self.homoglyph_gate
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether the homoglyph ASCII-gate is enabled (default on).
    pub(crate) fn homoglyph_gate_enabled(&self) -> bool {
        BoolOverride::from_raw(self.homoglyph_gate.load(Relaxed))
            .resolve(ScannerTuningConfig::HOMOGLYPH_GATE_DEFAULT)
    }

    // ── Homoglyph inert-variant skip ───────────────────────────────────────

    /// Override the homoglyph ASCII-skip (test/diagnostic). `Some(true)` forces
    /// it on, `Some(false)` off, `None` = compiled default. The differential gate
    /// `homoglyph_ascii_skip_parity` flips this on a single scanner to prove that
    /// skipping every homoglyph variant on a pure-ASCII chunk drops no finding.
    pub(crate) fn set_homoglyph_ascii_skip(&self, mode: Option<bool>) {
        self.homoglyph_ascii_skip
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    pub(crate) fn homoglyph_ascii_skip_enabled(&self) -> bool {
        BoolOverride::from_raw(self.homoglyph_ascii_skip.load(Relaxed))
            .resolve(ScannerTuningConfig::HOMOGLYPH_ASCII_SKIP_DEFAULT)
    }

    // ── Diagnostic extraction-order reversal ───────────────────────────────

    /// Diagnostic: override the phase-2 extraction-order reversal (test hook).
    pub(crate) fn set_phase2_reverse(&self, mode: Option<bool>) {
        self.phase2_reverse
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Diagnostic: reverse the phase-2 active-pattern extraction order, to prove
    /// the final finding set is INDEPENDENT of phase-2 extraction order.
    pub(crate) fn phase2_reverse_enabled(&self) -> bool {
        BoolOverride::from_raw(self.phase2_reverse.load(Relaxed))
            .resolve(ScannerTuningConfig::FALLBACK_REVERSE_DEFAULT)
    }

    // ── Prefilter {N,}→{N} truncation ──────────────────────────────────────

    /// Override the prefilter `{N,}`→`{N}` truncation (the lazy-DFA lever).
    /// `Some(true)` forces it on, `Some(false)` off, `None` = compiled default.
    /// Recall-identical (the truncated set is a sound SUPERSET marking gate;
    /// extraction with the full pattern filters), proven by
    /// `prefilter_truncate_parity`.
    pub(crate) fn set_prefilter_truncate(&self, mode: Option<bool>) {
        self.prefilter_truncate
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    // ── Prefix-literal skip gate ───────────────────────────────────────────

    /// Override the phase-2 prefix-literal skip gate (test/diagnostic).
    /// Recall-identical, the gate only skips batches whose patterns ALL provably
    /// require a prefix literal absent from the chunk.
    pub(crate) fn set_phase2_prefix_gate(&self, mode: Option<bool>) {
        self.phase2_prefix_gate
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    // ── Decode-recursion focus restriction ─────────────────────────────────

    /// Override the decode-recursion FOCUS restriction (the real lever).
    /// `Some(true)` forces it on, `Some(false)` off, `None` = compiled default (on).
    /// Recall-validated by `decode_focus_parity`.
    pub(crate) fn set_decode_focus(&self, mode: Option<bool>) {
        self.decode_focus
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether the decode-recursion focus restriction is enabled (default on):
    /// the phase-2 pass on a decode sub-chunk scans only a window around the
    /// freshly decoded text instead of the whole spliced parent context.
    pub(crate) fn decode_focus_enabled(&self) -> bool {
        BoolOverride::from_raw(self.decode_focus.load(Relaxed))
            .resolve(ScannerTuningConfig::DECODE_FOCUS_DEFAULT)
    }

    // ── Confirmed-pass suffix gate ─────────────────────────────────────────

    /// Override the confirmed-pass suffix gate (test/diagnostic). `Some(true)`
    /// forces it on, `Some(false)` off, `None` = compiled default (on). Recall is
    /// identical either way, the gate only skips patterns whose required suffix
    /// literal is absent (so they cannot match), so it is safe to flip.
    pub(crate) fn set_confirmed_suffix_gate(&self, mode: Option<bool>) {
        self.confirmed_suffix_gate
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether the confirmed-pass suffix gate is enabled (default on): one AC
    /// pass marks which required-suffix literals are present, so a triggered
    /// pattern whose suffix literals are ALL absent skips its whole-chunk regex.
    pub(crate) fn confirmed_suffix_gate_enabled(&self) -> bool {
        BoolOverride::from_raw(self.confirmed_suffix_gate.load(Relaxed))
            .resolve(ScannerTuningConfig::CONFIRMED_SUFFIX_GATE_DEFAULT)
    }

    /// Override the confirmed-pass companion gate (test/diagnostic). `Some(true)`
    /// forces it on, `Some(false)` off, `None` = compiled default (on). Recall is
    /// identical either way: the gate only skips patterns whose required mid-literals
    /// are absent, so they cannot match.
    pub(crate) fn set_confirmed_companion_gate(&self, mode: Option<bool>) {
        self.confirmed_companion_gate
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether the confirmed-pass companion mid-literal gate is enabled (default on).
    pub(crate) fn confirmed_companion_gate_enabled(&self) -> bool {
        BoolOverride::from_raw(self.confirmed_companion_gate.load(Relaxed))
            .resolve(ScannerTuningConfig::CONFIRMED_COMPANION_GATE_DEFAULT)
    }

    // ── SWE-101 combined no-candidate prefilter gate ───────────────────────

    /// Override the SWE-101 combined no-candidate gate (test/diagnostic).
    /// `Some(true)` forces it on, `Some(false)` off (the prefilter runs its full
    /// per-pattern body on every chunk, the pre-fix behavior), `None` = compiled default
    /// (on). Recall-identical: the gate only skips a chunk it has positively proven
    /// cannot fire any always-active pattern. The differential parity test forces
    /// it OFF on one scanner to prove the gate changes no finding.
    pub(crate) fn set_no_candidate_gate(&self, mode: Option<bool>) {
        self.no_candidate_gate
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    // ── Phase-2 plain-pattern localizer ───────────────────────────────────

    /// Override phase-2 plain-pattern localization (test/diagnostic).
    pub(crate) fn set_phase2_plain_localizer(&self, mode: Option<bool>) {
        self.phase2_plain_localizer
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether the localized plain-pattern phase-2 path is enabled. Default
    /// OFF: the localizer's per-chunk AC overhead is a net end-to-end loss on
    /// decode-recursion-heavy inputs, while the plain-pattern RegexSet path is
    /// the better shipped default.
    pub(crate) fn phase2_plain_localizer_enabled(&self) -> bool {
        BoolOverride::from_raw(self.phase2_plain_localizer.load(Relaxed))
            .resolve(ScannerTuningConfig::FALLBACK_LOCALIZER_DEFAULT)
    }

    // ── GPU region-presence CPU recall floor ──────────────────────────────

    /// Override the full CPU trigger floor for GPU region-presence parity runs.
    /// Default OFF: the production GPU path pays for CPU triggers only when
    /// host-only detectors require them. Enabling this is explicit diagnostic
    /// coverage: it lets the shared CPU trigger net recover any GPU under-fire,
    /// and the region-presence path reports that recovery loudly.
    pub(crate) fn set_gpu_recall_floor(&self, mode: Option<bool>) {
        self.gpu_recall_floor
            .store(BoolOverride::from_option(mode).as_byte(), Relaxed);
    }

    /// Whether GPU region presence should compute the full CPU trigger floor
    /// even when host-only detectors are absent.
    #[cfg(feature = "gpu")]
    pub(crate) fn gpu_recall_floor_enabled(&self) -> bool {
        BoolOverride::from_raw(self.gpu_recall_floor.load(Relaxed))
            .resolve(ScannerTuningConfig::GPU_RECALL_FLOOR_DEFAULT)
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    /// WHY: runtime snapshots and configuration identity must resolve through
    /// one owner. Equality on the complete resolved struct makes every added
    /// tuning field fail this test until runtime ownership is explicit.
    #[test]
    fn runtime_snapshot_equals_canonical_effective_configuration() {
        let runtime = ScannerTuning::from_defaults();
        assert_eq!(
            runtime.resolve(),
            ScannerTuningConfig::default().effective()
        );

        let configured = ScannerTuningConfig {
            phase2_hs: Some(false),
            hs_prefilter_max_len: Some(8192),
            hs_shard_target: Some(777),
            phase2_anchor: Some(false),
            homoglyph_gate: Some(false),
            homoglyph_ascii_skip: Some(false),
            fallback_reverse: Some(true),
            prefilter_truncate: Some(false),
            fallback_prefix_gate: Some(true),
            decode_focus: Some(false),
            confirmed_suffix_gate: Some(false),
            confirmed_companion_gate: Some(false),
            no_candidate_gate: Some(false),
            fallback_localizer: Some(false),
            gpu_recall_floor: Some(true),
            chunk_lane_threshold: Some(2048),
        };
        runtime.apply_config(&configured).expect("valid tuning");
        assert_eq!(runtime.resolve(), configured.effective());
    }
}
