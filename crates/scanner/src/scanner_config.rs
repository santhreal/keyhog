//! Scanner configuration and tuning types.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use keyhog_core::{Calibration, ScanConfig};

/// Explicit per-scanner performance-route tuning.
///
/// Each field is optional: `None` means the compiled shipped default, while
/// `Some(value)` is an explicit config override. These knobs choose
/// recall-equivalent routes inside the scanner (prefilter engine, anchor
/// localization, no-candidate gates, decode focus), so they must be part of the
/// resolved scan config and autoroute cache identity instead of ambient process
/// environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ScannerTuningConfig {
    pub phase2_hs: Option<bool>,
    pub hs_prefilter_max_len: Option<usize>,
    pub hs_shard_target: Option<usize>,
    pub phase2_anchor: Option<bool>,
    pub homoglyph_gate: Option<bool>,
    pub homoglyph_ascii_skip: Option<bool>,
    pub fallback_reverse: Option<bool>,
    pub prefilter_truncate: Option<bool>,
    pub fallback_prefix_gate: Option<bool>,
    pub decode_focus: Option<bool>,
    pub confirmed_suffix_gate: Option<bool>,
    pub no_candidate_gate: Option<bool>,
    pub fallback_localizer: Option<bool>,
    pub gpu_recall_floor: Option<bool>,
    pub gpu_moe_timeout_ms: Option<u64>,
}

impl ScannerTuningConfig {
    pub(crate) const FALLBACK_HS_DEFAULT: bool = true;
    /// Chunk-size ceiling above which the always-active prefilter falls back from
    /// the Hyperscan engine to the portable RegexSet batches. Held at 4096: HS is
    /// findings-identical to the RegexSet AND ~2× faster on large ASCII chunks (the
    /// `|| is_ascii` clause in `hs_prefilter_engages` runs HS there), but on
    /// large NON-ASCII chunks HS is NOT a win. Forcing HS on non-ASCII was tried
    /// (route the unicode-vs-byte divergent `.`/`\w`/`\s` patterns to a supplemental
    /// unicode host RegexSet so byte-mode HS stays recall-exact), recall held, but
    /// it cost **2.75× more CPU** than the RegexSet (51.9s vs 18.8s on a 2 MiB
    /// non-ASCII corpus): HS byte-mode ≈ the RegexSet's cost there, and the
    /// supplemental divergent set is dot-heavy and CANNOT be prefix-AC-gated the
    /// way the portable batches are, so it is pure overhead. DEAD END (Law 7), the
    /// recall-required work dominates non-ASCII either way, so the RegexSet (with
    /// its prefix gating) is strictly faster. Gate stays a Tier-A knob for opt-in.
    pub(crate) const HS_PREFILTER_MAX_LEN_DEFAULT: usize = 4096;
    pub(crate) const HS_SHARD_TARGET_DEFAULT: usize = 320;
    pub(crate) const FALLBACK_ANCHOR_DEFAULT: bool = true;
    pub(crate) const HOMOGLYPH_GATE_DEFAULT: bool = true;
    pub(crate) const HOMOGLYPH_ASCII_SKIP_DEFAULT: bool = true;
    pub(crate) const FALLBACK_REVERSE_DEFAULT: bool = false;
    pub(crate) const PREFILTER_TRUNCATE_DEFAULT: bool = true;
    pub(crate) const FALLBACK_PREFIX_GATE_DEFAULT: bool = false;
    pub(crate) const DECODE_FOCUS_DEFAULT: bool = true;
    pub(crate) const CONFIRMED_SUFFIX_GATE_DEFAULT: bool = true;
    pub(crate) const NO_CANDIDATE_GATE_DEFAULT: bool = true;
    pub(crate) const FALLBACK_LOCALIZER_DEFAULT: bool = false;
    pub(crate) const GPU_RECALL_FLOOR_DEFAULT: bool = false;
    pub(crate) const GPU_MOE_TIMEOUT_MS_DEFAULT: u64 = 30_000;

    pub fn effective(&self) -> ResolvedScannerTuningConfig {
        ResolvedScannerTuningConfig {
            fallback_hs: self.fallback_hs_effective(),
            hs_prefilter_max_len: self.hs_prefilter_max_len_effective(),
            hs_shard_target: self.hs_shard_target_effective(),
            fallback_anchor: self.fallback_anchor_effective(),
            homoglyph_gate: self.homoglyph_gate_effective(),
            homoglyph_ascii_skip: self.homoglyph_ascii_skip_effective(),
            fallback_reverse: self.fallback_reverse_effective(),
            prefilter_truncate: self.prefilter_truncate_effective(),
            fallback_prefix_gate: self.fallback_prefix_gate_effective(),
            decode_focus: self.decode_focus_effective(),
            confirmed_suffix_gate: self.confirmed_suffix_gate_effective(),
            no_candidate_gate: self.no_candidate_gate_effective(),
            fallback_localizer: self.fallback_localizer_effective(),
            gpu_recall_floor: self.gpu_recall_floor_effective(),
            gpu_moe_timeout_ms: self.gpu_moe_timeout_ms_effective(),
        }
    }

    pub(crate) fn fallback_hs_effective(&self) -> bool {
        self.phase2_hs.unwrap_or(Self::FALLBACK_HS_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn hs_prefilter_max_len_effective(&self) -> usize {
        self.hs_prefilter_max_len
            .unwrap_or(Self::HS_PREFILTER_MAX_LEN_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn hs_shard_target_effective(&self) -> usize {
        self.hs_shard_target
            .unwrap_or(Self::HS_SHARD_TARGET_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner compile tuning, recall-safe.
    }

    pub(crate) fn fallback_anchor_effective(&self) -> bool {
        self.phase2_anchor.unwrap_or(Self::FALLBACK_ANCHOR_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn homoglyph_gate_effective(&self) -> bool {
        self.homoglyph_gate.unwrap_or(Self::HOMOGLYPH_GATE_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn homoglyph_ascii_skip_effective(&self) -> bool {
        self.homoglyph_ascii_skip
            .unwrap_or(Self::HOMOGLYPH_ASCII_SKIP_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn fallback_reverse_effective(&self) -> bool {
        self.fallback_reverse
            .unwrap_or(Self::FALLBACK_REVERSE_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn prefilter_truncate_effective(&self) -> bool {
        self.prefilter_truncate
            .unwrap_or(Self::PREFILTER_TRUNCATE_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn fallback_prefix_gate_effective(&self) -> bool {
        self.fallback_prefix_gate
            .unwrap_or(Self::FALLBACK_PREFIX_GATE_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn decode_focus_effective(&self) -> bool {
        self.decode_focus.unwrap_or(Self::DECODE_FOCUS_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn confirmed_suffix_gate_effective(&self) -> bool {
        self.confirmed_suffix_gate
            .unwrap_or(Self::CONFIRMED_SUFFIX_GATE_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn no_candidate_gate_effective(&self) -> bool {
        self.no_candidate_gate
            .unwrap_or(Self::NO_CANDIDATE_GATE_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn fallback_localizer_effective(&self) -> bool {
        self.fallback_localizer
            .unwrap_or(Self::FALLBACK_LOCALIZER_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn gpu_recall_floor_effective(&self) -> bool {
        self.gpu_recall_floor
            .unwrap_or(Self::GPU_RECALL_FLOOR_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }

    pub(crate) fn gpu_moe_timeout_ms_effective(&self) -> u64 {
        self.gpu_moe_timeout_ms
            .unwrap_or(Self::GPU_MOE_TIMEOUT_MS_DEFAULT) // LAW10: documented default; unset/absent config means shipped scanner tuning, recall-safe.
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedScannerTuningConfig {
    pub fallback_hs: bool,
    pub hs_prefilter_max_len: usize,
    pub hs_shard_target: usize,
    pub fallback_anchor: bool,
    pub homoglyph_gate: bool,
    pub homoglyph_ascii_skip: bool,
    pub fallback_reverse: bool,
    pub prefilter_truncate: bool,
    pub fallback_prefix_gate: bool,
    pub decode_focus: bool,
    pub confirmed_suffix_gate: bool,
    pub no_candidate_gate: bool,
    pub fallback_localizer: bool,
    pub gpu_recall_floor: bool,
    pub gpu_moe_timeout_ms: u64,
}

/// Recall-equivalent execution choices resolved for one scan request.
///
/// This is separate from [`ScannerTuningConfig`]: tuning supplies the default,
/// while autoroute can select a measured route for an exact workload without
/// mutating scanner-global state or racing concurrent requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanExecutionRoute {
    /// Localize eligible folded plain patterns before residual extraction.
    pub phase2_plain_localizer: bool,
    /// Localize eligible keyword-anchored patterns before residual extraction.
    pub phase2_keyword_localizer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ResolvedRuntimeTuningConfig {
    pub fallback_hs: bool,
    pub hs_prefilter_max_len: usize,
    pub fallback_anchor: bool,
    pub homoglyph_gate: bool,
    pub homoglyph_ascii_skip: bool,
    pub fallback_reverse: bool,
    pub prefilter_truncate: bool,
    pub fallback_prefix_gate: bool,
    pub decode_focus: bool,
    pub confirmed_suffix_gate: bool,
    pub no_candidate_gate: bool,
    pub fallback_localizer: bool,
    pub gpu_recall_floor: bool,
    pub gpu_moe_timeout_ms: u64,
}

impl ResolvedRuntimeTuningConfig {
    #[cfg(feature = "ml")]
    pub(crate) fn gpu_moe_timeout(&self) -> Duration {
        Duration::from_millis(self.gpu_moe_timeout_ms)
    }
}

/// Scanner-side configuration: the canonical [`ScanConfig`], the single owned
/// source of truth for every shared detection knob (decode depth, entropy, ML,
/// confidence floor, keyword lists, …). PLUS the two knobs that are
/// scanner-crate-local and have no place on `keyhog-core`'s `ScanConfig`:
///
/// - `multiline`: its type ([`crate::multiline::MultilineConfig`]) is defined
///   in THIS crate, and `keyhog-core` cannot depend on `keyhog-scanner` without
///   a dependency cycle, so the field cannot live on `ScanConfig`.
/// - `penalize_test_paths`: a scanner-internal suppression toggle the CLI flips
///   for `--no-suppress-test-fixtures`; it never appears on the on-disk config.
///
/// This is the "thin newtype over `ScanConfig`" MC-01 calls for. It deliberately
/// does **not** restate any of `ScanConfig`'s fields: every shared knob is read
/// and written straight through [`Deref`]/[`DerefMut`] (`config.min_confidence`,
/// `config.entropy_enabled`, `config.known_prefixes`, …), so there is exactly
/// ONE definition of each, no parallel field list that can drift, and the
/// `From<ScanConfig>` impl below is a structural wrap, never a hand-maintained
/// field-by-field copy.
///
/// `ScanConfig`'s `max_file_size` / `dedup` fields are reachable through the
/// deref but are NOT consumed by the scan engine, they are enforced elsewhere
/// (the source walker and the verifier) and carry that caveat in their own doc
/// comments on `ScanConfig`. Their presence here is the wrapped truth, not a
/// second silent copy. `min_secret_len` is consumed by the entropy fallback.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// The canonical shared detection config, single source of truth for every
    /// knob the engine and CLI agree on. Reached transparently via `Deref`, so
    /// callers write `config.min_confidence`, not `config.scan.min_confidence`.
    pub scan: ScanConfig,
    /// Explicit Tier-A scan override for detector-local BPE policy. `None`
    /// means each detector TOML owns its ceiling and the wrapped ScanConfig
    /// value is only the compatibility fallback. `Some` means TOML/CLI scan
    /// configuration explicitly requested one ceiling for every eligible
    /// detector; CLI/config presence is preserved so precedence remains
    /// compiled default -> detector TOML -> scan TOML -> CLI.
    pub entropy_bpe_max_bytes_per_token_override: Option<f64>,
    /// Explicit Tier-A override for detector-local ML scoring weights. `None`
    /// keeps each detector TOML authoritative; presence applies one diagnostic
    /// or benchmarking override across eligible detector paths.
    pub ml_weight_override: Option<f64>,
    /// Configuration for multiline concatenation (scanner-local type).
    pub multiline: crate::multiline::MultilineConfig,
    /// Apply test/example path confidence and hard-suppression heuristics.
    /// The CLI disables this for `--no-suppress-test-fixtures`.
    pub penalize_test_paths: bool,
    /// Optional caller-resolved per-chunk scan deadline in milliseconds.
    pub per_chunk_timeout_ms: Option<u64>,
    /// Emit the scanner-owned hierarchical profile report to stderr.
    pub profile: bool,
    /// Emit low-level phase timing traces for GPU/perf investigation.
    pub perf_trace: bool,
    /// Explicit per-detector Bayesian calibration store. Absent means the scan
    /// is hermetic and score-stable; the scanner never reads a default disk
    /// cache on its own because that would make findings depend on stray host
    /// state.
    pub calibration: Option<Arc<Calibration>>,
}

impl Deref for ScannerConfig {
    type Target = ScanConfig;
    fn deref(&self) -> &ScanConfig {
        &self.scan
    }
}

impl DerefMut for ScannerConfig {
    fn deref_mut(&mut self) -> &mut ScanConfig {
        &mut self.scan
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        ScanConfig::default().into()
    }
}

impl ScannerConfig {
    /// Confidence floor for [`ScannerConfig::high_precision`]. Distinct from the
    /// canonical `ScanConfig::default()` floor (0.40) on purpose: precision mode
    /// trades recall for a near-zero false-positive rate at mass-scan scale.
    pub const HIGH_PRECISION_MIN_CONFIDENCE: f64 = 0.85;

    /// Deep mode admits one complete production scan chunk into decode-through.
    /// The default stays at 512 KiB to bound routine work; deep intentionally
    /// spends more memory and CPU to recover encoded values anywhere in a
    /// filesystem window.
    pub const DEEP_MAX_DECODE_BYTES: usize = crate::types::MAX_SCAN_CHUNK_BYTES;

    pub fn fast() -> Self {
        let mut config = Self::default();
        config.max_decode_depth = 0;
        config.ml_enabled = false;
        config.entropy_enabled = false;
        config
    }

    pub fn thorough() -> Self {
        // `min_confidence` intentionally omitted: it inherits the canonical
        // `ScanConfig::default()` floor (single source of truth) instead of
        // forking a second literal. Deep scanning widens decode/entropy, not
        // the confidence bar.
        let mut config = Self::default();
        config.max_decode_depth = 10;
        config.max_decode_bytes = Self::DEEP_MAX_DECODE_BYTES;
        config.ml_enabled = true;
        config.entropy_enabled = true;
        config.entropy_in_source_files = true;
        config.entropy_ml_authoritative = false;
        config.scan_comments = true;
        config
    }

    /// High-precision mass-scan preset: minimise false positives at the cost of
    /// some recall, for scanning huge corpora where every FP is expensive to
    /// triage. Fully offline, with ML confidence scoring, no entropy sweep, and
    /// shallow decode.
    ///
    /// - `entropy_enabled = false`: generic high-entropy matching is the single
    ///   largest FP source; precision mode drops it entirely.
    /// - `ml_enabled = true` (inherited): ML is the confidence discriminator that
    ///   lifts genuine secrets over the high floor while leaving FP-shaped tokens
    ///   below it. Disabling it would crater the scores the 0.85 bar relies on,
    ///   so precision KEEPS ML (this mode trades recall for precision, not for
    ///   speed (use `--fast` when speed is the goal)).
    /// - `min_confidence = HIGH_PRECISION_MIN_CONFIDENCE` (0.85): combined with
    ///   the engine's checksum policy (valid token → floored 0.9, invalid →
    ///   capped 0.1) and clamped over every detector's self-declared floor, this
    ///   bar admits checksum-validated tokens and strong ML-scored findings while
    ///   dropping checksum-failures and weak-signal matches.
    /// - `max_decode_depth = 1`: deep-decoded payloads are a FP source at scale.
    ///
    /// `penalize_test_paths` stays on (the default) to suppress fixture-shaped
    /// hits. A `--min-confidence` override still layers on top of this preset.
    pub fn high_precision() -> Self {
        let mut config = Self::default();
        config.max_decode_depth = 1;
        config.entropy_enabled = false;
        // High-precision mode does not admit low-entropy keyword-anchored
        // values: that surface trades precision for real-world recall, the
        // opposite of this preset's contract. Restores the high
        // `generic-secret` floor.
        config.generic_keyword_low_entropy = false;
        config.min_confidence = Self::HIGH_PRECISION_MIN_CONFIDENCE;
        config
    }

    pub fn min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    pub(crate) fn per_chunk_deadline(&self) -> Option<Instant> {
        self.per_chunk_timeout_ms
            .map(|ms| Instant::now() + Duration::from_millis(ms))
    }

    /// Clamp every float field into its valid range and replace any
    /// NaN with a safe default. A user-supplied
    /// `--min-confidence=-5.0` or a corrupt config TOML feeding
    /// `min_confidence = nan` would otherwise NaN-infect the
    /// confidence-comparison path and silently drop every finding
    /// (NaN comparisons are always false, so `conf < min_confidence`
    /// is `false`, but `conf >= min_confidence` is also `false`,
    /// behaviour-dependent on the call site).
    ///
    /// Idempotent - sanitising an already-sane config is a no-op.
    /// Called inside `From<ScanConfig>` so any path that constructs
    /// a ScannerConfig from a user-influenced source pays this
    /// once at config-build time.
    pub fn sanitise(&mut self) {
        // Probabilities: clamp to [0.0, 1.0], NaN → canonical default. The
        // NaN fallbacks READ FROM `ScanConfig::default()` rather than repeating
        // a literal, so a corrupt-config scrub can never fork from the shipped
        // floor (currently ml_weight 0.5, min_confidence 0.40) - one source.
        let canon = keyhog_core::ScanConfig::default();
        if !self.ml_weight.is_finite() {
            self.ml_weight = canon.ml_weight;
        } else {
            self.ml_weight = self.ml_weight.clamp(0.0, 1.0);
        }
        if self
            .ml_weight_override
            .is_some_and(|weight| !weight.is_finite() || !(0.0..=1.0).contains(&weight))
        {
            self.ml_weight_override = None;
        }
        if !self.min_confidence.is_finite() {
            self.min_confidence = canon.min_confidence;
        } else {
            self.min_confidence = self.min_confidence.clamp(0.0, 1.0);
        }
        // Shannon entropy: 8.0 is the mathematical upper bound for byte-level
        // entropy (a genuine constant, not a config default). NaN / negative →
        // the CANONICAL `ScanConfig::default()` floor, read from `canon` like the
        // `ml_weight` / `min_confidence` scrubs above. NOT a forked literal, so a
        // future change to the shipped entropy default can never silently diverge
        // on the corrupt-config path (single source of truth).
        if !self.entropy_threshold.is_finite() || self.entropy_threshold < 0.0 {
            self.entropy_threshold = canon.entropy_threshold;
        } else if self.entropy_threshold > 8.0 {
            self.entropy_threshold = 8.0;
        }
        // BPE bytes-per-token suppression bound. NaN would silently break the
        // `cpt > bound` gate (NaN comparisons are always false → nothing ever
        // suppressed), and a negative bound would suppress EVERY candidate
        // (cpt is always ≥ ~0.5 > any negative). Both scrub to the CANONICAL
        // shipped bound, read from `canon` like the scrubs above, never a
        // forked literal. No upper clamp: a deliberately large bound is the
        // documented way to disable the gate (trade precision for recall).
        if !self.entropy_bpe_max_bytes_per_token.is_finite()
            || self.entropy_bpe_max_bytes_per_token <= 0.0
        {
            self.entropy_bpe_max_bytes_per_token = canon.entropy_bpe_max_bytes_per_token;
        }
        if self
            .entropy_bpe_max_bytes_per_token_override
            .is_some_and(|bound| !bound.is_finite() || bound <= 0.0)
        {
            // Invalid presence must not manufacture a scan-wide override. Drop
            // it so detector-local TOML policy remains authoritative; the
            // operator-facing CLI/TOML boundaries reject these values before
            // construction, while this defensive library scrub stays safe for
            // programmatic callers.
            self.entropy_bpe_max_bytes_per_token_override = None;
        }
        // Recursion-depth + chunk-size caps. The decode-depth ceiling is the
        // same contract used by CLI parsing and TOML validation.
        let max_decode_depth = keyhog_core::max_decode_depth_limit();
        if self.max_decode_depth > max_decode_depth {
            self.max_decode_depth = max_decode_depth;
        }
        if self.max_matches_per_chunk > 1_000_000 {
            self.max_matches_per_chunk = 1_000_000;
        }
        if self.max_matches_per_chunk == 0 {
            self.max_matches_per_chunk = 1000;
        }
        if self.per_chunk_timeout_ms == Some(0) {
            self.per_chunk_timeout_ms = None;
        }
    }

    pub fn with_calibration(mut self, calibration: Arc<Calibration>) -> Self {
        self.calibration = Some(calibration);
        self
    }

    /// Set an explicit scan-wide BPE ceiling while preserving presence even
    /// when `bound` equals the compiled fallback. Library callers should use
    /// this instead of relying on [`From<ScanConfig>`] when they intend a value
    /// of `2.2` to override detector-local TOML policy: `ScanConfig` stores only
    /// the number and cannot distinguish “omitted default” from “explicitly set
    /// to the default.” The complete shared scan config is validated before the
    /// override is accepted, so invalid programmatic policy fails closed.
    pub fn with_entropy_bpe_max_bytes_per_token_override(
        mut self,
        bound: f64,
    ) -> Result<Self, keyhog_core::ConfigError> {
        self.scan.entropy_bpe_max_bytes_per_token = bound;
        self.scan.validate()?;
        self.entropy_bpe_max_bytes_per_token_override = Some(bound);
        Ok(self)
    }

    /// Set an explicit scan-wide model-weight override. Ordinary scans should
    /// leave this absent so detector TOMLs retain their calibrated weights.
    pub fn with_ml_weight_override(
        mut self,
        weight: f64,
    ) -> Result<Self, keyhog_core::ConfigError> {
        self.scan.ml_weight = weight;
        self.scan.validate()?;
        self.ml_weight_override = Some(weight);
        Ok(self)
    }
}

impl From<ScanConfig> for ScannerConfig {
    fn from(scan: ScanConfig) -> Self {
        // Structural wrap, NOT a field-by-field copy: the canonical `ScanConfig`
        // is moved in whole into `self.scan`, so there is no parallel field list
        // that can silently drift from the owned truth (the original lossy
        // `From`: which renamed/invented/dropped fields, was MC-01's core
        // complaint; a wrap makes that class of bug structurally impossible).
        //
        // The only additions are the two scanner-crate-local knobs:
        //   - `multiline`: its type lives in this crate; `keyhog-core` cannot
        //     depend on `keyhog-scanner` (cycle), so it cannot sit on
        //     `ScanConfig`. Takes the scanner default here.
        //   - `penalize_test_paths`: defaults on; the CLI flips it off for
        //     `--no-suppress-test-fixtures`.
        let canonical_bpe_bound = ScanConfig::default().entropy_bpe_max_bytes_per_token;
        let entropy_bpe_max_bytes_per_token_override =
            (scan.entropy_bpe_max_bytes_per_token.to_bits() != canonical_bpe_bound.to_bits())
                .then_some(scan.entropy_bpe_max_bytes_per_token);
        let canonical_ml_weight = ScanConfig::default().ml_weight;
        let ml_weight_override =
            (scan.ml_weight.to_bits() != canonical_ml_weight.to_bits()).then_some(scan.ml_weight);
        let mut out = Self {
            scan,
            entropy_bpe_max_bytes_per_token_override,
            ml_weight_override,
            multiline: crate::multiline::MultilineConfig::default(),
            penalize_test_paths: true,
            per_chunk_timeout_ms: None,
            profile: false,
            perf_trace: false,
            calibration: None,
        };
        // Defensive clamp + NaN scrub on every user-influenced numeric field
        // (applied to the wrapped `ScanConfig` via `DerefMut`). Idempotent.
        // See `ScannerConfig::sanitise` for rationale.
        out.sanitise();
        out
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn tuning_effective_resolves_compiled_defaults_when_unset() {
        let cfg = ScannerTuningConfig::default();
        assert!(cfg.fallback_hs_effective());
        assert_eq!(
            cfg.hs_prefilter_max_len_effective(),
            ScannerTuningConfig::HS_PREFILTER_MAX_LEN_DEFAULT
        );
        assert_eq!(
            cfg.hs_shard_target_effective(),
            ScannerTuningConfig::HS_SHARD_TARGET_DEFAULT
        );
        assert!(cfg.fallback_anchor_effective());
        assert!(!cfg.fallback_reverse_effective()); // FALLBACK_REVERSE_DEFAULT = false
        assert_eq!(
            cfg.gpu_moe_timeout_ms_effective(),
            ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT
        );
    }

    #[test]
    fn tuning_effective_honors_explicit_overrides() {
        let cfg = ScannerTuningConfig {
            phase2_hs: Some(false),
            hs_shard_target: Some(999),
            fallback_reverse: Some(true),
            gpu_moe_timeout_ms: Some(1_500),
            ..ScannerTuningConfig::default()
        };
        assert!(!cfg.fallback_hs_effective());
        assert_eq!(cfg.hs_shard_target_effective(), 999);
        assert!(cfg.fallback_reverse_effective());
        assert_eq!(cfg.gpu_moe_timeout_ms_effective(), 1_500);
    }

    #[test]
    fn sanitise_scrubs_nan_probabilities_to_canonical_defaults() {
        let canon = keyhog_core::ScanConfig::default();
        let mut cfg = ScannerConfig::default();
        cfg.ml_weight = f64::NAN;
        cfg.min_confidence = f64::NAN;
        cfg.sanitise();
        assert_eq!(cfg.ml_weight, canon.ml_weight);
        assert_eq!(cfg.min_confidence, canon.min_confidence);
    }

    #[test]
    fn sanitise_clamps_out_of_range_probabilities() {
        let mut cfg = ScannerConfig::default();
        cfg.ml_weight = 5.0;
        cfg.min_confidence = -2.0;
        cfg.sanitise();
        assert_eq!(cfg.ml_weight, 1.0);
        assert_eq!(cfg.min_confidence, 0.0);
    }

    #[test]
    fn sanitise_bounds_entropy_threshold() {
        let canon = keyhog_core::ScanConfig::default();
        // NaN and negative both scrub to the canonical shipped floor.
        let mut nanned = ScannerConfig::default();
        nanned.entropy_threshold = f64::NAN;
        nanned.sanitise();
        assert_eq!(nanned.entropy_threshold, canon.entropy_threshold);
        let mut negative = ScannerConfig::default();
        negative.entropy_threshold = -1.0;
        negative.sanitise();
        assert_eq!(negative.entropy_threshold, canon.entropy_threshold);
        // Above the 8-bit byte-entropy ceiling clamps to exactly 8.0.
        let mut high = ScannerConfig::default();
        high.entropy_threshold = 99.0;
        high.sanitise();
        assert_eq!(high.entropy_threshold, 8.0);
    }

    #[test]
    fn sanitise_scrubs_bpe_bound_nan_and_nonpositive_but_keeps_high() {
        let canon = keyhog_core::ScanConfig::default();
        // NaN would silently break the `cpt > bound` gate (all comparisons false
        // → nothing ever suppressed); it must scrub to the canonical 2.2.
        let mut nanned = ScannerConfig::default();
        nanned.entropy_bpe_max_bytes_per_token = f64::NAN;
        nanned.sanitise();
        assert_eq!(
            nanned.entropy_bpe_max_bytes_per_token,
            canon.entropy_bpe_max_bytes_per_token
        );
        // A negative bound would suppress EVERY candidate (cpt is always ≥ ~0.5 >
        // any negative); it scrubs to the canonical default, not left as a footgun.
        let mut negative = ScannerConfig::default();
        negative.entropy_bpe_max_bytes_per_token = -1.0;
        negative.sanitise();
        assert_eq!(
            negative.entropy_bpe_max_bytes_per_token,
            canon.entropy_bpe_max_bytes_per_token
        );
        let mut zero = ScannerConfig::default();
        zero.entropy_bpe_max_bytes_per_token = 0.0;
        zero.sanitise();
        assert_eq!(
            zero.entropy_bpe_max_bytes_per_token,
            canon.entropy_bpe_max_bytes_per_token
        );
        // A deliberately HIGH bound is the documented way to disable the gate
        // (trade precision for recall) and must be preserved, NOT clamped.
        let mut high = ScannerConfig::default();
        high.entropy_bpe_max_bytes_per_token = 99.0;
        high.sanitise();
        assert_eq!(high.entropy_bpe_max_bytes_per_token, 99.0);
    }

    #[test]
    fn scan_config_conversion_preserves_explicit_bpe_precedence() {
        let default = ScannerConfig::default();
        assert_eq!(default.entropy_bpe_max_bytes_per_token_override, None);

        let mut scan = ScanConfig::default();
        scan.entropy_bpe_max_bytes_per_token = 3.4;
        let explicit = ScannerConfig::from(scan);
        assert_eq!(explicit.entropy_bpe_max_bytes_per_token_override, Some(3.4));

        let explicit_default = ScannerConfig::default()
            .with_entropy_bpe_max_bytes_per_token_override(2.2)
            .expect("the compiled default is a valid explicit override");
        assert_eq!(
            explicit_default.entropy_bpe_max_bytes_per_token_override,
            Some(2.2),
            "library callers must be able to preserve an explicit default-valued override"
        );

        let rejected = ScannerConfig::default()
            .with_entropy_bpe_max_bytes_per_token_override(0.0)
            .expect_err("a zero BPE ceiling must fail closed");
        assert!(matches!(
            rejected,
            keyhog_core::ConfigError::InvalidBpeBound(bound) if bound == 0.0
        ));

        let mut invalid = ScannerConfig::default();
        invalid.entropy_bpe_max_bytes_per_token_override = Some(f64::NAN);
        invalid.sanitise();
        assert_eq!(
            invalid.entropy_bpe_max_bytes_per_token_override, None,
            "an invalid programmatic override must restore detector-local policy"
        );
    }

    #[test]
    fn detector_ml_weight_remains_authoritative_until_override_is_explicit() {
        let default = ScannerConfig::default();
        assert_eq!(default.ml_weight_override, None);

        let explicit = ScannerConfig::default()
            .with_ml_weight_override(0.75)
            .expect("a unit-interval model weight is valid");
        assert_eq!(explicit.ml_weight_override, Some(0.75));

        let invalid = ScannerConfig::default().with_ml_weight_override(1.5);
        assert!(invalid.is_err());
    }
}
