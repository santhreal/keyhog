//! Scanner configuration and scan state types.

use std::collections::{BinaryHeap, HashSet};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use keyhog_core::ScanConfig;
use keyhog_core::SensitiveString;

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
    pub(crate) const HS_PREFILTER_MAX_LEN_DEFAULT: usize = 4096;
    pub(crate) const HS_SHARD_TARGET_DEFAULT: usize = 80;
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

/// Scanner-side configuration: the canonical [`ScanConfig`] — the single owned
/// source of truth for every shared detection knob (decode depth, entropy, ML,
/// confidence floor, keyword lists, …) — PLUS the two knobs that are
/// scanner-crate-local and have no place on `keyhog-core`'s `ScanConfig`:
///
/// - `multiline` — its type ([`crate::multiline::MultilineConfig`]) is defined
///   in THIS crate, and `keyhog-core` cannot depend on `keyhog-scanner` without
///   a dependency cycle, so the field cannot live on `ScanConfig`.
/// - `penalize_test_paths` — a scanner-internal suppression toggle the CLI flips
///   for `--no-suppress-test-fixtures`; it never appears on the on-disk config.
///
/// This is the "thin newtype over `ScanConfig`" MC-01 calls for. It deliberately
/// does **not** restate any of `ScanConfig`'s fields: every shared knob is read
/// and written straight through [`Deref`]/[`DerefMut`] (`config.min_confidence`,
/// `config.entropy_enabled`, `config.known_prefixes`, …), so there is exactly
/// ONE definition of each — no parallel field list that can drift, and the
/// `From<ScanConfig>` impl below is a structural wrap, never a hand-maintained
/// field-by-field copy.
///
/// `ScanConfig`'s `max_file_size` / `dedup` fields are reachable through the
/// deref but are NOT consumed by the scan engine — they are enforced elsewhere
/// (the source walker and the verifier) and carry that caveat in their own doc
/// comments on `ScanConfig`. Their presence here is the wrapped truth, not a
/// second silent copy. `min_secret_len` is consumed by the entropy fallback.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// The canonical shared detection config — single source of truth for every
    /// knob the engine and CLI agree on. Reached transparently via `Deref`, so
    /// callers write `config.min_confidence`, not `config.scan.min_confidence`.
    pub scan: ScanConfig,
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

    pub fn fast() -> Self {
        let mut c = Self::default();
        c.max_decode_depth = 0;
        c.ml_enabled = false;
        c.entropy_enabled = false;
        c
    }

    pub fn thorough() -> Self {
        // `min_confidence` intentionally omitted: it inherits the canonical
        // `ScanConfig::default()` floor (single source of truth) instead of
        // forking a second literal. Deep scanning widens decode/entropy, not
        // the confidence bar.
        let mut c = Self::default();
        c.max_decode_depth = 10;
        c.ml_enabled = true;
        c.entropy_enabled = true;
        c
    }

    /// High-precision mass-scan preset: minimise false positives at the cost of
    /// some recall, for scanning huge corpora where every FP is expensive to
    /// triage. Fully offline and fast (no ML, no entropy sweep, shallow decode).
    ///
    /// - `entropy_enabled = false`: generic high-entropy matching is the single
    ///   largest FP source; precision mode drops it entirely.
    /// - `ml_enabled = true` (inherited): ML is the confidence discriminator that
    ///   lifts genuine secrets over the high floor while leaving FP-shaped tokens
    ///   below it. Disabling it would crater the scores the 0.85 bar relies on,
    ///   so precision KEEPS ML (this mode trades recall for precision, not for
    ///   speed — use `--fast` when speed is the goal).
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
        let mut c = Self::default();
        c.max_decode_depth = 1;
        c.entropy_enabled = false;
        // High-precision mode does not admit low-entropy keyword-anchored
        // values: that surface trades precision for real-world recall, the
        // opposite of this preset's contract. Restores the high
        // `generic-secret` floor.
        c.generic_keyword_low_entropy = false;
        c.min_confidence = Self::HIGH_PRECISION_MIN_CONFIDENCE;
        c
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
        if !self.min_confidence.is_finite() {
            self.min_confidence = canon.min_confidence;
        } else {
            self.min_confidence = self.min_confidence.clamp(0.0, 1.0);
        }
        // Shannon entropy: 8.0 is the upper bound for byte-level
        // entropy. NaN / negative → conservative default.
        if !self.entropy_threshold.is_finite() || self.entropy_threshold < 0.0 {
            self.entropy_threshold = 4.5;
        } else if self.entropy_threshold > 8.0 {
            self.entropy_threshold = 8.0;
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
}

impl From<ScanConfig> for ScannerConfig {
    fn from(scan: ScanConfig) -> Self {
        // Structural wrap, NOT a field-by-field copy: the canonical `ScanConfig`
        // is moved in whole into `self.scan`, so there is no parallel field list
        // that can silently drift from the owned truth (the original lossy
        // `From` — which renamed/invented/dropped fields — was MC-01's core
        // complaint; a wrap makes that class of bug structurally impossible).
        //
        // The only additions are the two scanner-crate-local knobs:
        //   - `multiline` — its type lives in this crate; `keyhog-core` cannot
        //     depend on `keyhog-scanner` (cycle), so it cannot sit on
        //     `ScanConfig`. Takes the scanner default here.
        //   - `penalize_test_paths` — defaults on; the CLI flips it off for
        //     `--no-suppress-test-fixtures`.
        let mut out = Self {
            scan,
            multiline: crate::multiline::MultilineConfig::default(),
            penalize_test_paths: true,
            per_chunk_timeout_ms: None,
            profile: false,
            perf_trace: false,
        };
        // Defensive clamp + NaN scrub on every user-influenced numeric field
        // (applied to the wrapped `ScanConfig` via `DerefMut`). Idempotent.
        // See `ScannerConfig::sanitise` for rationale.
        out.sanitise();
        out
    }
}

/// Queued ML match waiting for batch inference at the end of a scan.
#[cfg(feature = "ml")]
#[derive(Debug, Clone)]
pub(crate) struct MlPendingMatch {
    /// The raw match built with heuristic confidence only.
    pub(crate) raw_match: keyhog_core::RawMatch,
    /// Heuristic confidence before ML blending.
    pub(crate) heuristic_conf: f64,
    /// Inferred code context for post-ML adjustments.
    pub(crate) code_context: crate::context::CodeContext,
    /// Credential text for feature extraction.
    pub(crate) credential: String,
    /// Surrounding context passed to the ML scorer.
    pub(crate) ml_context: String,
    /// When true, the MoE score is AUTHORITATIVE for this candidate: the final
    /// confidence is the model score directly, NOT `max(heuristic, ml)`. Set for
    /// entropy phase-2 candidates, whose "heuristic" is bare entropy magnitude -
    /// exactly the signal that mislabels high-entropy non-secrets (FQDNs, git
    /// SHAs, base64 blobs) as findings. Flooring by that heuristic (as the
    /// detector path does, where the regex IS positive evidence) would defeat the
    /// model's ability to suppress those FPs. Detector/generic matches set this
    /// false and keep the heuristic floor. See `apply_ml_batch_scores`.
    pub(crate) model_authoritative: bool,
}

/// Borrowed ordering key for a `RawMatch` candidate.
///
/// Hot emitters can decide whether a candidate can enter the capped match heap
/// before constructing the owned `RawMatch`, avoiding detector metadata
/// refcount bumps for candidates that would be immediately discarded.
#[cfg(any(feature = "entropy", feature = "simdsieve"))]
pub(crate) struct RawMatchPriority<'a> {
    pub(crate) confidence: Option<f64>,
    pub(crate) severity: keyhog_core::Severity,
    pub(crate) detector_id: &'a str,
    pub(crate) credential: &'a str,
    pub(crate) offset: usize,
    pub(crate) line: Option<usize>,
}

#[cfg(any(feature = "entropy", feature = "simdsieve"))]
impl RawMatchPriority<'_> {
    fn cmp_raw_match(&self, other: &keyhog_core::RawMatch) -> std::cmp::Ordering {
        let self_conf = self.confidence.unwrap_or(0.0); // LAW10: absent confidence => 0.0 for capped-heap ordering only; finding remains eligible
        let other_conf = other.confidence.unwrap_or(0.0); // LAW10: absent confidence => 0.0 for capped-heap ordering only; finding remains eligible

        match other_conf.total_cmp(&self_conf) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match other.severity.cmp(&self.severity) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.detector_id.cmp(other.detector_id.as_ref()) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.credential.cmp(other.credential.as_ref()) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.offset.cmp(&other.location.offset) {
            std::cmp::Ordering::Equal => self.line.cmp(&other.location.line),
            ord => ord,
        }
    }
}

/// Internal state for a single scan operation (tracks matches and ML cache).
#[derive(Default)]
pub(crate) struct ScanState {
    /// Matches collected for this chunk, prioritized by confidence.
    /// `RawMatch::Ord` sorts best findings first (`best < worst`), so the
    /// BinaryHeap root is the worst retained finding and can be replaced when a
    /// better candidate arrives after the cap is full.
    pub(crate) matches: BinaryHeap<keyhog_core::RawMatch>,
    /// Interner for credentials found in this chunk to save memory on duplicates.
    pub(crate) credential_interner: HashSet<SensitiveString>,
    /// Static string cache for detector metadata. Uses
    /// `HashSet<Arc<str>>` (not `HashMap<String, Arc<str>>`) so a
    /// cache miss allocates ONLY the `Arc<str>` - the prior shape
    /// also allocated a `String` to serve as the HashMap key, paying
    /// twice for what's a single dedup slot. `HashSet::get(&s)` works
    /// via `Arc<str>: Borrow<str>`, no allocation on hits.
    ///
    /// Hit ONLY by dynamic strings now: the scanner-wide
    /// `StaticInterner` (vyre CHD perfect hash) handles every
    /// `(detector_id, detector_name, service, source_type)` lookup
    /// without per-scan allocation.
    pub(crate) metadata_interner: HashSet<Arc<str>>,
    /// Optional reference to the scanner's frozen static-string
    /// interner. When `Some`, `intern_metadata` checks here first
    /// before falling through to the per-scan `metadata_interner`.
    /// Lock-free on read so concurrent rayon workers share one
    /// instance without contention.
    pub(crate) static_intern: Option<Arc<crate::static_intern::StaticInterner>>,
    /// Detector matches queued for batch ML scoring at the end of the scan.
    #[cfg(feature = "ml")]
    pub(crate) ml_pending: Vec<MlPendingMatch>,
}

impl ScanState {
    /// Intern a credential string, returning a shared zeroizing allocation.
    pub(crate) fn intern_credential(&mut self, s: &str) -> SensitiveString {
        if let Some(existing) = self.credential_interner.get(s) {
            existing.clone()
        } else {
            let shared = SensitiveString::from(s);
            self.credential_interner.insert(shared.clone());
            shared
        }
    }

    /// Intern a metadata string (detector_id, name, service, source_type, ...).
    ///
    /// Lookup order:
    ///   1. Scanner-wide `StaticInterner` (vyre CHD perfect hash) for
    ///      detector metadata that's frozen at scanner construction -
    ///      O(1), no allocation, no lock contention.
    ///   2. Per-scan `metadata_interner` `HashSet` for dynamic strings
    ///      (file paths, commit SHAs, author names, dates).
    pub(crate) fn intern_metadata(&mut self, s: &str) -> Arc<str> {
        if let Some(intern) = self.static_intern.as_ref() {
            if let Some(arc) = intern.lookup(s) {
                return arc;
            }
        }
        if let Some(existing) = self.metadata_interner.get(s) {
            return existing.clone();
        }
        let shared: Arc<str> = Arc::from(s);
        self.metadata_interner.insert(shared.clone());
        shared
    }

    /// Construct a `ScanState` that consults the scanner-wide static
    /// interner first. Use this from any path that has a
    /// `&CompiledScanner` in scope; falls back to `default()` for
    /// stand-alone unit tests.
    pub(crate) fn with_static_intern(intern: Arc<crate::static_intern::StaticInterner>) -> Self {
        Self {
            static_intern: Some(intern),
            ..Self::default()
        }
    }

    /// Push a match to the state, maintaining priority and capacity.
    /// High-confidence secrets will displace lower-confidence findings.
    pub(crate) fn push_match(&mut self, m: keyhog_core::RawMatch, limit: usize) {
        if self.matches.len() < limit {
            self.matches.push(m);
        } else if let Some(mut worst) = self.matches.peek_mut() {
            if m < *worst {
                *worst = m;
            }
        }
    }

    #[cfg(any(feature = "entropy", feature = "simdsieve"))]
    pub(crate) fn push_match_lazy<F>(
        &mut self,
        priority: RawMatchPriority<'_>,
        limit: usize,
        build: F,
    ) where
        F: FnOnce(&mut Self) -> keyhog_core::RawMatch,
    {
        if self.matches.len() < limit {
            let m = build(self);
            self.matches.push(m);
            return;
        }

        let admit = self
            .matches
            .peek()
            .is_some_and(|worst| priority.cmp_raw_match(worst).is_lt());
        if admit {
            let m = build(self);
            if let Some(mut worst) = self.matches.peek_mut() {
                *worst = m;
            }
        }
    }

    /// Drain all matches into a sorted vector. Dedups identical findings
    /// (same detector + same credential + same offset) - two engines can
    /// produce the same finding for the same pattern (e.g. ac_map's
    /// literal hit + homoglyph fallback variant both fire on plain ASCII
    /// because the homoglyph char-class includes the original char). The
    /// caller only wants one of them in the result set.
    pub(crate) fn into_matches(self) -> Vec<keyhog_core::RawMatch> {
        let mut matches: Vec<_> = self.matches.into_iter().collect();
        // Sort by RawMatch's best-first order for final output.
        matches.sort();
        // Dedup identical findings (same detector + credential + offset).
        // 0 or 1 match cannot contain a duplicate, so skip all dedup work -
        // no HashSet alloc, no refcount traffic - on the overwhelmingly
        // common small-chunk case.
        if matches.len() <= 1 {
            return matches;
        }
        // For small N a sort-based adjacent dedup beats a HashSet: it adds
        // no allocation and no `Arc::clone` (two atomics per match) - it
        // only borrows the identity fields for comparison. The Vec is
        // already sorted best-first above; `sort_by` is a STABLE sort, so
        // grouping by (detector_id, credential, offset) preserves that
        // best-first order within each identity group. The
        // first element of each run is therefore the highest-confidence
        // entry, which `dedup_by` keeps. A final `sort()` restores the
        // canonical output order. Same result as the HashSet path, no alloc.
        if matches.len() <= 64 {
            matches.sort_by(|a, b| {
                a.detector_id
                    .cmp(&b.detector_id)
                    .then_with(|| a.credential.cmp(&b.credential))
                    .then_with(|| a.location.offset.cmp(&b.location.offset))
            });
            matches.dedup_by(|a, b| {
                a.detector_id == b.detector_id
                    && a.credential == b.credential
                    && a.location.offset == b.location.offset
            });
            // Restore best-first order for output.
            matches.sort();
            return matches;
        }
        // Large N: HashSet dedup amortises better than repeated sorts.
        // Stable: keeps the highest-confidence entry of any duplicate set
        // thanks to the confidence sort above.
        let mut seen: std::collections::HashSet<(std::sync::Arc<str>, SensitiveString, usize)> =
            std::collections::HashSet::with_capacity(matches.len());
        matches.retain(|m| {
            seen.insert((
                std::sync::Arc::clone(&m.detector_id),
                m.credential.clone(),
                m.location.offset,
            ))
        });
        matches
    }
}
