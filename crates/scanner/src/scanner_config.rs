//! Scanner configuration and scan state types.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
#[cfg(feature = "ml")]
use std::collections::{HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use keyhog_core::config::ScanConfig;

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
/// `ScanConfig`'s `min_secret_len` / `max_file_size` / `dedup` fields are
/// reachable through the deref but are NOT consumed by the scan engine — they
/// are enforced elsewhere (the source walker and the verifier) and carry that
/// caveat in their own doc comments on `ScanConfig`. Their presence here is the
/// wrapped truth, not a second silent copy.
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
        let canon = keyhog_core::config::ScanConfig::default();
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
        let max_decode_depth = keyhog_core::config::max_decode_depth_limit();
        if self.max_decode_depth > max_decode_depth {
            self.max_decode_depth = max_decode_depth;
        }
        if self.max_matches_per_chunk > 1_000_000 {
            self.max_matches_per_chunk = 1_000_000;
        }
        if self.max_matches_per_chunk == 0 {
            self.max_matches_per_chunk = 1000;
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
pub struct MlPendingMatch {
    /// The raw match built with heuristic confidence only.
    pub raw_match: keyhog_core::RawMatch,
    /// Heuristic confidence before ML blending.
    pub heuristic_conf: f64,
    /// Inferred code context for post-ML adjustments.
    pub code_context: crate::context::CodeContext,
    /// Credential text for feature extraction.
    pub credential: String,
    /// Surrounding context passed to the ML scorer.
    pub ml_context: String,
    /// When true, the MoE score is AUTHORITATIVE for this candidate: the final
    /// confidence is the model score directly, NOT `max(heuristic, ml)`. Set for
    /// entropy-fallback candidates, whose "heuristic" is bare entropy magnitude -
    /// exactly the signal that mislabels high-entropy non-secrets (FQDNs, git
    /// SHAs, base64 blobs) as findings. Flooring by that heuristic (as the
    /// detector path does, where the regex IS positive evidence) would defeat the
    /// model's ability to suppress those FPs. Detector/generic matches set this
    /// false and keep the heuristic floor. See `apply_ml_batch_scores`.
    pub model_authoritative: bool,
}

/// Internal state for a single scan operation (tracks matches and ML cache).
#[derive(Default)]
pub struct ScanState {
    /// Matches collected for this chunk, prioritized by confidence.
    /// Uses Reverse to make it a min-heap so we can easily pop the LOWEST confidence.
    pub matches: BinaryHeap<Reverse<keyhog_core::RawMatch>>,
    /// Interner for credentials found in this chunk to save memory on duplicates.
    pub credential_interner: HashSet<Arc<str>>,
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
    pub metadata_interner: HashSet<Arc<str>>,
    /// Optional reference to the scanner's frozen static-string
    /// interner. When `Some`, `intern_metadata` checks here first
    /// before falling through to the per-scan `metadata_interner`.
    /// Lock-free on read so concurrent rayon workers share one
    /// instance without contention.
    pub static_intern: Option<Arc<crate::static_intern::StaticInterner>>,
    #[cfg(feature = "ml")]
    pub ml_score_cache: HashMap<(String, String), f64>,
    #[cfg(feature = "ml")]
    pub ml_cache_order: VecDeque<(String, String)>,
    #[cfg(feature = "ml")]
    pub ml_cache_bytes: usize,
    #[cfg(feature = "ml")]
    /// Detector matches queued for batch ML scoring at the end of the scan.
    pub ml_pending: Vec<MlPendingMatch>,
}

impl ScanState {
    /// Intern a credential string, returning an `Arc<str>`.
    pub fn intern_credential(&mut self, s: &str) -> Arc<str> {
        if let Some(existing) = self.credential_interner.get(s) {
            existing.clone()
        } else {
            let shared: Arc<str> = Arc::from(s);
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
    pub fn intern_metadata(&mut self, s: &str) -> Arc<str> {
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
    pub fn with_static_intern(intern: Arc<crate::static_intern::StaticInterner>) -> Self {
        Self {
            static_intern: Some(intern),
            ..Self::default()
        }
    }

    /// Push a match to the state, maintaining priority and capacity.
    /// High-confidence secrets will displace lower-confidence findings.
    pub fn push_match(&mut self, m: keyhog_core::RawMatch, limit: usize) {
        if self.matches.len() < limit {
            self.matches.push(Reverse(m));
        } else if let Some(mut lowest) = self.matches.peek_mut() {
            if m > lowest.0 {
                *lowest = Reverse(m);
            }
        }
    }

    /// Drain all matches into a sorted vector. Dedups identical findings
    /// (same detector + same credential + same offset) - two engines can
    /// produce the same finding for the same pattern (e.g. ac_map's
    /// literal hit + homoglyph fallback variant both fire on plain ASCII
    /// because the homoglyph char-class includes the original char). The
    /// caller only wants one of them in the result set.
    pub fn into_matches(self) -> Vec<keyhog_core::RawMatch> {
        let mut matches: Vec<_> = self.matches.into_iter().map(|r| r.0).collect();
        // Sort descending by confidence for final output
        matches.sort_by(|a, b| b.cmp(a));
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
        // already sorted confidence-descending above; `sort_by` is a STABLE
        // sort, so grouping by (detector_id, credential, offset) preserves
        // that confidence-descending order within each identity group. The
        // first element of each run is therefore the highest-confidence
        // entry, which `dedup_by` keeps. A final `b.cmp(a)` restores the
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
            // Restore confidence-descending order for output.
            matches.sort_by(|a, b| b.cmp(a));
            return matches;
        }
        // Large N: HashSet dedup amortises better than repeated sorts.
        // Stable: keeps the highest-confidence entry of any duplicate set
        // thanks to the confidence sort above.
        let mut seen: std::collections::HashSet<(std::sync::Arc<str>, std::sync::Arc<str>, usize)> =
            std::collections::HashSet::with_capacity(matches.len());
        matches.retain(|m| {
            seen.insert((
                std::sync::Arc::clone(&m.detector_id),
                std::sync::Arc::clone(&m.credential),
                m.location.offset,
            ))
        });
        matches
    }
}
