//! Runtime state for one scan operation.
//!
//! Configuration lives in `scanner_config`; this module owns the per-scan
//! match heap, credential/metadata interners, and ML batch queue.

#[cfg(feature = "ml")]
use std::collections::HashMap;
use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;

use crate::candidate_provenance::CandidateProvenance;
use keyhog_core::SensitiveString;

#[cfg(feature = "ml")]
pub(crate) fn ml_context_for_candidate(
    text: &str,
    line: usize,
    file_path: Option<&str>,
    context_radius_lines: usize,
) -> String {
    let text_context = crate::pipeline::local_context_window(text, line, context_radius_lines);
    match file_path {
        Some(path) => format!("file:{path}\n{text_context}"),
        None => text_context.to_string(),
    }
}

#[cfg(feature = "ml")]
pub(crate) fn ml_features_for_candidate(
    text: &str,
    line_index: &crate::context::LineContextIndex,
    line: usize,
    file_path: Option<&str>,
    credential: &str,
    context_radius_lines: usize,
    config: &crate::types::ScannerConfig,
    detector_service: &str,
    detector_features: crate::ml_scorer::ml_features::CompiledDetectorMlFeatures,
    channel: crate::ml_scorer::MlCandidateChannel,
) -> [f32; crate::ml_scorer::NUM_FEATURES] {
    if credential.is_empty() {
        return [0.0; crate::ml_scorer::NUM_FEATURES];
    }
    let text_context = line_index.context_window(text, line, context_radius_lines);
    crate::ml_scorer::ml_features::compute_features_for_compiled_detector_from_source_window(
        credential,
        text_context,
        file_path,
        &config.known_prefixes,
        &config.secret_keywords,
        &config.test_keywords,
        &config.placeholder_keywords,
        detector_service,
        detector_features,
        channel,
    )
}

/// Owned finding payload queued for ML without computing its persistent
/// credential digest or constructing the public `RawMatch`.
///
/// The plaintext and source metadata must outlive extraction so batch scoring
/// can run after the chunk walk. The SHA-256 digest is deliberately absent:
/// [`materialize`](Self::materialize) is called only after final adjudication
/// returns an emit verdict.
#[cfg(feature = "ml")]
#[derive(Debug, Clone)]
pub(crate) struct PendingRawMatch {
    pub(crate) detector_id: Arc<str>,
    pub(crate) detector_name: Arc<str>,
    pub(crate) service: Arc<str>,
    pub(crate) severity: keyhog_core::Severity,
    pub(crate) credential: SensitiveString,
    pub(crate) companions: keyhog_core::CompanionMap,
    pub(crate) location: keyhog_core::MatchLocation,
    pub(crate) entropy: Option<f64>,
    pub(crate) provenance: CandidateProvenance,
}

#[cfg(feature = "ml")]
impl PendingRawMatch {
    pub(crate) fn materialize(self, confidence: f64) -> AttributedRawMatch {
        #[cfg(test)]
        RAW_MATCH_MATERIALIZATIONS.with(|count| count.set(count.get() + 1));

        let credential_hash = crate::sha256_hash(self.credential.as_ref());
        AttributedRawMatch::new(
            keyhog_core::RawMatch {
                detector_id: self.detector_id,
                detector_name: self.detector_name,
                service: self.service,
                severity: self.severity,
                credential: self.credential,
                credential_hash,
                companions: self.companions,
                location: self.location,
                entropy: self.entropy,
                confidence: Some(confidence),
            },
            self.provenance,
        )
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.detector_id == other.detector_id
            && self.credential == other.credential
            && self.location.offset == other.location.offset
    }

    fn cmp_with_confidence(
        &self,
        confidence: f64,
        other: &Self,
        other_confidence: f64,
    ) -> std::cmp::Ordering {
        match other_confidence.total_cmp(&confidence) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        match other.severity.cmp(&self.severity) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.detector_id.cmp(&other.detector_id) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.credential.cmp(&other.credential) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.location.offset.cmp(&other.location.offset) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.location.line.cmp(&other.location.line) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        self.detector_name
            .cmp(&other.detector_name)
            .then_with(|| self.service.cmp(&other.service))
            // Equal plaintext credentials have equal SHA-256 digests, so the
            // omitted `RawMatch::credential_hash` tiebreak cannot affect this
            // pending-queue comparison.
            .then_with(|| pending_companion_map_cmp(&self.companions, &other.companions))
            .then_with(|| self.location.source.cmp(&other.location.source))
            .then_with(|| self.location.file_path.cmp(&other.location.file_path))
            .then_with(|| self.location.commit.cmp(&other.location.commit))
            .then_with(|| self.location.author.cmp(&other.location.author))
            .then_with(|| self.location.date.cmp(&other.location.date))
            .then_with(|| pending_opt_f64_total_cmp(self.entropy, other.entropy))
            .then_with(|| confidence.total_cmp(&other_confidence))
    }
}

#[cfg(all(feature = "ml", test))]
thread_local! {
    static RAW_MATCH_MATERIALIZATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(all(feature = "ml", test))]
pub(crate) fn reset_raw_match_materialization_count_for_test() {
    RAW_MATCH_MATERIALIZATIONS.with(|count| count.set(0));
}

#[cfg(all(feature = "ml", test))]
pub(crate) fn raw_match_materialization_count_for_test() -> usize {
    RAW_MATCH_MATERIALIZATIONS.with(std::cell::Cell::get)
}

#[cfg(feature = "ml")]
fn pending_opt_f64_total_cmp(left: Option<f64>, right: Option<f64>) -> std::cmp::Ordering {
    match (left, right) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(left), Some(right)) => left.total_cmp(&right),
    }
}

#[cfg(feature = "ml")]
fn pending_companion_map_cmp(
    left: &keyhog_core::CompanionMap,
    right: &keyhog_core::CompanionMap,
) -> std::cmp::Ordering {
    if left == right {
        return std::cmp::Ordering::Equal;
    }
    match left.len().cmp(&right.len()) {
        std::cmp::Ordering::Equal => {}
        ordering => return ordering,
    }

    let mut left_after: Option<&str> = None;
    let mut right_after: Option<&str> = None;
    for _ in 0..left.len() {
        let Some(left_entry) = left
            .iter()
            .filter(|(key, _)| left_after.is_none_or(|after| key.as_ref() > after))
            .min_by(|a, b| a.0.cmp(b.0))
        else {
            return std::cmp::Ordering::Equal;
        };
        let Some(right_entry) = right
            .iter()
            .filter(|(key, _)| right_after.is_none_or(|after| key.as_ref() > after))
            .min_by(|a, b| a.0.cmp(b.0))
        else {
            return std::cmp::Ordering::Equal;
        };
        match left_entry.cmp(&right_entry) {
            std::cmp::Ordering::Equal => {
                left_after = Some(left_entry.0.as_ref());
                right_after = Some(right_entry.0.as_ref());
            }
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

/// Queued ML candidate waiting for batch inference at the end of a scan.
#[cfg(feature = "ml")]
#[derive(Debug, Clone)]
pub(crate) struct MlPendingMatch {
    /// Owned finding payload without a persistent digest or public `RawMatch`.
    pub(crate) pending_raw_match: PendingRawMatch,
    /// Heuristic confidence before detector-owned ML scoring.
    pub(crate) heuristic_conf: f64,
    /// Inferred code context for post-ML adjustments.
    pub(crate) code_context: crate::context::CodeContext,
    /// Detector-owned multiplier for `code_context`, resolved before batching.
    pub(crate) context_multiplier: f64,
    /// Detector-owned hard-suppression threshold for `code_context`.
    pub(crate) context_suppression_threshold: Option<f64>,
    /// Detector-owned penalties applied after optional model scoring.
    pub(crate) post_match: keyhog_core::DetectorPostMatchConfidenceSpec,
    /// Exact serve-path features computed while source context is still local.
    pub(crate) ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
    /// Producer class baked into the feature vector. Keeping it typed here
    /// prevents pending deduplication from merging pattern and entropy evidence.
    channel: crate::ml_scorer::MlCandidateChannel,
    /// Detector-local model contribution, already resolved against an explicit
    /// scan-wide diagnostic override before this candidate enters the queue.
    pub(crate) ml_weight: f64,
    /// Confidence floor that applies after detector-owned ML scoring.
    pub(crate) min_confidence_floor: f64,
    /// Whether the original producer classified this as a named detector after
    /// applying weak-anchor exclusions.
    pub(crate) is_named_detector: bool,
    /// Detector-local generic classification carried from the producer. This
    /// avoids reparsing the reporting ID after batched inference.
    pub(crate) is_generic_detector: bool,
    /// The active detector's exact TOML policy proved this candidate is
    /// canonical hex key material for its assignment keyword and length.
    /// This evidence must survive batching so the unified finalizer does not
    /// silently reclassify the value as a digest or low-diversity blob.
    pub(crate) allow_canonical_hex_key: bool,
    /// Preserve detector-owned encoded-text evidence in the common finalizer.
    pub(crate) allow_encoded_text_lift: bool,
    /// Offline validator verdict computed once before queueing. ML batching
    /// must not rediscover detector policy or rerun validation.
    pub(crate) checksum: crate::checksum::ChecksumConfidenceDecision,
    /// Compiled detector-owned scoring behavior. The inactive state is removed
    /// before queueing, so every pending match has an executable policy.
    pub(crate) ml_mode: crate::detector_ml_policy::ActiveMlMode,
}

#[cfg(feature = "ml")]
impl MlPendingMatch {
    pub(crate) fn detector_candidate(
        pending_raw_match: PendingRawMatch,
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        context_multiplier: f64,
        context_suppression_threshold: Option<f64>,
        post_match: keyhog_core::DetectorPostMatchConfidenceSpec,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        is_named_detector: bool,
        is_generic_detector: bool,
        allow_canonical_hex_key: bool,
        allow_encoded_text_lift: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) -> Self {
        Self {
            pending_raw_match,
            heuristic_conf,
            code_context,
            context_multiplier,
            context_suppression_threshold,
            post_match,
            ml_features,
            channel: crate::ml_scorer::MlCandidateChannel::Pattern,
            ml_weight,
            min_confidence_floor,
            is_named_detector,
            is_generic_detector,
            allow_canonical_hex_key,
            allow_encoded_text_lift,
            checksum,
            ml_mode,
        }
    }

    #[cfg(feature = "entropy")]
    pub(crate) fn entropy_candidate(
        pending_raw_match: PendingRawMatch,
        heuristic_conf: f64,
        context_multiplier: f64,
        context_suppression_threshold: Option<f64>,
        post_match: keyhog_core::DetectorPostMatchConfidenceSpec,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        allow_canonical_hex_key: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) -> Self {
        Self {
            pending_raw_match,
            heuristic_conf,
            code_context: crate::context::CodeContext::Unknown,
            context_multiplier,
            context_suppression_threshold,
            post_match,
            ml_features,
            channel: crate::ml_scorer::MlCandidateChannel::Entropy,
            ml_weight,
            min_confidence_floor,
            is_named_detector: false,
            is_generic_detector: true,
            allow_canonical_hex_key,
            allow_encoded_text_lift: false,
            checksum,
            ml_mode,
        }
    }
}

#[cfg(feature = "ml")]
impl MlPendingMatch {
    fn has_same_execution_as(&self, other: &Self) -> bool {
        self.channel == other.channel
            && self.code_context == other.code_context
            && self.context_multiplier.to_bits() == other.context_multiplier.to_bits()
            && self.context_suppression_threshold.map(f64::to_bits)
                == other.context_suppression_threshold.map(f64::to_bits)
            && post_match_execution_eq(self.post_match, other.post_match)
            && self.ml_features == other.ml_features
            && self.ml_weight.to_bits() == other.ml_weight.to_bits()
            && self.min_confidence_floor.to_bits() == other.min_confidence_floor.to_bits()
            && self.is_named_detector == other.is_named_detector
            && self.is_generic_detector == other.is_generic_detector
            && self.allow_canonical_hex_key == other.allow_canonical_hex_key
            && self.allow_encoded_text_lift == other.allow_encoded_text_lift
            && self.checksum == other.checksum
            && self.ml_mode == other.ml_mode
    }
}

#[cfg(feature = "ml")]
fn post_match_execution_eq(
    left: keyhog_core::DetectorPostMatchConfidenceSpec,
    right: keyhog_core::DetectorPostMatchConfidenceSpec,
) -> bool {
    left.placeholder_multiplier.to_bits() == right.placeholder_multiplier.to_bits()
        && left.minimum_byte_diversity.to_bits() == right.minimum_byte_diversity.to_bits()
        && left.low_diversity_multiplier.to_bits() == right.low_diversity_multiplier.to_bits()
        && left.maximum_repeat_ratio.to_bits() == right.maximum_repeat_ratio.to_bits()
        && left.degenerate_run_min_length == right.degenerate_run_min_length
        && left.degenerate_repeat_multiplier.to_bits()
            == right.degenerate_repeat_multiplier.to_bits()
        && left.data_envelope_multiplier.map(f64::to_bits)
            == right.data_envelope_multiplier.map(f64::to_bits)
        && left.fixture_path_multiplier.to_bits() == right.fixture_path_multiplier.to_bits()
        && left.ml_context_reapply_below.to_bits() == right.ml_context_reapply_below.to_bits()
}

#[cfg(feature = "ml")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PendingMatchIdentity {
    detector_id: Arc<str>,
    credential: SensitiveString,
    offset: usize,
    channel: crate::ml_scorer::MlCandidateChannel,
}

#[cfg(feature = "ml")]
impl From<&MlPendingMatch> for PendingMatchIdentity {
    fn from(pending: &MlPendingMatch) -> Self {
        Self {
            detector_id: pending.pending_raw_match.detector_id.clone(),
            credential: pending.pending_raw_match.credential.clone(),
            offset: pending.pending_raw_match.location.offset,
            channel: pending.channel,
        }
    }
}

/// Borrowed ordering key for a `RawMatch` candidate.
///
/// Hot emitters can decide whether a candidate can enter the capped match heap
/// before constructing the owned `RawMatch`, avoiding detector metadata
/// refcount bumps for candidates that would be immediately discarded.
#[cfg(any(feature = "entropy", test))]
pub(crate) struct RawMatchPriority<'a> {
    pub(crate) confidence: Option<f64>,
    pub(crate) severity: keyhog_core::Severity,
    pub(crate) detector_id: &'a str,
    pub(crate) credential: &'a str,
    pub(crate) offset: usize,
    pub(crate) line: Option<usize>,
}

#[cfg(any(feature = "entropy", test))]
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

fn raw_match_identity_cmp(
    a: &keyhog_core::RawMatch,
    b: &keyhog_core::RawMatch,
) -> std::cmp::Ordering {
    MatchIdentity::from(a).cmp(&MatchIdentity::from(b))
}

fn same_raw_match_identity(a: &keyhog_core::RawMatch, b: &keyhog_core::RawMatch) -> bool {
    MatchIdentity::from(a) == MatchIdentity::from(b)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MatchIdentity<'a> {
    detector_id: &'a str,
    credential: &'a str,
    offset: usize,
}

impl<'a> From<&'a keyhog_core::RawMatch> for MatchIdentity<'a> {
    fn from(raw_match: &'a keyhog_core::RawMatch) -> Self {
        Self {
            detector_id: raw_match.detector_id.as_ref(),
            credential: raw_match.credential.as_ref(),
            offset: raw_match.location.offset,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct OwnedMatchIdentity {
    detector_id: Arc<str>,
    credential: SensitiveString,
    offset: usize,
}

impl From<&keyhog_core::RawMatch> for OwnedMatchIdentity {
    fn from(raw_match: &keyhog_core::RawMatch) -> Self {
        Self {
            detector_id: raw_match.detector_id.clone(),
            credential: raw_match.credential.clone(),
            offset: raw_match.location.offset,
        }
    }
}

impl OwnedMatchIdentity {
    /// Zero-alloc identity equality against a live match. Compares the exact
    /// three fields `From<&RawMatch>` builds and the derived `Eq` checks
    /// (`SensitiveString::eq` is itself `as_str() == as_str()`), but borrows the
    /// credential as `&str` instead of cloning its `SensitiveString`: a heap
    /// allocation + zeroize-on-drop, for every element compared on the
    /// claim/replace path (`.any`/`.position`/`.find` over the whole match heap).
    fn matches_raw(&self, m: &keyhog_core::RawMatch) -> bool {
        self.offset == m.location.offset
            && self.detector_id.as_ref() == m.detector_id.as_ref()
            && self.credential.as_ref() == m.credential.as_ref()
    }
}

impl OwnedMatchIdentity {
    #[cfg(any(feature = "entropy", test))]
    fn from_priority(priority: &RawMatchPriority<'_>) -> Self {
        Self {
            detector_id: Arc::from(priority.detector_id),
            credential: SensitiveString::from(priority.credential),
            offset: priority.offset,
        }
    }
}

/// A finalized public finding paired with scanner-internal producer provenance.
///
/// Ordering deliberately delegates to `RawMatch`, preserving the exact heap,
/// cap, deduplication, and output behavior that predates provenance retention.
#[derive(Clone)]
pub(crate) struct AttributedRawMatch {
    raw: keyhog_core::RawMatch,
    pub(crate) provenance: CandidateProvenance,
}

impl AttributedRawMatch {
    pub(crate) fn new(raw: keyhog_core::RawMatch, provenance: CandidateProvenance) -> Self {
        debug_assert!(provenance.is_well_formed());
        Self { raw, provenance }
    }

    pub(crate) fn into_raw(self) -> keyhog_core::RawMatch {
        let Self { raw, provenance } = self;
        debug_assert!(provenance.is_well_formed());
        raw
    }
}

impl std::ops::Deref for AttributedRawMatch {
    type Target = keyhog_core::RawMatch;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl PartialEq for AttributedRawMatch {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for AttributedRawMatch {}

impl PartialOrd for AttributedRawMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AttributedRawMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

/// Internal state for a single scan operation.
#[derive(Default)]
pub(crate) struct ScanState {
    /// Matches collected for this chunk, prioritized by confidence.
    /// `RawMatch::Ord` sorts best findings first (`best < worst`), so the
    /// BinaryHeap root is the worst retained finding and can be replaced when a
    /// better candidate arrives after the cap is full.
    pub(crate) matches: BinaryHeap<AttributedRawMatch>,
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
    /// `StaticInterner` handles every
    /// `(detector_id, detector_name, service, source_type)` lookup
    /// without per-scan allocation.
    pub(crate) metadata_interner: HashSet<Arc<str>>,
    /// Finding identities already accepted in this scan state. The simdsieve
    /// hot-prefix lane and confirmed regex lane can both prove the same
    /// canonical detector candidate; the first accepted identity owns the heap
    /// slot so duplicates cannot consume `max_matches_per_chunk` capacity before
    /// final output deduplication runs.
    claimed_match_identities: HashSet<OwnedMatchIdentity>,
    /// Count of successful `push_match` accepts (including in-place heap
    /// replacements and same-identity upgrades). Heap `len()` alone cannot
    /// detect stage progress once `max_matches_per_chunk` is reached.
    pub(crate) accepted_match_events: u64,
    /// Optional reference to the scanner's frozen static-string
    /// interner. When `Some`, `intern_metadata` checks here first
    /// before falling through to the per-scan `metadata_interner`.
    /// Lock-free on read so concurrent rayon workers share one
    /// instance without contention.
    pub(crate) static_intern: Option<Arc<crate::static_intern::StaticInterner>>,
    /// Detector matches queued for batch ML scoring at the end of the scan.
    #[cfg(feature = "ml")]
    pub(crate) ml_pending: Vec<MlPendingMatch>,
    /// Indexes the latest pending row for an identity without retaining a
    /// second plaintext credential. Exact credential and policy equality are
    /// still checked before a row is replaced.
    #[cfg(feature = "ml")]
    ml_pending_index: HashMap<PendingMatchIdentity, usize>,
    /// Successful ML-pending accepts, including in-place identity upgrades.
    #[cfg(feature = "ml")]
    pub(crate) accepted_ml_events: u64,
}

/// Borrowed identity view shared by finalized and ML-pending candidates.
pub(crate) struct ProducedMatchRef<'a> {
    pub(crate) detector_id: &'a str,
    pub(crate) offset: usize,
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
    ///   1. Scanner-wide `StaticInterner` for
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

    #[cfg(feature = "ml")]
    pub(crate) fn push_detector_ml_pending(
        &mut self,
        pending_raw_match: PendingRawMatch,
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        context_multiplier: f64,
        context_suppression_threshold: Option<f64>,
        post_match: keyhog_core::DetectorPostMatchConfidenceSpec,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        is_named_detector: bool,
        is_generic_detector: bool,
        allow_canonical_hex_key: bool,
        allow_encoded_text_lift: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) -> bool {
        self.push_ml_pending(MlPendingMatch::detector_candidate(
            pending_raw_match,
            heuristic_conf,
            code_context,
            context_multiplier,
            context_suppression_threshold,
            post_match,
            ml_features,
            ml_weight,
            min_confidence_floor,
            is_named_detector,
            is_generic_detector,
            allow_canonical_hex_key,
            allow_encoded_text_lift,
            checksum,
            ml_mode,
        ))
    }

    #[cfg(all(feature = "ml", feature = "entropy"))]
    pub(crate) fn push_entropy_ml_pending(
        &mut self,
        pending_raw_match: PendingRawMatch,
        heuristic_conf: f64,
        context_multiplier: f64,
        context_suppression_threshold: Option<f64>,
        post_match: keyhog_core::DetectorPostMatchConfidenceSpec,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        allow_canonical_hex_key: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) -> bool {
        self.push_ml_pending(MlPendingMatch::entropy_candidate(
            pending_raw_match,
            heuristic_conf,
            context_multiplier,
            context_suppression_threshold,
            post_match,
            ml_features,
            ml_weight,
            min_confidence_floor,
            allow_canonical_hex_key,
            checksum,
            ml_mode,
        ))
    }

    #[cfg(feature = "ml")]
    fn push_ml_pending(&mut self, candidate: MlPendingMatch) -> bool {
        let identity = PendingMatchIdentity::from(&candidate);
        if let Some(&index) = self.ml_pending_index.get(&identity) {
            let existing = &mut self.ml_pending[index];
            if candidate
                .pending_raw_match
                .same_identity(&existing.pending_raw_match)
                && candidate.has_same_execution_as(existing)
            {
                // Retain the same complete pending record `RawMatch::Ord` would
                // choose, without constructing or hashing either candidate.
                if candidate.pending_raw_match.cmp_with_confidence(
                    candidate.heuristic_conf,
                    &existing.pending_raw_match,
                    existing.heuristic_conf,
                ) == std::cmp::Ordering::Less
                {
                    *existing = candidate;
                    self.accepted_ml_events = self.accepted_ml_events.saturating_add(1);
                    return true;
                }
                return false;
            }
        }

        let index = self.ml_pending.len();
        self.ml_pending.push(candidate);
        self.ml_pending_index.insert(identity, index);
        self.accepted_ml_events = self.accepted_ml_events.saturating_add(1);
        true
    }

    #[cfg(feature = "ml")]
    pub(crate) fn take_ml_pending(&mut self) -> Vec<MlPendingMatch> {
        self.ml_pending_index.clear();
        std::mem::take(&mut self.ml_pending)
    }

    #[cfg(all(feature = "ml", feature = "entropy"))]
    pub(crate) fn for_each_pre_entropy_pending_ml_line<F>(&self, mut visit: F)
    where
        F: FnMut(Option<usize>),
    {
        for pending in &self.ml_pending {
            // This is called before phase-2 entropy can queue candidates, so
            // every pending row is an existing pattern/generic finding.
            visit(pending.pending_raw_match.location.line);
        }
    }

    /// Visit every candidate already produced by a pre-ML scanner stage.
    /// Confirmed extraction uses this after the hot-prefix lane, when a valid
    /// hot finding may live in either the final heap or the ML queue. Keeping
    /// both stores behind this boundary prevents a queued candidate from being
    /// extracted and featurized a second time before batch inference.
    pub(crate) fn for_each_produced_match<F>(&self, mut visit: F)
    where
        F: FnMut(ProducedMatchRef<'_>),
    {
        for found in &self.matches {
            visit(ProducedMatchRef {
                detector_id: found.detector_id.as_ref(),
                offset: found.location.offset,
            });
        }
        #[cfg(feature = "ml")]
        for pending in &self.ml_pending {
            visit(ProducedMatchRef {
                detector_id: pending.pending_raw_match.detector_id.as_ref(),
                offset: pending.pending_raw_match.location.offset,
            });
        }
    }

    /// Compatibility insertion for callers that do not own producer provenance.
    /// Production candidate lanes must use `push_match_with_provenance`.
    pub(crate) fn push_unattributed_match(
        &mut self,
        raw: keyhog_core::RawMatch,
        limit: usize,
    ) -> bool {
        self.push_match_with_provenance(raw, CandidateProvenance::unattributed(), limit)
    }

    pub(crate) fn push_match_with_provenance(
        &mut self,
        raw: keyhog_core::RawMatch,
        provenance: CandidateProvenance,
        limit: usize,
    ) -> bool {
        let candidate = AttributedRawMatch::new(raw, provenance);
        self.push_attributed_match(candidate, limit)
    }

    pub(crate) fn push_attributed_match(
        &mut self,
        candidate: AttributedRawMatch,
        limit: usize,
    ) -> bool {
        let identity = OwnedMatchIdentity::from(&*candidate);
        if self.claimed_match_identities.contains(&identity) {
            let accepted = self.replace_claimed_match_if_better(&identity, candidate);
            if accepted {
                self.accepted_match_events = self.accepted_match_events.saturating_add(1);
            }
            return accepted;
        }

        if self.matches.len() < limit {
            self.claimed_match_identities.insert(identity);
            self.matches.push(candidate);
            self.accepted_match_events = self.accepted_match_events.saturating_add(1);
            return true;
        }

        if let Some(mut worst) = self.matches.peek_mut() {
            if candidate < *worst {
                let displaced = OwnedMatchIdentity::from(&**worst);
                *worst = candidate;
                drop(worst);
                self.claimed_match_identities.remove(&displaced);
                self.claimed_match_identities.insert(identity);
                self.accepted_match_events = self.accepted_match_events.saturating_add(1);
                return true;
            }
        }

        false
    }
    fn replace_claimed_match_if_better(
        &mut self,
        identity: &OwnedMatchIdentity,
        candidate: AttributedRawMatch,
    ) -> bool {
        let should_replace = self
            .matches
            .iter()
            .any(|existing| identity.matches_raw(existing) && candidate < *existing);
        if !should_replace {
            return false;
        }

        let mut data = std::mem::take(&mut self.matches).into_vec();
        let idx = data
            .iter()
            .position(|existing| identity.matches_raw(existing))
            .expect("identity in claimed_match_identities implies heap entry");
        data[idx] = candidate;
        // `BinaryHeap::from` re-heapifies the whole vec (O(n) rebuild), so a manual
        // sift here would be thrown away (let `from` restore heap order).
        self.matches = BinaryHeap::from(data);
        true
    }

    #[cfg(any(feature = "entropy", test))]
    fn claimed_priority_would_replace(
        &self,
        identity: &OwnedMatchIdentity,
        priority: &RawMatchPriority<'_>,
    ) -> bool {
        self.matches
            .iter()
            .find(|existing| identity.matches_raw(existing))
            .is_none_or(|existing| !priority.cmp_raw_match(existing).is_gt())
    }

    #[cfg(any(feature = "entropy", test))]
    pub(crate) fn push_unattributed_match_lazy<F>(
        &mut self,
        priority: RawMatchPriority<'_>,
        limit: usize,
        build: F,
    ) where
        F: FnOnce(&mut Self) -> keyhog_core::RawMatch,
    {
        self.push_match_lazy_with_provenance(
            priority,
            CandidateProvenance::unattributed(),
            limit,
            build,
        );
    }

    #[cfg(any(feature = "entropy", test))]
    pub(crate) fn push_match_lazy_with_provenance<F>(
        &mut self,
        priority: RawMatchPriority<'_>,
        provenance: CandidateProvenance,
        limit: usize,
        build: F,
    ) where
        F: FnOnce(&mut Self) -> keyhog_core::RawMatch,
    {
        if limit == 0 {
            return;
        }
        if self.matches.len() >= limit
            && self
                .matches
                .peek()
                .is_some_and(|worst| priority.cmp_raw_match(worst).is_gt())
        {
            return;
        }

        let identity = OwnedMatchIdentity::from_priority(&priority);
        if self.claimed_match_identities.contains(&identity) {
            if !self.claimed_priority_would_replace(&identity, &priority) {
                return;
            }
            let candidate = AttributedRawMatch::new(build(self), provenance);
            if self.replace_claimed_match_if_better(&identity, candidate) {
                self.accepted_match_events = self.accepted_match_events.saturating_add(1);
            }
            return;
        }

        if self.matches.len() < limit {
            let candidate = AttributedRawMatch::new(build(self), provenance);
            self.claimed_match_identities.insert(identity);
            self.matches.push(candidate);
            self.accepted_match_events = self.accepted_match_events.saturating_add(1);
            return;
        }

        let candidate = AttributedRawMatch::new(build(self), provenance);
        if let Some(mut worst) = self.matches.peek_mut() {
            if candidate < *worst {
                let displaced = OwnedMatchIdentity::from(&**worst);
                *worst = candidate;
                drop(worst);
                self.claimed_match_identities.remove(&displaced);
                self.claimed_match_identities.insert(identity);
                self.accepted_match_events = self.accepted_match_events.saturating_add(1);
            }
        }
    }

    /// Drain all matches into the unchanged public finding vector.
    /// The ABI projection moves owned handles; it does not clone credential bytes.
    pub(crate) fn into_matches(self) -> Vec<keyhog_core::RawMatch> {
        self.into_attributed_matches()
            .into_iter()
            .map(AttributedRawMatch::into_raw)
            .collect()
    }

    /// Drain matches while retaining secret-safe producer provenance.
    pub(crate) fn into_attributed_matches(self) -> Vec<AttributedRawMatch> {
        let mut matches = self.matches.into_vec();
        if matches.len() <= 1 {
            return matches;
        }
        // Identity-first ordering makes equal identities adjacent; the best-first
        // tiebreak retains the same winner regardless of unstable sort order.
        matches.sort_unstable_by(|a, b| raw_match_identity_cmp(&**a, &**b).then_with(|| a.cmp(b)));
        matches.dedup_by(|a, b| same_raw_match_identity(&**a, &**b));
        matches.sort_unstable();
        matches
    }
}
