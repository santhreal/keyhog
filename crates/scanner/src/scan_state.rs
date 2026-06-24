//! Runtime state for one scan operation.
//!
//! Configuration lives in `scanner_config`; this module owns the per-scan
//! match heap, credential/metadata interners, and ML batch queue.

use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;

use keyhog_core::SensitiveString;

#[cfg(feature = "ml")]
pub(crate) fn ml_context_for_candidate(text: &str, line: usize, file_path: Option<&str>) -> String {
    let text_context =
        crate::pipeline::local_context_window(text, line, crate::types::ML_CONTEXT_RADIUS_LINES);
    match file_path {
        Some(path) => format!("file:{path}\n{text_context}"),
        None => text_context.to_string(),
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
    /// Confidence floor that applies to this pending candidate after ML blending.
    pub(crate) min_confidence_floor: f64,
    /// Whether the original producer classified this as a named detector after
    /// applying weak-anchor exclusions.
    pub(crate) is_named_detector: bool,
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

#[cfg(feature = "ml")]
impl MlPendingMatch {
    pub(crate) fn detector_candidate(
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: String,
        ml_context: String,
        min_confidence_floor: f64,
        is_named_detector: bool,
    ) -> Self {
        Self {
            raw_match,
            heuristic_conf,
            code_context,
            credential,
            ml_context,
            min_confidence_floor,
            is_named_detector,
            model_authoritative: false,
        }
    }

    pub(crate) fn entropy_authoritative(
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        credential: String,
        ml_context: String,
        min_confidence_floor: f64,
    ) -> Self {
        Self {
            raw_match,
            heuristic_conf,
            code_context: crate::context::CodeContext::Unknown,
            credential,
            ml_context,
            min_confidence_floor,
            is_named_detector: false,
            model_authoritative: true,
        }
    }
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

/// Internal state for a single scan operation.
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
    /// Absolute file offsets already claimed by the Stripe secret-key detector
    /// in this scan state. The simdsieve hot-prefix lane and confirmed regex
    /// lane can both prove the same `sk_live_` start; the first accepted
    /// canonical detector candidate owns that start so fallback verifier walks
    /// cannot re-emit an overlapping Stripe finding at the same byte.
    pub(crate) stripe_secret_key_offsets: HashSet<usize>,
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

    pub(crate) fn claim_stripe_secret_key_offset(
        &mut self,
        detector_id: &str,
        absolute_offset: usize,
    ) -> bool {
        if detector_id != crate::detector_ids::STRIPE_SECRET_KEY {
            return true;
        }
        self.stripe_secret_key_offsets.insert(absolute_offset)
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
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: String,
        ml_context: String,
        min_confidence_floor: f64,
        is_named_detector: bool,
    ) {
        self.ml_pending.push(MlPendingMatch::detector_candidate(
            raw_match,
            heuristic_conf,
            code_context,
            credential,
            ml_context,
            min_confidence_floor,
            is_named_detector,
        ));
    }

    #[cfg(feature = "ml")]
    pub(crate) fn push_entropy_authoritative_ml_pending(
        &mut self,
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        credential: String,
        ml_context: String,
        min_confidence_floor: f64,
    ) {
        self.ml_pending.push(MlPendingMatch::entropy_authoritative(
            raw_match,
            heuristic_conf,
            credential,
            ml_context,
            min_confidence_floor,
        ));
    }

    #[cfg(feature = "ml")]
    pub(crate) fn extend_lines_with_pending_ml_matches(&self, lines: &mut HashSet<usize>) {
        lines.extend(
            self.ml_pending
                .iter()
                .filter_map(|pending| pending.raw_match.location.line),
        );
    }

    #[cfg(feature = "ml")]
    pub(crate) fn for_each_named_pending_ml_line<F>(&self, mut visit: F)
    where
        F: FnMut(Option<usize>),
    {
        for pending in &self.ml_pending {
            let id = &*pending.raw_match.detector_id;
            if !crate::detector_ids::is_generic_or_entropy_detector(id) {
                visit(pending.raw_match.location.line);
            }
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
        // Stable, allocation-free identity grouping. The Vec is already sorted
        // best-first above; stable `sort_by` grouping on the borrowed identity
        // fields preserves that best-first order within each duplicate run, so
        // `dedup_by` keeps the highest-confidence entry. A final `sort()`
        // restores canonical output order.
        matches.sort_by(raw_match_identity_cmp);
        matches.dedup_by(|a, b| same_raw_match_identity(a, b));
        matches.sort();
        matches
    }
}
