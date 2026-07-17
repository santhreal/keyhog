//! Runtime state for one scan operation.
//!
//! Configuration lives in `scanner_config`; this module owns the per-scan
//! match heap, credential/metadata interners, and ML batch queue.

use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;

use keyhog_core::SensitiveString;
#[cfg(feature = "ml")]
use zeroize::Zeroize;

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
    let text_context = crate::pipeline::local_context_window(text, line, context_radius_lines);
    let compute = |context: &str| {
        crate::ml_scorer::ml_features::compute_features_for_compiled_detector_with_config(
            credential,
            context,
            &config.known_prefixes,
            &config.secret_keywords,
            &config.test_keywords,
            &config.placeholder_keywords,
            detector_service,
            detector_features,
            channel,
        )
    };
    let Some(path) = file_path else {
        return compute(text_context);
    };
    thread_local! {
        static CONTEXT: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
    }
    CONTEXT.with(|cell| {
        let mut context = cell.borrow_mut();
        context.clear();
        context.push_str("file:");
        context.push_str(path);
        context.push('\n');
        context.push_str(text_context);
        let features = compute(&context);
        context.zeroize();
        features
    })
}

/// Queued ML match waiting for batch inference at the end of a scan.
#[cfg(feature = "ml")]
#[derive(Debug, Clone)]
pub(crate) struct MlPendingMatch {
    /// The raw match built with heuristic confidence only.
    pub(crate) raw_match: keyhog_core::RawMatch,
    /// Heuristic confidence before detector-owned ML scoring.
    pub(crate) heuristic_conf: f64,
    /// Inferred code context for post-ML adjustments.
    pub(crate) code_context: crate::context::CodeContext,
    /// Exact serve-path features computed while source context is still local.
    pub(crate) ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
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
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
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
            raw_match,
            heuristic_conf,
            code_context,
            ml_features,
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
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        allow_canonical_hex_key: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) -> Self {
        Self {
            raw_match,
            heuristic_conf,
            code_context: crate::context::CodeContext::Unknown,
            ml_features,
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
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        is_named_detector: bool,
        is_generic_detector: bool,
        allow_canonical_hex_key: bool,
        allow_encoded_text_lift: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) {
        self.ml_pending.push(MlPendingMatch::detector_candidate(
            raw_match,
            heuristic_conf,
            code_context,
            ml_features,
            ml_weight,
            min_confidence_floor,
            is_named_detector,
            is_generic_detector,
            allow_canonical_hex_key,
            allow_encoded_text_lift,
            checksum,
            ml_mode,
        ));
    }

    #[cfg(all(feature = "ml", feature = "entropy"))]
    pub(crate) fn push_entropy_ml_pending(
        &mut self,
        raw_match: keyhog_core::RawMatch,
        heuristic_conf: f64,
        ml_features: [f32; crate::ml_scorer::NUM_FEATURES],
        ml_weight: f64,
        min_confidence_floor: f64,
        allow_canonical_hex_key: bool,
        checksum: crate::checksum::ChecksumConfidenceDecision,
        ml_mode: crate::detector_ml_policy::ActiveMlMode,
    ) {
        self.ml_pending.push(MlPendingMatch::entropy_candidate(
            raw_match,
            heuristic_conf,
            ml_features,
            ml_weight,
            min_confidence_floor,
            allow_canonical_hex_key,
            checksum,
            ml_mode,
        ));
    }

    #[cfg(all(feature = "ml", feature = "entropy"))]
    pub(crate) fn for_each_pre_entropy_pending_ml_line<F>(&self, mut visit: F)
    where
        F: FnMut(Option<usize>),
    {
        for pending in &self.ml_pending {
            // This is called before phase-2 entropy can queue candidates, so
            // every pending row is an existing pattern/generic finding.
            visit(pending.raw_match.location.line);
        }
    }

    /// Push a match to the state, maintaining priority and capacity.
    /// High-confidence secrets will displace lower-confidence findings.
    pub(crate) fn push_match(&mut self, m: keyhog_core::RawMatch, limit: usize) -> bool {
        let identity = OwnedMatchIdentity::from(&m);
        if self.claimed_match_identities.contains(&identity) {
            return self.replace_claimed_match_if_better(&identity, m);
        }

        if self.matches.len() < limit {
            self.claimed_match_identities.insert(identity);
            self.matches.push(m);
            return true;
        }

        if let Some(mut worst) = self.matches.peek_mut() {
            if m < *worst {
                let displaced = OwnedMatchIdentity::from(&*worst);
                *worst = m;
                drop(worst);
                self.claimed_match_identities.remove(&displaced);
                self.claimed_match_identities.insert(identity);
                return true;
            }
        }

        false
    }

    fn replace_claimed_match_if_better(
        &mut self,
        identity: &OwnedMatchIdentity,
        candidate: keyhog_core::RawMatch,
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
    pub(crate) fn push_match_lazy<F>(
        &mut self,
        priority: RawMatchPriority<'_>,
        limit: usize,
        build: F,
    ) where
        F: FnOnce(&mut Self) -> keyhog_core::RawMatch,
    {
        // Reject from borrowed priority fields before constructing the owned
        // identity. At capacity, a candidate whose priority prefix is already
        // worse than the heap root cannot beat any retained match, including a
        // duplicate of its identity. This keeps the overwhelmingly common
        // rejection path free of Arc/SensitiveString allocation.
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
            let m = build(self);
            self.replace_claimed_match_if_better(&identity, m);
            return;
        }

        if self.matches.len() < limit {
            let m = build(self);
            self.claimed_match_identities.insert(identity);
            self.matches.push(m);
            return;
        }

        // The borrowed cap check above proved this prefix can still win. Build
        // once so the full identity tiebreakers can decide the retained match.
        let m = build(self);
        if let Some(mut worst) = self.matches.peek_mut() {
            if m < *worst {
                let displaced = OwnedMatchIdentity::from(&*worst);
                *worst = m;
                drop(worst);
                self.claimed_match_identities.remove(&displaced);
                self.claimed_match_identities.insert(identity);
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
        // 0 or 1 match cannot contain a duplicate and is already in canonical
        // order, so skip all sorting and dedup work entirely - no scratch
        // buffer, no HashSet alloc, no refcount traffic - on the overwhelmingly
        // common small-chunk case.
        if matches.len() <= 1 {
            return matches;
        }
        // Group identical findings (same detector + credential + offset)
        // adjacently with the BEST finding first within each group, in a single
        // pass: `raw_match_identity_cmp` is the primary key and `RawMatch`'s
        // best-first `Ord` is the tiebreak. `dedup_by` then keeps the first of
        // each run - i.e. the highest-confidence entry per identity.
        //
        // `sort_unstable_by` is correct AND allocation-free here: the previous
        // code paid for a separate leading stable `sort()` purely to seed a
        // stable identity grouping (three sorts total, each allocating an ~n/2
        // merge buffer). Folding best-first into the comparator's tiebreak makes
        // the grouping order self-sufficient, so stability is no longer needed -
        // the only elements an unstable sort may reorder are those Equal under
        // the *total* comparator, which are identical findings and thus
        // dedup-interchangeable.
        matches.sort_unstable_by(|a, b| raw_match_identity_cmp(a, b).then_with(|| a.cmp(b)));
        matches.dedup_by(|a, b| same_raw_match_identity(a, b));
        // Restore canonical best-first output order across the now-unique
        // findings. After dedup every element has a distinct identity, and
        // `RawMatch::Ord` is total with respect to that identity (Ord-Equal
        // implies same detector+credential+offset), so no two survivors compare
        // Equal - the sorted order is uniquely determined and an unstable sort
        // yields byte-identical output to a stable one, without the scratch
        // allocation.
        matches.sort_unstable();
        matches
    }
}
