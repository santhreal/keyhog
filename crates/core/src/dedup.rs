//! Match deduplication: group raw matches by detector, credential, and optional
//! scan scope.
//!
//! This module provides the canonical [`DedupedMatch`] type and
//! [`dedup_matches`] function. The full finding-identity taxonomy is documented
//! in `docs/ARCHITECTURE.md` under "Finding identity and dedup"; keep this
//! module focused on operator-visible report grouping, not window-overlap raw
//! hit dedup.

use indexmap::{Equivalent, IndexMap, IndexSet};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use crate::{sha256_hash, CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity};

/// Count of times [`dedup_cross_detector`] reached the (guard-impossible) empty
/// singleton-group branch, where a finding would otherwise vanish from the
/// report. Stays 0 in all correct runs; a non-zero value is a recall bug to
/// investigate.
pub(crate) static DEDUP_LOST_SINGLETON: AtomicU64 = AtomicU64::new(0);

/// Deduplication scope for grouping findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupScope {
    /// No deduplication: every raw match is reported as a unique finding.
    None,
    /// Deduplicate within each file: same secret in same file is one finding.
    File,
    /// Deduplicate across entire scan: same secret across all files is one finding.
    Credential,
}

/// A group of related raw matches representing a single distinct secret finding.
///
/// Manual `Debug` impl redacts the `credential` field - the previous
/// derive-`Debug` was a CRITICAL leak vector (kimi-wave1 audit finding 1.2).
#[derive(Clone, Serialize)]
pub struct DedupedMatch {
    /// Stable detector identifier.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub detector_id: Arc<str>,
    /// Human-readable detector name.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub detector_name: Arc<str>,
    /// Service namespace associated with the detector.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub service: Arc<str>,
    /// Severity preserved from the original match.
    pub severity: Severity,
    /// Unredacted credential for verification.
    pub credential: SensitiveString,
    /// SHA-256 hash of the original credential for internal correlation.
    /// Named credential digest for suppression, correlation, and reporting.
    pub credential_hash: CredentialHash,
    /// Optional companion credentials extracted nearby.
    #[serde(serialize_with = "serialize_companions_sorted")]
    pub companions: HashMap<String, String>,
    /// Primary source location.
    pub primary_location: MatchLocation,
    /// Additional duplicate locations.
    pub additional_locations: Vec<MatchLocation>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    pub confidence: Option<f64>,
}

impl std::fmt::Debug for DedupedMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupedMatch")
            .field("detector_id", &self.detector_id)
            .field("detector_name", &self.detector_name)
            .field("service", &self.service)
            .field("severity", &self.severity)
            .field(
                "credential",
                &format_args!("<redacted {} bytes>", self.credential.len()),
            )
            .field(
                "credential_hash",
                &crate::finding::hex_encode(self.credential_hash),
            )
            .field(
                "companions",
                &format_args!("<{} redacted companions>", self.companions.len()),
            )
            .field("primary_location", &self.primary_location)
            .field("additional_locations", &self.additional_locations)
            .field("confidence", &self.confidence)
            .finish()
    }
}

/// Deduplicate raw matches according to the given [`DedupScope`].
pub fn dedup_matches(matches: Vec<RawMatch>, scope: &DedupScope) -> Vec<DedupedMatch> {
    if *scope == DedupScope::None {
        return matches
            .into_iter()
            .map(|m| {
                let credential_hash =
                    effective_credential_hash(m.credential.as_ref(), m.credential_hash);
                DedupedMatch {
                    detector_id: m.detector_id,
                    detector_name: m.detector_name,
                    service: m.service,
                    severity: m.severity,
                    credential: m.credential,
                    credential_hash,
                    companions: m.companions,
                    primary_location: m.location,
                    additional_locations: Vec::new(),
                    confidence: m.confidence,
                }
            })
            .collect();
    }

    // IndexMap (not HashMap or BTreeMap) for the best of both worlds: O(1)
    // amortized insert like HashMap PLUS deterministic iteration order
    // (insertion order, which we sort post-pass for cross-run stability).
    // BTreeMap was O(log N) per insert and dominated dedup time on 1M+
    // matches - see docs/EXECUTION_PLAN.md.
    type DedupKey = (Arc<str>, SensitiveString, Option<FileScopeIdentity>);

    // O(1) per-match membership for additional_locations. The duplicate arm
    // used to run `existing.additional_locations.iter().any(is_same_location)`
    // once per duplicate, so a single (detector, credential, file) group of K
    // matches on K distinct lines (a generated credentials dump, an exported
    // .env, a .tfvars, a config with one token repeated per stanza) cost
    // 0+1+...+(K-1) = K(K-1)/2 = O(K^2) location comparisons, unbounded by the
    // per-chunk recall budget. Each group instead carries a HashSet of the
    // location-identity tuples (source, file_path, line, commit) it has already
    // recorded - the SAME identity `is_same_location` compares - keyed by the
    // group's slot in `groups`. Insert-returns-false is the exact negation of
    // the prior `.any()` scan, so output is byte-identical: a location is added
    // to additional_locations iff it differs from the primary AND from every
    // already-recorded additional, now in O(1) instead of O(K). Turns a
    // K-repeat group from O(K^2) to O(K).
    // Sort by offset ascending so that for any group of (detector, credential,
    // file) matches the LOWEST offset becomes the primary_location and any
    // higher-offset duplicates land in additional_locations (or get
    // suppressed by the same-(file, line) guard below). Without this the
    // structured-preprocessor synthetic-line alias of a match arrives in
    // raw-vec order: parallel rayon scans can produce that alias FIRST,
    // making "primary at offset 80 in a 51-byte file" the report. Sorting
    // by offset is O(N log N) instead of O(N) but N is bounded by the
    // detector recall budget (max_matches_per_chunk) so the cost is small
    // compared to extract_matches and ML scoring. Cross-file scope keeps
    // the same group key so per-file primary selection picks the smallest
    // offset per file independently. #16 regression: hot-github_pat
    // primary at offset 79 in a 64-byte file.
    let mut matches = matches;
    let match_count = matches.len();
    let mut groups: IndexMap<DedupKey, DedupedMatch> = IndexMap::with_capacity(match_count);
    let mut seen_locations: Vec<IndexSet<LocationIdentity>> = Vec::with_capacity(match_count);
    matches.sort_by(|a, b| {
        a.location
            .file_path
            .cmp(&b.location.file_path)
            .then_with(|| a.location.offset.cmp(&b.location.offset))
            .then_with(|| a.location.line.cmp(&b.location.line))
            .then_with(|| a.location.source.cmp(&b.location.source))
            .then_with(|| a.location.commit.cmp(&b.location.commit))
            .then_with(|| a.detector_id.cmp(&b.detector_id))
            .then_with(|| a.credential.cmp(&b.credential))
    });

    for matched in matches {
        let detector_id_arc = Arc::clone(&matched.detector_id);
        let credential = matched.credential.clone();

        let key: DedupKey = match scope {
            DedupScope::Credential => (detector_id_arc, credential, None),
            DedupScope::File => {
                let file = Some(file_scope_identity(&matched.location));
                (detector_id_arc, credential, file)
            }
            DedupScope::None => continue,
        };

        match groups.get_full_mut(&key) {
            Some((idx, _, existing)) => {
                if is_decoder_alias_pair(&existing.primary_location, &matched.location) {
                    if is_decoder_location(&existing.primary_location)
                        && !is_decoder_location(&matched.location)
                    {
                        // The primary's identity changes; keep the seen-set in
                        // sync so a later true duplicate of the new primary is
                        // still recognized as same-as-primary (the
                        // is_same_location(primary, ...) guard below handles it,
                        // but recording it keeps the set a faithful mirror).
                        let seen = &mut seen_locations[idx];
                        seen.shift_remove(&location_identity_ref(&existing.primary_location));
                        seen.insert(location_identity(&matched.location));
                        existing.primary_location = matched.location;
                    }
                    merge_companions(&mut existing.companions, matched.companions);
                    existing.confidence = max_confidence(existing.confidence, matched.confidence);
                    continue;
                }
                // Drop locations that are the same (file_path, line) as the
                // primary OR any already-recorded additional. They are the
                // structured-preprocessor synthetic alias of an original
                // match: build_preprocessed_text appends a `"key: value"`
                // line after the original chunk text so detectors that
                // need keyword context still see the value. The regex
                // then fires twice on the same value - once at the real
                // offset, once at original_end+offset_within_synthetic
                // (past EOF on a single-line .env file). #16 regression:
                // single-secret .env reported `+1 more locations` at
                // offset 80 in a 51-byte file. Same (file, line) implies
                // same finding; the synthetic match adds no signal.
                //
                // Membership is O(1) via the per-group seen-locations set
                // (initialized with the primary's identity), so a K-repeat
                // group is O(K) instead of the old O(K^2) `.any()` sweep. The
                // set insert returns false exactly when the identity already
                // exists (primary OR a prior additional), reproducing the old
                // two-part guard with identical output.
                if insert_new_location_identity(&mut seen_locations[idx], &matched.location) {
                    existing.additional_locations.push(matched.location);
                }
                merge_companions(&mut existing.companions, matched.companions);
                existing.confidence = max_confidence(existing.confidence, matched.confidence);
            }
            None => {
                let mut seen = IndexSet::with_capacity(1);
                seen.insert(location_identity(&matched.location));
                let credential_hash =
                    effective_credential_hash(matched.credential.as_ref(), matched.credential_hash);
                groups.insert(
                    key,
                    DedupedMatch {
                        detector_id: matched.detector_id,
                        detector_name: matched.detector_name,
                        service: matched.service,
                        severity: matched.severity,
                        credential: matched.credential,
                        credential_hash,
                        companions: matched.companions,
                        primary_location: matched.location,
                        additional_locations: Vec::new(),
                        confidence: matched.confidence,
                    },
                );
                // groups.insert on a fresh key appends at the tail, so the new
                // group's slot index is the prior length - keep seen_locations
                // index-aligned with the IndexMap.
                debug_assert_eq!(seen_locations.len(), groups.len() - 1);
                seen_locations.push(seen);
            }
        }
    }

    // Sort by key for cross-run determinism (the IndexMap iteration order is
    // insertion order, which depends on input ordering). SARIF fingerprints,
    // baselines, and CI diffs all need stable output across reruns.
    let mut deduped: Vec<(DedupKey, DedupedMatch)> = groups.into_iter().collect();
    deduped.sort_by(|a, b| a.0.cmp(&b.0));
    deduped.into_iter().map(|(_, v)| v).collect()
}

fn is_decoder_alias_pair(a: &MatchLocation, b: &MatchLocation) -> bool {
    if a.file_path != b.file_path || a.commit != b.commit {
        return false;
    }
    if is_decoder_location(a) == is_decoder_location(b) {
        return false;
    }
    match (a.line, b.line) {
        (Some(left), Some(right)) if left.abs_diff(right) <= 1 => return true,
        (Some(_), Some(_)) => return false,
        _ => {}
    }
    a.offset.abs_diff(b.offset) <= 16
}

fn serialize_companions_sorted<S>(
    companions: &HashMap<String, String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut entries: Vec<_> = companions.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (key, value) in entries {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

fn is_decoder_location(location: &MatchLocation) -> bool {
    const DECODER_SUFFIXES: &[&str] = &[
        "/base64", "/hex", "/url", "/json", "/z85", "/reverse", "/caesar",
    ];
    DECODER_SUFFIXES
        .iter()
        .any(|suffix| location.source.ends_with(suffix))
}

fn effective_credential_hash(credential: &str, credential_hash: CredentialHash) -> CredentialHash {
    if credential_hash.is_zero() {
        sha256_hash(credential)
    } else {
        credential_hash
    }
}

/// Cross-detector dedup at emit time.
///
/// One credential value commonly matches multiple detectors - `AIza...` keys
/// fire google-api, google-maps, google-places, google-translate; opaque
/// 32-hex strings fire entropy + several service-specific generic detectors.
/// The first-pass `dedup_matches` keeps each `(detector, credential)` pair
/// separate. This second pass groups the deduped Vec by `credential_hash`
/// and folds related detectors into the WINNING DedupedMatch's companions
/// map under a `cross_detector` namespace, so a reporter sees ONE finding
/// per credential with the alternate service guesses listed as evidence -
/// docs/EXECUTION_PLAN.md innovation #5, "Cuts noise ~30%".
///
/// The winning detector is chosen by:
///   1. Highest confidence (Some(f64)::total_cmp).
///   2. Highest severity.
///   3. Lexicographic detector_id (deterministic tiebreak).
///
/// Loser entries' detector_id, detector_name, and service are folded into
/// the winner's `companions` under keys like `cross_detector.0`,
/// `cross_detector.1`, ... in confidence-descending order.
pub fn dedup_cross_detector(deduped: Vec<DedupedMatch>) -> Vec<DedupedMatch> {
    if deduped.len() < 2 {
        return deduped;
    }

    // Group by (credential_hash, primary_location.file_path) - splitting by
    // file keeps file-scope dedup intact when the caller used DedupScope::File.
    type GroupKey = (CredentialHash, Option<Arc<str>>);
    let mut groups: IndexMap<GroupKey, Vec<DedupedMatch>> = IndexMap::with_capacity(deduped.len());
    for m in deduped {
        let key = (m.credential_hash, m.primary_location.file_path.clone());
        groups.entry(key).or_default().push(m);
    }

    let mut out: Vec<DedupedMatch> = Vec::with_capacity(groups.len());
    for (_, mut group) in groups {
        if group.len() == 1 {
            // Law 10: the `len() == 1` guard proves `pop()` is `Some`, so this is
            // not a silent drop today. But to be recall-safe against a future
            // guard refactor, the impossible `None` arm is made LOUD: a lost
            // dedup group would otherwise silently disappear a finding from the
            // report. We surface it (eprintln + counter) instead of skipping.
            match group.pop() {
                Some(only) => out.push(only),
                None => {
                    DEDUP_LOST_SINGLETON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "keyhog: BUG — dedup_cross_detector hit an empty group under \
                         a len()==1 guard; a finding may have been dropped. Please \
                         report this with the scanned input shape."
                    );
                }
            }
            continue;
        }
        // Sort: highest-confidence first, then severity desc, then detector_id
        // asc, then credential / credential_hash / offset so the order is TOTAL.
        // The winner is `group.remove(0)`; without the trailing keys, two
        // matches sharing (confidence, severity, detector_id) — e.g. the same
        // detector firing on two credentials at one (file, line, commit) scope —
        // compare Equal, so which becomes the primary (vs. a `cross_detector.*`
        // companion) is decided by input order, which is HashMap-iteration /
        // thread nondeterministic. A total key fixes the primary credential.
        group.sort_by(|a, b| {
            // A `None` confidence sorts as 0.0 (lowest) for winner selection — a
            // deterministic ordering choice, not a swallowed value; the
            // credential/hash/offset tiebreaks below keep the order TOTAL so no
            // finding is dropped or nondeterministically reordered.
            let ac = a.confidence.unwrap_or(0.0); // LAW10: sort default, see note above
            let bc = b.confidence.unwrap_or(0.0); // LAW10: sort default, see note above
            bc.total_cmp(&ac)
                .then_with(|| b.severity.cmp(&a.severity))
                .then_with(|| a.detector_id.cmp(&b.detector_id))
                .then_with(|| a.credential.cmp(&b.credential))
                .then_with(|| a.credential_hash.cmp(&b.credential_hash))
                .then_with(|| a.primary_location.offset.cmp(&b.primary_location.offset))
        });
        let mut winner = group.remove(0);
        let mut seen_locations = IndexSet::new();
        insert_new_location_identity(&mut seen_locations, &winner.primary_location);
        for loc in &winner.additional_locations {
            insert_new_location_identity(&mut seen_locations, loc);
        }
        for (idx, loser) in group.into_iter().enumerate() {
            let key = format!("cross_detector.{idx}");
            let value = format!(
                "{} ({}) [{}]",
                loser.service,
                loser.detector_name,
                loser
                    .confidence
                    .map(|c| format!("{c:.2}"))
                    .unwrap_or_else(|| "n/a".to_string()) // LAW10: display-only label for absent confidence in cross_detector evidence, no recall impact
            );
            winner.companions.entry(key).or_insert(value);
            merge_cross_detector_locations(&mut winner, &mut seen_locations, loser);
        }
        out.push(winner);
    }

    // Re-sort for cross-run determinism (insertion order is input-dependent).
    out.sort_by(|a, b| {
        a.detector_id
            .cmp(&b.detector_id)
            .then_with(|| a.credential_hash.cmp(&b.credential_hash))
    });
    out
}

fn merge_cross_detector_locations(
    winner: &mut DedupedMatch,
    seen_locations: &mut IndexSet<LocationIdentity>,
    loser: DedupedMatch,
) {
    if insert_new_location_identity(seen_locations, &loser.primary_location) {
        winner.additional_locations.push(loser.primary_location);
    }
    for loc in loser.additional_locations {
        if insert_new_location_identity(seen_locations, &loc) {
            winner.additional_locations.push(loc);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FileScopeIdentity {
    source: Arc<str>,
    file_path: Option<Arc<str>>,
    commit: Option<Arc<str>>,
}

fn file_scope_identity(location: &MatchLocation) -> FileScopeIdentity {
    FileScopeIdentity {
        source: Arc::clone(&location.source),
        file_path: location.file_path.clone(),
        commit: location.commit.clone(),
    }
}

/// The hashable identity `(source, file_path, line, commit)` that defines
/// when two locations are "the same finding" and must collapse. Offset is
/// intentionally excluded: the structured preprocessor's synthetic-line append
/// produces matches whose offset lies past the source file's EOF (the offset is
/// into final_text, not the original chunk text), but whose `line` field is
/// correctly remapped via LineMapping to the original source line. So
/// same-(file, line) means the dedupe SHOULD collapse them: emitting both as
/// "primary at line 1 offset 27" + "additional at line 1 offset 80 (past EOF)"
/// is a confusing duplicate, not two findings. Used as the per-group seen-set
/// element so additional_locations membership is O(1) instead of an O(K)
/// linear scan.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LocationIdentity {
    source: Arc<str>,
    file_path: Option<Arc<str>>,
    line: Option<usize>,
    commit: Option<Arc<str>>,
}

struct LocationIdentityRef<'a> {
    source: &'a str,
    file_path: Option<&'a str>,
    line: Option<usize>,
    commit: Option<&'a str>,
}

impl Hash for LocationIdentityRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.source.hash(state);
        self.file_path.hash(state);
        self.line.hash(state);
        self.commit.hash(state);
    }
}

impl Equivalent<LocationIdentity> for LocationIdentityRef<'_> {
    fn equivalent(&self, key: &LocationIdentity) -> bool {
        self.source == key.source.as_ref()
            && self.file_path == key.file_path.as_deref()
            && self.line == key.line
            && self.commit == key.commit.as_deref()
    }
}

fn location_identity(loc: &MatchLocation) -> LocationIdentity {
    LocationIdentity {
        source: Arc::clone(&loc.source),
        file_path: loc.file_path.clone(),
        line: loc.line,
        commit: loc.commit.clone(),
    }
}

fn location_identity_ref(loc: &MatchLocation) -> LocationIdentityRef<'_> {
    LocationIdentityRef {
        source: loc.source.as_ref(),
        file_path: loc.file_path.as_deref(),
        line: loc.line,
        commit: loc.commit.as_deref(),
    }
}

fn insert_new_location_identity(
    seen: &mut IndexSet<LocationIdentity>,
    location: &MatchLocation,
) -> bool {
    let identity = location_identity_ref(location);
    if seen.contains(&identity) {
        return false;
    }
    seen.insert(location_identity(location));
    true
}

fn merge_companions(existing: &mut HashMap<String, String>, incoming: HashMap<String, String>) {
    // Sort incoming by key so the merged " | "-delimited string is stable
    // across runs even though the existing field is a HashMap. Without this,
    // rerunning the same scan can produce different companion orderings.
    let mut sorted: Vec<(String, String)> = incoming.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in sorted {
        match existing.get_mut(&name) {
            Some(current) if current != &value => {
                let already_present = current
                    .split(" | ")
                    .any(|candidate| candidate == value.as_str());
                if !already_present {
                    current.push_str(" | ");
                    current.push_str(&value);
                }
            }
            Some(_) => {}
            None => {
                existing.insert(name, value);
            }
        }
    }
}

fn max_confidence(lhs: Option<f64>, rhs: Option<f64>) -> Option<f64> {
    match (lhs, rhs) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}
