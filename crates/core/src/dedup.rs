//! Match deduplication: group raw matches by (detector, credential) with
//! configurable scope (credential-level, file-level, or no deduplication).
//!
//! This module provides the canonical [`DedupedMatch`] type and
//! [`dedup_matches`] function.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{MatchLocation, RawMatch, Severity};

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
    #[serde(with = "crate::finding::serde_arc_str")]
    pub credential: Arc<str>,
    /// SHA-256 hash of the original credential for internal correlation.
    /// Raw 32 bytes (matching `Finding`/`RawMatch`); hex at the serde boundary.
    #[serde(with = "crate::finding::serde_hash_hex")]
    pub credential_hash: [u8; 32],
    /// Optional companion credentials extracted nearby.
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
                &crate::finding::hex_encode(&self.credential_hash),
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
                let credential_hash = sha256_hash(&m.credential);
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
    // matches - see audits/legendary-2026-04-26.
    type DedupKey = (Arc<str>, Arc<str>, Option<Arc<str>>);
    let mut groups: IndexMap<DedupKey, DedupedMatch> = IndexMap::new();

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
        let credential_arc = Arc::clone(&matched.credential);

        let key: DedupKey = match scope {
            DedupScope::Credential => (detector_id_arc, credential_arc, None),
            DedupScope::File => {
                let file = Some(file_scope_identity(&matched.location));
                (detector_id_arc, credential_arc, file)
            }
            DedupScope::None => continue,
        };

        match groups.get_mut(&key) {
            Some(existing) => {
                if is_decoder_alias_pair(&existing.primary_location, &matched.location) {
                    if is_decoder_location(&existing.primary_location)
                        && !is_decoder_location(&matched.location)
                    {
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
                if !is_same_location(&existing.primary_location, &matched.location)
                    && !existing
                        .additional_locations
                        .iter()
                        .any(|loc| is_same_location(loc, &matched.location))
                {
                    existing.additional_locations.push(matched.location);
                }
                merge_companions(&mut existing.companions, matched.companions);
                existing.confidence = max_confidence(existing.confidence, matched.confidence);
            }
            None => {
                let credential_hash = sha256_hash(&matched.credential);
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
        _ => {}
    }
    a.offset.abs_diff(b.offset) <= 16
}

fn is_decoder_location(location: &MatchLocation) -> bool {
    const DECODER_SUFFIXES: &[&str] = &[
        "/base64", "/hex", "/url", "/json", "/z85", "/reverse", "/caesar",
    ];
    DECODER_SUFFIXES
        .iter()
        .any(|suffix| location.source.ends_with(suffix))
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
/// audits/legendary-2026-04-26 innovation #5, "Cuts noise ~30%".
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
    type GroupKey = ([u8; 32], Option<Arc<str>>);
    let mut groups: IndexMap<GroupKey, Vec<DedupedMatch>> = IndexMap::new();
    for m in deduped {
        let key = (
            m.credential_hash.clone(),
            m.primary_location.file_path.clone(),
        );
        groups.entry(key).or_default().push(m);
    }

    let mut out: Vec<DedupedMatch> = Vec::with_capacity(groups.len());
    for (_, mut group) in groups {
        if group.len() == 1 {
            // Safety: the `group.len() == 1` guard above means pop()
            // `pop()` is None only on an empty group; the
            // `len() == 1` guard above proves non-empty here. Use
            // `if let` instead of `.expect()` so a future refactor
            // of the guard turns this into a silent skip (one lost
            // dedup pair, no findings emitted twice) rather than a
            // worker-killing panic on the dedup hot path.
            if let Some(only) = group.pop() {
                out.push(only);
            }
            continue;
        }
        // Sort: highest-confidence first, then severity desc, then detector_id asc.
        group.sort_by(|a, b| {
            let ac = a.confidence.unwrap_or(0.0);
            let bc = b.confidence.unwrap_or(0.0);
            bc.total_cmp(&ac)
                .then_with(|| b.severity.cmp(&a.severity))
                .then_with(|| a.detector_id.cmp(&b.detector_id))
        });
        let mut winner = group.remove(0);
        for (idx, loser) in group.into_iter().enumerate() {
            let key = format!("cross_detector.{idx}");
            let value = format!(
                "{} ({}) [{}]",
                loser.service,
                loser.detector_name,
                loser
                    .confidence
                    .map(|c| format!("{c:.2}"))
                    .unwrap_or_else(|| "n/a".to_string())
            );
            winner.companions.entry(key).or_insert(value);
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

/// Two locations are "the same finding" when they share (source, file_path,
/// line, commit). Offset is intentionally NOT in the tuple - the structured
/// preprocessor's synthetic-line append produces matches whose offset lies
/// past the source file's EOF (the offset is into final_text, not the
/// original chunk text), but whose `line` field is correctly remapped via
/// LineMapping to the original source line. So same-(file, line) means the
/// dedupe SHOULD collapse them: emitting both as "primary at line 1 offset
/// 27" + "additional at line 1 offset 80 (past EOF)" is a confusing
/// duplicate, not two findings.
fn is_same_location(a: &MatchLocation, b: &MatchLocation) -> bool {
    a.source == b.source && a.file_path == b.file_path && a.line == b.line && a.commit == b.commit
}

fn file_scope_identity(location: &MatchLocation) -> Arc<str> {
    let mut identity = String::new();
    identity.push_str(location.source.as_ref());
    identity.push('\0');
    identity.push_str(location.file_path.as_deref().unwrap_or("<unknown>"));
    identity.push('\0');
    identity.push_str(location.commit.as_deref().unwrap_or("<no-commit>"));
    Arc::from(identity)
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

fn sha256_hash(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}
