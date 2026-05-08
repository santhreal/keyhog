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
/// Manual `Debug` impl redacts the `credential` field — the previous
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
    pub credential_hash: String,
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
            .field("credential_hash", &self.credential_hash)
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
    // matches — see audits/legendary-2026-04-26.
    type DedupKey = (Arc<str>, Arc<str>, Option<Arc<str>>);
    let mut groups: IndexMap<DedupKey, DedupedMatch> = IndexMap::new();

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
                existing.additional_locations.push(matched.location);
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

/// Cross-detector dedup at emit time.
///
/// One credential value commonly matches multiple detectors — `AIza...` keys
/// fire google-api, google-maps, google-places, google-translate; opaque
/// 32-hex strings fire entropy + several service-specific generic detectors.
/// The first-pass `dedup_matches` keeps each `(detector, credential)` pair
/// separate. This second pass groups the deduped Vec by `credential_hash`
/// and folds related detectors into the WINNING DedupedMatch's companions
/// map under a `cross_detector` namespace, so a reporter sees ONE finding
/// per credential with the alternate service guesses listed as evidence —
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

    // Group by (credential_hash, primary_location.file_path) — splitting by
    // file keeps file-scope dedup intact when the caller used DedupScope::File.
    type GroupKey = (String, Option<Arc<str>>);
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
            out.push(group.pop().unwrap());
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

fn sha256_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn make_match(detector: &str, service: &str, conf: f64) -> DedupedMatch {
        DedupedMatch {
            detector_id: Arc::from(detector),
            detector_name: Arc::from(detector),
            service: Arc::from(service),
            severity: Severity::High,
            credential: Arc::from("AIza_FAKE_KEY_NOT_REAL_VALUE_1234567890"),
            credential_hash: "deadbeef".to_string(),
            companions: HashMap::new(),
            primary_location: MatchLocation {
                source: Arc::from("test"),
                file_path: Some(Arc::from("config.js")),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            additional_locations: Vec::new(),
            confidence: Some(conf),
        }
    }

    #[test]
    fn cross_detector_dedup_collapses_overlapping_detectors() {
        let input = vec![
            make_match("google-api-key", "google-api", 0.85),
            make_match("google-maps-api-key", "google-maps", 0.75),
            make_match("google-places-api-key", "google-places", 0.70),
        ];
        let out = dedup_cross_detector(input);
        assert_eq!(out.len(), 1, "three same-credential matches → one finding");
        let winner = &out[0];
        // Highest confidence wins.
        assert_eq!(winner.detector_id.as_ref(), "google-api-key");
        // Losers folded into companions.
        assert!(winner.companions.contains_key("cross_detector.0"));
        assert!(winner.companions.contains_key("cross_detector.1"));
    }

    #[test]
    fn cross_detector_dedup_keeps_distinct_credentials_separate() {
        let mut a = make_match("github-pat", "github", 0.9);
        a.credential_hash = "aaaaaaaa".into();
        let mut b = make_match("openai-key", "openai", 0.9);
        b.credential_hash = "bbbbbbbb".into();
        let out = dedup_cross_detector(vec![a, b]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn cross_detector_dedup_does_not_cross_files() {
        let a = make_match("aws-access-key", "aws", 0.9);
        let mut b = make_match("aws-access-key", "aws", 0.9);
        // Same credential, different files — should stay separate.
        b.primary_location.file_path = Some(Arc::from("other.js"));
        let out = dedup_cross_detector(vec![a, b]);
        assert_eq!(
            out.len(),
            2,
            "same credential in two files = two findings (file scope)"
        );
    }

    #[test]
    fn cross_detector_dedup_is_deterministic() {
        let a = make_match("zzz-detector", "zzz", 0.9);
        let b = make_match("aaa-detector", "aaa", 0.9);
        let out1 = dedup_cross_detector(vec![a.clone(), b.clone()]);
        let out2 = dedup_cross_detector(vec![b, a]);
        assert_eq!(
            out1.len(),
            out2.len(),
            "cardinality stable regardless of input order"
        );
    }

    /// Full-pipeline determinism: identical inputs (in any input
    /// order) must produce byte-identical output orders. CI diffs,
    /// SARIF fingerprints, and baseline files all depend on this.
    /// `IndexMap` + post-sort + cross-detector dedup is the chain;
    /// this test locks it in so a future "let's swap to HashMap"
    /// refactor can't silently re-introduce non-determinism.
    fn make_raw(detector: &str, credential: &str, conf: f64) -> RawMatch {
        RawMatch {
            detector_id: Arc::from(detector),
            detector_name: Arc::from(detector),
            service: Arc::from(detector.split('-').next().unwrap_or(detector)),
            severity: Severity::High,
            credential: Arc::from(credential),
            credential_hash: format!("hash_of_{credential}"),
            companions: HashMap::new(),
            location: MatchLocation {
                source: Arc::from("test"),
                file_path: Some(Arc::from("file.rs")),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: Some(4.0),
            confidence: Some(conf),
        }
    }

    fn fingerprint(out: &[DedupedMatch]) -> String {
        let mut parts: Vec<String> = out
            .iter()
            .map(|m| format!("{}|{}|{:?}", m.detector_id, m.credential, m.confidence))
            .collect();
        // Order is what we're testing; do NOT sort here.
        parts.join(",")
    }

    #[test]
    fn full_dedup_pipeline_is_deterministic_across_input_orders() {
        let inputs = vec![
            make_raw("aws-key", "AKIAIOSFODNN7EXAMPLE_AAAA", 0.9),
            make_raw("ghp-token", "ghp_aBcDeF1234567890_BBBB", 0.85),
            make_raw("slack-bot", "xoxb-1234-5678-CCCC_test", 0.8),
            make_raw("aws-key", "AKIAIOSFODNN7EXAMPLE_AAAA", 0.9), // dup
            make_raw("stripe-secret", "sk_test_4eC39HqLyjW_DDDD", 0.95),
        ];

        let scope = DedupScope::Credential;
        let out_a = dedup_cross_detector(dedup_matches(inputs.clone(), &scope));

        // Reverse the input order — output must be byte-identical.
        let mut reversed = inputs.clone();
        reversed.reverse();
        let out_b = dedup_cross_detector(dedup_matches(reversed, &scope));

        assert_eq!(
            fingerprint(&out_a),
            fingerprint(&out_b),
            "dedup output order must be input-order-independent"
        );

        // Shuffle within: pairs swap.
        let shuffled = vec![
            inputs[2].clone(),
            inputs[4].clone(),
            inputs[0].clone(),
            inputs[3].clone(),
            inputs[1].clone(),
        ];
        let out_c = dedup_cross_detector(dedup_matches(shuffled, &scope));
        assert_eq!(
            fingerprint(&out_a),
            fingerprint(&out_c),
            "shuffled inputs must still produce identical output order"
        );
    }
}
