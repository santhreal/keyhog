//! Regression coverage for keyhog-core finding dedup (`core::dedup`), owned by
//! `keyhog_core` (the scanner neither defines nor re-exports these functions).
//!
//! This file locks the load-bearing operator-visible dedup contract with EXACT
//! counts, distinct from the sibling `new_core_finding_dedup.rs` /
//! `regression_finding_dedup_merge.rs` / `dedup_decoder_alias.rs` files:
//!
//!   * the SAME credential at the SAME location is emitted exactly ONCE with no
//!     extra location (positive);
//!   * the SAME value at DIFFERENT locations is KEPT (one finding, both
//!     locations preserved under Credential scope; two findings under File
//!     scope, the negative twin);
//!   * cross-detector fold collapses N detectors on one value into exactly ONE
//!     finding with exactly N-1 `cross_detector.*` companions, is FILE-SCOPED,
//!     breaks confidence ties by severity then detector_id, and emits a
//!     byte-exact companion evidence string;
//!   * a full mixed batch produces PRECISE first-pass and cross-detector counts.
//!
//! Every assertion checks a concrete value (exact count, exact detector id,
//! exact companion string, exact line numbers, f64 within epsilon), never
//! `is_empty()` / `is_ok()` / `len() > 0` alone. Host-independent: pure
//! in-process API, no accelerator, no scanner engine.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, CredentialHash, DedupScope, MatchLocation, RawMatch,
    SensitiveString, Severity,
};
use std::collections::HashMap;
use std::sync::Arc;

const EPS: f64 = 1e-9;

fn sha256(s: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    CredentialHash::from_bytes(h.finalize().into())
}

fn loc(file: &str, line: usize, offset: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from(file)),
        line: Some(line),
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn raw(
    detector_id: &str,
    detector_name: &str,
    service: &str,
    severity: Severity,
    credential: &str,
    location: MatchLocation,
    confidence: Option<f64>,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_name),
        service: Arc::from(service),
        severity,
        credential: SensitiveString::from(credential),
        credential_hash: sha256(credential),
        companions: HashMap::new(),
        location,
        entropy: None,
        confidence,
    }
}

// ---------------------------------------------------------------------------
// 1. Same credential at the SAME location -> emitted exactly once.
// ---------------------------------------------------------------------------

#[test]
fn same_credential_same_location_emitted_once() {
    // Three byte-identical matches (same detector, value, file, line, offset).
    let m = || {
        raw(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            "AKIAIOSFODNN7EXAMPLE",
            loc("creds.env", 1, 0),
            Some(0.9),
        )
    };
    let out = dedup_matches(vec![m(), m(), m()], &DedupScope::Credential);
    assert_eq!(
        out.len(),
        1,
        "identical matches must collapse to ONE finding"
    );
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "same (file,line) as primary must add no additional location"
    );
    assert_eq!(&*out[0].detector_id, "aws-access-key");
    assert_eq!(out[0].primary_location.line, Some(1));
    assert_eq!(out[0].primary_location.offset, 0);
    assert!((out[0].confidence.unwrap() - 0.9).abs() < EPS);
}

// ---------------------------------------------------------------------------
// 2. Same value at DIFFERENT locations (different files) -> ONE finding,
//    BOTH locations kept (Credential scope collapses across files).
// ---------------------------------------------------------------------------

#[test]
fn same_value_different_files_credential_scope_keeps_both_locations() {
    let a = raw(
        "det",
        "Detector",
        "svc",
        Severity::Medium,
        "shared-secret-value",
        loc("aaa.env", 3, 40),
        Some(0.6),
    );
    let b = raw(
        "det",
        "Detector",
        "svc",
        Severity::Medium,
        "shared-secret-value",
        loc("bbb.env", 7, 10),
        Some(0.6),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(
        out.len(),
        1,
        "same value+detector across files -> one finding"
    );
    // Primary is the lowest (file_path, offset): "aaa.env" sorts before "bbb.env".
    assert_eq!(
        out[0].primary_location.file_path.as_deref(),
        Some("aaa.env")
    );
    assert_eq!(
        out[0].additional_locations.len(),
        1,
        "the other file's location must be KEPT, not discarded"
    );
    assert_eq!(
        out[0].additional_locations[0].file_path.as_deref(),
        Some("bbb.env")
    );
    assert_eq!(out[0].additional_locations[0].line, Some(7));
}

// ---------------------------------------------------------------------------
// 3. Negative twin of #2: under File scope, the same value in two files is
//    TWO separate findings.
// ---------------------------------------------------------------------------

#[test]
fn same_value_different_files_file_scope_stays_two_findings() {
    let a = raw(
        "det",
        "Detector",
        "svc",
        Severity::Medium,
        "shared-secret-value",
        loc("aaa.env", 3, 40),
        Some(0.6),
    );
    let b = raw(
        "det",
        "Detector",
        "svc",
        Severity::Medium,
        "shared-secret-value",
        loc("bbb.env", 7, 10),
        Some(0.6),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::File);
    assert_eq!(
        out.len(),
        2,
        "File scope must keep one finding PER FILE for the same value"
    );
    let mut files: Vec<String> = out
        .iter()
        .map(|d| d.primary_location.file_path.as_deref().unwrap().to_string())
        .collect();
    files.sort();
    assert_eq!(files, vec!["aaa.env".to_string(), "bbb.env".to_string()]);
    // Neither finding carries the other as an additional location.
    assert_eq!(out[0].additional_locations.len(), 0);
    assert_eq!(out[1].additional_locations.len(), 0);
}

// ---------------------------------------------------------------------------
// 4. Same value, same file, K distinct lines -> ONE finding with exactly K-1
//    additional locations (the O(K) seen-set path), all lines recorded.
// ---------------------------------------------------------------------------

#[test]
fn same_value_same_file_many_lines_records_all_additional() {
    let mk = |line: usize, off: usize| {
        raw(
            "det",
            "Detector",
            "svc",
            Severity::Low,
            "repeated-token",
            loc("dump.env", line, off),
            Some(0.5),
        )
    };
    // 5 distinct lines, inserted out of offset order to prove offset-sort picks
    // the primary, not input order.
    let out = dedup_matches(
        vec![mk(5, 400), mk(1, 0), mk(3, 200), mk(4, 300), mk(2, 100)],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1, "one value in one file -> one finding");
    assert_eq!(out[0].primary_location.line, Some(1));
    assert_eq!(out[0].primary_location.offset, 0);
    assert_eq!(
        out[0].additional_locations.len(),
        4,
        "K=5 distinct lines -> exactly K-1 additional locations"
    );
    let mut lines: Vec<usize> = out[0]
        .additional_locations
        .iter()
        .map(|l| l.line.unwrap())
        .collect();
    lines.sort_unstable();
    assert_eq!(lines, vec![2, 3, 4, 5]);
}

// ---------------------------------------------------------------------------
// 5. Same value, same line, DIFFERENT offset -> collapses to one (offset is
//    intentionally excluded from location identity), zero additional.
// ---------------------------------------------------------------------------

#[test]
fn same_value_same_line_different_offset_collapses_zero_additional() {
    // The synthetic-preprocessor alias: the regex fires twice on one value, once
    // at the real offset and once past EOF, but at the SAME remapped line.
    let real = raw(
        "det",
        "Detector",
        "svc",
        Severity::Low,
        "secret",
        loc("one-line.env", 1, 12),
        Some(0.5),
    );
    let alias = raw(
        "det",
        "Detector",
        "svc",
        Severity::Low,
        "secret",
        loc("one-line.env", 1, 512),
        Some(0.5),
    );
    let out = dedup_matches(vec![alias, real], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "same (file,line) with a different offset must NOT be a second location"
    );
    assert_eq!(
        out[0].primary_location.offset, 12,
        "primary is the lower offset"
    );
}

// ---------------------------------------------------------------------------
// 6. Cross-detector: N=3 detectors on one value -> ONE finding, exactly N-1=2
//    cross_detector companions.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_three_detectors_folds_to_one_with_two_companions() {
    let value = "AIzaSyExampleSharedKeyForThreeDets00";
    let deduped = dedup_matches(
        vec![
            raw(
                "det-hi",
                "Hi Det",
                "svc-hi",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.9),
            ),
            raw(
                "det-mid",
                "Mid Det",
                "svc-mid",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.5),
            ),
            raw(
                "det-lo",
                "Lo Det",
                "svc-lo",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.2),
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        deduped.len(),
        3,
        "first pass keeps three detectors separate"
    );

    let folded = dedup_cross_detector(deduped);
    assert_eq!(
        folded.len(),
        1,
        "three detectors on one value -> ONE finding"
    );
    let w = &folded[0];
    assert_eq!(
        &*w.detector_id, "det-hi",
        "highest-confidence detector wins"
    );
    assert!((w.confidence.unwrap() - 0.9).abs() < EPS);
    assert_eq!(
        w.companions.len(),
        2,
        "exactly N-1 losers folded as cross_detector.* companions"
    );
    assert!(w.companions.contains_key("cross_detector.0"));
    assert!(w.companions.contains_key("cross_detector.1"));
    // No additional location: all three matches share (file,line).
    assert_eq!(w.additional_locations.len(), 0);
}

// ---------------------------------------------------------------------------
// 7. Cross-detector companion value has the exact "service (name) [conf]" form,
//    and losers are ordered confidence-descending (cross_detector.0 = 0.50).
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_companion_value_exact_format() {
    let value = "AIzaSyExampleSharedKeyFormatCheck0000";
    let folded = dedup_cross_detector(dedup_matches(
        vec![
            raw(
                "det-hi",
                "Hi Det",
                "svc-hi",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.9),
            ),
            raw(
                "det-mid",
                "Mid Det",
                "svc-mid",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.5),
            ),
            raw(
                "det-lo",
                "Lo Det",
                "svc-lo",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.2),
            ),
        ],
        &DedupScope::Credential,
    ));
    assert_eq!(folded.len(), 1);
    let w = &folded[0];
    // Loser order is confidence-descending: 0.50 then 0.20.
    assert_eq!(
        w.companions.get("cross_detector.0").map(String::as_str),
        Some("svc-mid (Mid Det) [0.50]"),
        "cross_detector.0 is the byte-exact evidence for the 0.50 loser"
    );
    assert_eq!(
        w.companions.get("cross_detector.1").map(String::as_str),
        Some("svc-lo (Lo Det) [0.20]")
    );
}

// ---------------------------------------------------------------------------
// 8. Cross-detector: a loser with None confidence renders the "[n/a]" label.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_none_confidence_companion_label_na() {
    let value = "AIzaSyExampleSharedKeyNaConfidence000";
    let folded = dedup_cross_detector(dedup_matches(
        vec![
            raw(
                "det-hi",
                "Hi Det",
                "svc-hi",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.7),
            ),
            raw(
                "det-na",
                "Na Det",
                "svc-na",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                None,
            ),
        ],
        &DedupScope::Credential,
    ));
    assert_eq!(folded.len(), 1);
    let w = &folded[0];
    // None confidence sorts as lowest -> loser; winner is the Some(0.7) detector.
    assert_eq!(&*w.detector_id, "det-hi");
    assert_eq!(
        w.companions.get("cross_detector.0").map(String::as_str),
        Some("svc-na (Na Det) [n/a]"),
        "absent confidence renders as [n/a], not a fabricated number"
    );
}

// ---------------------------------------------------------------------------
// 9. Cross-detector winner tie-break: equal confidence -> higher severity wins.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_winner_severity_breaks_confidence_tie() {
    let value = "AIzaSyExampleSharedKeySeverityTie0000";
    let folded = dedup_cross_detector(dedup_matches(
        vec![
            raw(
                "det-low-sev",
                "Low Sev",
                "svc-a",
                Severity::Low,
                value,
                loc("k.json", 1, 0),
                Some(0.5),
            ),
            raw(
                "det-crit-sev",
                "Crit Sev",
                "svc-b",
                Severity::Critical,
                value,
                loc("k.json", 1, 0),
                Some(0.5),
            ),
        ],
        &DedupScope::Credential,
    ));
    assert_eq!(folded.len(), 1);
    assert_eq!(
        &*folded[0].detector_id, "det-crit-sev",
        "equal confidence -> Critical severity wins over Low"
    );
    assert_eq!(folded[0].severity, Severity::Critical);
    // The Low loser is the recorded companion.
    assert_eq!(
        folded[0]
            .companions
            .get("cross_detector.0")
            .map(String::as_str),
        Some("svc-a (Low Sev) [0.50]")
    );
}

// ---------------------------------------------------------------------------
// 10. Cross-detector winner tie-break: equal confidence AND severity ->
//     lexicographically smallest detector_id wins (deterministic).
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_winner_detector_id_breaks_full_tie() {
    let value = "AIzaSyExampleSharedKeyIdTieBreak00000";
    let folded = dedup_cross_detector(dedup_matches(
        vec![
            raw(
                "zzz-det",
                "Zzz",
                "svc-z",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.5),
            ),
            raw(
                "aaa-det",
                "Aaa",
                "svc-a",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.5),
            ),
        ],
        &DedupScope::Credential,
    ));
    assert_eq!(folded.len(), 1);
    assert_eq!(
        &*folded[0].detector_id, "aaa-det",
        "confidence+severity tie -> smallest detector_id wins for determinism"
    );
}

// ---------------------------------------------------------------------------
// 11. Cross-detector fold is FILE-SCOPED: the same value in two different files
//     is NOT folded across files -> two findings survive.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_is_file_scoped_same_value_two_files_stays_two() {
    let value = "AIzaSyExampleSharedKeyAcrossTwoFiles0";
    // Two DIFFERENT detectors (so the first pass keeps them separate), same
    // value, but each primary lives in a different file.
    let deduped = dedup_matches(
        vec![
            raw(
                "det-a",
                "A",
                "svc-a",
                Severity::High,
                value,
                loc("file-a.json", 1, 0),
                Some(0.9),
            ),
            raw(
                "det-b",
                "B",
                "svc-b",
                Severity::High,
                value,
                loc("file-b.json", 1, 0),
                Some(0.9),
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(deduped.len(), 2);
    let folded = dedup_cross_detector(deduped);
    assert_eq!(
        folded.len(),
        2,
        "cross-detector fold keys on (value_hash, file) -> different files never merge"
    );
    let mut ids: Vec<String> = folded.iter().map(|d| d.detector_id.to_string()).collect();
    ids.sort();
    assert_eq!(ids, vec!["det-a".to_string(), "det-b".to_string()]);
    // Neither absorbed the other as a companion.
    assert!(!folded[0].companions.contains_key("cross_detector.0"));
    assert!(!folded[1].companions.contains_key("cross_detector.0"));
}

// ---------------------------------------------------------------------------
// 12. Cross-detector: losers sharing the winner's (file,line) add NO extra
//     location, but a loser at a DISTINCT line IS preserved.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_location_merge_is_identity_aware() {
    let value = "AIzaSyExampleSharedKeyLocationMerge00";
    // Winner (highest conf) at line 1; one loser co-located (line 1), one loser
    // at a distinct line 9.
    let folded = dedup_cross_detector(dedup_matches(
        vec![
            raw(
                "det-win",
                "Win",
                "svc-w",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.9),
            ),
            raw(
                "det-same",
                "Same",
                "svc-s",
                Severity::High,
                value,
                loc("k.json", 1, 0),
                Some(0.6),
            ),
            raw(
                "det-far",
                "Far",
                "svc-f",
                Severity::High,
                value,
                loc("k.json", 9, 500),
                Some(0.3),
            ),
        ],
        &DedupScope::Credential,
    ));
    assert_eq!(folded.len(), 1);
    let w = &folded[0];
    assert_eq!(&*w.detector_id, "det-win");
    assert_eq!(
        w.additional_locations.len(),
        1,
        "co-located loser drops; only the distinct-line loser survives as a location"
    );
    assert_eq!(w.additional_locations[0].line, Some(9));
    assert_eq!(w.additional_locations[0].offset, 500);
    // Both losers are still recorded as evidence companions.
    assert_eq!(w.companions.len(), 2);
}

// ---------------------------------------------------------------------------
// 13. Cross-detector output is sorted by detector_id (cross-run determinism).
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_output_sorted_by_detector_id() {
    // Three distinct credentials -> three non-folding singleton findings; the
    // final pass sorts them by detector_id regardless of input order.
    let deduped = dedup_matches(
        vec![
            raw(
                "m-det",
                "M",
                "svc",
                Severity::Low,
                "val-m",
                loc("m.env", 1, 0),
                Some(0.5),
            ),
            raw(
                "z-det",
                "Z",
                "svc",
                Severity::Low,
                "val-z",
                loc("z.env", 1, 0),
                Some(0.5),
            ),
            raw(
                "a-det",
                "A",
                "svc",
                Severity::Low,
                "val-a",
                loc("a.env", 1, 0),
                Some(0.5),
            ),
        ],
        &DedupScope::Credential,
    );
    let folded = dedup_cross_detector(deduped);
    let ids: Vec<&str> = folded.iter().map(|d| &*d.detector_id).collect();
    assert_eq!(
        ids,
        vec!["a-det", "m-det", "z-det"],
        "cross-detector output must be detector_id-sorted for stable reports"
    );
}

// ---------------------------------------------------------------------------
// 14. Boundary: cross-detector on an empty input returns empty (len < 2 arm).
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_empty_input_returns_empty() {
    let folded = dedup_cross_detector(Vec::new());
    assert_eq!(
        folded.len(),
        0,
        "empty in -> empty out, no panic on the len<2 guard"
    );
}

// ---------------------------------------------------------------------------
// 15. Full mixed batch: exact first-pass and cross-detector counts end to end.
// ---------------------------------------------------------------------------

#[test]
fn exact_final_count_mixed_batch() {
    let cred_x = "AIzaSyExampleMixedBatchCredValueXxxxx";
    let cred_y = "AIzaSyExampleMixedBatchCredValueYyyyy";
    let matches = vec![
        // det-alpha / cred_x in fileF, line 1 (real).
        raw(
            "det-alpha",
            "Alpha",
            "svc",
            Severity::High,
            cred_x,
            loc("F.env", 1, 0),
            Some(0.8),
        ),
        // det-alpha / cred_x in fileF, line 1 (synthetic alias, off 90) -> drops.
        raw(
            "det-alpha",
            "Alpha",
            "svc",
            Severity::High,
            cred_x,
            loc("F.env", 1, 90),
            Some(0.8),
        ),
        // det-alpha / cred_x in fileF, line 5 -> additional location.
        raw(
            "det-alpha",
            "Alpha",
            "svc",
            Severity::High,
            cred_x,
            loc("F.env", 5, 200),
            Some(0.8),
        ),
        // det-beta / cred_x in fileF, line 1 -> distinct detector, folds w/ alpha.
        raw(
            "det-beta",
            "Beta",
            "svc",
            Severity::Medium,
            cred_x,
            loc("F.env", 1, 0),
            Some(0.5),
        ),
        // det-alpha / cred_y in fileF -> distinct value, own finding.
        raw(
            "det-alpha",
            "Alpha",
            "svc",
            Severity::High,
            cred_y,
            loc("F.env", 9, 300),
            Some(0.7),
        ),
        // det-gamma / cred_x in fileG -> same value, DIFFERENT file, own finding.
        raw(
            "det-gamma",
            "Gamma",
            "svc",
            Severity::Low,
            cred_x,
            loc("G.env", 1, 0),
            Some(0.3),
        ),
    ];

    // First pass: 4 (detector,value) groups.
    let deduped = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(
        deduped.len(),
        4,
        "first pass -> 4 (detector,value) findings"
    );

    // Second pass: alpha/cred_x + beta/cred_x share (hash, fileF) and fold;
    // cred_y (fileF) and gamma/cred_x (fileG) stay separate -> 3 findings.
    let folded = dedup_cross_detector(deduped);
    assert_eq!(folded.len(), 3, "cross-detector fold -> 3 findings");

    // Exactly one finding carries a folded companion (the alpha/beta merge).
    let folded_count = folded
        .iter()
        .filter(|d| d.companions.contains_key("cross_detector.0"))
        .count();
    assert_eq!(
        folded_count, 1,
        "exactly one finding absorbed a cross-detector loser"
    );

    // The alpha/cred_x winner (in fileF) keeps its distinct line-5 location.
    let alpha_x = folded
        .iter()
        .find(|d| &*d.detector_id == "det-alpha" && d.credential_hash == sha256(cred_x))
        .expect("alpha/cred_x winner present");
    assert_eq!(alpha_x.primary_location.line, Some(1));
    assert_eq!(alpha_x.primary_location.offset, 0);
    assert_eq!(
        alpha_x.additional_locations.len(),
        1,
        "the distinct line-5 hit survives; the same-line alias and beta co-location do not"
    );
    assert_eq!(alpha_x.additional_locations[0].line, Some(5));
}

// ---------------------------------------------------------------------------
// 16. K-repeat of one value at one location under Credential scope -> one
//     finding, zero additional, confidence == max over the group.
// ---------------------------------------------------------------------------

#[test]
fn k_repeat_same_location_credential_scope_one_finding_max_confidence() {
    let mk = |conf: f64| {
        raw(
            "det",
            "Detector",
            "svc",
            Severity::High,
            "hot-repeated-token",
            loc("config.env", 4, 20),
            Some(conf),
        )
    };
    // Five identical-location matches with varying confidence; max is 0.88.
    let out = dedup_matches(
        vec![mk(0.10), mk(0.88), mk(0.40), mk(0.60), mk(0.25)],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1, "K identical-location repeats -> one finding");
    assert_eq!(
        out[0].additional_locations.len(),
        0,
        "repeats at the same (file,line) add no locations"
    );
    assert!(
        (out[0].confidence.unwrap() - 0.88).abs() < EPS,
        "the merged finding keeps the MAX confidence, got {:?}",
        out[0].confidence
    );
    assert_eq!(out[0].primary_location.line, Some(4));
    assert_eq!(out[0].primary_location.offset, 20);
}
