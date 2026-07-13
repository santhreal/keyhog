//! Regression coverage for keyhog-core finding dedup/merge (`core::dedup`).
//!
//! Locks the operator-visible grouping contract of `dedup_matches` and
//! `dedup_cross_detector`:
//!   * two identical findings collapse to exactly ONE report entry;
//!   * the dedup key is `(detector_id, file-scope-path, credential-value-hash)`
//!, changing any one of the three keeps the findings separate;
//!   * merging a group keeps the EXACT higher confidence (max), order-independent;
//!   * `DedupScope::None` disables grouping (differing-line matches stay separate);
//!   * cross-detector folding picks the highest-confidence winner and preserves
//!     every distinct location.
//!
//! Every assertion checks a concrete value (collapse count, exact detector id,
//! f64 confidence within epsilon, line numbers, companion contents, hash bytes),
//! never `is_empty()` / `is_ok()` alone.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, hex_encode, CredentialHash, DedupScope, MatchLocation,
    RawMatch, SensitiveString, Severity,
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
// Identical findings collapse to exactly one.
// ---------------------------------------------------------------------------

#[test]
fn two_identical_findings_credential_scope_collapse_to_one() {
    let m = || {
        raw(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::High,
            "AKIAIOSFODNN7EXAMPLE",
            loc("a.env", 1, 0),
            Some(0.9),
        )
    };
    let out = dedup_matches(vec![m(), m()], &DedupScope::Credential);
    assert_eq!(out.len(), 1, "identical findings must collapse to one");
    // Same (file, line) as primary => the duplicate adds NO extra location.
    assert!(
        out[0].additional_locations.is_empty(),
        "identical location must not appear as an additional location: {:?}",
        out[0].additional_locations
    );
    assert_eq!(out[0].detector_id.as_ref(), "aws-access-key");
    assert_eq!(out[0].primary_location.line, Some(1));
    assert!((out[0].confidence.unwrap() - 0.9).abs() < EPS);
}

#[test]
fn identical_findings_file_scope_also_collapse_to_one() {
    let m = || {
        raw(
            "gh-pat",
            "GitHub PAT",
            "github",
            Severity::Critical,
            "ghp_exampletoken0000000000000000000000",
            loc("cfg/app.env", 3, 12),
            Some(0.77),
        )
    };
    let out = dedup_matches(vec![m(), m(), m()], &DedupScope::File);
    assert_eq!(out.len(), 1, "three identical matches -> one finding");
    assert!(out[0].additional_locations.is_empty());
    assert_eq!(out[0].primary_location.offset, 12);
}

// ---------------------------------------------------------------------------
// DedupScope::None keeps every raw match (differing-line matches stay 2).
// ---------------------------------------------------------------------------

#[test]
fn dedup_scope_none_keeps_every_identical_match() {
    let m = || {
        raw(
            "det",
            "Detector",
            "svc",
            Severity::Medium,
            "cred-value-xyz",
            loc("f.txt", 1, 0),
            Some(0.5),
        )
    };
    let out = dedup_matches(vec![m(), m()], &DedupScope::None);
    assert_eq!(out.len(), 2, "None scope must not dedup anything");
    assert!(out[0].additional_locations.is_empty());
    assert!(out[1].additional_locations.is_empty());
}

#[test]
fn findings_differing_only_in_line_stay_two_under_none() {
    let a = raw(
        "det",
        "Detector",
        "svc",
        Severity::Low,
        "same-secret",
        loc("f.txt", 1, 0),
        Some(0.5),
    );
    let b = raw(
        "det",
        "Detector",
        "svc",
        Severity::Low,
        "same-secret",
        loc("f.txt", 2, 40),
        Some(0.5),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::None);
    assert_eq!(
        out.len(),
        2,
        "None scope reports each line as its own finding"
    );
    let mut lines: Vec<usize> = out
        .iter()
        .map(|m| m.primary_location.line.unwrap())
        .collect();
    lines.sort_unstable();
    assert_eq!(lines, vec![1, 2]);
}

// ---------------------------------------------------------------------------
// Same credential on different lines collapses, keeping the extra location.
// ---------------------------------------------------------------------------

#[test]
fn same_credential_different_line_collapses_with_additional_location() {
    // Primary must be the LOWEST offset (dedup sorts by offset ascending).
    let low = raw(
        "det",
        "Detector",
        "svc",
        Severity::Medium,
        "repeated-secret",
        loc("multi.env", 1, 0),
        Some(0.6),
    );
    let high = raw(
        "det",
        "Detector",
        "svc",
        Severity::Medium,
        "repeated-secret",
        loc("multi.env", 5, 200),
        Some(0.6),
    );
    // Insert high-offset first to prove offset-sort, not input order, picks primary.
    let out = dedup_matches(vec![high, low], &DedupScope::Credential);
    assert_eq!(out.len(), 1, "same secret in one file -> one finding");
    assert_eq!(out[0].primary_location.line, Some(1));
    assert_eq!(out[0].primary_location.offset, 0);
    assert_eq!(
        out[0].additional_locations.len(),
        1,
        "the second line must be recorded as an additional location"
    );
    assert_eq!(out[0].additional_locations[0].line, Some(5));
    assert_eq!(out[0].additional_locations[0].offset, 200);
}

// ---------------------------------------------------------------------------
// Dedup key = (detector_id, file-scope-path, credential-value-hash).
// Changing any single component keeps the findings separate.
// ---------------------------------------------------------------------------

#[test]
fn dedup_key_path_component_different_files_stay_two() {
    let a = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "same-secret",
        loc("one.env", 1, 0),
        Some(0.8),
    );
    let b = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "same-secret",
        loc("two.env", 1, 0),
        Some(0.8),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::File);
    assert_eq!(
        out.len(),
        2,
        "different files -> different findings under File scope"
    );
    let mut files: Vec<String> = out
        .iter()
        .map(|m| m.primary_location.file_path.as_deref().unwrap().to_string())
        .collect();
    files.sort();
    assert_eq!(files, vec!["one.env".to_string(), "two.env".to_string()]);
}

#[test]
fn dedup_key_detector_component_different_detectors_stay_two() {
    let a = raw(
        "detector-a",
        "A",
        "svc",
        Severity::High,
        "same-secret",
        loc("f.env", 1, 0),
        Some(0.8),
    );
    let b = raw(
        "detector-b",
        "B",
        "svc",
        Severity::High,
        "same-secret",
        loc("f.env", 1, 0),
        Some(0.8),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(
        out.len(),
        2,
        "different detectors do not collapse in first pass"
    );
    let mut ids: Vec<String> = out.iter().map(|m| m.detector_id.to_string()).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec!["detector-a".to_string(), "detector-b".to_string()]
    );
}

#[test]
fn dedup_key_value_hash_component_different_credentials_stay_two() {
    let a = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "secret-one",
        loc("f.env", 1, 0),
        Some(0.8),
    );
    let b = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "secret-two",
        loc("f.env", 2, 20),
        Some(0.8),
    );
    let out = dedup_matches(vec![a, b], &DedupScope::Credential);
    assert_eq!(
        out.len(),
        2,
        "different credential values are different findings"
    );
    assert_ne!(
        out[0].credential_hash, out[1].credential_hash,
        "distinct credentials must carry distinct value hashes"
    );
}

#[test]
fn deduped_credential_hash_is_sha256_of_value() {
    let out = dedup_matches(
        vec![raw(
            "det",
            "Detector",
            "svc",
            Severity::High,
            "hash-me-please",
            loc("f.env", 1, 0),
            Some(0.8),
        )],
        &DedupScope::Credential,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].credential_hash,
        sha256("hash-me-please"),
        "the value-hash key component is SHA-256 of the credential"
    );
    // The wire hex is the lower-case digest, 64 chars.
    let hexd = hex_encode(&out[0].credential_hash);
    assert_eq!(hexd.len(), 64);
    assert_eq!(hexd, hex_encode(sha256("hash-me-please")));
}

#[test]
fn zero_credential_hash_is_backfilled_with_real_sha256() {
    // Adversarial: a match carrying the historical all-zero sentinel hash must
    // get the true SHA-256 computed so its value-hash key is correct.
    let mut m = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "sentinel-cred",
        loc("f.env", 1, 0),
        Some(0.8),
    );
    m.credential_hash = CredentialHash::ZERO;
    let out = dedup_matches(vec![m], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert!(
        !out[0].credential_hash.is_zero(),
        "zero sentinel must be replaced"
    );
    assert_eq!(out[0].credential_hash, sha256("sentinel-cred"));
}

// ---------------------------------------------------------------------------
// Merge keeps the EXACT higher confidence, order-independent.
// ---------------------------------------------------------------------------

#[test]
fn merge_keeps_higher_confidence_value() {
    let lo = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "conf-secret",
        loc("f.env", 1, 0),
        Some(0.31),
    );
    let hi = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "conf-secret",
        loc("f.env", 1, 0),
        Some(0.94),
    );
    let out = dedup_matches(vec![lo, hi], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert!(
        (out[0].confidence.unwrap() - 0.94).abs() < EPS,
        "merge must keep max confidence, got {:?}",
        out[0].confidence
    );
}

#[test]
fn merge_confidence_max_is_order_independent() {
    let mk = |c: f64| {
        raw(
            "det",
            "Detector",
            "svc",
            Severity::High,
            "conf-secret",
            loc("f.env", 1, 0),
            Some(c),
        )
    };
    // Highest-confidence match arrives FIRST this time.
    let out = dedup_matches(vec![mk(0.94), mk(0.10), mk(0.55)], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert!((out[0].confidence.unwrap() - 0.94).abs() < EPS);
}

#[test]
fn merge_confidence_some_wins_over_none() {
    let none = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "conf-secret",
        loc("f.env", 1, 0),
        None,
    );
    let some = raw(
        "det",
        "Detector",
        "svc",
        Severity::High,
        "conf-secret",
        loc("f.env", 1, 0),
        Some(0.42),
    );
    let out = dedup_matches(vec![none, some], &DedupScope::Credential);
    assert_eq!(out.len(), 1);
    assert!((out[0].confidence.unwrap() - 0.42).abs() < EPS);
}

// ---------------------------------------------------------------------------
// Cross-detector fold: winner = highest confidence; locations preserved.
// ---------------------------------------------------------------------------

#[test]
fn cross_detector_winner_is_highest_confidence() {
    // Same credential, same file, two detectors -> first pass keeps them
    // separate; cross-detector fold picks the higher-confidence winner.
    let deduped = dedup_matches(
        vec![
            raw(
                "detector-a",
                "A Det",
                "asvc",
                Severity::Medium,
                "AIzaSyExampleGoogleApiKey000000000000",
                loc("f.env", 1, 0),
                Some(0.40),
            ),
            raw(
                "detector-b",
                "B Det",
                "bsvc",
                Severity::Medium,
                "AIzaSyExampleGoogleApiKey000000000000",
                loc("f.env", 1, 0),
                Some(0.85),
            ),
        ],
        &DedupScope::Credential,
    );
    assert_eq!(
        deduped.len(),
        2,
        "first pass keeps the two detectors separate"
    );

    let folded = dedup_cross_detector(deduped);
    assert_eq!(
        folded.len(),
        1,
        "one credential -> one cross-detector finding"
    );
    let w = &folded[0];
    assert_eq!(
        w.detector_id.as_ref(),
        "detector-b",
        "winner is higher confidence"
    );
    assert!((w.confidence.unwrap() - 0.85).abs() < EPS);
    // Loser is folded into companions under cross_detector.0.
    let comp = w
        .companions
        .get("cross_detector.0")
        .expect("loser must be recorded as cross_detector.0");
    assert!(comp.contains("asvc"), "loser service in evidence: {comp}");
    assert!(comp.contains("A Det"), "loser name in evidence: {comp}");
    assert!(comp.contains("0.40"), "loser confidence label: {comp}");
}

#[test]
fn cross_detector_preserves_distinct_loser_location() {
    let deduped = dedup_matches(
        vec![
            raw(
                "detector-a",
                "A Det",
                "asvc",
                Severity::Medium,
                "AIzaSyExampleGoogleApiKey000000000000",
                loc("f.env", 7, 300),
                Some(0.40),
            ),
            raw(
                "detector-b",
                "B Det",
                "bsvc",
                Severity::Medium,
                "AIzaSyExampleGoogleApiKey000000000000",
                loc("f.env", 1, 0),
                Some(0.85),
            ),
        ],
        &DedupScope::Credential,
    );
    let folded = dedup_cross_detector(deduped);
    assert_eq!(folded.len(), 1);
    let w = &folded[0];
    assert_eq!(w.primary_location.line, Some(1));
    assert_eq!(
        w.additional_locations.len(),
        1,
        "loser's distinct line must survive as an additional location"
    );
    assert_eq!(w.additional_locations[0].line, Some(7));
    assert_eq!(w.additional_locations[0].offset, 300);
}

#[test]
fn cross_detector_below_two_is_identity() {
    let deduped = dedup_matches(
        vec![raw(
            "solo",
            "Solo",
            "svc",
            Severity::High,
            "lonely-secret",
            loc("f.env", 1, 0),
            Some(0.66),
        )],
        &DedupScope::Credential,
    );
    let folded = dedup_cross_detector(deduped);
    assert_eq!(folded.len(), 1, "single finding passes through unchanged");
    assert_eq!(folded[0].detector_id.as_ref(), "solo");
    assert!((folded[0].confidence.unwrap() - 0.66).abs() < EPS);
    assert!(
        !folded[0].companions.contains_key("cross_detector.0"),
        "no cross-detector evidence for a lone finding"
    );
}
