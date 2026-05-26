//! Dedup must merge identical `(detector, credential)` pairs into one group
//! keyed by the SHA-256 credential hash oracle.

use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

const CREDENTIAL: &str = "secret-alpha";
const DETECTOR: &str = "oracle-detector";
const EXPECTED_CREDENTIAL_HASH: &str =
    "64ecef5aac3a8511ce62357b4b861d7367364103373201727fee8420c68b79e7";

fn sample_match(path: &str, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: DETECTOR.into(),
        detector_name: DETECTOR.into(),
        service: "oracle".into(),
        severity: Severity::High,
        credential: CREDENTIAL.into(),
        credential_hash: format!("stale-hash-{path}"),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "fs".into(),
            file_path: Some(path.into()),
            line: Some(1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
    }
}

/// Same credential across two files collapses to one group with the canonical hash.
#[test]
fn dedup_same_credential_one_group() {
    let matches = vec![sample_match("alpha.env", 10), sample_match("beta.env", 20)];

    let deduped = dedup_matches(matches, &DedupScope::Credential);

    assert_eq!(
        deduped.len(),
        1,
        "identical detector+credential pairs must merge into one group, got {} groups",
        deduped.len()
    );
    assert_eq!(
        deduped[0].credential.as_ref(),
        CREDENTIAL,
        "merged group must preserve the credential value"
    );
    assert_eq!(
        deduped[0].credential_hash, EXPECTED_CREDENTIAL_HASH,
        "group id (credential_hash) must be SHA-256 of credential bytes, not the stale per-match hash"
    );
    assert_eq!(
        deduped[0].additional_locations.len(),
        1,
        "second distinct file location must land in additional_locations"
    );
    assert_eq!(
        deduped[0].additional_locations[0]
            .file_path
            .as_deref()
            .map(str::to_string),
        Some("beta.env".to_string()),
        "additional location must retain the duplicate file path"
    );
}
