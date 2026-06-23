//! Dedup must merge identical `(detector, credential)` pairs into one group
//! keyed by the SHA-256 credential hash oracle.

use keyhog_core::{CredentialHash, DedupScope, MatchLocation, RawMatch, Severity, dedup_matches};
use std::collections::HashMap;

const CREDENTIAL: &str = "secret-alpha";
const DETECTOR: &str = "oracle-detector";
const EXPECTED_CREDENTIAL_HASH: [u8; 32] = [
    0x64, 0xec, 0xef, 0x5a, 0xac, 0x3a, 0x85, 0x11, 0xce, 0x62, 0x35, 0x7b, 0x4b, 0x86, 0x1d, 0x73,
    0x67, 0x36, 0x41, 0x03, 0x37, 0x32, 0x01, 0x72, 0x7f, 0xee, 0x84, 0x20, 0xc6, 0x8b, 0x79, 0xe7,
];

fn sample_match(path: &str, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: DETECTOR.into(),
        detector_name: DETECTOR.into(),
        service: "oracle".into(),
        severity: Severity::High,
        credential: CREDENTIAL.into(),
        credential_hash: [0; 32].into(),
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
        deduped[0].credential_hash,
        CredentialHash::from_bytes(EXPECTED_CREDENTIAL_HASH),
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
