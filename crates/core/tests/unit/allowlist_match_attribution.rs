//! WHY: Allowlist suppression match attribution and unused entry governance contract (Row 54, Row 91):
//! Every parsed suppression entry in `.keyhogignore` must be attributed an exact match
//! count during scanning, unused suppressions (0 matches) must be enumerated and reported,
//! and planted suppressions whose detector/path/hash no longer exists must be identified.
//!
//! WHAT IT DOES NOT CATCH:
//! Suppressions defined in external vendor gate systems outside KeyHog `.keyhogignore` files.

use keyhog_core::{Allowlist, CredentialHash, MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::path::Path;

fn make_finding(detector_id: &str, file_path: &str, hash_hex: &str) -> VerifiedFinding {
    let hash_bytes = hex::decode(hash_hex).expect("decode hex");
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);

    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: detector_id.into(),
        service: "test-service".into(),
        severity: Severity::High,
        credential_redacted: "***".into(),
        credential_hash: CredentialHash::from(hash_arr),
        companions_redacted: HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some(file_path.into()),
            line: Some(10),
            offset: 100,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        evidence_score: None,
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

#[test]
fn every_suppression_entry_is_attributed_match_counts() {
    let content = r#"
# Active suppressions
detector:active-detector
path:src/fixtures/*.txt
hash:1111111111111111111111111111111111111111111111111111111111111111

# Dead / unused suppressions
detector:dead-detector-never-fires
path:obsolete/legacy/path/*.env
hash:9999999999999999999999999999999999999999999999999999999999999999
"#;

    let allowlist = Allowlist::parse(content);
    assert_eq!(allowlist.rules.len(), 6, "must parse all 6 rules");

    // Findings that match the 3 active rules
    let f1 = make_finding(
        "active-detector",
        "src/other.rs",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let f2 = make_finding(
        "other-detector",
        "src/fixtures/sample.txt",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let f3 = make_finding(
        "other-detector",
        "src/other.rs",
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    let f4 = make_finding(
        "active-detector",
        "src/fixtures/sample.txt",
        "1111111111111111111111111111111111111111111111111111111111111111",
    );

    // Record matches
    assert!(allowlist.record_match(&f1));
    assert!(allowlist.record_match(&f2));
    assert!(allowlist.record_match(&f3));
    assert!(allowlist.record_match(&f4));

    let counts = allowlist.attributed_match_counts();
    let count_map: HashMap<String, usize> = counts.into_iter().collect();

    assert_eq!(count_map.get("detector:active-detector"), Some(&2));
    assert_eq!(count_map.get("path:src/fixtures/*.txt"), Some(&2));
    assert_eq!(
        count_map.get("hash:1111111111111111111111111111111111111111111111111111111111111111"),
        Some(&2)
    );

    // Check unused entries
    let unused = allowlist.unused_entries();
    assert_eq!(unused.len(), 3, "must report exactly the 3 unused entries");

    let unused_entries: Vec<&str> = unused.iter().map(|u| u.entry.as_str()).collect();
    assert!(unused_entries.contains(&"detector:dead-detector-never-fires"));
    assert!(unused_entries.contains(&"path:obsolete/legacy/path/*.env"));
    assert!(unused_entries.contains(&"hash:9999999999999999999999999999999999999999999999999999999999999999"));
}

#[test]
fn mutation_planted_suppression_for_nonexistent_detector_is_identified() {
    let content = "detector:nonexistent-legacy-detector-2024\n";
    let allowlist = Allowlist::parse(content);

    // Scan runs with findings for real detectors (e.g. AWS, GitHub PAT)
    let finding = make_finding(
        "github-classic-pat",
        "src/lib.rs",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    );
    let matched = allowlist.record_match(&finding);
    assert!(!matched, "finding for active detector does not match nonexistent suppression");

    let unused = allowlist.unused_entries();
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0].entry, "detector:nonexistent-legacy-detector-2024");
    assert_eq!(unused[0].match_count, 0);
}
