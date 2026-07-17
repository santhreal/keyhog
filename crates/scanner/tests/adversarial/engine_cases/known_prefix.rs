use super::support::*;

#[test]
fn known_prefix_credential_always_detected_despite_low_confidence_context() {
    use keyhog_core::Severity;

    // Stripe secret key in a comment context - normally heavily suppressed.
    let stripe_credential = concat!("sk_li", "ve_51H7xKjGf0a1b2c3d4e5f6g7h");
    let detector = DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "stripe-secret-key".into(),
        name: "Stripe Secret Key".into(),
        service: "stripe".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"sk_live_[a-zA-Z0-9]{24}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["sk_live_".into()],
        min_confidence: None,
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // Place inside a comment block - a context that normally suppresses low-confidence matches.
    let chunk = make_chunk(&format!(
        "// TODO: remove before deploy\n// STRIPE_KEY={}\n",
        stripe_credential
    ));
    let matches = scanner.scan(&chunk);

    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == stripe_credential),
        "known-prefix credential must be detected even in comment context"
    );
}

#[test]
fn resolution_prefers_specific_detector_over_generic_for_known_prefix() {
    use keyhog_core::{MatchLocation, RawMatch, Severity};
    use keyhog_scanner::resolution::resolve_matches;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn credential_hash(credential: &str) -> [u8; 32] {
        Sha256::digest(credential.as_bytes()).into()
    }

    fn make_match(detector_id: &str, credential: &str, confidence: Option<f64>) -> RawMatch {
        let service = keyhog_core::detector_spec_by_id(detector_id)
            .map(|spec| Arc::from(spec.service.as_str()))
            .unwrap_or_else(|| Arc::from("test"));
        RawMatch {
            detector_id: Arc::from(detector_id),
            detector_name: Arc::from(detector_id),
            service,
            severity: Severity::High,
            credential: keyhog_core::SensitiveString::from(credential),
            credential_hash: credential_hash(credential).into(),
            companions: HashMap::new(),
            location: MatchLocation {
                source: Arc::from("test"),
                file_path: Some(Arc::from("test.txt")),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence,
        }
    }

    let stripe_credential = concat!("sk_li", "ve_51H7xKjGf0a1b2c3d4e5f6g7h");
    // Generic detector has higher confidence, but specific detector must win.
    let matches = vec![
        make_match("generic-api-key", stripe_credential, Some(0.95)),
        make_match("stripe-secret-key", stripe_credential, Some(0.80)),
    ];

    let resolved = resolve_matches(matches);
    assert_eq!(
        resolved.len(),
        1,
        "resolution should keep exactly one match for the same credential"
    );
    assert_eq!(
        resolved[0].detector_id.as_ref(),
        "stripe-secret-key",
        "specific detector must win over generic for known-prefix credential"
    );
}

// Detector-owned checksum proof is applied after the shared scoring penalties.
// The repetitive body exercises the penalty while the corrupted twin proves
// that the confidence floor cannot bypass the same detector's validator.
#[test]
fn checksum_valid_known_prefix_survives_post_scoring_penalties() {
    // Simulate a credential that would normally be crushed by post-scoring penalties
    // because it has a repetitive (30×'a') body. Known prefixes should still
    // survive because the floor is applied after all penalties. The trailing 6
    // chars are the base62 CRC32 of the 30-'a' body, so the token is checksum-
    // VALID (a fabricated `ghp_` is now correctly dropped before scoring) while
    // the repeat-run body still exercises the post-scoring penalty path.
    let credential = concat!("gh", "p_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1yLcDB");
    let detector = DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "github-classic-pat".into(),
        name: "GitHub Classic PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        validators: vec![keyhog_core::DetectorValidatorSpec::Crc32Base62 {
            prefixes: vec!["ghp_".into()],
            entropy_len: 30,
            checksum_len: 6,
            reject_overlong: true,
            confidence_floor: 0.9,
        }],
        patterns: vec![PatternSpec {
            regex: r"ghp_[a-zA-Z0-9]{36}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["ghp_".into()],
        min_confidence: None,
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let chunk = make_chunk(&format!("GITHUB_TOKEN={}\n", credential));
    let matches = scanner.scan(&chunk);

    assert!(
        matches.iter().any(|m| m.credential.as_ref() == credential),
        "known-prefix credential must survive post-ML penalties"
    );
    if let Some(m) = matches.iter().find(|m| m.credential.as_ref() == credential) {
        assert!(
            m.confidence.unwrap_or(0.0) >= 0.9,
            "detector-owned checksum proof must retain its declared 0.9 floor"
        );
    }

    let invalid = format!("{}A", &credential[..credential.len() - 1]);
    let invalid_matches = scanner.scan(&make_chunk(&format!("GITHUB_TOKEN={invalid}\n")));
    assert!(
        invalid_matches
            .iter()
            .all(|matched| matched.credential.as_ref() != invalid.as_str()),
        "the same detector must reject a checksum-corrupted twin"
    );
}
