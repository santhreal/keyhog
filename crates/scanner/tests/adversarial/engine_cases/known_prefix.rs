use super::support::*;

#[test]
fn known_prefix_credential_always_detected_despite_low_confidence_context() {
    use keyhog_core::Severity;

    // Stripe secret key in a comment context — normally heavily suppressed.
    let stripe_credential = "sk_live_51H7xKjGf0a1b2c3d4e5f6g7h";
    let detector = DetectorSpec {
        id: "stripe-secret-key".into(),
        name: "Stripe Secret Key".into(),
        service: "stripe".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"sk_live_[a-zA-Z0-9]{24}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["sk_live_".into()],
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // Place inside a comment block — a context that normally suppresses low-confidence matches.
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
    use std::sync::Arc;

    fn make_match(detector_id: &str, credential: &str, confidence: Option<f64>) -> RawMatch {
        RawMatch {
            detector_id: Arc::from(detector_id),
            detector_name: Arc::from(detector_id),
            service: Arc::from("test"),
            severity: Severity::High,
            credential: Arc::from(credential),
            credential_hash: format!("hash-{}", credential),
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

    let stripe_credential = "sk_live_51H7xKjGf0a1b2c3d4e5f6g7h";
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

// Validates the post-ML confidence-floor logic; meaningful only with the `ml`
// feature on. Under `--no-default-features` the matcher's checksum gate fires
// first and rejects the synthetic CRC32-invalid `ghp_aaaa…` credential before
// any ML/penalty path runs, so the assertion has no test surface to evaluate.
#[cfg(feature = "ml")]
#[test]
fn known_prefix_survives_ml_and_context_penalties() {
    // Simulate a credential that would normally be crushed by post-ML penalties
    // because it contains repetitive-looking suffixes. Known prefixes should still
    // survive because the floor is applied after all penalties.
    let credential = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let detector = DetectorSpec {
        id: "github-classic-pat".into(),
        name: "GitHub Classic PAT".into(),
        service: "github".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"ghp_[a-zA-Z0-9]{36}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["ghp_".into()],
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
            m.confidence.unwrap_or(0.0) >= 0.8,
            "known-prefix confidence must never drop below 0.8"
        );
    }
}
