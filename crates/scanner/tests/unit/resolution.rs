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
        companions: std::collections::HashMap::new(),
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

#[test]
fn named_beats_entropy() {
    let matches = vec![
        make_match("github-classic-pat", "ghp_ABC123", Some(0.75)),
        make_match("entropy-generic", "ghp_ABC123", Some(0.90)),
    ];
    let resolved = resolve_matches(matches);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].detector_id.as_ref(), "github-classic-pat");
    assert_eq!(resolved[0].credential.as_ref(), "ghp_ABC123");
}
