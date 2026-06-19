use keyhog_core::{
    dedup_cross_detector, dedup_matches, DedupScope, DedupedMatch, MatchLocation, RawMatch,
    Severity,
};
use std::collections::HashMap;
use std::sync::Arc;

fn make_raw(detector: &str, credential: &str, conf: f64) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(detector.split('-').next().unwrap_or(detector)),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: [0; 32],
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
    out.iter()
        .map(|m| format!("{}|{}|{:?}", m.detector_id, m.credential, m.confidence))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn full_dedup_pipeline_is_deterministic_across_input_orders() {
    let inputs = vec![
        make_raw("aws-key", "AKIAIOSFODNN7EXAMPLE_AAAA", 0.9),
        make_raw("ghp-token", "ghp_aBcDeF1234567890_BBBB", 0.85),
        make_raw("slack-bot", "xoxb-1234-5678-CCCC_test", 0.8),
        make_raw("aws-key", "AKIAIOSFODNN7EXAMPLE_AAAA", 0.9),
        make_raw("stripe-secret", "sk_test_4eC39HqLyjW_DDDD", 0.95),
    ];
    let scope = DedupScope::Credential;
    let out_a = dedup_cross_detector(dedup_matches(inputs.clone(), &scope));
    let mut reversed = inputs.clone();
    reversed.reverse();
    let out_b = dedup_cross_detector(dedup_matches(reversed, &scope));
    assert_eq!(fingerprint(&out_a), fingerprint(&out_b));
    let shuffled = vec![
        inputs[2].clone(),
        inputs[4].clone(),
        inputs[0].clone(),
        inputs[3].clone(),
        inputs[1].clone(),
    ];
    let out_c = dedup_cross_detector(dedup_matches(shuffled, &scope));
    assert_eq!(fingerprint(&out_a), fingerprint(&out_c));
}
