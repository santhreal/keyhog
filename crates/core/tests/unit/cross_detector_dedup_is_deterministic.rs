use keyhog_core::{dedup_cross_detector, DedupedMatch, MatchLocation, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn make_deduped(detector: &str, service: &str, conf: f64) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("AIza_FAKE_KEY_NOT_REAL_VALUE_1234567890"),
        credential_hash: [0; 32].into(),
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
fn cross_detector_dedup_is_deterministic() {
    let a = make_deduped("zzz-detector", "zzz", 0.9);
    let b = make_deduped("aaa-detector", "aaa", 0.9);
    let out1 = dedup_cross_detector(vec![a.clone(), b.clone()]);
    let out2 = dedup_cross_detector(vec![b, a]);
    assert_eq!(
        out1.len(),
        out2.len(),
        "cardinality stable regardless of input order"
    );
}
