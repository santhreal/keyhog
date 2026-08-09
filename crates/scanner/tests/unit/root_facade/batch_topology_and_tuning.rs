use keyhog_core::{Chunk, CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity};
use keyhog_scanner::testing::named_detector_fixture_defaults;
use keyhog_scanner::CompiledScanner;
use std::sync::Arc;

#[test]
fn test_decoded_candidates_sort_total_ordering_determinism() {
    fn dummy_raw_match(id: &str, cred: &str, offset: usize, severity: Severity) -> RawMatch {
        RawMatch {
            detector_id: Arc::from(id),
            detector_name: Arc::from(id),
            service: Arc::from("service"),
            severity,
            credential: SensitiveString::from(cred),
            credential_hash: CredentialHash::from([0u8; 32]),
            companions: Default::default(),
            location: MatchLocation {
                source: Arc::from("filesystem"),
                file_path: Some(Arc::from("test.txt")),
                line: Some(1),
                offset,
                commit: None,
                author: None,
                date: None,
            },
            entropy: Some(4.5),
            confidence: Some(0.9),
        }
    }

    let m1 = dummy_raw_match("det_a", "cred1", 100, Severity::High);
    let m2 = dummy_raw_match("det_b", "cred2", 100, Severity::Critical);
    let m3 = dummy_raw_match("det_a", "cred3", 100, Severity::Medium);

    let mut list_1 = vec![m1.clone(), m2.clone(), m3.clone()];
    let mut list_2 = vec![m3.clone(), m1.clone(), m2.clone()];

    let sort_fn = |a: &RawMatch, b: &RawMatch| {
        a.location
            .offset
            .cmp(&b.location.offset)
            .then_with(|| a.cmp(b))
    };

    list_1.sort_by(sort_fn);
    list_2.sort_by(sort_fn);

    assert_eq!(
        list_1, list_2,
        "total ordering sorting must yield deterministic results regardless of input order"
    );
}

#[test]
fn test_is_hot_confirmed_pattern_fails_closed_on_out_of_bounds() {
    let scanner = CompiledScanner::compile(vec![]).expect("empty scanner compiles");
    assert!(!scanner.is_hot_confirmed_pattern(usize::MAX));
    assert!(!scanner.is_hot_confirmed_pattern(999_999));
}
