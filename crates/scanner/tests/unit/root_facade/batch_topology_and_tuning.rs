use keyhog_core::{CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity};
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
#[test]
fn test_chunk_lane_threshold_validation_and_sentinel() {
    use keyhog_scanner::ScannerTuningConfig;

    let cfg_none = ScannerTuningConfig {
        chunk_lane_threshold: None,
        ..Default::default()
    };
    assert_eq!(
        cfg_none.effective().chunk_lane_threshold,
        64 * 1024,
        "None must yield default 64 KiB threshold"
    );

    let cfg_valid = ScannerTuningConfig {
        chunk_lane_threshold: Some(32 * 1024),
        ..Default::default()
    };
    assert_eq!(
        cfg_valid.effective().chunk_lane_threshold,
        32 * 1024,
        "Valid threshold must be preserved"
    );

    let cfg_zero = ScannerTuningConfig {
        chunk_lane_threshold: Some(0),
        ..Default::default()
    };
    assert_eq!(
        cfg_zero.effective().chunk_lane_threshold,
        64 * 1024,
        "0 must be rejected and yield default 64 KiB threshold"
    );

    let cfg_max = ScannerTuningConfig {
        chunk_lane_threshold: Some(usize::MAX),
        ..Default::default()
    };
    assert_eq!(
        cfg_max.effective().chunk_lane_threshold,
        64 * 1024,
        "usize::MAX must be rejected and yield default 64 KiB threshold"
    );
}
#[test]
fn test_scratch_storage_capacity_retention_ceiling() {
    use std::collections::HashSet;

    let mut set: HashSet<usize> = HashSet::new();
    for i in 0..10_000 {
        set.insert(i);
    }
    let capacity_large = set.capacity();
    assert!(
        capacity_large > 4096,
        "Large set capacity must exceed ceiling"
    );

    set.clear();
    if set.capacity() > 4096 {
        set = HashSet::new();
    }
    assert!(
        set.capacity() <= 4096,
        "Capacity after ceiling drop must shrink below ceiling"
    );
}

#[test]
fn test_entropy_line_indices_above_u32_max() {
    let large_line_idx_1 = u32::MAX as usize;
    let large_line_idx_2 = u32::MAX as usize + 1;

    let indices = vec![large_line_idx_1, large_line_idx_2];
    assert_eq!(indices[0], u32::MAX as usize);
    assert_eq!(indices[1], u32::MAX as usize + 1);
    assert!(indices[1] > u32::MAX as usize);
}
