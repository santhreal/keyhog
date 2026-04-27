use keyhog::{
    inline_suppression::filter_inline_suppressions,
    value_parsers::{parse_byte_size, parse_decode_depth, parse_min_confidence},
};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;
use std::thread;

fn dummy_match(file_path: Option<&str>, line: Option<usize>, detector_id: &str) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: Arc::from("secret"),
        credential_hash: String::new(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: file_path.map(Arc::from),
            line,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    }
}

#[test]
fn test_empty_parse_byte_size() {
    assert_eq!(parse_byte_size("").unwrap(), 0);
}

#[test]
fn test_empty_parse_decode_depth() {
    assert!(parse_decode_depth("").is_err());
}

#[test]
fn test_empty_parse_min_confidence() {
    assert!(parse_min_confidence("").is_err());
}

#[test]
fn test_empty_filter_inline_suppressions() {
    let result = filter_inline_suppressions(vec![]);
    assert!(result.is_empty());
}

#[test]
fn test_null_bytes_parse_byte_size() {
    assert!(parse_byte_size("\0").is_err());
    assert!(parse_byte_size("10\0MB").is_err());
}

#[test]
fn test_null_bytes_parse_decode_depth() {
    assert!(parse_decode_depth("\0").is_err());
}

#[test]
fn test_null_bytes_parse_min_confidence() {
    assert!(parse_min_confidence("\0").is_err());
}

#[test]
fn test_null_bytes_filter_inline_suppressions() {
    let m = dummy_match(Some("test.txt\0"), Some(1), "test\0");
    let result = filter_inline_suppressions(vec![m.clone()]);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_max_u64_parse_byte_size() {
    let max_u64_str = format!("{}B", u64::MAX);
    assert!(parse_byte_size(&max_u64_str).is_err());
}

#[test]
fn test_max_usize_parse_decode_depth() {
    let max_usize_str = format!("{}", usize::MAX);
    assert!(parse_decode_depth(&max_usize_str).is_err());
}

#[test]
fn test_large_f64_parse_min_confidence() {
    assert!(parse_min_confidence("1e100").is_err());
}

#[test]
fn test_1mb_parse_byte_size() {
    let mut large_str = String::from("1");
    large_str.push_str(&"0".repeat(1024 * 1024));
    large_str.push_str("MB");
    assert!(parse_byte_size(&large_str).is_err());
}

#[test]
fn test_1mb_parse_decode_depth() {
    let large_str = "1".repeat(1024 * 1024);
    assert!(parse_decode_depth(&large_str).is_err());
}

#[test]
fn test_1mb_parse_min_confidence() {
    let mut large_str = String::from("0.");
    large_str.push_str(&"1".repeat(1024 * 1024));
    assert!(parse_min_confidence(&large_str).is_ok()); // Valid long fractional string
}

#[test]
fn test_1mb_filter_inline_suppressions() {
    let path = "A".repeat(1024 * 1024);
    let m = dummy_match(Some(&path), Some(1), "test");
    let result = filter_inline_suppressions(vec![m]);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_concurrent_filter_inline_suppressions() {
    let mut handles = vec![];
    for _ in 0..8 {
        handles.push(thread::spawn(|| {
            for _ in 0..100 {
                let m = dummy_match(Some("test.txt"), Some(1), "test");
                let result = filter_inline_suppressions(vec![m]);
                assert_eq!(result.len(), 1);
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_malformed_parse_byte_size() {
    assert!(parse_byte_size("MB").is_err());
    assert!(parse_byte_size("10 M B").is_err());
    assert!(parse_byte_size("10XB").is_err());
}

#[test]
fn test_malformed_parse_decode_depth() {
    assert!(parse_decode_depth("5.5").is_err());
    assert!(parse_decode_depth("-1").is_err());
}

#[test]
fn test_malformed_parse_min_confidence() {
    assert!(parse_min_confidence("abc").is_err());
    assert!(parse_min_confidence("0.5.5").is_err());
}

#[test]
fn test_unicode_parse_byte_size() {
    assert!(parse_byte_size("10💩").is_err());
    assert!(parse_byte_size("١٠MB").is_err());
}

#[test]
fn test_unicode_parse_decode_depth() {
    assert!(parse_decode_depth("５").is_err()); // Fullwidth digit 5
}

#[test]
fn test_unicode_parse_min_confidence() {
    assert!(parse_min_confidence("０.５").is_err());
}

#[test]
fn test_unicode_filter_inline_suppressions() {
    let m = dummy_match(Some("test💩.txt"), Some(1), "test💩");
    let result = filter_inline_suppressions(vec![m]);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_duplicate_filter_inline_suppressions() {
    let m1 = dummy_match(Some("test.txt"), Some(1), "test");
    let m2 = dummy_match(Some("test.txt"), Some(1), "test");
    let result = filter_inline_suppressions(vec![m1, m2]);
    assert_eq!(result.len(), 2);
}

#[test]
fn test_duplicate_paths_different_lines() {
    let m1 = dummy_match(Some("test.txt"), Some(1), "test");
    let m2 = dummy_match(Some("test.txt"), Some(2), "test");
    let result = filter_inline_suppressions(vec![m1, m2]);
    assert_eq!(result.len(), 2);
}

#[test]
fn test_off_by_one_parse_decode_depth() {
    assert!(parse_decode_depth("0").is_err());
    assert!(parse_decode_depth("11").is_err());
}

#[test]
fn test_off_by_one_parse_min_confidence() {
    assert!(parse_min_confidence("-0.00001").is_err());
    assert!(parse_min_confidence("1.00001").is_err());
}

#[test]
fn test_exhaustion_filter_inline_suppressions() {
    let mut matches = Vec::with_capacity(100_000);
    for i in 0..100_000 {
        matches.push(dummy_match(Some("test.txt"), Some(i), "test"));
    }
    let result = filter_inline_suppressions(matches);
    assert_eq!(result.len(), 100_000);
}

#[test]
fn test_exhaustion_many_files() {
    let mut matches = Vec::with_capacity(100_000);
    for i in 0..100_000 {
        let path = format!("file_{}.txt", i);
        matches.push(dummy_match(Some(&path), Some(1), "test"));
    }
    let result = filter_inline_suppressions(matches);
    assert_eq!(result.len(), 100_000);
}

#[test]
fn test_filter_suppressions_no_line() {
    let m = dummy_match(Some("test.txt"), None, "test");
    let result = filter_inline_suppressions(vec![m]);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_filter_suppressions_non_filesystem() {
    let mut m = dummy_match(Some("test.txt"), Some(1), "test");
    m.location.source = Arc::from("git");
    let result = filter_inline_suppressions(vec![m]);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_filter_suppressions_no_path() {
    let m = dummy_match(None, Some(1), "test");
    let result = filter_inline_suppressions(vec![m]);
    assert_eq!(result.len(), 1);
}

// Make up for 33 total tests with more adversarial edge cases
#[test]
fn test_negative_byte_size() {
    assert!(parse_byte_size("-10MB").is_err());
}

#[test]
fn test_huge_byte_size() {
    assert!(parse_byte_size("10000000000000000000000000000MB").is_err());
}

#[test]
fn test_empty_unit_byte_size() {
    assert!(parse_byte_size("10").is_err());
}

#[test]
fn test_byte_size_lowercase_unit() {
    assert!(parse_byte_size("10gb").is_ok()); // Just a sanity check that standard works
}

#[test]
fn test_invalid_unit_byte_size() {
    assert!(parse_byte_size("10ZB").is_err());
}

#[test]
fn test_very_long_path_filter_inline_suppressions() {
    let path = "a/".repeat(5000);
    let m = dummy_match(Some(&path), Some(1), "test");
    let result = filter_inline_suppressions(vec![m]);
    assert_eq!(result.len(), 1);
}
