//! Outlier cases for the massive handwritten adversarial integration suite.
//!
//! Exclusively validates SSRF bogon checks, loopback evasion variations, DNS caches,
//! and verifier cache lookups.

use keyhog_verifier::ssrf::{is_private_ip_addr_fast, is_private_url};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =========================================================================
// 1. SSRF BOGON AND LOOPBACK IP ADDRESS FAST CHECKS
// =========================================================================

#[test]
fn adv3_ssrf_ipv4_loopback_127_0_0_1_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_loopback_127_255_255_254_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_private_class_a_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_private_class_b_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(172, 20, 30, 40));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_private_class_c_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 20));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_link_local_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_unspecified_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_multicast_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_cgnat_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(100, 64, 5, 6));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_broadcast_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_loopback_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_unspecified_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_link_local_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_unique_local_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_multicast_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_public_must_not_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(!is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_public_must_not_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    assert!(!is_private_ip_addr_fast(&ip));
}

// =========================================================================
// 2. SSRF URL SCHEME AND DOMAIN EVASION CHECKS
// =========================================================================

#[test]
fn adv3_ssrf_url_localhost_domain_must_be_blocked() {
    assert!(is_private_url("http://localhost/verify"));
}

#[test]
fn adv3_ssrf_url_localhost_capitalized_must_be_blocked() {
    assert!(is_private_url("http://LOCALHOST/verify"));
}

#[test]
fn adv3_ssrf_url_dot_local_domain_must_be_blocked() {
    assert!(is_private_url("http://service.local/verify"));
}

#[test]
fn adv3_ssrf_url_dot_internal_domain_must_be_blocked() {
    assert!(is_private_url("http://database.internal/verify"));
}

#[test]
fn adv3_ssrf_url_dot_localdomain_must_be_blocked() {
    assert!(is_private_url("http://router.localdomain/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_loopback_dotted_must_be_blocked() {
    assert!(is_private_url("http://127.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_private_class_a_dotted_must_be_blocked() {
    assert!(is_private_url("http://10.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_private_class_b_dotted_must_be_blocked() {
    assert!(is_private_url("http://172.16.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_private_class_c_dotted_must_be_blocked() {
    assert!(is_private_url("http://192.168.1.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv6_loopback_bracketed_must_be_blocked() {
    assert!(is_private_url("http://[::1]/verify"));
}

#[test]
fn adv3_ssrf_url_ipv6_unspecified_bracketed_must_be_blocked() {
    assert!(is_private_url("http://[::]/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_decimal_integer_representation_must_be_blocked() {
    assert!(is_private_url("http://2130706433/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_hex_representation_must_be_blocked() {
    assert!(is_private_url("http://0x7f000001/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_hex_caps_representation_must_be_blocked() {
    assert!(is_private_url("http://0X7F000001/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_octal_representation_must_be_blocked() {
    assert!(is_private_url("http://017700000001/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_octal_dotted_representation_must_be_blocked() {
    assert!(is_private_url("http://0177.0.0.1/verify")); // 127.0.0.1 octal
}

#[test]
fn adv3_ssrf_url_ipv4_hex_dotted_representation_must_be_blocked() {
    // Malformed IP representation checks
    assert!(is_private_url("http://0x7f.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_malformed_ip_with_negative_octets_must_be_blocked() {
    assert!(is_private_url("http://127.0.0.-1/verify"));
}

#[test]
fn adv3_ssrf_url_malformed_ip_with_too_many_dots_must_be_blocked() {
    assert!(is_private_url("http://127.0.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_malformed_ip_with_hex_prefix_and_negative_must_be_blocked() {
    assert!(is_private_url("http://0x7f.0.0.-1/verify"));
}

#[test]
fn adv3_ssrf_url_public_domain_must_not_be_blocked() {
    assert!(!is_private_url("https://api.stripe.com/v1/charges"));
}

#[test]
fn adv3_ssrf_url_public_ip_dotted_must_not_be_blocked() {
    assert!(!is_private_url("http://8.8.8.8/verify"));
}
// Verifier/cache outliers for the massive handwritten adversarial suite.
// Validates deduplication logic, scope rules, cross-detector folding,
// confidence aggregation, companion merging, and location equivalence.

use keyhog_core::{
    dedup_cross_detector, dedup_matches, redact, DedupScope, MatchLocation, RawMatch, Severity,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

fn credential_hash(credential: &str) -> [u8; 32] {
    Sha256::digest(credential.as_bytes()).into()
}

// Helper to build a RawMatch
fn make_raw_match(
    detector_id: &str,
    credential: &str,
    file_path: &str,
    line: usize,
    offset: usize,
    severity: Severity,
    confidence: Option<f64>,
    companions: HashMap<String, String>,
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(format!("Name-{detector_id}")),
        service: Arc::from(format!("Service-{detector_id}")),
        severity,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: credential_hash(credential).into(),
        companions,
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: Some(Arc::from(file_path)),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.0),
        confidence,
    }
}

// =========================================================================
// 1. DEDUPLICATION SCOPE NONE TESTS
// =========================================================================

#[test]
fn adv4_dedup_scope_none_keeps_all_distinct() {
    let m1 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        2,
        20,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let res = dedup_matches(vec![m1, m2], &DedupScope::None);
    assert_eq!(res.len(), 2);
}

// =========================================================================
// 2. DEDUPLICATION SCOPE FILE TESTS
// =========================================================================

#[test]
fn adv4_dedup_scope_file_groups_same_file() {
    let m1 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        2,
        20,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let res = dedup_matches(vec![m1, m2], &DedupScope::File);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].additional_locations.len(), 1);
}

#[test]
fn adv4_dedup_scope_file_separates_different_files() {
    let m1 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws",
        "AKIA1",
        "b.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let res = dedup_matches(vec![m1, m2], &DedupScope::File);
    assert_eq!(res.len(), 2);
}

// =========================================================================
// 3. DEDUPLICATION SCOPE CREDENTIAL TESTS
// =========================================================================

#[test]
fn adv4_dedup_scope_credential_groups_across_files() {
    let m1 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws",
        "AKIA1",
        "b.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let res = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].additional_locations.len(), 1);
}

// =========================================================================
// 4. CROSS DETECTOR GROUPING AND PRIORITY RULES
// =========================================================================

#[test]
fn adv4_cross_detector_priority_highest_confidence_wins() {
    let m1 = make_raw_match(
        "aws-low-conf",
        "SECRET123",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.4),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws-high-conf",
        "SECRET123",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.9),
        HashMap::new(),
    );
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let res = dedup_cross_detector(deduped);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].detector_id.as_ref(), "aws-high-conf");
}

#[test]
fn adv4_cross_detector_priority_highest_severity_wins_on_equal_confidence() {
    let m1 = make_raw_match(
        "aws-med-sev",
        "SECRET123",
        "a.txt",
        1,
        10,
        Severity::Medium,
        Some(0.8),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws-critical-sev",
        "SECRET123",
        "a.txt",
        1,
        10,
        Severity::Critical,
        Some(0.8),
        HashMap::new(),
    );
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let res = dedup_cross_detector(deduped);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].detector_id.as_ref(), "aws-critical-sev");
}

#[test]
fn adv4_cross_detector_priority_lexicographic_tiebreak() {
    let m1 = make_raw_match(
        "aws-b-detector",
        "SECRET123",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let m2 = make_raw_match(
        "aws-a-detector",
        "SECRET123",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        HashMap::new(),
    );
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let res = dedup_cross_detector(deduped);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].detector_id.as_ref(), "aws-a-detector");
}

// =========================================================================
// 5. COMPANION MERGING AND ALPHABETICAL DELIMITING
// =========================================================================

#[test]
fn adv4_companion_merging_keeps_distinct_values_delimited() {
    let mut c1 = HashMap::new();
    c1.insert("org".to_string(), "org-1".to_string());
    let mut c2 = HashMap::new();
    c2.insert("org".to_string(), "org-2".to_string());

    let m1 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        1,
        10,
        Severity::High,
        Some(0.8),
        c1,
    );
    let m2 = make_raw_match(
        "aws",
        "AKIA1",
        "a.txt",
        2,
        20,
        Severity::High,
        Some(0.8),
        c2,
    );

    let res = dedup_matches(vec![m1, m2], &DedupScope::File);
    assert_eq!(res.len(), 1);
    let org_val = res[0].companions.get("org").unwrap();
    assert!(org_val.contains("org-1"));
    assert!(org_val.contains("org-2"));
    assert!(org_val.contains(" | "));
}

// =========================================================================
// 6. REDACTION UTILITY ADVERSARIAL CASES
// =========================================================================

#[test]
fn adv4_redact_short_credential_produces_four_asterisks() {
    assert_eq!(redact("123"), "****");
    assert_eq!(redact("12345678"), "****");
}

#[test]
fn adv4_redact_long_ascii_credential_preserves_two_edge_chars() {
    assert_eq!(redact("123456789"), "12...89");
}

#[test]
fn adv4_redact_utf8_long_credential_preserves_two_edge_chars() {
    // UTF-8 path: 9 characters
    let credential = "🦀🦀🦀🦀🔥🦖🦖🦖🦖";
    assert_eq!(redact(credential), "🦀🦀...🦖🦖");
}

#[test]
fn adv4_redact_utf8_short_credential_produces_four_asterisks() {
    assert_eq!(redact("🦀🦀🦀"), "****");
}
