//! Unit tests for the offline AWS account-ID decode + canary classification in
//! [`keyhog_core::aws`]. Migrated out of `src/aws.rs`: `core/src` must stay free
//! of inline `#[cfg(test)]` modules (KH-GAP-004 / `gap::no_inline_tests_in_src`),
//! so the shared decode/canary logic is exercised here under `tests/unit/`.

use keyhog_core::aws::{
    account_is_canary, aws_account_from_key_id, finding_metadata, key_id_is_canary,
};

#[test]
fn decodes_canonical_truffle_sample() {
    assert_eq!(
        aws_account_from_key_id("ASIAY34FZKBOKMUTVV7A").as_deref(),
        Some("609629065308")
    );
}

#[test]
fn decodes_akia_with_leading_zero_account() {
    // canarytokens.org / Thinkst account; the leading zero MUST be kept.
    assert_eq!(
        aws_account_from_key_id("AKIAAYLPMN5HAAAAAAAA").as_deref(),
        Some("052310077262")
    );
}

#[test]
fn rejects_non_aws_and_malformed_ids() {
    assert_eq!(aws_account_from_key_id("not-an-aws-key"), None);
    assert_eq!(aws_account_from_key_id("AKIA1234"), None);
    assert_eq!(aws_account_from_key_id("ZZZZY34FZKBOKMUTVV7A"), None);
    assert_eq!(aws_account_from_key_id("ASIAy34FZKBOKMUTVV7A"), None);
}

#[test]
fn canary_account_is_recognised() {
    assert!(account_is_canary("052310077262"));
    assert!(account_is_canary("044858866125"));
    assert!(!account_is_canary("609629065308"));
}

#[test]
fn canary_key_id_round_trips_through_decode() {
    assert!(key_id_is_canary("AKIAAYLPMN5HAAAAAAAA"));
    assert!(!key_id_is_canary("ASIAY34FZKBOKMUTVV7A"));
    assert!(!key_id_is_canary("hunter2"));
}

#[test]
fn finding_metadata_surfaces_account_id() {
    let meta = finding_metadata("ASIAY34FZKBOKMUTVV7A").expect("decodable");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("609629065308")
    );
    assert!(finding_metadata("hunter2").is_none());
}

#[test]
fn finding_metadata_flags_canary_and_suppression_note() {
    let meta = finding_metadata("AKIAAYLPMN5HAAAAAAAA").expect("decodable canary key");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("052310077262")
    );
    assert_eq!(meta.get("is_canary").map(String::as_str), Some("true"));
    assert!(meta
        .get("canary_message")
        .is_some_and(|m| m.contains("canarytokens.org")));

    let normal = finding_metadata("ASIAY34FZKBOKMUTVV7A").expect("decodable");
    assert_eq!(normal.get("is_canary"), None);
}
