//! Gap test: the scanner's `aws` shim actually re-exports the canonical offline
//! AWS account/canary decoder.
//!
//! `crates/scanner/src/aws.rs` is a one-line `pub use keyhog_core::finding_metadata;`
//! shim. Its whole reason to exist is that `keyhog_scanner::aws::finding_metadata`
//! keeps resolving to the fleet-canonical decoder so the CLI postprocess path
//! (`orchestrator/postprocess.rs`: `keyhog_scanner::aws::finding_metadata(credential)`)
//! attaches the decoded account id + canary flag with no live verify. The decode
//! itself is tested at the source in `crates/core/tests/unit/aws.rs`; this pins
//! the SCANNER-side re-export contract with the same exact vectors, which had no
//! scanner-side coverage.

use keyhog_scanner::aws::finding_metadata;

#[test]
fn scanner_aws_reexport_decodes_account_id() {
    let meta = finding_metadata("ASIAY34FZKBOKMUTVV7A").expect("a real key id must decode");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("609629065308"),
        "the scanner re-export must decode the offline AWS account id"
    );
    // A normal (non-canary) account carries no canary flag through the shim.
    assert_eq!(meta.get("is_canary"), None);
}

#[test]
fn scanner_aws_reexport_flags_canary_with_suppression_note() {
    let meta = finding_metadata("AKIAAYLPMN5HAAAAAAAA").expect("a canary key id must still decode");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("052310077262"),
        "the canary key's account id must decode through the scanner re-export"
    );
    assert_eq!(meta.get("is_canary").map(String::as_str), Some("true"));
    assert!(
        meta.get("canary_message")
            .is_some_and(|m| m.contains("canarytokens.org")),
        "a canary finding must carry the do-not-verify suppression note"
    );
}

#[test]
fn scanner_aws_reexport_returns_none_for_undecodable() {
    assert!(
        finding_metadata("hunter2").is_none(),
        "a non-key-id string must not produce AWS metadata"
    );
}
