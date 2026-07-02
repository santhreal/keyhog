//! Regression coverage for the verifier's AWS canary / account-ID suppression
//! short-circuit (`crate::verify::aws::build_aws_probe`).
//!
//! An AWS access-key ID (`AKIA…`/`ASIA…`) embeds its 12-digit owning account
//! number, recoverable fully offline. When that decoded account belongs to a
//! known canary issuer (canarytokens.org / Thinkst), the verifier MUST refuse
//! to send any live STS probe — a signed request would alert whoever planted
//! the tripwire. This suite pins:
//!   * the exact suppression decision (`VerificationResult::Unverifiable`),
//!   * the exact suppression reason surfaced in metadata (`is_canary=true`,
//!     the decoded `account_id`, and the canarytokens note),
//!   * that suppression fires BEFORE the empty-secret / format / region gates
//!     (fail-closed ordering, no network egress), and
//!   * that a real (non-canary) account is NOT suppressed as a canary.
//!
//! Known-answer fixtures (verified against `keyhog_core::aws` decode):
//!   * `AKIAAYLPMN5HAAAAAAAA` -> account `052310077262` (first-party canary)
//!   * `ASIAY34FZKBOKMUTVV7A` -> account `609629065308` (real, non-canary)

use std::collections::HashMap;

use keyhog_core::VerificationResult;
use keyhog_core::{finding_metadata, key_id_canary_status, parse_canary_account_ids};
use keyhog_verifier::testing::{TestApi as VerifierApi, VerifierTestApi};

// A well-formed AWS access-key ID whose embedded account (052310077262) is a
// canarytokens.org / Thinkst first-party issuer account.
const CANARY_KEY: &str = "AKIAAYLPMN5HAAAAAAAA";
const CANARY_ACCOUNT: &str = "052310077262";

// A well-formed, decodable AWS access-key ID for a real (non-canary) account.
const REAL_KEY: &str = "ASIAY34FZKBOKMUTVV7A";
const REAL_ACCOUNT: &str = "609629065308";

// A syntactically valid AWS secret access key (40 chars, base64 alphabet).
const VALID_SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// -------------------------------------------------------------------------
// Verifier probe short-circuit: canary key is suppressed with exact reason.
// -------------------------------------------------------------------------

#[tokio::test]
async fn canary_key_is_unverifiable_with_full_canary_metadata_before_network() {
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test(CANARY_KEY, VALID_SECRET, "us-east-1")
        .await;

    // Exact enum variant: the suppression decision is Unverifiable, never a
    // live/dead/error verdict that would have required a network probe.
    assert_eq!(result, VerificationResult::Unverifiable);

    // Exact suppression reason, surfaced to the operator via metadata.
    assert_eq!(metadata.get("is_canary").map(String::as_str), Some("true"));
    assert_eq!(
        metadata.get("account_id").map(String::as_str),
        Some(CANARY_ACCOUNT)
    );
    assert!(
        metadata
            .get("canary_message")
            .is_some_and(|m| m.contains("canarytokens.org")),
        "canary suppression must explain WHY via the canarytokens note: {metadata:?}"
    );

    // Canary suppression is a conclusive decision, never a transient/retryable
    // one (the probe never left the process).
    assert!(!transient);
}

#[tokio::test]
async fn canary_suppression_fires_before_empty_secret_gate() {
    // An empty secret would normally return Unverifiable with EMPTY metadata.
    // The canary short-circuit must win, so the metadata still carries the
    // canary reason — proving suppression precedes the empty-secret branch.
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test(CANARY_KEY, "", "us-east-1")
        .await;

    assert_eq!(result, VerificationResult::Unverifiable);
    assert_eq!(metadata.get("is_canary").map(String::as_str), Some("true"));
    assert_eq!(
        metadata.get("account_id").map(String::as_str),
        Some(CANARY_ACCOUNT)
    );
    assert!(!transient);
}

#[tokio::test]
async fn canary_suppression_fires_before_invalid_region_gate() {
    // An invalid region ("us/east-1") would normally short-circuit to
    // VerificationResult::Error. The canary gate runs first, so we still get
    // the canary Unverifiable decision, never the region Error.
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test(CANARY_KEY, VALID_SECRET, "us/east-1")
        .await;

    assert_eq!(result, VerificationResult::Unverifiable);
    assert!(
        !matches!(result, VerificationResult::Error(_)),
        "canary key must never surface a region Error before suppression"
    );
    assert_eq!(metadata.get("is_canary").map(String::as_str), Some("true"));
    assert!(!transient);
}

#[tokio::test]
async fn canary_suppression_fires_before_format_gate() {
    // A too-short secret ("short") would normally short-circuit to Dead with
    // format_valid=false. The canary gate wins, so no format metadata appears
    // and the decision stays Unverifiable.
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test(CANARY_KEY, "short", "us-east-1")
        .await;

    assert_eq!(result, VerificationResult::Unverifiable);
    assert_eq!(metadata.get("format_valid"), None);
    assert_eq!(metadata.get("is_canary").map(String::as_str), Some("true"));
    assert!(!transient);
}

// -------------------------------------------------------------------------
// Negative twin: a real (non-canary) account is NOT suppressed as a canary.
// -------------------------------------------------------------------------

#[tokio::test]
async fn real_account_key_passes_canary_gate_and_reaches_region_error() {
    // The real key clears the canary short-circuit; with an invalid region it
    // then falls through to the region Error branch. Crucially it is NOT the
    // canary Unverifiable decision and carries NO canary metadata.
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test(REAL_KEY, VALID_SECRET, "us/east-1")
        .await;

    assert_eq!(
        result,
        VerificationResult::Error(keyhog_verifier::testing::INVALID_AWS_REGION_ERROR.into())
    );
    assert_eq!(metadata.get("is_canary"), None);
    assert!(
        metadata.is_empty(),
        "non-canary region-error path must not claim any AWS metadata: {metadata:?}"
    );
    assert!(!transient);
}

#[tokio::test]
async fn real_account_empty_secret_is_unverifiable_but_not_a_canary() {
    // Adversarial collision: an empty secret ALSO yields Unverifiable, exactly
    // like a canary. The decisions must be distinguishable by their reason —
    // the canary carries is_canary metadata, the empty-secret path is bare.
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test(REAL_KEY, "", "us-east-1")
        .await;

    assert_eq!(result, VerificationResult::Unverifiable);
    assert_eq!(metadata.get("is_canary"), None);
    assert_eq!(metadata.get("canary_message"), None);
    assert!(
        metadata.is_empty(),
        "empty-secret Unverifiable must be a bare decision, not a canary: {metadata:?}"
    );
    assert!(!transient);
}

#[tokio::test]
async fn undecodable_access_key_is_dead_not_canary_suppressed() {
    // "ZZZZ…" is not a decodable AKIA/ASIA id, so canary status is false and
    // the format gate marks it Dead. No canary metadata may leak.
    let (result, metadata, transient) = VerifierApi
        .build_aws_probe_final_for_test("ZZZZ1234567890ABCDEF", VALID_SECRET, "us-east-1")
        .await;

    assert_eq!(result, VerificationResult::Dead);
    assert_eq!(
        metadata.get("format_valid").map(String::as_str),
        Some("false")
    );
    assert_eq!(metadata.get("is_canary"), None);
    assert!(!transient);
}

// -------------------------------------------------------------------------
// Core account-suppression decision inputs (single source of truth used by
// both scanner metadata and the verifier short-circuit above).
// -------------------------------------------------------------------------

#[test]
fn key_id_canary_status_is_exact_for_canary_real_and_garbage() {
    assert_eq!(key_id_canary_status(CANARY_KEY), Ok(true));
    assert_eq!(key_id_canary_status(REAL_KEY), Ok(false));
    // Non-AWS garbage decodes to no account, so it is definitively non-canary.
    assert_eq!(key_id_canary_status("hunter2"), Ok(false));
}

#[test]
fn finding_metadata_for_canary_carries_account_flag_and_note() {
    let meta = finding_metadata(CANARY_KEY).expect("canary key is decodable");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some(CANARY_ACCOUNT)
    );
    assert_eq!(meta.get("is_canary").map(String::as_str), Some("true"));
    assert!(
        meta.get("canary_message")
            .is_some_and(|m| m.contains("canarytokens.org")),
        "canary metadata must carry the suppression note: {meta:?}"
    );
}

#[test]
fn finding_metadata_for_real_account_has_id_but_no_canary_flag() {
    let meta = finding_metadata(REAL_KEY).expect("real key is decodable");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some(REAL_ACCOUNT)
    );
    assert_eq!(meta.get("is_canary"), None);
    assert_eq!(meta.get("canary_message"), None);
    // Exactly one field: the decoded account, nothing more.
    assert_eq!(meta.len(), 1);
}

#[test]
fn finding_metadata_for_undecodable_key_is_none() {
    assert_eq!(finding_metadata("not-an-aws-key"), None);
    // Right length but a non-base32 body ('!' is out of alphabet).
    assert_eq!(finding_metadata("AKIA1234567890ABCDE!"), None);
}

#[test]
fn account_classifier_distinguishes_first_party_knockoff_and_real() {
    use keyhog_core::testing::{CoreTestApi, TestApi as CoreApi};

    // First-party canarytokens.org issuer account.
    assert!(CoreApi.aws_account_is_canary(CANARY_ACCOUNT));
    // Off-brand knockoff account from the Tier-B `[knockoff]` table.
    assert!(CoreApi.aws_account_is_canary("044858866125"));
    // A real customer account (the STS example account) is NOT a canary.
    assert!(!CoreApi.aws_account_is_canary("123456789012"));
    assert!(!CoreApi.aws_account_is_canary(REAL_ACCOUNT));
}

#[test]
fn configured_canary_account_parser_dedups_and_rejects_malformed() {
    let parsed = parse_canary_account_ids([" 609629065308 ", "609629065308", "000000000001"])
        .expect("valid 12-digit accounts parse");
    // Whitespace-trimmed duplicate collapses to a single entry.
    assert_eq!(parsed.len(), 2);
    assert!(parsed.contains("609629065308"));
    assert!(parsed.contains("000000000001"));

    // A short (non-12-digit) account id must fail closed.
    let err = parse_canary_account_ids(["1234"]).expect_err("short account id must be rejected");
    assert!(
        err.contains("1234"),
        "rejection must name the offending account id: {err}"
    );
}
