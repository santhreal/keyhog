//! Regression: the AWS SigV4 verify preflight must SANITIZE + RESOLVE every
//! signed field before the strict format / region screens.
//!
//! `build_aws_probe` resolves `access_key` / `secret_key` / `session_token` /
//! `region` from the captured credential + companions, then gates on
//! `valid_aws_format` (EXACT 20-char all-alphanumeric access key, >=40-char
//! base64 secret) and `validate_aws_region` (`[A-Za-z0-9-]`, <=30 chars). Two
//! everyday inputs are not valid literals of those shapes:
//!   * a line-anchored capture appends a trailing newline / control byte, so a
//!     LIVE `AKIA...\n` key is 21 chars with a control byte -> `valid_aws_format`
//!     false -> the probe used to return `Dead`, silently MISSING a live secret;
//!   * a `region` given as `companion.region` is a template reference, and `.`
//!     is not `[A-Za-z0-9-]`, so the region screen rejected it verbatim and a
//!     companion-sourced region never verified.
//!
//! The fix threads `sanitize_raw_value(&resolve_field(field, ...))` -- the same
//! resolve+sanitize the sibling `AuthSpec::Query` arm in `auth.rs` already
//! applies -- across all four fields. These tests lock that contract with real
//! values, including one that drives the real `build_aws_probe` preflight.

use keyhog_core::VerificationResult;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

/// The canonical AWS documentation example key pair: well-formed (`AKIA` + 16
/// alphanumerics = 20 chars; a 40-char `+//=`-bearing base64 secret).
const EXAMPLE_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const EXAMPLE_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

#[test]
fn trailing_newline_key_is_recovered_by_sanitization_not_marked_dead() {
    // A line-anchored capture yields the real key plus a trailing newline.
    let raw_access = format!("{EXAMPLE_ACCESS_KEY}\n");
    let raw_secret = format!("{EXAMPLE_SECRET_KEY}\n");

    // UNSANITIZED, the strict format screen rejects it (len 21 + a control byte)
    // -- the exact path that used to misreport a LIVE key as Dead.
    assert!(
        !TestApi.valid_aws_format_for_test(&raw_access, &raw_secret),
        "the raw newline-carrying capture must fail the strict format screen"
    );

    // build_aws_probe now sanitizes (control-strip) before the format screen.
    let access = TestApi.sanitize_raw_value(&raw_access);
    let secret = TestApi.sanitize_raw_value(&raw_secret);
    assert_eq!(access, EXAMPLE_ACCESS_KEY);
    assert_eq!(secret, EXAMPLE_SECRET_KEY);
    assert!(
        TestApi.valid_aws_format_for_test(&access, &secret),
        "a live key captured with a trailing newline must pass format after sanitization"
    );
}

#[test]
fn companion_region_reference_resolves_and_passes_region_screen() {
    let companions = HashMap::from([("region".to_string(), "eu-west-1".to_string())]);

    // The raw template is NOT a valid region literal (`.` is not `[A-Za-z0-9-]`).
    assert!(
        TestApi
            .validate_aws_region_for_test("companion.region")
            .is_err(),
        "the unresolved companion reference must fail the region screen"
    );

    // build_aws_probe now resolves + sanitizes region the same way as the keys.
    let resolved = TestApi.sanitize_raw_value(&TestApi.resolve_field(
        "companion.region",
        EXAMPLE_ACCESS_KEY,
        &companions,
    ));
    assert_eq!(resolved, "eu-west-1");
    assert!(
        TestApi.validate_aws_region_for_test(&resolved).is_ok(),
        "the resolved companion region must pass the region screen"
    );
}

#[tokio::test]
async fn control_only_secret_is_sanitized_empty_then_unverifiable_not_dead() {
    // Drive the REAL build_aws_probe preflight. A secret that is entirely control
    // bytes sanitizes to empty -> the empty-secret arm returns Unverifiable BEFORE
    // any network egress, with empty metadata. Without the sanitize step the
    // 4-byte "\r\n\r\n" secret is non-empty and < 40 chars, so the format arm
    // would instead return Dead. Asserting Unverifiable + empty metadata proves
    // the sanitize runs INSIDE build_aws_probe (not merely in the helper), and
    // distinguishes it from the canary arm (which returns non-empty metadata).
    let (result, metadata, transient) = TestApi
        .build_aws_probe_final_for_test(EXAMPLE_ACCESS_KEY, "\r\n\r\n", "us-east-1")
        .await;
    assert_eq!(result, VerificationResult::Unverifiable);
    assert!(
        metadata.is_empty(),
        "empty-secret arm returns empty metadata; got {metadata:?} \
         (canary arm would be non-empty -- pick a non-canary access key if this fires)"
    );
    assert!(!transient);
}
