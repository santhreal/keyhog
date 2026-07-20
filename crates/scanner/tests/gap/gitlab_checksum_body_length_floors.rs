//! Gap test: GitLab structural-checksum body-length floors are exact.
//!
//! The `glpat-` and `glrt-` detectors own a 20-byte body floor. The `glcbt-`
//! detector owns a 16-byte floor. All three share a 64-byte ceiling. These tests
//! compile those exact detector patterns into the validator and pin each
//! boundary so one token family's floor cannot leak into another.

use keyhog_scanner::testing::gitlab_checksum_verdict_for_test;

fn body(n: usize) -> String {
    "a".repeat(n)
}

#[test]
fn classic_glpat_floor_is_twenty() {
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glpat-{}", body(20))),
        "structurally-valid",
        "a 20-char classic body is at the floor"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glpat-{}", body(19))),
        "invalid",
        "19 chars is below the classic floor -> fabricated/truncated"
    );
}

#[test]
fn detector_owned_floors_are_distinct() {
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glrt-{}", body(20))),
        "structurally-valid",
        "a 20-char runner body is at the glrt floor"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glrt-{}", body(19))),
        "invalid",
        "19 chars is below the glrt floor"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glcbt-{}", body(16))),
        "structurally-valid",
        "a 16-char CI job token is at the glcbt floor"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glcbt-{}", body(15))),
        "invalid",
        "15 chars is below the glcbt floor"
    );
}

#[test]
fn shared_ceiling_and_overlong_are_not_applicable() {
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glpat-{}", body(64))),
        "structurally-valid",
        "64 chars is at the shared ceiling"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glpat-{}", body(65))),
        "not-applicable",
        "65 chars is an unmodelled length -> do not false-drop"
    );
}

#[test]
fn bad_charset_and_missing_prefix() {
    // 16-char body containing a non-token char: charset gate fires before length.
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glrt-{}!", body(15))),
        "invalid",
        "a body char a GitLab token cannot contain -> Invalid"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test("ghp_0123456789abcdefABCDEF"),
        "not-applicable",
        "no GitLab prefix -> NotApplicable"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the exact floor/ceiling boundaries. These properties
// sweep the detector-owned bands and charset gate. Bodies use the exact
// `[A-Za-z0-9._-]` alphabet, so only length decides the verdict.

use keyhog_scanner::testing::gitlab_checksum_verdict_for_test as verdict;
use proptest::prelude::*;

const GITLAB_PREFIXES: &[&str] = &["glpat-", "glrt-", "glcbt-"];
/// Bytes outside the GitLab body charset (`[A-Za-z0-9._-]`).
const BAD_BODY_CHARS: &[char] = &['!', ' ', '#', '/', '+', '@'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Classic `glpat-` body in the 20..=64 band is structurally valid.
    #[test]
    fn classic_body_in_band_is_structurally_valid(body in "[A-Za-z0-9._-]{20,64}") {
        prop_assert_eq!(verdict(&format!("glpat-{body}")), "structurally-valid");
    }

    /// Classic `glpat-` body below the 20-char floor is invalid.
    #[test]
    fn classic_body_below_floor_is_invalid(body in "[A-Za-z0-9._-]{0,19}") {
        prop_assert_eq!(verdict(&format!("glpat-{body}")), "invalid");
    }


    /// Runner `glrt-` bodies use the detector-owned 20..=64 band.
    #[test]
    fn runner_body_in_band_is_structurally_valid(body in "[A-Za-z0-9._-]{20,64}") {
        prop_assert_eq!(verdict(&format!("glrt-{body}")), "structurally-valid");
    }

    /// Runner `glrt-` bodies below 20 bytes are invalid.
    #[test]
    fn runner_body_below_floor_is_invalid(body in "[A-Za-z0-9._-]{0,19}") {
        prop_assert_eq!(verdict(&format!("glrt-{body}")), "invalid");
    }

    /// CI job `glcbt-` bodies use the detector-owned 16..=64 band.
    #[test]
    fn ci_job_body_in_band_is_structurally_valid(body in "[A-Za-z0-9._-]{16,64}") {
        prop_assert_eq!(verdict(&format!("glcbt-{body}")), "structurally-valid");
    }

    /// CI job `glcbt-` bodies below 16 bytes are invalid.
    #[test]
    fn ci_job_body_below_floor_is_invalid(body in "[A-Za-z0-9._-]{0,15}") {
        prop_assert_eq!(verdict(&format!("glcbt-{body}")), "invalid");
    }

    /// Every GitLab family treats a body over 64 bytes as unmodelled.
    #[test]
    fn overlong_body_is_not_applicable(
        p in 0usize..GITLAB_PREFIXES.len(),
        body in "[A-Za-z0-9._-]{65,120}",
    ) {
        let tok = format!("{}{body}", GITLAB_PREFIXES[p]);
        prop_assert_eq!(verdict(&tok), "not-applicable");
    }

    /// A body with ANY out-of-charset byte is Invalid regardless of length, the
    /// charset gate runs before the length classification.
    #[test]
    fn out_of_charset_body_is_invalid(
        p in 0usize..GITLAB_PREFIXES.len(),
        pre in "[A-Za-z0-9._-]{0,40}",
        post in "[A-Za-z0-9._-]{0,40}",
        b in 0usize..BAD_BODY_CHARS.len(),
    ) {
        let tok = format!("{}{pre}{}{post}", GITLAB_PREFIXES[p], BAD_BODY_CHARS[b]);
        prop_assert_eq!(verdict(&tok), "invalid");
    }

    /// No GitLab prefix at all → not-applicable (defer, do not reject).
    #[test]
    fn no_gitlab_prefix_is_not_applicable(cred in "(?s).{0,40}") {
        prop_assume!(!GITLAB_PREFIXES.iter().any(|p| cred.starts_with(p)));
        prop_assert_eq!(verdict(&cred), "not-applicable");
    }
}
