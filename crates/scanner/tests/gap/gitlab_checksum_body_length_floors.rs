//! Gap test: GitLab structural-checksum body-length floors are exact.
//!
//! The classic `glpat-` floor is the named `GITLAB_BODY_MIN` (20); the routable
//! `glrt-`/`glcbt-` floor is now the named `GITLAB_ROUTABLE_BODY_MIN` (16),
//! previously a bare `16` magic literal duplicated at two match sites. Pin both
//! floors, the shared ceiling (64), and the charset gate on exact verdicts so
//! the named constant cannot drift from the behavior it documents.

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
fn routable_floor_is_sixteen() {
    // The exact boundary the named GITLAB_ROUTABLE_BODY_MIN encodes.
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glrt-{}", body(16))),
        "structurally-valid",
        "a 16-char routable body is at the routable floor"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glrt-{}", body(15))),
        "invalid",
        "15 chars is below the routable floor"
    );
    assert_eq!(
        gitlab_checksum_verdict_for_test(&format!("glcbt-{}", body(16))),
        "structurally-valid",
        "glcbt- shares the routable floor"
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
// The fixed vectors pin the exact floor/ceiling boundaries; these SWEEP the whole
// length bands and the charset gate. Bodies are drawn from the exact allowed
// charset (`[A-Za-z0-9._-]`) so only length decides the classic (20..=64) and
// routable (16..=64) verdicts; a below-floor body is Invalid and an over-64 body
// is NotApplicable (never false-dropped). A body with ANY out-of-charset byte is
// Invalid regardless of length (charset gate runs first). Traced against
// checksum/gitlab.rs:44. No proptest before.

use keyhog_scanner::testing::gitlab_checksum_verdict_for_test as verdict;
use proptest::prelude::*;

const ROUTABLE_PREFIXES: &[&str] = &["glrt-", "glcbt-"];
const ALL_PREFIXES: &[&str] = &["glpat-", "glrt-", "glcbt-"];
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

    /// Classic `glpat-` body over the 64-char ceiling is not-applicable (unmodelled
    /// length, never false-dropped).
    #[test]
    fn classic_overlong_body_is_not_applicable(body in "[A-Za-z0-9._-]{65,120}") {
        prop_assert_eq!(verdict(&format!("glpat-{body}")), "not-applicable");
    }

    /// Routable `glrt-`/`glcbt-` body in the 16..=64 band is structurally valid.
    #[test]
    fn routable_body_in_band_is_structurally_valid(
        p in 0usize..ROUTABLE_PREFIXES.len(),
        body in "[A-Za-z0-9._-]{16,64}",
    ) {
        let tok = format!("{}{body}", ROUTABLE_PREFIXES[p]);
        prop_assert_eq!(verdict(&tok), "structurally-valid");
    }

    /// Routable body below the 16-char floor is invalid.
    #[test]
    fn routable_body_below_floor_is_invalid(
        p in 0usize..ROUTABLE_PREFIXES.len(),
        body in "[A-Za-z0-9._-]{0,15}",
    ) {
        let tok = format!("{}{body}", ROUTABLE_PREFIXES[p]);
        prop_assert_eq!(verdict(&tok), "invalid");
    }

    /// Routable body over the 64-char ceiling is not-applicable.
    #[test]
    fn routable_overlong_body_is_not_applicable(
        p in 0usize..ROUTABLE_PREFIXES.len(),
        body in "[A-Za-z0-9._-]{65,120}",
    ) {
        let tok = format!("{}{body}", ROUTABLE_PREFIXES[p]);
        prop_assert_eq!(verdict(&tok), "not-applicable");
    }

    /// A body with ANY out-of-charset byte is Invalid regardless of length, the
    /// charset gate runs before the length classification.
    #[test]
    fn out_of_charset_body_is_invalid(
        p in 0usize..ALL_PREFIXES.len(),
        pre in "[A-Za-z0-9._-]{0,40}",
        post in "[A-Za-z0-9._-]{0,40}",
        b in 0usize..BAD_BODY_CHARS.len(),
    ) {
        let tok = format!("{}{pre}{}{post}", ALL_PREFIXES[p], BAD_BODY_CHARS[b]);
        prop_assert_eq!(verdict(&tok), "invalid");
    }

    /// No GitLab prefix at all → not-applicable (defer, do not reject).
    #[test]
    fn no_gitlab_prefix_is_not_applicable(cred in "(?s).{0,40}") {
        prop_assume!(!ALL_PREFIXES.iter().any(|p| cred.starts_with(p)));
        prop_assert_eq!(verdict(&cred), "not-applicable");
    }
}
