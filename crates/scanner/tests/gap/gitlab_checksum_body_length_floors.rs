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
