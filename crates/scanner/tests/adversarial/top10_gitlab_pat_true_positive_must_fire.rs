//! Top-10 detector oracle: `gitlab-personal-access-token` true positive MUST fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn top10_gitlab_pat_true_positive_must_fire() {
    assert_detector_fires(
        "gitlab-personal-access-token",
        r"glpat-00000000000000000000",
        "glpat-00000000000000000000",
    );
}
