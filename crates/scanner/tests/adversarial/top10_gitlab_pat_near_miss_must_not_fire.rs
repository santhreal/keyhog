//! Top-10 detector oracle: `gitlab-personal-access-token` near-miss must NOT fire.

use super::oracle_support::assert_detector_silent;

#[test]
fn top10_gitlab_pat_near_miss_must_not_fire() {
    assert_detector_silent("gitlab-personal-access-token", r"glpat-short");
}
