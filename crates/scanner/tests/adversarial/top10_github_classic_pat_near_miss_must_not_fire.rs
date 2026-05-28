//! Top-10 detector oracle: `github-classic-pat` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top10_github_classic_pat_near_miss_must_not_fire() {
    assert_detector_silent("github-classic-pat", r"ghp_ tag in a sentence");
}
