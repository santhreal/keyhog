//! Top-50 detector oracle: `goto-meeting-api` near-miss must NOT fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent;

#[test]
fn top50_goto_meeting_api_near_miss_must_not_fire() {
    assert_detector_silent("goto-meeting-api", "GOTO_MEETING=short");
}
