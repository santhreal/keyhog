//! Top-50 chunk-boundary oracle: `goto-meeting-api` near-miss must NOT fire when split across chunks.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_silent_across_chunk_boundary;

#[test]
fn top50_goto_meeting_api_near_miss_chunk_boundary_must_not_fire() {
    assert_detector_silent_across_chunk_boundary("goto-meeting-api", "GOTO_MEETING=short");
}
