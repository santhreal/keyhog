//! KH-GAP-164: Invalid embedded checksum must drop named-service matches.

use crate::adversarial::oracle_support::assert_detector_silent;

#[test]
fn r5_checksum_invalid_drops_named_service_match() {
    assert_detector_silent(
        "npm-access-token",
        "npm_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaXXXXXX",
    );
    assert_detector_silent(
        "github-pat-fine-grained",
        "github_pat_KhYxNqJ4pVbZ7Lm5RfWcGs_9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwMPqW3rTaBxxxxxx",
    );
}
