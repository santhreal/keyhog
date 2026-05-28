//! KH-GAP-126 FN twin: named aws-access-key must bypass shape-gate suppression.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::assert_detector_fires;

#[test]
fn named_detector_hex_body_bypasses_shape_gates_in_pipeline() {
    assert_detector_fires(
        "aws-access-key",
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA",
        "AKIAQYLPMN5HFIQR7XYA",
    );
}
