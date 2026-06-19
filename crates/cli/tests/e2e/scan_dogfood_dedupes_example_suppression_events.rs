//! R1-D2 / KH-GAP-091: `--dogfood` must emit one event per logical suppression,
//! not one per internal pipeline stage.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_dogfood_dedupes_example_suppression_events() {
    let (_dir, path) = write_temp_file("demo.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--dogfood",
            "--format",
            "text",
        ])
        .arg(&path)
        .output()
        .expect("spawn");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let trace: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("dogfood JSON on stderr");
    let events = trace["dogfood"]["events"]
        .as_array()
        .expect("dogfood.events array");

    assert_eq!(
        events.len(),
        1,
        "expected exactly one dogfood event per suppressed example credential, got {}: {stderr}",
        events.len()
    );

    // The surviving event must be the EXAMPLE suppression (the informative
    // "this is a known placeholder" reason), not the generic shape/weak-anchor
    // event that fires later in the cascade for the same credential. The
    // example-token gate runs first, so first-wins dedup keeps it.
    assert_eq!(
        events[0]["kind"].as_str(),
        Some("example_suppressed"),
        "the single retained event must be the example suppression (the most \
         informative reason), got: {}",
        events[0]
    );
    assert_eq!(
        events[0]["reason"].as_str(),
        Some("contains_EXAMPLE_token"),
        "the retained example event must keep its specific reason; got: {}",
        events[0]
    );
}
