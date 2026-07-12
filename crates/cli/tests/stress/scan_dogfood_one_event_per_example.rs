//! R3-D / KH-GAP-091: `--dogfood` emits one event per suppressed credential.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_dogfood_one_event_per_example_suppression() {
    let (_dir, path) = write_temp_file("demo.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
    let output = Command::new(binary())
        // Pin the deterministic CPU-SIMD backend (the e2e convention): this
        // verifies dogfood-event dedup, not autoroute selection, and an
        // un-calibrated `auto` scan fails closed by design.
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--dogfood",
            "--format",
            "text",
        ])
        .arg(&path)
        .output()
        .expect("spawn");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trace: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("dogfood JSON on stderr");
    assert_eq!(
        trace["dogfood"]["events"].as_array().map(|a| a.len()),
        Some(1),
        "expected exactly one dogfood event; stderr={stderr}"
    );
    assert_eq!(
        trace["dogfood"]["example_suppressions_total"].as_u64(),
        Some(8),
        "counter still tracks every pipeline-stage suppression; stderr={stderr}"
    );
    assert_eq!(
        trace["dogfood"]["events"][0]["kind"].as_str(),
        Some("example_suppressed")
    );
}
