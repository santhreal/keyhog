use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

const SECRET: &str = concat!("ghp_", "69121b4cdeeff121c88dffac1f9dbc2giIjE");

#[test]
fn dogfood_reports_typed_static_recovery_rejections_without_source_bytes() {
    let source = format!(
        "const planted = '{SECRET}'; \
         const bad = [256]; const key = [1]; \
         String.fromCharCode(...bad.map((b, i) => b ^ key[i % key.length]));"
    );
    let (_dir, path) = write_temp_file("malformed-recovery.js", &source);
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--deep",
            "--dogfood",
            "--format",
            "text",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog");

    assert_eq!(
        output.status.code(),
        Some(1),
        "the original source must still produce its planted finding: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trace: serde_json::Value =
        serde_json::from_str(stderr.trim()).expect("dogfood JSON on stderr");
    assert_eq!(
        trace["dogfood"]["static_recovery_rejections"]["literal_byte_array_element"].as_u64(),
        Some(1),
        "typed rejection counter missing: {stderr}"
    );
    let event = trace["dogfood"]["events"]
        .as_array()
        .expect("dogfood events array")
        .iter()
        .find(|event| event["kind"] == "static_recovery_rejected")
        .expect("static recovery rejection event");
    assert_eq!(event["kind"].as_str(), Some("static_recovery_rejected"));
    assert_eq!(event["decoder"].as_str(), Some("javascript-static"));
    assert_eq!(event["reason"].as_str(), Some("literal_byte_array_element"));
    assert!(event.get("credential").is_none());
    assert!(event.get("source").is_none());
}
