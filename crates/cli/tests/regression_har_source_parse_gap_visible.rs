use std::{path::PathBuf, process::Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn malformed_har_parse_fallback_is_visible_to_operator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broken.har");
    std::fs::write(
        &path,
        r#"{"log": {"entries": [{"request": {"method": "GET", "url": "https://example.test", "headers": [{"name": "X-Key", "value": "har-cli-raw-marker"}]"#,
    )
    .expect("write malformed HAR");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--progress",
            "--format",
            "json",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn keyhog");

    assert!(
        output.status.success(),
        "malformed HAR raw-text fallback should complete cleanly; status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("structured source file(s) only PARTIALLY scanned"),
        "operator-visible summary must name the structured-source coverage gap; stderr={stderr}"
    );
    assert!(
        stderr.contains("raw text was scanned")
            && stderr.contains("request/response/body chunks were not expanded"),
        "summary must distinguish recall-preserving raw text fallback from missing HAR expansion; stderr={stderr}"
    );
}

#[test]
fn malformed_har_parse_fallback_is_visible_in_sarif_notifications() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("broken.har");
    std::fs::write(
        &path,
        r#"{"log": {"entries": [{"request": {"method": "GET", "url": "https://example.test", "headers": [{"name": "X-Key", "value": "har-cli-raw-marker"}]"#,
    )
    .expect("write malformed HAR");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--format",
            "sarif",
        ])
        .arg(&path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn keyhog");

    assert!(
        output.status.success(),
        "malformed HAR raw-text fallback should complete cleanly; status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("SARIF stdout must be JSON");
    let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("structured-source coverage gap must create SARIF notifications");
    assert!(
        notifications.iter().any(|notification| {
            notification["properties"]["reason"].as_str()
                == Some("structured source parse failed (raw text scanned; derived chunks not expanded)")
                && notification["properties"]["count"].as_u64() == Some(1)
        }),
        "SARIF notifications must include the structured-source parse gap; sarif={sarif}"
    );
}
