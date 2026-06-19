//! Contract: `backend --self-test --json` emits parseable skip JSON on no-GPU runners.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn backend_self_test_json_skip_contract() {
    let output = Command::new(binary())
        .args(["backend", "--self-test", "--json", "--no-gpu"])
        .output()
        .expect("spawn backend --self-test --json");

    assert_eq!(
        output.status.code(),
        Some(0),
        "no-GPU self-test skip must exit zero; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("self-test stdout must be JSON");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["status"], "skip");
    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["gpu_available"], false);
    assert_eq!(parsed["recommended_backend"], "simd-regex");
    assert_eq!(parsed["probes"][0]["name"], "gpu_adapter");
    assert_eq!(parsed["probes"][0]["status"], "skip");
}
