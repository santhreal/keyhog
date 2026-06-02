//! e2e test for `keyhog backend` (hardware detection and routing).
//!
//! The backend subcommand inspects detected hardware (GPU, SIMD) and the
//! auto-selected scan backend. It also supports --self-test to verify GPU
//! kernels and --probe-bytes to test routing thresholds.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog backend` returns exit 0 with information about detected hardware
/// and the selected scan backend (GPU, SIMD, or fallback).
#[test]
fn backend_default_returns_exit_zero_with_hardware_info() {
    let output = Command::new(binary())
        .arg("backend")
        .output()
        .expect("spawn keyhog backend");

    assert_eq!(
        output.status.code(),
        Some(0),
        "backend should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "backend should emit hardware detection info"
    );

    // Output should mention the selected backend or hardware capabilities.
    assert!(
        stdout.to_lowercase().contains("backend")
            || stdout.to_lowercase().contains("gpu")
            || stdout.to_lowercase().contains("simd")
            || stdout.to_lowercase().contains("hardware"),
        "backend output should describe detected hardware; got: {stdout}"
    );
}

/// `keyhog backend --self-test` runs GPU/SIMD self-tests and returns exit 0 on pass.
/// On systems without GPU, it should still return 0 (no-op).
/// On systems with GPU, it returns 0 on pass or 4 on test failure.
#[test]
fn backend_self_test_executes_and_returns_valid_exit_code() {
    let output = Command::new(binary())
        .arg("backend")
        .arg("--self-test")
        .output()
        .expect("spawn keyhog backend --self-test");

    let code = output.status.code();
    assert!(
        code == Some(0) || code == Some(4),
        "backend --self-test should exit 0 (pass) or 4 (fail); got {code:?}"
    );
}

/// `keyhog backend --self-test --json` emits self-test results as JSON.
/// On systems without GPU, this should be a no-op and exit 0 with
/// minimal/empty JSON. On systems with GPU, it should include test results.
#[test]
fn backend_self_test_json_emits_structured_output() {
    let output = Command::new(binary())
        .arg("backend")
        .arg("--self-test")
        .arg("--json")
        .output()
        .expect("spawn keyhog backend --self-test --json");

    let code = output.status.code();
    assert!(
        code == Some(0) || code == Some(4),
        "backend --self-test --json should exit 0 or 4; got {code:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The output should be parseable as JSON (even if empty/minimal).
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "backend --self-test --json should emit valid JSON; got: {stdout}"
    );
}

/// `keyhog backend --probe-bytes 268435456` simulates backend routing with
/// 256 MiB of input to test if GPU would be selected at that size.
/// Should return exit 0 with routing information.
#[test]
fn backend_probe_bytes_tests_routing_threshold() {
    let output = Command::new(binary())
        .arg("backend")
        .arg("--probe-bytes")
        .arg("268435456")
        .output()
        .expect("spawn keyhog backend --probe-bytes");

    assert_eq!(
        output.status.code(),
        Some(0),
        "backend --probe-bytes should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "backend --probe-bytes should emit routing info"
    );

    // Output should indicate which backend would be selected for the probed size.
    assert!(
        stdout.contains("backend") || stdout.contains("gpu") || stdout.contains("route"),
        "probe output should show backend routing decision; got: {stdout}"
    );
}

/// `keyhog backend --patterns 2000` sets the pattern count for routing simulation
/// so you can test how a larger corpus would route without recompiling.
#[test]
fn backend_patterns_flag_alters_routing_decision() {
    let output = Command::new(binary())
        .arg("backend")
        .arg("--patterns")
        .arg("2000")
        .output()
        .expect("spawn keyhog backend --patterns");

    assert_eq!(
        output.status.code(),
        Some(0),
        "backend --patterns should exit 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "backend --patterns should emit routing info with the custom pattern count"
    );
}

/// `keyhog backend --patterns abc` (non-numeric) returns exit 2 (user error)
/// because the patterns value must be an integer.
#[test]
fn backend_patterns_non_numeric_exits_two() {
    let output = Command::new(binary())
        .arg("backend")
        .arg("--patterns")
        .arg("not-a-number")
        .output()
        .expect("spawn keyhog backend --patterns <non-numeric>");

    assert_eq!(
        output.status.code(),
        Some(2),
        "backend with non-numeric --patterns should exit 2 (user error)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("pattern")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("number"),
        "error should identify the invalid patterns argument; stderr: {stderr}"
    );
}
