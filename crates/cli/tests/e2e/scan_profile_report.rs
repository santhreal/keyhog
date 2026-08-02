use super::support::{binary, write_temp_file};
use std::process::Command;

/// A profiled scan must emit one causal run report with source, backend, input, state, and resource evidence.
#[test]
fn scan_profile_emits_causal_run_identity_and_macro_measurements() {
    let (_dir, path) = write_temp_file("clean.txt", "ordinary profile fixture\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--quiet",
            "--profile",
            path.to_str().expect("utf-8 fixture path"),
        ])
        .output()
        .expect("run profiled scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert_eq!(stdout, "[]");
    assert!(!stderr.contains("=== keyhog profile [keyhog scan] ==="));
    assert!(stderr.contains(
        "state=completed source=filesystem workload=runtime-batches \
         backend_requested=cpu-fallback backend_selected=cpu-fallback cache=disabled daemon=off"
    ));
    assert!(stderr.contains("input_bytes=25 input_units=1 throughput_mib_s="));
    assert!(stderr.contains("source-acquire"));
    assert!(stderr.contains("source-walk"));
    assert!(stderr.contains("source-read"));
    assert!(stderr.contains("source-queue-wait"));
    assert!(stderr.contains("backend-select"));
    assert!(stderr.contains("result-merge"));
    assert!(stderr.contains("macro scanning"));
    assert!(stderr.contains("macro resolving"));
    assert!(stderr.contains("bottleneck macro="));
    assert!(stderr.contains("backend-dispatch"));
    assert!(stderr.contains("suppression"));
    assert!(stderr.contains("live-verification"));
    assert!(stderr.contains("reporting"));
    assert!(stderr.contains("resources aggregate_cpu="));
    assert!(stderr.contains("max_observed_rss_bytes="));
}

/// The opt-in perf trace must retain detailed per-pattern diagnostics without coupling them to the low-overhead run profile.
#[test]
fn perf_trace_owns_expensive_scanner_diagnostics() {
    let (_dir, path) = write_temp_file("clean.txt", "ordinary perf trace fixture\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--quiet",
            "--perf-trace",
            path.to_str().expect("utf-8 fixture path"),
        ])
        .output()
        .expect("run detailed perf trace");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert_eq!(stdout, "[]");
    assert!(stderr.contains("=== keyhog profile [keyhog scan] ==="));
    assert!(!stderr.contains("state=completed source=filesystem"));
}

/// A failure after profiling begins must finalize the record as failed instead of dropping all evidence.
#[test]
fn scan_profile_marks_reporting_failure_as_failed() {
    let (dir, path) = write_temp_file("clean.txt", "ordinary profile fixture\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--quiet",
            "--profile",
            "--output",
            dir.path().to_str().expect("utf-8 output directory"),
            path.to_str().expect("utf-8 fixture path"),
        ])
        .output()
        .expect("run profiled scan with invalid output path");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("state=failed source=filesystem workload=runtime-batches"));
    assert!(stderr.contains("backend_requested=cpu-fallback backend_selected=cpu-fallback"));
    assert!(stderr.contains("reporting"));
    assert!(stderr.contains("resources aggregate_cpu="));
}
