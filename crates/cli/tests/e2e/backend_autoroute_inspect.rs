//! E2E: `keyhog backend --autoroute` inspects the persisted calibration cache.
//!
//! This is the operator's window into autoroute: after a fail-closed
//! "no decision for workload bucket ..." scan error, `backend --autoroute` shows
//! which resolved configs and workload buckets ARE calibrated, the backend each
//! resolved to, and whether the cache is stale for this build. Multi-backend
//! unhealthy states are a health gate (exit 4); a single-backend build reports
//! its direct route and remains healthy without a cache.

use crate::e2e::support::{autoroute_calibration_slot, binary};
use std::process::Command;
use tempfile::TempDir;

fn unhealthy_inspection_exit() -> i32 {
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        4
    } else {
        0
    }
}

/// An absent cache reports whether this build actually has a backend choice.
#[test]
fn backend_autoroute_reports_uncalibrated_cache_cleanly() {
    let cache = TempDir::new().unwrap();
    let out = Command::new(binary())
        .args(["backend", "--autoroute"])
        .env("XDG_CACHE_HOME", cache.path())
        .output()
        .expect("spawn keyhog backend --autoroute");
    assert_eq!(
        out.status.code(),
        Some(unhealthy_inspection_exit()),
        "backend --autoroute health exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("autoroute calibration cache"),
        "must render the cache header; got: {stdout}"
    );
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        assert!(
            stdout.contains("not calibrated yet"),
            "a multi-backend build must report missing calibration; got: {stdout}"
        );
    } else {
        assert!(
            stdout.contains("calibration not required") && stdout.contains("cpu-fallback directly"),
            "a single-backend build must report that no routing evidence is needed; got: {stdout}"
        );
    }
}

/// `--json` emits a valid object that marks an absent cache as `present:false`
/// with an empty `configs` array (a stable shape for scripted health checks).
#[test]
fn backend_autoroute_json_is_valid_and_marks_absence() {
    let cache = TempDir::new().unwrap();
    let out = Command::new(binary())
        .args(["backend", "--autoroute", "--json"])
        .env("XDG_CACHE_HOME", cache.path())
        .output()
        .expect("spawn keyhog backend --autoroute --json");
    assert_eq!(
        out.status.code(),
        Some(unhealthy_inspection_exit()),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("backend --autoroute --json must emit valid JSON");
    assert_eq!(
        value["calibration_required"],
        serde_json::json!(keyhog_scanner::hw_probe::multiple_backends_compiled()),
        "JSON must reflect the scanner-owned compiled candidate set; json={value}"
    );
    let expected_direct_backend = if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        serde_json::Value::Null
    } else {
        serde_json::json!("cpu-fallback")
    };
    assert_eq!(
        value["direct_backend"], expected_direct_backend,
        "JSON must name the direct route exactly when calibration is unnecessary; json={value}"
    );
    assert_eq!(value["present"], serde_json::json!(false), "json={value}");
    assert_eq!(
        value["health"],
        serde_json::json!(if keyhog_scanner::hw_probe::multiple_backends_compiled() {
            "calibration_required"
        } else {
            "direct"
        }),
        "JSON must expose the same health state used for its process exit; json={value}"
    );
    assert_eq!(
        value["repair_command"],
        if keyhog_scanner::hw_probe::multiple_backends_compiled() {
            serde_json::json!("keyhog calibrate-autoroute")
        } else {
            serde_json::Value::Null
        },
        "JSON repair must follow the same readiness state; json={value}"
    );
    assert!(
        value["configs"]
            .as_array()
            .expect("configs array")
            .is_empty(),
        "absent cache lists no configs; json={value}"
    );
}

#[test]
fn backend_autoroute_disabled_cache_reports_compiled_route_contract() {
    let out = Command::new(binary())
        .args([
            "backend",
            "--autoroute",
            "--json",
            "--autoroute-cache",
            "off",
        ])
        .output()
        .expect("inspect disabled autoroute cache");
    assert_eq!(
        out.status.code(),
        Some(unhealthy_inspection_exit()),
        "inspection health exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("disabled-cache inspection JSON");

    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        assert_eq!(value["calibration_required"], serde_json::json!(true));
        assert_eq!(value["direct_backend"], serde_json::Value::Null);
        assert_eq!(value["health"], serde_json::json!("disabled"));
        assert_eq!(
            value["repair_command"],
            serde_json::json!("keyhog calibrate-autoroute --autoroute-cache <PATH>")
        );
        assert!(value["error"]
            .as_str()
            .is_some_and(|error| error.contains("explicit --backend")));
    } else {
        assert_eq!(value["calibration_required"], serde_json::json!(false));
        assert_eq!(value["direct_backend"], serde_json::json!("cpu-fallback"));
        assert_eq!(value["health"], serde_json::json!("direct"));
        assert_eq!(value["repair_command"], serde_json::Value::Null);
        assert_eq!(value["error"], serde_json::Value::Null);
    }
}

/// Inspection must read the same explicit cache path a scan or project config
/// uses. Otherwise a healthy non-default cache is falsely reported absent.
#[test]
fn backend_autoroute_inspects_explicit_cache_path() {
    let dir = TempDir::new().unwrap();
    let cache = dir.path().join("project-autoroute.json");
    std::fs::write(&cache, b"not autoroute json").unwrap();

    let out = Command::new(binary())
        .args(["backend", "--autoroute", "--json", "--autoroute-cache"])
        .arg(&cache)
        .output()
        .expect("inspect explicit autoroute cache");
    assert_eq!(
        out.status.code(),
        Some(unhealthy_inspection_exit()),
        "inspection health exit; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("explicit-path inspection JSON");
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        assert_eq!(value["health"], serde_json::json!("invalid"));
        assert_eq!(
            value["repair_command"],
            serde_json::json!("keyhog calibrate-autoroute")
        );
    } else {
        assert_eq!(value["health"], serde_json::json!("direct"));
        assert_eq!(value["repair_command"], serde_json::Value::Null);
    }
    assert_eq!(
        value["path"],
        serde_json::json!(cache.display().to_string()),
        "inspection must disclose the exact requested cache; json={value}"
    );
    assert_eq!(value["present"], serde_json::json!(true), "json={value}");
    assert!(
        value["error"]
            .as_str()
            .is_some_and(|error| error.contains("not valid cache JSON")),
        "the explicit file must be read rather than the platform default; json={value}"
    );
}

/// After a canonical all-candidate `--autoroute-calibrate` scan writes a
/// decision, `backend --autoroute --json` lists the resolved config, its
/// workload decision(s), and a real backend label, and reports the
/// freshly-written cache as matching this build.
#[test]
fn backend_autoroute_shows_calibrated_decisions_after_calibration() {
    let _calibration_slot = autoroute_calibration_slot();
    let cache = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let target = work.path().join("c.txt");
    std::fs::write(&target, "api_key = \"abcdefghijklmnop\"\n").unwrap();

    let calibrate = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--autoroute-calibrate",
            "--autoroute-gpu",
            "--format",
            "json",
        ])
        .arg(&target)
        .env("XDG_CACHE_HOME", cache.path())
        .output()
        .expect("spawn keyhog scan --autoroute-calibrate --autoroute-gpu");
    // A calibration scan runs calibration THEN scans, so it returns the scan code
    // (0 clean / 1 found). Anything >= 2 means calibration failed.
    assert!(
        matches!(calibrate.status.code(), Some(0) | Some(1)),
        "calibration scan must succeed (exit 0/1); code={:?} stderr={}",
        calibrate.status.code(),
        String::from_utf8_lossy(&calibrate.stderr)
    );

    let out = Command::new(binary())
        .args(["backend", "--autoroute", "--json"])
        .env("XDG_CACHE_HOME", cache.path())
        .output()
        .expect("spawn keyhog backend --autoroute --json");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(value["present"], serde_json::json!(true), "json={value}");
    assert_eq!(
        value["identity_matches_build"],
        serde_json::json!(true),
        "a cache written by this exact binary must match this build; json={value}"
    );
    let configs = value["configs"].as_array().expect("configs array");
    assert!(
        !configs.is_empty(),
        "a calibrated cache must list >= 1 config; json={value}"
    );
    let decisions = configs[0]["decisions"].as_array().expect("decisions array");
    assert!(
        !decisions.is_empty(),
        "a calibrated config must list >= 1 workload decision; json={value}"
    );
    let backend = decisions[0]["backend"]
        .as_str()
        .expect("decision backend is a string");
    assert!(
        !backend.is_empty(),
        "a decision must name the resolved backend; json={value}"
    );
    let decision = &decisions[0];
    assert!(
        decision["calibrated_at_unix_ms"].as_u64().is_some()
            && decision["calibration_age_ms"].as_u64().is_some()
            && value["inspected_at_unix_ms"].as_u64().is_some(),
        "inspection must expose the persisted timestamp and its derived age; json={value}"
    );
    assert!(
        decision["confidence_separated"].is_boolean(),
        "inspection must disclose whether one-shot confidence is separated; json={value}"
    );
    assert!(
        matches!(
            decision["selection_basis"].as_str(),
            Some("exact-plan-paired-95pct-confidence")
                | Some("peer-separated-compiled-default-plan")
                | Some("peer-separated-statistically-tied-plan")
        ),
        "inspection must disclose the one-shot selection rule; json={value}"
    );
    assert!(
        decision["daemon_backend"]
            .as_str()
            .is_some_and(|backend| !backend.is_empty()),
        "inspection must name the warm persistent-daemon route; json={value}"
    );
    assert!(
        decision["daemon_confidence_separated"].is_boolean()
            && decision["daemon_selection_basis"].is_string(),
        "inspection must disclose daemon confidence and selection rule; json={value}"
    );
    let receipts = decision["candidate_receipts"]
        .as_array()
        .expect("candidate receipts array");
    assert!(
        !receipts.is_empty()
            && receipts.iter().all(|receipt| {
                receipt["backend"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
                    && receipt["correctness_digest"]
                        .as_str()
                        .is_some_and(|value| value.len() == 16)
                    && receipt["completed_trials"].as_u64() == Some(7)
                    && receipt["evidence_digest"]
                        .as_str()
                        .is_some_and(|value| value.len() == 16)
            }),
        "each measured candidate must expose its parity receipt; decision={decision}"
    );
    let workload = decisions[0]["workload"]
        .as_str()
        .expect("decision workload is a string");
    assert!(
        workload.contains("bytes_log2=")
            && workload.contains("phase1_alphabet_rejected_chunks_log2=")
            && workload.contains("phase1_bigram_rejected_bytes_log2=")
            && workload.contains("phase1_admitted_bytes_log2=")
            && workload.contains("source_mixture="),
        "the workload bucket must render in the same field layout as the fail-closed \
         scan error so operators can match them; got: {workload}"
    );

    let text = Command::new(binary())
        .args(["backend", "--autoroute", "--verbose"])
        .env("XDG_CACHE_HOME", cache.path())
        .output()
        .expect("spawn verbose text autoroute inspection");
    assert_eq!(text.status.code(), Some(0));
    let text_stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        text_stdout.contains("evidence age:") && text_stdout.contains("calibrated_at_unix_ms="),
        "text inspection must make evidence age and its timestamp visible; got: {text_stdout}"
    );
    assert!(
        text_stdout.contains("parity:") && text_stdout.contains("/trials=7/receipt="),
        "text inspection must make per-candidate parity receipts visible; got: {text_stdout}"
    );
}
