//! WHY: Closes the defect class where profiler queue depths, blocked wait attribution,
//! and per-worker blocked time were left empty in the profile artifact despite having dedicated schema (Row 107).
//! Without queue depths and blocked wait attribution, producer backpressure (`SourceQueueWait`)
//! and consumer starvation (`ScannerQueueWait`) are indistinguishable and unexplainable.
//!
//! What this does NOT catch: OS kernel scheduler latency during non-channel context switches.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn row_107_profile_artifact_populates_queue_depths_and_blocked_waits() {
    let target_bin = env!("CARGO_BIN_EXE_keyhog");
    let temp = tempdir().expect("tempdir");
    let scan_dir = temp.path().join("scan_target");
    fs::create_dir_all(&scan_dir).expect("create scan dir");

    // Create a series of files to ensure batches flow through the dispatch channel
    for i in 0..20 {
        let file_path = scan_dir.join(format!("file_{i}.txt"));
        fs::write(&file_path, format!("normal test content in file {i}\n")).expect("write file");
    }

    let profile_out_path = temp.path().join("profile.json");

    let output = Command::new(target_bin)
        .arg("scan")
        .arg(&scan_dir)
        .arg("--profile-out")
        .arg(&profile_out_path)
        .arg("--backend")
        .arg("cpu")
        .output()
        .expect("run scan with profile-out");

    assert!(
        output.status.success(),
        "scan failed: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(profile_out_path.exists(), "profile.json should be written");
    let profile_content = fs::read_to_string(&profile_out_path).expect("read profile");
    let profile: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    // 1. Worker occupancy must be present and have workers
    let worker_occupancy = profile
        .get("worker_occupancy")
        .expect("worker_occupancy field present");
    assert!(!worker_occupancy.is_null());
    let workers = worker_occupancy
        .get("workers")
        .and_then(|w| w.as_array())
        .expect("workers array present");
    assert!(!workers.is_empty(), "workers list must not be empty");

    // 2. Queue depths collection must be populated
    let queue_depths = profile
        .get("queue_depths")
        .and_then(|q| q.as_array())
        .expect("queue_depths array present");
    assert!(
        !queue_depths.is_empty(),
        "queue_depths collection must be populated for scanned workload"
    );

    let scanner_work_queue = queue_depths.iter().find(|entry| {
        entry
            .get("queue")
            .and_then(|q| q.as_str())
            .map_or(false, |q| q == "scanner-work")
    });
    assert!(
        scanner_work_queue.is_some(),
        "scanner-work queue must be tracked in queue_depths"
    );

    // 3. Blocked waits collection must be populated when wait stages are present
    let blocked_waits = profile
        .get("blocked_waits")
        .and_then(|b| b.as_array())
        .expect("blocked_waits array present");
    // When wait stages are measured, blocked_waits must contain attribution records
    assert!(
        !blocked_waits.is_empty(),
        "blocked_waits collection must not be empty when wait stages execute"
    );
}

#[test]
fn row_107_declared_profile_collections_are_wired() {
    let target_bin = env!("CARGO_BIN_EXE_keyhog");
    let temp = tempdir().expect("tempdir");
    let scan_dir = temp.path().join("scan_target");
    fs::create_dir_all(&scan_dir).expect("create scan dir");

    let file_path = scan_dir.join("sample.txt");
    fs::write(&file_path, "sample content for scanner\n").expect("write sample");

    let profile_out_path = temp.path().join("profile_schema.json");

    let output = Command::new(target_bin)
        .arg("scan")
        .arg(&scan_dir)
        .arg("--profile-out")
        .arg(&profile_out_path)
        .output()
        .expect("run scan with profile-out");

    assert!(output.status.success());

    let profile_content = fs::read_to_string(&profile_out_path).expect("read profile");
    let profile: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    // Dynamic runtime derivation of declared collections in CausalProfileV2 schema:
    // Every declared collection in the profile envelope must be serialized (not missing)
    let declared_collections = [
        "stage_concurrency",
        "worker_occupancy",
        "queue_depths",
        "blocked_waits",
        "caches",
        "indexed_counters",
        "retries",
    ];

    for field in declared_collections {
        assert!(
            profile.get(field).is_some(),
            "declared profile schema field '{field}' must be present in profile output"
        );
    }
}
