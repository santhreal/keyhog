//! Regression test for Row 101: Daemon concurrent scan counter isolation.
//!
//! WHY:
//! Closes the defect class where concurrent daemon client scans shared mutable
//! process-global atomic counters (such as source skip counts, example suppressions,
//! and scanner coverage gaps) and reset calls from one scan would zero or pollute
//! another concurrent scan's in-flight telemetry. Under this fix, every daemon unit
//! of work (such as `ScanPath`, `ScanChunks`, `ScanText`, mass filesystem streaming)
//! allocates and binds a scoped `SourceSkipTelemetry` and `ScanTelemetry` container
//! via `with_source_telemetry` and `with_scan_telemetry`. Concurrent scans over
//! disjoint payloads receive strictly independent, isolated coverage gap and skip
//! counts without cross-contamination or reset races.
//!
//! What it does not catch:
//! Process-level fatal signals (e.g. SIGKILL) or kernel OOM terminations that
//! tear down the daemon host process.

#![cfg(unix)]

use keyhog::testing::{CliTestApi as _, API};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

fn sample_detector_specs() -> Vec<keyhog_core::DetectorSpec> {
    keyhog_core::load_embedded_detectors_or_fail().expect("embedded detectors must load")
}

async fn send_raw_frame(stream: &mut UnixStream, json_payload: &str) -> anyhow::Result<()> {
    let bytes = json_payload.as_bytes();
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_raw_frame(stream: &mut UnixStream) -> anyhow::Result<serde_json::Value> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    let val: serde_json::Value = serde_json::from_slice(&body)?;
    Ok(val)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_daemon_scans_maintain_isolated_skip_and_telemetry_counts() {
    let runtime_dir = TempDir::new().expect("runtime tempdir");
    std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure runtime dir");
    let socket_path = runtime_dir.path().join("concurrent_isolation.sock");

    let detectors = sample_detector_specs();
    let _server_handle = API.spawn_daemon_for_test(socket_path.clone(), detectors);

    // Wait for socket to become ready
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!("Daemon socket did not appear within 10s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Prepare disjoint fixture files
    let fixture_root = TempDir::new().expect("fixture tempdir");

    // File A: binary file (null bytes) -> source skip `binary` count = 1
    let file_a = fixture_root.path().join("file_a.bin");
    std::fs::write(&file_a, vec![0u8; 512]).expect("write file_a");

    // File B: clean text file without secrets -> 0 skips, 0 suppressions, 0 matches
    let file_b = fixture_root.path().join("file_b.txt");
    std::fs::write(
        &file_b,
        "const PORT = 8080;\nconsole.log('clean server');\n",
    )
    .expect("write file_b");

    // File C: text with example token -> 0 skips, 1 example suppression
    let file_c = fixture_root.path().join("file_c.txt");
    std::fs::write(&file_c, "const AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\";\n").expect("write file_c");

    // Launch concurrent client scan tasks against the running daemon
    let concurrency = 24;
    let mut handles = Vec::new();

    for client_id in 0..concurrency {
        let socket = socket_path.clone();
        let target_file: PathBuf = match client_id % 3 {
            0 => file_a.clone(),
            1 => file_b.clone(),
            _ => file_c.clone(),
        };
        let expected_binary_skips: u64 = match client_id % 3 {
            0 => 1,
            _ => 0,
        };
        let expected_example_suppressions: u64 = match client_id % 3 {
            2 => 3,
            _ => 0,
        };
        handles.push(tokio::spawn(async move {
            let mut stream = UnixStream::connect(&socket)
                .await
                .unwrap_or_else(|e| panic!("Client {client_id} connect failed: {e}"));

            // Handshake (Hello)
            let hello = serde_json::json!({
                "op": "hello",
                "client_version": "1.0.0",
                "protocol_version": 1
            });
            send_raw_frame(&mut stream, &serde_json::to_string(&hello).unwrap())
                .await
                .expect("send hello");
            let hello_resp = read_raw_frame(&mut stream).await.expect("read hello resp");
            assert_eq!(
                hello_resp.get("kind").and_then(|v| v.as_str()),
                Some("hello"),
                "Client {client_id} handshake must succeed: {hello_resp:?}"
            );

            // Send ScanPath request
            let scan_req = serde_json::json!({
                "op": "scan_path",
                "path": target_file.to_str().unwrap(),
                "working_dir": null,
                "dogfood": true,
                "profile": false
            });
            send_raw_frame(&mut stream, &serde_json::to_string(&scan_req).unwrap())
                .await
                .expect("send scan_path");
            let scan_resp = read_raw_frame(&mut stream).await.expect("read scan_path resp");

            assert_eq!(
                scan_resp.get("kind").and_then(|v| v.as_str()),
                Some("scan_results"),
                "Client {client_id} must receive scan_results response: {scan_resp:?}"
            );

            let gaps = scan_resp
                .get("source_coverage_gaps")
                .expect("must include source_coverage_gaps");
            let binary_skips = gaps
                .get("binary")
                .and_then(|v| v.as_u64())
                .expect("binary skip count");

            assert_eq!(
                binary_skips, expected_binary_skips,
                "Client {client_id} targeting {} must report exactly {expected_binary_skips} binary skips, observed {binary_skips}",
                target_file.display()
            );

            let example_suppressions = scan_resp
                .get("engine_example_suppressions")
                .and_then(|v| v.as_u64())
                .expect("engine_example_suppressions");
            assert_eq!(
                example_suppressions, expected_example_suppressions,
                "Client {client_id} targeting {} must report exactly {expected_example_suppressions} example suppressions, observed {example_suppressions}",
                target_file.display()
            );

            let over_max_size = gaps
                .get("over_max_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            assert_eq!(
                over_max_size, 0,
                "Client {client_id} must observe 0 over_max_size skips"
            );
        }));
    }

    for handle in handles {
        handle.await.expect("client task panicked");
    }
}

#[test]
fn scoped_source_telemetry_isolation_across_threads() {
    let thread_count = 8;
    let iterations = 100;
    let mut join_handles = Vec::new();

    for thread_idx in 0..thread_count {
        let handle = std::thread::spawn(move || {
            let telemetry = Arc::new(keyhog_sources::SourceSkipTelemetry::new());
            keyhog_sources::with_source_telemetry(&telemetry, || {
                for _ in 0..iterations {
                    if thread_idx % 2 == 0 {
                        keyhog_sources::testing::TestApi.bump_skipped_binary(1);
                    } else {
                        keyhog_sources::testing::TestApi.bump_skipped_over_max_size(1);
                    }
                }

                let snapshot = telemetry.snapshot();
                if thread_idx % 2 == 0 {
                    assert_eq!(snapshot.binary, iterations);
                    assert_eq!(snapshot.over_max_size, 0);
                } else {
                    assert_eq!(snapshot.binary, 0);
                    assert_eq!(snapshot.over_max_size, iterations);
                }
            });
        });
        join_handles.push(handle);
    }

    for handle in join_handles {
        handle.join().expect("thread join failed");
    }
}
