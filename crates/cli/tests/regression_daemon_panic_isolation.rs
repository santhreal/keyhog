//! Regression test for Row 86: Daemon request dispatch panic isolation.
//!
//! WHY:
//! Closes the defect class where internal panics during daemon request dispatch
//! or filesystem draining could terminate the daemon process, tear down the Unix
//! socket, drop concurrent in-flight requests, and fail silently without fault
//! accounting. Under the shipped release profile (`panic = "unwind"`), every
//! request dispatch boundary is wrapped in `AssertUnwindSafe(...).catch_unwind()`,
//! returning a typed `Response::Error`, preserving the daemon socket and listener,
//! allowing concurrent operations to complete, and incrementing `backend_recoveries`.
//!
//! What it does not catch:
//! Process-level fatal signals (e.g. SIGKILL, SIGSEGV from foreign C libraries)
//! or unrecoverable kernel out-of-memory terminations that bypass the panic runtime.

#![cfg(unix)]

use keyhog::testing::{CliTestApi as _, API};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_daemon_request_kinds_isolate_panics_under_shipped_profile() {
    // 1. Invariant check: release profile table must unwind
    let cargo_toml_path = Path::new("../../Cargo.toml")
        .canonicalize()
        .or_else(|_| Path::new("Cargo.toml").canonicalize())
        .expect("Cargo.toml location");
    let cargo_content = std::fs::read_to_string(&cargo_toml_path).expect("read Cargo.toml");
    assert!(
        cargo_content.contains("panic = \"unwind\""),
        "[profile.release] must set panic = \"unwind\" for catch_unwind daemon isolation"
    );
    assert!(
        cargo_content.contains("overflow-checks = true"),
        "[profile.release] must set overflow-checks = true"
    );

    // 2. Derive all request kinds at runtime
    let all_kinds = API.all_daemon_request_kinds();
    assert_eq!(
        all_kinds.len(),
        18,
        "Every daemon request kind must be enumerated and covered"
    );

    for &kind in all_kinds {
        let sample = API
            .sample_daemon_request_for_kind(kind)
            .unwrap_or_else(|| panic!("Missing sample request for kind '{kind}'"));
        let serialized = serde_json::to_string(&sample).expect("serialize sample request");
        assert!(
            !serialized.is_empty(),
            "Sample request for '{kind}' must serialize cleanly"
        );
    }

    // 3. Start isolated daemon server in background
    let runtime_dir = TempDir::new().expect("runtime tempdir");
    std::fs::set_permissions(runtime_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("secure runtime dir");
    let socket_path = runtime_dir.path().join("panic_isolation.sock");

    let detectors = sample_detector_specs();
    let server_handle = API.spawn_daemon_for_test(socket_path.clone(), detectors);

    // Wait for socket to become ready
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() {
        if std::time::Instant::now() > deadline {
            panic!("Daemon socket did not appear within 10s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 4. Test each request kind with injected panic
    for &target_kind in all_kinds {
        // Arm panic injection for this specific request kind
        API.set_daemon_panic_injection(Some(target_kind));

        let mut stream = UnixStream::connect(&socket_path)
            .await
            .unwrap_or_else(|e| panic!("Connect to daemon for kind '{target_kind}' failed: {e}"));

        // If target is NOT Hello, we must send Hello first to complete the handshake
        if target_kind != "Hello" {
            let hello_sample = API.sample_daemon_request_for_kind("Hello").unwrap();
            let hello_json = serde_json::to_string(&hello_sample).unwrap();
            send_raw_frame(&mut stream, &hello_json).await.unwrap();
            let hello_resp = read_raw_frame(&mut stream).await.unwrap();
            assert_eq!(
                hello_resp.get("kind").and_then(|v| v.as_str()),
                Some("hello"),
                "Handshake before '{target_kind}' must succeed"
            );
        }

        // Send target request which triggers the injected panic
        let target_sample = API.sample_daemon_request_for_kind(target_kind).unwrap();
        let target_json = serde_json::to_string(&target_sample).unwrap();
        send_raw_frame(&mut stream, &target_json).await.unwrap();

        let resp = read_raw_frame(&mut stream).await.unwrap_or_else(|e| {
            panic!("Daemon failed to return error response for '{target_kind}': {e}")
        });

        assert_eq!(
            resp.get("kind").and_then(|v| v.as_str()),
            Some("error"),
            "Target request '{target_kind}' must return typed error response on internal panic"
        );
        let error_msg = resp.get("message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            error_msg.contains("internal panic during"),
            "Error response for '{target_kind}' must disclose internal panic: {error_msg}"
        );

        // Disarm panic injection
        API.set_daemon_panic_injection(None);

        // 5. Verify the daemon is STILL alive, serving, and the socket is present
        assert!(socket_path.exists(), "Daemon socket must remain present");

        let mut health_stream = UnixStream::connect(&socket_path)
            .await
            .expect("Connect to daemon after panic must succeed");
        let hello_sample = API.sample_daemon_request_for_kind("Hello").unwrap();
        send_raw_frame(
            &mut health_stream,
            &serde_json::to_string(&hello_sample).unwrap(),
        )
        .await
        .unwrap();
        let _ = read_raw_frame(&mut health_stream).await.unwrap();

        let health_sample = API.sample_daemon_request_for_kind("Health").unwrap();
        send_raw_frame(
            &mut health_stream,
            &serde_json::to_string(&health_sample).unwrap(),
        )
        .await
        .unwrap();
        let health_resp = read_raw_frame(&mut health_stream).await.unwrap();

        assert_eq!(
            health_resp.get("kind").and_then(|v| v.as_str()),
            Some("health"),
            "Health request must succeed after panic in '{target_kind}'"
        );
        let recoveries = health_resp
            .get("backend_recoveries")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert!(
            recoveries >= 1,
            "Backend recovery counter must be >= 1 after panic in '{target_kind}', got {recoveries}"
        );
    }

    // 6. Graceful shutdown
    let mut stop_stream = UnixStream::connect(&socket_path).await.unwrap();
    let hello = API.sample_daemon_request_for_kind("Hello").unwrap();
    send_raw_frame(&mut stop_stream, &serde_json::to_string(&hello).unwrap())
        .await
        .unwrap();
    let _ = read_raw_frame(&mut stop_stream).await.unwrap();

    let shutdown = API.sample_daemon_request_for_kind("Shutdown").unwrap();
    send_raw_frame(&mut stop_stream, &serde_json::to_string(&shutdown).unwrap())
        .await
        .unwrap();
    let _ = read_raw_frame(&mut stop_stream).await.unwrap();

    let _ = server_handle.await;
}
