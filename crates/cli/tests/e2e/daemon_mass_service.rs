#![cfg(unix)]

use crate::e2e::support::{binary, DaemonGuard};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn aws_fixture() -> &'static str {
    "AWS_ACCESS_KEY_ID=AKIA7ZQWERTYUIOP1234\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE1234\n"
}

fn scan_json(guard: &DaemonGuard, cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .current_dir(cwd)
        .env("XDG_RUNTIME_DIR", guard.runtime_dir())
        .args(args)
        .output()
        .expect("spawn mass daemon scan")
}

fn scan_stdin_json(guard: &DaemonGuard, cwd: &std::path::Path, body: &str) -> std::process::Output {
    let mut child = Command::new(binary())
        .current_dir(cwd)
        .env("XDG_RUNTIME_DIR", guard.runtime_dir())
        .args([
            "scan",
            "--daemon=mass",
            "--stdin",
            "--format",
            "json-envelope",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stdin mass scan");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(body.as_bytes())
        .expect("write stdin fixture");
    child.wait_with_output().expect("collect stdin mass scan")
}

fn serve_proxy_once(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint fixture");
    let address = listener.local_addr().expect("endpoint fixture address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept endpoint request");
        let mut request = [0_u8; 4_096];
        let read = stream.read(&mut request).expect("read endpoint request");
        assert!(
            String::from_utf8_lossy(&request[..read]).contains("/.env.secret HTTP/1."),
            "unexpected endpoint request: {}",
            String::from_utf8_lossy(&request[..read])
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
        .expect("write endpoint response");
    });
    (format!("http://{address}"), server)
}

/// A mass worker must scan every file in a directory without compiling a client-side scanner.
#[test]
fn mass_daemon_directory_scan_reports_exact_finding_location() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    std::fs::write(work.path().join("clean.txt"), "service=example\n").expect("clean fixture");
    let secret = work.path().join(".env.secret");
    std::fs::write(&secret, aws_fixture()).expect("secret fixture");

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--format",
            "json-envelope",
            work.path().to_str().expect("utf-8 work path"),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "mass directory scan must report the planted secret; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "exactly one credential should survive");
    assert_eq!(findings[0]["detector_id"], "aws-access-key");
    assert_eq!(
        findings[0]["location"]["file_path"],
        secret.to_string_lossy().as_ref()
    );
    assert_eq!(findings[0]["location"]["line"], 1);
    assert_eq!(report["metadata"]["source_bytes_scanned"], 119);
    assert_eq!(report["metadata"]["source_chunks_scanned"], 2);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "mass daemon: 1 batches, 2 chunks, 119 bytes; GPU 0 batches, 0 chunks, 0 bytes (0.0%, primary: no);"
        ),
        "mass execution receipt must prove the exact CPU/GPU byte split; stderr={stderr}"
    );
    assert!(
        stderr.contains("transport=daemon-local-path"),
        "local directory payload must stay out of IPC frames; stderr={stderr}"
    );
}

/// The merkle racy-clean guard drops every cache entry whose file mtime shares a
/// clock-second with the index write, because a same-size edit in that window is
/// invisible to `(mtime, size)`. A fixture written immediately before the first
/// scan is therefore always re-read on the second scan, so any test that asserts
/// a warm skip must first leave that window.
fn settle_racy_clean_window() {
    std::thread::sleep(std::time::Duration::from_millis(1_100));
}

/// WHY: daemon-local incremental scans must retain the warm scanner while
/// skipping unchanged clean files, but must rescan every file that produced a
/// finding so secrets remain visible on every invocation.
#[test]
fn mass_daemon_incremental_skips_clean_files_and_replays_secret_files() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    let cache = TempDir::new().expect("cache dir");
    let cache_path = cache.path().join("merkle.idx");
    let relative_cache_path = std::path::PathBuf::from("..")
        .join(cache.path().file_name().expect("cache directory name"))
        .join("merkle.idx");
    std::fs::write(work.path().join("clean.txt"), "service=example\n").expect("clean fixture");
    std::fs::write(work.path().join(".env.secret"), aws_fixture()).expect("secret fixture");
    settle_racy_clean_window();
    let root = work.path().to_str().expect("utf-8 work path");
    let cache_arg = relative_cache_path.to_str().expect("utf-8 cache path");

    let first = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--incremental",
            "--incremental-cache",
            cache_arg,
            "--format",
            "json-envelope",
            root,
        ],
    );
    assert_eq!(
        first.status.code(),
        Some(1),
        "first scan must report the planted secret; stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        cache_path.is_file(),
        "first scan must publish the Merkle generation"
    );

    let second = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--incremental",
            "--incremental-cache",
            cache_arg,
            "--format",
            "json-envelope",
            root,
        ],
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert_eq!(second.status.code(), Some(1), "stderr={stderr}");
    assert!(
        stderr.contains("mass daemon: 1 batches, 1 chunks, 103 bytes"),
        "the unchanged clean file must bypass read and scan while the secret file is rescanned; stderr={stderr}"
    );
    let report: Value = serde_json::from_slice(&second.stdout).expect("valid JSON envelope");
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["detector_id"], "aws-access-key");
    std::thread::sleep(std::time::Duration::from_millis(2));
    std::fs::write(work.path().join("clean.txt"), "service=changed\n")
        .expect("change clean fixture without changing its size");
    let third = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--incremental",
            "--incremental-cache",
            cache_arg,
            "--format",
            "json-envelope",
            root,
        ],
    );
    let stderr = String::from_utf8_lossy(&third.stderr);
    assert_eq!(third.status.code(), Some(1), "stderr={stderr}");
    assert!(
        stderr.contains("mass daemon: 1 batches, 2 chunks, 119 bytes"),
        "a same-size clean-file change must invalidate the metadata skip while the secret remains visible; stderr={stderr}"
    );
}

/// WHY: a trusted all-clean Merkle hit is complete coverage even though no
/// source bytes reach the scanner. The daemon must carry the skip count across
/// the wire so reporting does not relabel a successful warm scan as partial.
#[test]
fn mass_daemon_all_unchanged_incremental_scan_is_complete_coverage() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    let cache = TempDir::new().expect("cache dir");
    let cache_path = cache.path().join("merkle.idx");
    std::fs::write(work.path().join("clean.txt"), "service=example\n").expect("clean fixture");
    settle_racy_clean_window();
    let root = work.path().to_str().expect("utf-8 work path");
    let cache_arg = cache_path.to_str().expect("utf-8 cache path");
    let args = [
        "scan",
        "--daemon=mass",
        "--incremental",
        "--incremental-cache",
        cache_arg,
        "--format",
        "json-envelope",
        root,
    ];

    let first = scan_json(&guard, work.path(), &args);
    assert_eq!(
        first.status.code(),
        Some(0),
        "cold clean scan must succeed; stderr={}",
        String::from_utf8_lossy(&first.stderr)
    );
    let assert_warm_complete = |output: &std::process::Output, path: &str| {
        assert_eq!(
            output.status.code(),
            Some(0),
            "{path} warm scan must retain complete coverage; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
        assert_eq!(report["scan_status"], "success");
        assert_eq!(report["metadata"]["source_bytes_scanned"], 0);
        assert_eq!(
            report["coverage_gap_summary"]
                .as_array()
                .expect("coverage gap array")
                .len(),
            0
        );
    };

    let metadata_skip = scan_json(&guard, work.path(), &args);
    assert_warm_complete(&metadata_skip, "metadata");
    std::thread::sleep(std::time::Duration::from_millis(2));
    std::fs::write(work.path().join("clean.txt"), "service=example\n")
        .expect("rewrite unchanged content");
    let content_skip = scan_json(&guard, work.path(), &args);
    assert_warm_complete(&content_skip, "content-confirmed");
}

/// WHY: a daemon-side cache write failure is a system failure, not an
/// operator-input error or a clean scan.
#[test]
fn mass_daemon_incremental_cache_write_failure_exits_system_error() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    let cache = TempDir::new().expect("cache dir");
    std::fs::write(work.path().join("clean.txt"), "service=example\n").expect("clean fixture");
    let blocked_parent = cache.path().join("not-a-directory");
    std::fs::write(&blocked_parent, "file").expect("blocked cache parent");
    let cache_path = blocked_parent.join("merkle.idx");

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--incremental",
            "--incremental-cache",
            cache_path.to_str().expect("utf-8 cache path"),
            "--format",
            "json-envelope",
            work.path().to_str().expect("utf-8 work path"),
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(3),
        "incremental cache I/O must retain the documented system-error exit; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mass daemon incremental cache publication")
            && stderr.contains("cannot persist mass incremental cache"),
        "cache failure must retain actionable daemon and client context; stderr={stderr}"
    );
    assert!(!cache_path.exists());
}

/// A daemon-local directory larger than the chunk ceiling must stay bounded and account for every file.
#[test]
fn mass_daemon_local_directory_splits_at_chunk_ceiling() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    for index in 0..1_025 {
        std::fs::write(work.path().join(format!("clean-{index:04}.txt")), "x\n")
            .expect("clean fixture");
    }

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--format",
            "json-envelope",
            work.path().to_str().expect("utf-8 work path"),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("mass daemon: 2 batches, 1025 chunks, 2050 bytes"),
        "chunk ceiling must produce two exact batches; stderr={stderr}"
    );
    assert!(
        stderr.contains("transport=daemon-local-path"),
        "local payload bytes must not cross the socket; stderr={stderr}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(report["metadata"]["source_chunks_scanned"], 1_025);
    assert_eq!(report["metadata"]["source_bytes_scanned"], 2_050);
}

/// A GPU-primary mass service must reject a CPU-majority receipt instead of accepting hidden fallback.
#[test]
fn mass_gpu_primary_contract_fails_closed_on_cpu_worker() {
    let guard = DaemonGuard::start_mass_gpu_primary();
    let work = TempDir::new().expect("work dir");
    std::fs::write(work.path().join("clean.txt"), "service=example\n").expect("clean fixture");

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--format",
            "json-envelope",
            work.path().to_str().expect("utf-8 work path"),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(
        stderr.contains("GPU-primary contract failed: GPU processed 0 of 16 bytes (0.0%)"),
        "stderr={stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "a rejected execution receipt must not produce a success-shaped report"
    );
}

fn assert_mass_gpu_primary_backend(backend: &'static str) {
    let guard = DaemonGuard::start_mass_gpu_primary_with_backend(backend);
    let work = TempDir::new().expect("work dir");
    let secret = work.path().join(".env.secret");
    std::fs::write(&secret, aws_fixture()).expect("secret fixture");

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--format",
            "json-envelope",
            work.path().to_str().expect("utf-8 work path"),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{backend}: stderr={stderr}");
    assert!(
        stderr.contains(
            "mass daemon: 1 batches, 1 chunks, 103 bytes; GPU 1 batches, 1 chunks, 103 bytes (100.0%, primary: yes);",
        ),
        "GPU-primary receipt must bind every source byte to {backend} execution; stderr={stderr}"
    );
    assert!(
        stderr.contains("transport=daemon-local-path"),
        "{backend} execution must preserve daemon-local path transport; stderr={stderr}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["detector_id"], "aws-access-key");
    assert_eq!(
        findings[0]["location"]["file_path"],
        secret.to_string_lossy().as_ref()
    );
}

/// A forced CUDA mass worker must certify every processed byte as GPU work.
#[test]
#[ignore = "GPU-host gate; run explicitly on a host with a physical CUDA adapter"]
fn mass_gpu_primary_contract_accepts_full_cuda_execution() {
    assert_mass_gpu_primary_backend("gpu-cuda");
}

/// A forced native Metal mass worker must certify every processed byte as GPU work.
#[test]
#[ignore = "GPU-host gate; run explicitly on a macOS host with a physical Metal adapter"]
fn mass_gpu_primary_contract_accepts_full_metal_execution() {
    assert_mass_gpu_primary_backend("gpu-metal");
}

/// A forced WGPU mass worker must certify every processed byte as GPU work.
#[test]
#[ignore = "GPU-host gate; run explicitly on a host with a physical WGPU adapter"]
fn mass_gpu_primary_contract_accepts_full_wgpu_execution() {
    assert_mass_gpu_primary_backend("gpu-wgpu");
}

/// A warm-only daemon must reject mass mode instead of silently running the in-process scanner.
#[test]
fn mass_mode_rejects_warm_only_daemon_without_fallback() {
    let guard = DaemonGuard::start();
    let work = TempDir::new().expect("work dir");
    std::fs::write(work.path().join(".env.secret"), aws_fixture()).expect("secret fixture");

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            work.path().to_str().expect("utf-8 work path"),
        ],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("warm-only service"), "stderr={stderr}");
    assert!(
        !stderr.contains("aws-access-key"),
        "rejection must not scan; stderr={stderr}"
    );
}

/// A stdin scan must preserve exact bytes and null file attribution across protected IPC.
#[test]
fn mass_daemon_stdin_success_uses_protected_chunk_transport() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    let output = scan_stdin_json(&guard, work.path(), aws_fixture());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(
        stderr.contains(
            "mass daemon: 1 batches, 1 chunks, 103 bytes; GPU 0 batches, 0 chunks, 0 bytes (0.0%, primary: no);",
        ) && stderr.contains("transport=protected-chunks"),
        "stdin receipt must bind exact bytes to protected IPC; stderr={stderr}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(report["metadata"]["source_chunks_scanned"], 1);
    assert_eq!(report["metadata"]["source_bytes_scanned"], 103);
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["detector_id"], "aws-access-key");
    assert_eq!(findings[0]["location"]["file_path"], Value::Null);
    assert_eq!(findings[0]["location"]["line"], 1);
}

/// A successful endpoint scan must use protected wire chunks and preserve URL attribution.
#[test]
fn mass_daemon_endpoint_success_uses_protected_chunk_transport() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");
    let url = "http://93.184.216.34/.env.secret";
    let (proxy, server) = serve_proxy_once(aws_fixture());

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--url",
            &url,
            "--proxy",
            &proxy,
            "--format",
            "json-envelope",
        ],
    );
    server.join().expect("endpoint fixture server");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(
        stderr.contains(
            "mass daemon: 1 batches, 1 chunks, 103 bytes; GPU 0 batches, 0 chunks, 0 bytes (0.0%, primary: no);",
        ) && stderr.contains("transport=protected-chunks"),
        "endpoint receipt must bind exact client-acquired bytes to protected IPC; stderr={stderr}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON envelope");
    assert_eq!(report["metadata"]["source_chunks_scanned"], 1);
    assert_eq!(report["metadata"]["source_bytes_scanned"], 103);
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["detector_id"], "aws-access-key");
    assert_eq!(findings[0]["location"]["file_path"], url);
    assert_eq!(findings[0]["location"]["line"], 1);
}

/// A failed endpoint acquisition must produce exit 13 and a fail-closed envelope, never clean
/// status. Row 163 pins `failed` (not `partial`) whenever a source failed outright; see
/// `crates/cli/tests/regression_row_163_fail_closed_scan_document_status.rs`.
#[test]
fn mass_daemon_endpoint_failure_preserves_coverage_error() {
    let guard = DaemonGuard::start_mass();
    let work = TempDir::new().expect("work dir");

    let output = scan_json(
        &guard,
        work.path(),
        &[
            "scan",
            "--daemon=mass",
            "--url",
            "http://127.0.0.1:9/.env.secret",
            "--format",
            "json-envelope",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(13),
        "failed remote source must fail closed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid envelope");
    assert_eq!(report["scan_status"], "failed");
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not reporting \"clean\""),
        "stderr={stderr}"
    );
}
