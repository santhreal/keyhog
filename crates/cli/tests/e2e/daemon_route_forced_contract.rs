#![cfg(unix)]

use crate::e2e::support::{binary, DaemonGuard};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
fn daemon_docs_do_not_claim_forced_daemon_fallback() {
    let docs = [(
        "docs/src/workflows/daemon.md",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/src/workflows/daemon.md"
        )),
    )];
    for (path, doc) in docs {
        let doc = doc
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for stale in [
            "client falls back",
            "falls back to an in-process scan",
            "daemon wasn't reachable",
        ] {
            assert!(
                !doc.contains(stale),
                "{path} must not advertise a fallback for forced daemon mode: {stale:?}"
            );
        }
        for required in [
            "--daemon=on",
            "require the daemon route",
            "is an error",
            "--daemon=auto",
            "use a reachable daemon only when it can honor the request",
            "--daemon=off",
        ] {
            assert!(
                doc.contains(required),
                "{path} must distinguish forced daemon mode from opportunistic daemon mode; missing {required:?}"
            );
        }
    }
}

#[test]
fn forced_daemon_rejects_directory_without_in_process_fallback() {
    let work = TempDir::new().expect("work dir");
    std::fs::write(work.path().join("leak.env"), aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(work.path())
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon over a directory must fail instead of falling back to in-process; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("single regular file"),
        "forced-daemon rejection must explain the unsupported shape; output={combined}"
    );
    assert!(
        !combined.contains("aws-access-key"),
        "forced daemon rejection must not scan and report findings; output={combined}"
    );
}

#[test]
fn forced_daemon_missing_file_reports_path_inspection_error() {
    let runtime = TempDir::new().expect("isolated runtime");
    let work = TempDir::new().expect("work dir");
    let missing = work.path().join("missing.env");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(&missing)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon over a missing file must fail before daemon connect or in-process scan; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("daemon single-file route cannot inspect")
            && combined.contains(&missing.to_string_lossy().to_string()),
        "forced-daemon rejection must name the path-inspection failure; output={combined}"
    );
    assert!(
        !combined.contains("directories, git, remote"),
        "missing-file metadata errors must not collapse into the generic unsupported-shape message; output={combined}"
    );
}

#[test]
fn forced_daemon_rejects_unenforceable_policy_without_in_process_fallback() {
    let work = TempDir::new().expect("work dir");
    let secret = aws_key();
    let path = work.path().join("leak.env");
    std::fs::write(&path, format!("AWS_ACCESS_KEY_ID = \"{secret}\"\n")).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--show-secrets", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon with policy the daemon cannot enforce must fail; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("policy the daemon cannot enforce"),
        "forced-daemon rejection must name the policy mismatch; output={combined}"
    );
    assert!(
        !combined.contains(&secret),
        "forced daemon rejection must not run the in-process show-secrets path; output={combined}"
    );
}

#[test]
fn forced_daemon_rejects_per_detector_confidence_policy() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    std::fs::write(
        work.path().join(".keyhog.toml"),
        "[detector.aws-access-key]\nmin_confidence = 0.95\n",
    )
    .expect("write config");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon must not bypass client-local per-detector confidence policy; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("policy the daemon cannot enforce"),
        "forced-daemon rejection must expose the policy mismatch; output={combined}"
    );
    assert!(
        !combined.contains("aws-access-key"),
        "forced daemon rejection must not scan after discarding detector policy; output={combined}"
    );
}

/// A valid overlay corpus must reach forced-daemon compatibility validation
/// instead of being rejected earlier as an empty detector directory.
#[test]
fn forced_daemon_rejects_overlay_detector_corpus() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let detectors = work.path().join("custom-detectors");
    std::fs::create_dir(&detectors).expect("create detector directory");
    let repo_detectors =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors");
    for name in ["corpus.toml", "aws-access-key.toml"] {
        std::fs::copy(repo_detectors.join(name), detectors.join(name))
            .expect("copy valid custom detector corpus");
    }
    let runtime = TempDir::new().expect("isolated runtime");
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make runtime directory private");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--detectors"])
        .arg(&detectors)
        .args(["--detectors-mode=overlay", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon must not discard the selected detector corpus; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("`--detectors-mode=overlay`")
            && combined.contains("precompiled scanner"),
        "forced-daemon rejection must identify the unsupported overlay corpus; output={combined}"
    );
    assert!(
        !combined.contains("aws-access-key"),
        "forced daemon rejection must not scan with its embedded corpus; output={combined}"
    );
}

#[test]
fn forced_daemon_rejects_multiple_primary_sources() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let mut child = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--stdin", "--format", "json"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog scan");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(b"clean stdin\n")
        .expect("write stdin");

    let out = child.wait_with_output().expect("scan output");
    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon with --stdin plus a file must fail instead of dropping one source; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored") && combined.contains("exactly one"),
        "forced-daemon rejection must explain the multi-source mismatch; output={combined}"
    );
}

#[test]
fn forced_daemon_rejects_scan_mode_flags() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--no-decode", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon with scan-mode flags must fail instead of using a differently configured scanner; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("in-process scanner"),
        "forced-daemon rejection must explain the scanner-config mismatch; output={combined}"
    );
}

#[test]
fn forced_daemon_rejects_backend_routing_flags() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    for args in [
        &[
            "scan",
            "--daemon=on",
            "--backend",
            "simd",
            "--format",
            "json",
        ][..],
        &[
            "scan",
            "--daemon=on",
            "--autoroute-calibrate",
            "--format",
            "json",
        ][..],
    ] {
        let out = Command::new(binary())
            .env("XDG_RUNTIME_DIR", runtime.path())
            .args(args)
            .arg(&path)
            .output()
            .expect("spawn keyhog scan");

        let combined = combined_output(&out);
        assert_eq!(
            out.status.code(),
            Some(2),
            "forced daemon with backend routing flags must fail instead of ignoring them; output={combined}"
        );
        assert!(
            combined.contains("--daemon=on cannot be honored")
                && combined.contains("daemon protocol cannot honor"),
            "forced-daemon rejection must name the backend-routing mismatch; output={combined}"
        );
        assert!(
            !combined.contains("aws-access-key"),
            "forced daemon rejection must not scan after dropping backend-routing controls; output={combined}"
        );
    }
}

#[test]
fn forced_daemon_rejects_matcher_cache_override() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");
    let matcher_cache = TempDir::new().expect("matcher cache");
    let matcher_cache_path = matcher_cache
        .path()
        .to_str()
        .expect("utf8 matcher cache path")
        .to_string();

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args([
            "scan",
            "--daemon=on",
            "--matcher-cache",
            matcher_cache_path.as_str(),
            "--format",
            "json",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon with --matcher-cache <DIR> must fail instead of ignoring it; output={combined}"
    );
    assert!(
        combined.contains("--daemon=on cannot be honored")
            && combined.contains("precompiled daemon scanner cannot honor"),
        "forced-daemon rejection must name the matcher-cache mismatch; output={combined}"
    );
    assert!(
        !combined.contains("aws-access-key"),
        "forced daemon rejection must not scan after dropping matcher-cache; output={combined}"
    );
}

#[test]
fn forced_daemon_allows_matcher_cache_off() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args([
            "scan",
            "--daemon=on",
            "--matcher-cache",
            "off",
            "--format",
            "json",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert!(
        !combined.contains("precompiled daemon scanner cannot honor"),
        "--matcher-cache off must remain daemon-eligible; output={combined}"
    );
    assert!(
        !combined.contains("aws-access-key"),
        "forced daemon without a live daemon must not fall back to an in-process finding; output={combined}"
    );
}

#[test]
fn explicit_auto_stale_daemon_socket_surfaces_in_process_route() {
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");
    std::fs::write(runtime.path().join("keyhog.sock"), b"stale socket path")
        .expect("write stale daemon socket placeholder");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=auto", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(13),
        "explicit daemon auto should surface the daemon miss and leave the in-process batch unscanned; output={combined}"
    );
    assert!(
        combined.contains("daemon auto route unavailable")
            && combined.contains("running in-process scanner"),
        "explicit daemon auto route change must be operator-visible; output={combined}"
    );
    assert!(
        combined.contains("autoroute calibration required")
            && combined.contains("No backend was selected")
            && combined.contains("batch was not scanned")
            && !combined.contains("scalar correctness recovery"),
        "the in-process route must fail closed for missing calibration; output={combined}"
    );
}

#[test]
fn forced_daemon_scan_path_expands_har_base64_response() {
    let daemon = DaemonGuard::start();
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("capture.har");
    std::fs::write(&path, har_with_base64_response_body()).expect("write har fixture");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "forced daemon HAR scan must detect the decoded response body; output={combined}"
    );
    assert!(
        combined.contains("\"detector_id\":\"aws-access-key\""),
        "daemon HAR route must use the filesystem source expander, not raw text scan; output={combined}"
    );
}

#[test]
fn automatic_daemon_does_not_rescan_after_report_failure() {
    let daemon = DaemonGuard::start();
    let work = TempDir::new().expect("work dir");
    let path = work.path().join("leak.env");
    std::fs::write(&path, aws_key_line()).expect("write fixture");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["scan", "--daemon=auto", "--format", "json", "--output"])
        .arg(work.path())
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(3),
        "report failure must preserve the command error exit; output={combined}"
    );
    assert!(
        combined.contains("failed") || combined.contains("directory"),
        "report failure must stay operator-visible; output={combined}"
    );
    assert!(
        !combined.contains("daemon auto route unavailable")
            && !combined.contains("running in-process scanner"),
        "a report failure occurs after the daemon result was accepted and must not trigger a second scan; output={combined}"
    );
}

#[test]
fn forced_daemon_stdin_honors_cli_byte_limit() {
    let daemon = DaemonGuard::start();

    let out = daemon_stdin_scan(
        daemon.runtime_dir(),
        None,
        &["--limit-stdin-bytes", "4B"],
        b"abcdef",
    );

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "daemon stdin must enforce --limit-stdin-bytes before scanning; output={combined}"
    );
    assert!(
        combined.contains("stdin exceeds 4 byte limit"),
        "daemon stdin limit error must name the resolved CLI limit; output={combined}"
    );
}

#[test]
fn forced_daemon_stdin_honors_config_byte_limit() {
    let daemon = DaemonGuard::start();
    let work = TempDir::new().expect("work dir");
    std::fs::write(
        work.path().join(".keyhog.toml"),
        "[limits]\nstdin_bytes = \"4B\"\n",
    )
    .expect("write config");

    let out = daemon_stdin_scan(daemon.runtime_dir(), Some(work.path()), &[], b"abcdef");

    let combined = combined_output(&out);
    assert_eq!(
        out.status.code(),
        Some(2),
        "daemon stdin must enforce [limits].stdin_bytes from .keyhog.toml; output={combined}"
    );
    assert!(
        combined.contains("stdin exceeds 4 byte limit"),
        "daemon stdin limit error must name the resolved config limit; output={combined}"
    );
}

#[test]
fn forced_daemon_dogfood_prints_the_request_trace() {
    let daemon = DaemonGuard::start();
    let input = format!(
        "{}const malformed = [256]; const xorKey = [1]; \
         String.fromCharCode(...malformed.map((b, i) => b ^ xorKey[i % xorKey.length]));\n",
        aws_key_line()
    );
    let out = daemon_stdin_scan(daemon.runtime_dir(), None, &["--dogfood"], input.as_bytes());

    assert_eq!(
        out.status.code(),
        Some(1),
        "the planted secret must keep the normal finding exit code; output={}",
        combined_output(&out)
    );
    let stderr = String::from_utf8(out.stderr).expect("dogfood stderr is UTF-8");
    let payload = stderr
        .lines()
        .filter_map(
            |line| match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => Some(value),
                Err(_) => None,
            },
        )
        .find(|value| value.get("dogfood").is_some())
        .unwrap_or_else(|| panic!("daemon dogfood JSON missing from stderr: {stderr}"));
    let dogfood = &payload["dogfood"];
    assert_eq!(
        dogfood["static_recovery_rejections"]["literal_byte_array_element"],
        1
    );
    assert_eq!(dogfood["detail_events_dropped"], 0);
    assert_eq!(
        dogfood["events"]
            .as_array()
            .expect("dogfood events array")
            .iter()
            .filter(|event| event["kind"] == "static_recovery_rejected")
            .count(),
        1
    );
}

fn combined_output(out: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn aws_key_line() -> String {
    format!("AWS_ACCESS_KEY_ID = \"{}\"\n", aws_key())
}

fn aws_key() -> String {
    concat!("ASIA", "Y34FZKBOKMUTVV7A").to_string()
}

fn har_with_base64_response_body() -> String {
    r#"{
        "log": {
            "version": "1.2",
            "creator": {"name": "keyhog-test", "version": "1"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.invalid/secret",
                        "headers": [],
                        "queryString": []
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": [],
                        "content": {
                            "text": "QVdTX0FDQ0VTU19LRVlfSUQ9QVNJQVkzNEZaS0JPS01VVFZWN0EK",
                            "encoding": "base64"
                        }
                    }
                }
            ]
        }
    }"#
    .to_string()
}

fn daemon_stdin_scan(
    runtime_dir: &std::path::Path,
    current_dir: Option<&std::path::Path>,
    extra_args: &[&str],
    stdin_bytes: &[u8],
) -> std::process::Output {
    let mut cmd = Command::new(binary());
    cmd.env("XDG_RUNTIME_DIR", runtime_dir)
        .args(["scan", "--daemon=on", "--stdin", "--format", "json"])
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = current_dir {
        cmd.current_dir(dir);
    }

    let mut child = cmd.spawn().expect("spawn daemon stdin scan");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(stdin_bytes)
        .expect("write stdin");
    child.wait_with_output().expect("daemon stdin output")
}
