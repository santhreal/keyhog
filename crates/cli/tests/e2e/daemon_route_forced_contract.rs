#![cfg(unix)]

use crate::e2e::support::{binary, DaemonGuard};
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

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
    concat!("AKIA", "QYLPMN5HFIQR7XYA").to_string()
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
