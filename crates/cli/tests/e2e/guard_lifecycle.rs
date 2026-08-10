//! End-to-end guard lifecycle: add a root, check status, list, remove.
//!
//! Starts a real daemon on an isolated socket, then drives the full
//! guard subcommand lifecycle through the CLI binary:
//!
//! 1. `keyhog guard add <root> --mode repo`: registers a root
//! 2. `keyhog guard status <root>`: reports the root state
//! 3. `keyhog guard list`: lists all registered roots
//! 4. `keyhog guard remove <root>`: unregisters the root
//! 5. `keyhog guard list`: confirms the root is gone
//!
//! This proves the wire protocol, daemon dispatch, guard runtime, and
//! CLI formatting all work together end to end.

use crate::e2e::support::{binary, DaemonGuard};
use std::process::Command;

#[cfg(unix)]
#[test]
fn guard_lifecycle_add_status_list_remove() {
    let daemon = DaemonGuard::start_cpu_embedded();

    // Create a temporary directory to use as a guard root.
    let root = tempfile::tempdir().expect("guard root tempdir");
    let root_path = root.path().canonicalize().expect("canonicalize root");
    let root_arg = root_path.to_str().expect("root path");

    // 1. Add the root.
    let add = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "add", root_arg, "--mode", "repo"])
        .output()
        .expect("guard add");
    let add_code = add.status.code().unwrap_or(-1);
    // guard add triggers baseline reconciliation. An empty tempdir
    // should reach current (exit 0). Watcher events may mark it dirty
    // or degraded (exit 13). If findings are found, exit 1.
    assert!(
        add_code == 0 || add_code == 1 || add_code == 13,
        "guard add should succeed (0), exit 1 (findings), or exit 13 (degraded/stale): got {}: stdout={}; stderr={}",
        add_code,
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );

    // 2. Check status.
    let status = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "status", root_arg])
        .output()
        .expect("guard status");
    let status_code = status.status.code().unwrap_or(-1);
    assert!(
        status_code == 0 || status_code == 13,
        "guard status should succeed (0) or exit 13 (degraded/stale): got {}: stdout={}; stderr={}",
        status_code,
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let status_out = format!(
        "{}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    // After reconciliation, the root should be in a terminal state
    // (current, dirty, or blocked), not stopped or indexing.
    assert!(
        status_out.contains("current")
            || status_out.contains("dirty")
            || status_out.contains("blocked"),
        "guard status should show a reconciled state (current/dirty/blocked): got: {}",
        status_out
    );

    // 3. List roots.
    let list = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "list"])
        .output()
        .expect("guard list");
    assert!(
        list.status.success(),
        "guard list failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_err = String::from_utf8_lossy(&list.stderr);
    assert!(
        list_err.contains(root_arg),
        "guard list should contain the root path in stderr: got: {}",
        list_err
    );

    // 4. Remove the root.
    let remove = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "remove", root_arg])
        .output()
        .expect("guard remove");
    assert!(
        remove.status.success(),
        "guard remove failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&remove.stdout),
        String::from_utf8_lossy(&remove.stderr)
    );

    // 5. List again; root should be gone.
    let list_after = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "list"])
        .output()
        .expect("guard list after remove");
    assert!(
        list_after.status.success(),
        "guard list after remove failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&list_after.stdout),
        String::from_utf8_lossy(&list_after.stderr)
    );
    let list_after_err = String::from_utf8_lossy(&list_after.stderr);
    assert!(
        !list_after_err.contains(root_arg),
        "guard list after remove should not contain the root path in stderr: got: {}",
        list_after_err
    );
}

#[cfg(unix)]
#[test]
fn guard_status_json_format() {
    let daemon = DaemonGuard::start_cpu_embedded();

    let root = tempfile::tempdir().expect("guard root tempdir");
    let root_path = root.path().canonicalize().expect("canonicalize root");
    let root_arg = root_path.to_str().expect("root path");

    // Add the root.
    let add = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "add", root_arg, "--mode", "filesystem"])
        .output()
        .expect("guard add");
    let add_code = add.status.code().unwrap_or(-1);
    assert!(add_code == 0 || add_code == 13, "guard add should succeed or exit 13 (stopped)");

    // Get status in JSON format.
    let status = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "status", root_arg, "--format", "json"])
        .output()
        .expect("guard status json");
    let status_out = String::from_utf8_lossy(&status.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&status_out)
        .unwrap_or_else(|e| panic!("guard status --format json should produce valid JSON: {e}: got: {status_out}"));
    assert!(
        parsed.get("state").is_some(),
        "guard status JSON should have 'state' field: got: {}",
        status_out
    );
    // Verify the new status fields are present.
    for field in [
        "accepted_event_sequence",
        "completed_event_sequence",
        "scanner_residency",
        "backend_route_label",
        "autoroute_evidence_status",
        "store_schema_version",
    ] {
        assert!(
            parsed.get(field).is_some(),
            "guard status JSON should have '{field}' field: got: {status_out}"
        );
    }
}

#[cfg(unix)]
#[test]
fn guard_add_nonexistent_path_fails() {
    let daemon = DaemonGuard::start_cpu_embedded();

    let nonexistent = "/nonexistent/path/that/does/not/exist";
    let add = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "add", nonexistent, "--mode", "repo"])
        .output()
        .expect("guard add nonexistent");
    assert!(
        !add.status.success(),
        "guard add on nonexistent path should fail: stdout={}; stderr={}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );
}

#[cfg(unix)]
#[test]
fn guard_remove_nonexistent_fails() {
    let daemon = DaemonGuard::start_cpu_embedded();

    let remove = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["guard", "remove", "/nonexistent/path"])
        .output()
        .expect("guard remove nonexistent");
    assert!(
        !remove.status.success(),
        "guard remove on nonexistent root should fail"
    );
}
