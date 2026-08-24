//! E2E: an empty directory provides no coverage and fails closed.

use crate::e2e::support::scan_path;
use keyhog::exit_codes::EXIT_SOURCE_FAILED;
use tempfile::TempDir;

/// WHY: zero-byte input cannot prove that a target is clean. Empty,
/// fully-excluded, and wrong-target scans must not report success.
#[test]
fn scan_empty_dir_fails_closed() {
    let dir = TempDir::new().expect("tempdir");
    let output = scan_path(dir.path(), &[]);
    assert_eq!(
        output.status.code(),
        Some(EXIT_SOURCE_FAILED as i32),
        "empty dir must fail closed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ZERO bytes") && stderr.contains("Nothing was examined"),
        "empty-dir failure must state the missing coverage and corrective context: {stderr}"
    );
}
