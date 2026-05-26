//! E2E: scanning an empty directory exits 0.

use crate::e2e::support::{binary, scan_path};
use tempfile::TempDir;

#[test]
fn scan_empty_dir_exit_zero() {
    let dir = TempDir::new().expect("tempdir");
    let output = scan_path(dir.path(), &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "empty dir must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
