//! E2E: a `.keyhogignore` entry actually excludes a file from the scan, while
//! sibling files are still scanned. A broken ignore that scanned everything
//! would be noisy; one that ignored everything would silently miss leaks.

use crate::e2e::support::scan_path;
use tempfile::TempDir;

#[test]
fn keyhogignore_excludes_listed_file_but_scans_siblings() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("ignored.env"),
        "T=ghp_aB3xK9mZ1qW7rT5vY2nL8pH4jD6sF0gE1cV2\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("scanned.env"),
        "T=ghp_ZZ3xK9mZ1qW7rT5vY2nL8pH4jD6sF0gE1cVX\n",
    )
    .unwrap();
    std::fs::write(dir.path().join(".keyhogignore"), "ignored.env\n").unwrap();

    let out = scan_path(dir.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("ignored.env"),
        "the .keyhogignore'd file must NOT appear in findings; got: {stdout}"
    );
    assert!(
        stdout.contains("scanned.env"),
        "a non-ignored sibling file MUST still be scanned; got: {stdout}"
    );
}
