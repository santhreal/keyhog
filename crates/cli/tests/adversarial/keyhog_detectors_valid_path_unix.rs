//! Adversarial (Unix): KEYHOG_DETECTORS can aim at workspace detector tree.

#[cfg(unix)]
#[test]
fn keyhog_detectors_valid_path_unix() {
    use crate::support::{binary, workspace_detectors, write_temp_file};
    use std::process::Command;

    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let detectors = workspace_detectors();
    let output = Command::new(binary())
        .env("KEYHOG_DETECTORS", detectors)
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
