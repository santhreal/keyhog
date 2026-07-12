//! Adversarial (Unix): explicit --detectors works while legacy KEYHOG_DETECTORS is ignored.

#[cfg(unix)]
#[test]
fn keyhog_detectors_valid_path_unix() {
    use crate::support::{binary, workspace_detectors, write_temp_file};
    use std::process::Command;

    let (_dir, path) = write_temp_file("clean.txt", "ok\n");
    let detectors = workspace_detectors();
    let missing = tempfile::tempdir()
        .expect("tempdir")
        .path()
        .join("missing-detectors");
    let output = Command::new(binary())
        .env("KEYHOG_DETECTORS", missing)
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--detectors",
        ])
        .arg(detectors)
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
