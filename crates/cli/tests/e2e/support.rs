//! Shared helpers for end-to-end binary tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

pub fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("spawn keyhog")
}

pub fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

/// Write `content` to a temp file, scan with `--format json`, return output.
pub fn scan_text_file(content: &str, extra_args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, content).expect("write fixture");

    let mut cmd_args: Vec<String> = vec![
        "scan".into(),
        "--no-daemon".into(),
        "--format".into(),
        "json".into(),
    ];
    for arg in extra_args {
        cmd_args.push((*arg).into());
    }
    cmd_args.push(path.to_string_lossy().into_owned());

    let output = Command::new(binary())
        .args(&cmd_args)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

pub fn write_temp_file(name: &str, content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");
    (dir, path)
}

pub fn scan_path(path: &Path, extra_args: &[&str]) -> Output {
    let mut args = vec!["scan", "--no-daemon", "--format", "json"];
    args.extend(extra_args);
    args.push(path.to_str().expect("utf-8 path"));
    Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog scan")
}
