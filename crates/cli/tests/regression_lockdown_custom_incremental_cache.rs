//! Regression: `--lockdown` must refuse a configured incremental cache path
//! outside the default keyhog cache root.

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn run_lockdown_with_custom_cache(input: &Path, cache_path: &Path) -> (String, Option<i32>) {
    let home = TempDir::new().expect("home tempdir");
    let input = input.to_str().expect("utf-8 input path");
    let cache = cache_path.to_str().expect("utf-8 cache path");
    let args = [
        "scan",
        "--daemon=off",
        "--lockdown",
        "--incremental",
        "--incremental-cache",
        cache,
        "--format",
        "json",
        input,
    ];

    let direct = || {
        Command::new(binary())
            .args(args)
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path())
            .output()
            .expect("spawn keyhog")
    };

    let output = {
        let mut cmd = Command::new("prlimit");
        cmd.args(["--core=0"]).arg(binary()).args(args);
        cmd.env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path());
        match cmd.output() {
            Ok(output) => output,
            Err(_) => direct(),
        }
    };

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (combined, output.status.code())
}

#[test]
fn lockdown_refuses_custom_incremental_cache_file() {
    let input_dir = TempDir::new().expect("input tempdir");
    let input = input_dir.path().join("clean.txt");
    std::fs::write(&input, "clean\n").expect("write clean input");

    let cache_dir = TempDir::new().expect("cache tempdir");
    let cache_path = cache_dir.path().join("merkle.idx");
    std::fs::write(&cache_path, b"cached metadata\n").expect("write merkle cache");

    let (combined, code) = run_lockdown_with_custom_cache(&input, &cache_path);

    assert_eq!(
        code,
        Some(2),
        "lockdown with a custom existing incremental cache must exit 2; output={combined}"
    );
    assert!(
        combined.contains(&cache_path.to_string_lossy().to_string()),
        "lockdown error must name the configured cache path; output={combined}"
    );
    assert!(
        combined.contains("lockdown disk cache exists"),
        "lockdown error must identify the persistence-cache violation; output={combined}"
    );
}
