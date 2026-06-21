//! A `.keyhog.toml` keyword list containing an empty `""` entry must fail
//! closed at the config boundary, not crash mid-scan.
//!
//! An empty keyword is a meaningless match needle, and it reaches
//! `slice::windows(0)` in the entropy keyword/placeholder scan
//! (`entropy::keywords::is_keyword_assignment_line`,
//! `entropy::plausibility::is_placeholder_ci`), which panics with "size is
//! zero". Before the boundary check in `crates/cli/src/config.rs`
//! (`keyword_list_is_nonempty`), a config typo like
//! `placeholder_keywords = [""]` flowed through `apply_config_file` ->
//! `ScanConfig` -> the scanner and aborted a live scan with an opaque panic.
//! Now `resolve_scan_config` rejects it with the single operator-visible
//! "invalid .keyhog.toml configuration" error (exit code 2) before any scan
//! runs.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn assert_empty_keyword_rejected(field: &str, toml_line: &str) {
    let dir = TempDir::new().expect("tempdir");
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, format!("{toml_line}\n")).unwrap();
    // A high-entropy assignment that, absent the boundary check, would reach the
    // placeholder/keyword entropy path and panic on the empty needle.
    std::fs::write(
        dir.path().join("code.txt"),
        "api_key = \"a9F3kQz7Lm2Wp0Xr8Tb6Vn4Hc1Yd5G\"\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(2),
        "empty `{field}` entry must be a user/config error (exit 2), not a panic \
         or a defaults scan; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.is_empty(),
        "empty `{field}` entry must fail before any scan/report output; stdout={stdout}"
    );
    assert!(
        stderr.contains("invalid .keyhog.toml configuration"),
        "empty `{field}` entry must surface the operator config error; stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("{field}: entries must not be empty")),
        "config error must name the offending field `{field}` and the fix; stderr={stderr}"
    );
    // The bug it guards against is a `slice::windows(0)` panic; assert no panic
    // text leaked and the process did not abort with a panic/signal code.
    assert!(
        !stderr.contains("panicked") && !stderr.contains("size is zero"),
        "must fail closed at the config boundary, never panic; stderr={stderr}"
    );
}

#[test]
fn empty_placeholder_keyword_entry_fails_closed() {
    assert_empty_keyword_rejected("placeholder_keywords", "placeholder_keywords = [\"\"]");
}

#[test]
fn empty_secret_keyword_entry_fails_closed() {
    assert_empty_keyword_rejected("secret_keywords", "secret_keywords = [\"token\", \"\"]");
}

#[test]
fn empty_test_keyword_entry_fails_closed() {
    assert_empty_keyword_rejected("test_keywords", "test_keywords = [\"\"]");
}

#[test]
fn empty_known_prefix_entry_fails_closed() {
    assert_empty_keyword_rejected("known_prefixes", "known_prefixes = [\"sk-\", \"\"]");
}
