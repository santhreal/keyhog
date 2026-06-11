//! `--no-config`: hermetic scans that ignore any ambient `.keyhog.toml`.
//!
//! The benchmark harness lives inside the repo tree, so its corpora sit under
//! ancestors that may carry a `.keyhog.toml`. `find_config_file` walks up to the
//! filesystem root, so without an opt-out the benched config would silently
//! merge that stray file and drift from the shipped defaults the leaderboard
//! claims to measure (backlog MC-07). `--no-config` skips discovery entirely and
//! runs on the compiled Tier-A shipped defaults BY DESIGN.
//!
//! Bidirectional contract, driven through the real binary ("the product is the
//! binary", CLAUDE.md test type 10):
//!   * a `[detector.aws-access-key] enabled = false` config IS honored on the
//!     default path — the planted AWS key is suppressed (exit 0); and
//!   * the SAME config is IGNORED under `--no-config` — the key fires (exit 1).
//! Plus the clap guard: `--config` and `--no-config` together is a user error.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted AWS access key id (`aws-access-key` detector) — concatenated so the
/// literal token never appears in source and trips the repo's own self-scan.
const PLANTED: &str = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

/// Config that disables the detector the planted key fires.
const DISABLE_AWS: &str = "[detector.aws-access-key]\nenabled = false\n";

/// Write the planted fixture + a `.keyhog.toml` into a temp dir, scan the dir
/// with the given extra args, and return (exit code, stdout, stderr).
fn scan_dir_with_config(config: &str, extra: &[&str]) -> (Option<i32>, String, String) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("planted.txt"), PLANTED).expect("write fixture");
    std::fs::write(dir.path().join(".keyhog.toml"), config).expect("write config");

    let output = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--format")
        .arg("json")
        .args(extra)
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");

    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn ambient_config_is_honored_without_no_config() {
    // Baseline: the `.keyhog.toml` disables `aws-access-key`, so the planted key
    // is suppressed and the scan exits clean. This proves the config genuinely
    // changes behavior — without it the next test's assertion would be vacuous.
    let (code, stdout, stderr) = scan_dir_with_config(DISABLE_AWS, &[]);
    assert_eq!(
        code,
        Some(0),
        "an ambient `.keyhog.toml` disabling aws-access-key must be honored on \
         the default path (planted key suppressed → exit 0).\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}

#[test]
fn no_config_ignores_ambient_keyhog_toml() {
    // The identical `.keyhog.toml` is present, but `--no-config` skips discovery,
    // so the detector stays enabled and the planted key fires (exit 1). This is
    // the hermetic guarantee the bench relies on.
    let (code, stdout, stderr) = scan_dir_with_config(DISABLE_AWS, &["--no-config"]);
    assert_eq!(
        code,
        Some(1),
        "`--no-config` must ignore an ambient `.keyhog.toml`: the planted \
         aws-access-key key must still fire (exit 1) despite the on-disk \
         `enabled = false` (MC-07 hermeticity).\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stdout.contains("aws-access-key"),
        "the hermetic scan must report the aws-access-key finding the on-disk \
         config tried to suppress.\n--- stdout ---\n{stdout}"
    );
}

#[test]
fn config_and_no_config_conflict_is_a_user_error() {
    // clap `conflicts_with = "config"`: passing both is a usage error (exit 2),
    // so an operator can't ask to both ignore config and load a specific one.
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("planted.txt"), PLANTED).expect("write fixture");
    let cfg_path = dir.path().join("explicit.toml");
    std::fs::write(&cfg_path, DISABLE_AWS).expect("write config");

    let output = Command::new(binary())
        .arg("scan")
        .arg("--no-config")
        .arg("--config")
        .arg(&cfg_path)
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "`--no-config` together with `--config` must be a clap usage error \
         (exit 2).\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
