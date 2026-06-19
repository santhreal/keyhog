//! A malformed `.keyhog.toml` must fail closed once, not warn and scan defaults.
//!
//! `EffectivePolicy::resolve` (crates/cli/src/subcommands/scan.rs) applies the
//! config to a THROWAWAY probe clone to decide the daemon route, and the
//! orchestrator then applies it again on the real path. Before the fix BOTH
//! calls used the loud `apply_config_file`, so a parse failure printed
//! "Failed to parse .keyhog.toml" TWICE. Later, the single warning still fell
//! through to compiled defaults. The probe now records the parse error quietly,
//! and the real merge emits one user-error failure before any scan runs.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn malformed_config_fails_closed_with_one_operator_error() {
    let dir = TempDir::new().expect("tempdir");
    // Invalid TOML that `toml::from_str` rejects (the parse-failure branch).
    let config_path = dir.path().join(".keyhog.toml");
    std::fs::write(&config_path, "this is not = = valid toml [[[\n").unwrap();
    std::fs::write(dir.path().join("code.txt"), "nothing secret here\n").unwrap();

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "malformed config must be a user/config error; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.is_empty(),
        "malformed config must fail before scan/report output; stdout={stdout}"
    );
    let failures = stderr.matches("invalid .keyhog.toml configuration").count();
    assert_eq!(
        failures, 1,
        "a malformed .keyhog.toml must surface exactly one operator error. \
         Saw {failures} occurrence(s).\n\
         --- stderr ---\n{stderr}"
    );
    let config_display = config_path.to_string_lossy();
    for required in [
        config_display.as_ref(),
        "failed to parse TOML",
        "Fix: correct the TOML syntax",
    ] {
        assert!(
            stderr.contains(required),
            "stderr missing `{required}`; stderr={stderr}"
        );
    }
    assert!(
        !stderr.contains("Failed to parse .keyhog.toml"),
        "old warning-and-defaults path must not survive; stderr={stderr}"
    );
}
