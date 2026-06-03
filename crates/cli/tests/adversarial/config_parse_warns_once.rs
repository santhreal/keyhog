//! HUNT-2: a malformed `.keyhog.toml` must warn EXACTLY ONCE, not twice.
//!
//! `EffectivePolicy::resolve` (crates/cli/src/subcommands/scan.rs) applies the
//! config to a THROWAWAY probe clone to decide the daemon route, and the
//! orchestrator then applies it again on the real path. Before the fix BOTH
//! calls used the loud `apply_config_file`, so a parse failure printed
//! "Failed to parse .keyhog.toml" TWICE. The probe now uses the diagnostics-free
//! `apply_config_file_quiet`, leaving exactly one emission on the real merge.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn malformed_config_warns_exactly_once() {
    let dir = TempDir::new().expect("tempdir");
    // Invalid TOML that `toml::from_str` rejects (the parse-failure branch).
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "this is not = = valid toml [[[\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("code.txt"), "nothing secret here\n").unwrap();

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The eprintln warning text is capitalised ("Failed to parse"); the separate
    // tracing::warn uses lowercase ("failed to parse"), so this counts only the
    // operator-facing eprintln emissions.
    let warnings = stderr.matches("Failed to parse .keyhog.toml").count();
    assert_eq!(
        warnings, 1,
        "a malformed .keyhog.toml must warn EXACTLY ONCE — the daemon-routing \
         probe uses the diagnostics-free apply_config_file_quiet and the real \
         merge emits once (HUNT-2). Saw {warnings} occurrence(s).\n\
         --- stderr ---\n{stderr}"
    );
}
