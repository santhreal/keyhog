//! KH-GAP-147: `--dogfood` scan still printed "Pass --dogfood to see them"
//! even when --dogfood was already active.

use crate::e2e::support::binary;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn dogfood_active_summary_does_not_tell_user_to_pass_dogfood_again() {
    let demo = repo_root().join("demo/config/demo-secret.env");
    let out = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--dogfood",
            "--format",
            "text",
        ])
        .arg(&demo)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("Pass --dogfood"),
        "when --dogfood is active, summary must not say Pass --dogfood; stdout={stdout}"
    );
    assert!(
        stdout.contains("example/test key"),
        "summary must still mention suppressed examples; stdout={stdout}"
    );
}
