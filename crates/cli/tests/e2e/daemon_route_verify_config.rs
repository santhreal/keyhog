#![cfg(unix)]

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn forced_daemon_rejects_config_verify_without_connecting() {
    let work = TempDir::new().expect("work dir");
    std::fs::write(work.path().join(".keyhog.toml"), "verify = true\n").expect("write config");
    let path = work.path().join("leak.env");
    std::fs::write(&path, "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n").expect("write fixture");
    let runtime = TempDir::new().expect("isolated runtime");

    let out = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon=on", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "forced daemon with config verify=true must fail before daemon connect; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("--daemon=on cannot be honored")
            && stderr.contains("verification requires the in-process verifier"),
        "forced-daemon rejection must name the verifier mismatch; stderr={stderr:?}"
    );
    assert!(
        !stdout.contains("aws-access-key"),
        "forced daemon rejection must not scan after dropping config verify=true; stdout={stdout:?}"
    );
}
